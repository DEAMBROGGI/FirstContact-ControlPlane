from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .domain import AutomatedReviewStatus, DomainError, EventType, PublicationState
from .github_api import (
    GitHubApiError,
    GitHubRepositoryGateway,
    PullReviewCommentSnapshot,
)
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .github_review_auth import (
    GitHubReviewAuthError,
    GitHubReviewTokenProvider,
)
from .repository import load_events
from .service import (
    claim_codex_review_trigger_dispatch,
    complete_codex_review,
    complete_codex_review_trigger_dispatch,
    get_view,
    mark_codex_review_unavailable,
    release_codex_review_trigger_dispatch,
    request_codex_review,
)

_RESERVED_CODEX_MENTION = re.compile(r"(?i)(?<![A-Za-z0-9_])@codex\b")


class CodexReviewError(RuntimeError):
    pass


def assert_no_reserved_automation_mentions(value: str) -> None:
    if _RESERVED_CODEX_MENTION.search(value or ""):
        raise DomainError("@codex is reserved for Control Plane automation")


def _actor_key(value: str) -> str:
    return value.strip().lower()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError as exc:
        raise CodexReviewError("GitHub review timestamp is invalid") from exc


@dataclass(frozen=True, slots=True)
class CodexReviewObservation:
    run_id: str
    state: str
    matching_reviews: int
    matching_comments: int
    matching_reactions: int
    actors: tuple[str, ...]


class CodexReviewBroker:
    TRIGGER_TEXT = "@codex review"

    def __init__(
        self,
        *,
        token_provider: GitHubAppTokenProvider,
        github: GitHubRepositoryGateway,
        mode: str,
        allowed_actors: tuple[str, ...] = (),
        trigger_user: GitHubReviewTokenProvider | None = None,
    ) -> None:
        normalized_mode = mode.strip().lower()
        if normalized_mode not in {"disabled", "advisory", "required"}:
            raise CodexReviewError("invalid Codex review mode")
        self.token_provider = token_provider
        self.github = github
        self.mode = normalized_mode
        self.allowed_actors = tuple(
            _actor_key(actor)
            for actor in allowed_actors
            if actor.strip()
        )
        self.trigger_user = trigger_user

    @staticmethod
    def _marker(run_id: str, head_sha: str) -> str:
        return (
            "<!-- firstcontact-control-plane:codex-review "
            f"run={run_id} head={head_sha} -->"
        )

    @classmethod
    def _trigger_body(cls, run_id: str, head_sha: str) -> str:
        return f"{cls.TRIGGER_TEXT}\n\n{cls._marker(run_id, head_sha)}"

    def _review_access(self, repository: str):
        return self.token_provider.installation_access(
            repository,
            permissions={
                "issues": "read",
                "pull_requests": "read",
            },
        )

    @staticmethod
    def _published_at(session: Session, publication_id: str, head_sha: str) -> datetime:
        matches = [
            event
            for event in load_events(session, publication_id)
            if event["event_type"] == EventType.REMOTE_PUBLISHED.value
            and event["payload"].get("head_sha") == head_sha
        ]
        if not matches:
            raise CodexReviewError("published head has no publication event")
        observed = _parse_time(matches[-1].get("occurred_at"))
        if observed is None:
            raise CodexReviewError("published head timestamp is missing")
        # GitHub issue comments expose second precision. Flooring the
        # publication cutoff makes same-second invocations ambiguous and
        # therefore fail closed, while comments from earlier seconds remain
        # historical.
        return observed.replace(microsecond=0)

    @staticmethod
    def _verify_exact_pr(view, pull) -> None:
        if view.pull_request_number is None:
            raise CodexReviewError("publication has no pull request")
        if pull.number != view.pull_request_number:
            raise CodexReviewError("pull request identity mismatch")
        if pull.state != "open":
            raise CodexReviewError("pull request is not open")
        if pull.head_sha != view.remote_head_sha:
            raise CodexReviewError("pull request head moved")
        if view.remote_branch is not None and pull.head_ref != view.remote_branch:
            raise CodexReviewError("pull request head ref moved")
        if view.base_branch is not None and pull.base_ref != view.base_branch:
            raise CodexReviewError("pull request base moved")

    @staticmethod
    def _trigger_is_registered(view, head_sha: str) -> bool:
        if (
            view.automated_review_status is not AutomatedReviewStatus.RUNNING
            or view.automated_review_head_sha != head_sha
            or not view.automated_review_run_id
            or view.automated_review_trigger_comment_id is None
            or view.automated_review_trigger_comment_id <= 0
            or not view.automated_review_trigger_actor
            or not view.automated_review_trigger_actor.strip()
            or not view.automated_review_triggered_at
        ):
            return False
        try:
            return _parse_time(view.automated_review_triggered_at) is not None
        except CodexReviewError:
            return False

    def request(self, session: Session, publication_id: str):
        if self.mode == "disabled":
            raise DomainError("Codex review broker is disabled")

        view = get_view(session, publication_id)
        if view.remote_head_sha is None or view.pull_request_number is None:
            raise DomainError("Codex review requires published PR metadata")

        lease_id: str | None = None
        run_id: str | None = None
        try:
            access = self._review_access(view.repository)
            pull = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            self._verify_exact_pr(view, pull)

            # Re-read after the remote PR/head check so retries make their
            # decision from the current event fold, not a stale initial view.
            view = get_view(session, publication_id)
            if (
                view.remote_head_sha != pull.head_sha
                or view.pull_request_number != pull.number
            ):
                raise CodexReviewError(
                    "publication PR/head changed during Codex request"
                )
            self._verify_exact_pr(view, pull)

            same_review_head = view.automated_review_head_sha == pull.head_sha
            if same_review_head and view.automated_review_status in {
                AutomatedReviewStatus.PASS,
                AutomatedReviewStatus.CHANGES_REQUIRED,
            }:
                return view
            if same_review_head and view.automated_review_status is AutomatedReviewStatus.RUNNING:
                if view.automated_review_run_id is None:
                    raise CodexReviewError(
                        "active Codex review metadata is incomplete"
                    )
                if self._trigger_is_registered(view, pull.head_sha):
                    return view
            elif (
                view.automated_review_status is AutomatedReviewStatus.RUNNING
                and view.automated_review_head_sha != pull.head_sha
            ):
                raise CodexReviewError(
                    "active Codex review is bound to a different head"
                )

            if view.state is not PublicationState.IN_REVIEW:
                raise DomainError("Codex review requires IN_REVIEW state")

            if self.trigger_user is None:
                raise CodexReviewError(
                    "Codex trigger user credential is not configured"
                )
            trigger_access = self.trigger_user.access()

            locked = request_codex_review(
                session,
                publication_id,
                mode=self.mode,
                expected_head_sha=pull.head_sha,
            )
            if locked.automated_review_status is not AutomatedReviewStatus.RUNNING:
                return locked
            assert locked.automated_review_run_id is not None
            run_id = locked.automated_review_run_id

            marker = self._marker(run_id, locked.remote_head_sha or "")
            lease_id = str(uuid.uuid4())
            acquired = claim_codex_review_trigger_dispatch(
                session,
                publication_id,
                run_id=run_id,
                lease_id=lease_id,
            )
            if not acquired:
                return get_view(session, publication_id)

            published_at = self._published_at(
                session,
                publication_id,
                locked.remote_head_sha or "",
            )
            issue_comments = self.github.list_issue_comments(
                locked.repository,
                locked.pull_request_number or 0,
                access.token,
            )
            foreign_invocations = [
                item
                for item in issue_comments
                if _RESERVED_CODEX_MENTION.search(item.body or "")
                and marker not in item.body
                and (_parse_time(item.created_at) or published_at) >= published_at
            ]
            if foreign_invocations:
                raise CodexReviewError(
                    "pre-existing Codex invocation makes governed review ambiguous"
                )
            existing = [
                item for item in issue_comments if marker in item.body
            ]
            if any(
                _actor_key(item.actor) != _actor_key(trigger_access.login)
                for item in existing
            ):
                raise CodexReviewError(
                    "Codex trigger marker was emitted by an unexpected actor"
                )
            if len(existing) > 1:
                raise CodexReviewError("multiple Codex trigger comments exist")

            if existing:
                comment = existing[0]
            else:
                comment = self.github.add_issue_comment(
                    locked.repository,
                    locked.pull_request_number or 0,
                    self._trigger_body(run_id, locked.remote_head_sha or ""),
                    trigger_access.token,
                )
                if _actor_key(comment.actor) != _actor_key(trigger_access.login):
                    raise CodexReviewError(
                        "Codex trigger comment actor does not match authorized user"
                    )

            return complete_codex_review_trigger_dispatch(
                session,
                publication_id,
                run_id=run_id,
                lease_id=lease_id,
                comment_id=comment.comment_id,
                actor=comment.actor,
                created_at=comment.created_at,
            )
        except (
            GitHubAuthError,
            GitHubReviewAuthError,
            GitHubApiError,
            CodexReviewError,
            DomainError,
        ) as exc:
            if lease_id is not None and run_id is not None:
                release_codex_review_trigger_dispatch(
                    session,
                    publication_id,
                    run_id=run_id,
                    lease_id=lease_id,
                )
            latest = get_view(session, publication_id)
            if (
                latest.automated_review_status is AutomatedReviewStatus.RUNNING
                and latest.automated_review_run_id is not None
                and latest.automated_review_head_sha is not None
                and not self._trigger_is_registered(
                    latest,
                    latest.remote_head_sha or "",
                )
            ):
                mark_codex_review_unavailable(
                    session,
                    publication_id,
                    run_id=latest.automated_review_run_id,
                    reviewed_head_sha=latest.automated_review_head_sha,
                    reason="CODEX_TRIGGER_UNAVAILABLE",
                )
            raise CodexReviewError("Codex review trigger failed closed") from exc

    @staticmethod
    def _normalize_finding(
        comment: PullReviewCommentSnapshot,
    ) -> dict[str, object]:
        return {
            "provider_comment_id": comment.comment_id,
            "provider_review_id": comment.review_id,
            "path": comment.path,
            "line": comment.line,
            "body": comment.body.strip()[:4000],
        }

    def _is_allowed_actor(self, actor: str) -> bool:
        return _actor_key(actor) in self.allowed_actors
    def reconcile(
        self,
        session: Session,
        publication_id: str,
    ) -> CodexReviewObservation:
        view = get_view(session, publication_id)
        if view.automated_review_status is not AutomatedReviewStatus.RUNNING:
            raise DomainError("publication has no active Codex review")
        if (
            view.automated_review_run_id is None
            or view.automated_review_head_sha is None
            or view.pull_request_number is None
            or view.automated_review_trigger_comment_id is None
            or view.automated_review_trigger_actor is None
            or view.automated_review_triggered_at is None
        ):
            raise DomainError("active Codex review metadata is incomplete")
        if not self.allowed_actors:
            raise CodexReviewError("Codex review actor allowlist is not configured")

        trigger_time = _parse_time(view.automated_review_triggered_at)
        assert trigger_time is not None
        marker = self._marker(
            view.automated_review_run_id,
            view.automated_review_head_sha,
        )

        try:
            access = self._review_access(view.repository)
            pull = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            self._verify_exact_pr(view, pull)
            issue_comments = self.github.list_issue_comments(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            reviews = self.github.list_pull_reviews(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            comments = self.github.list_pull_review_comments(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            reactions = self.github.list_issue_comment_reactions(
                view.repository,
                view.automated_review_trigger_comment_id,
                access.token,
            )
        except (GitHubAuthError, GitHubApiError, CodexReviewError) as exc:
            raise CodexReviewError(
                "Codex review reconciliation failed closed"
            ) from exc

        trigger_matches = [
            item
            for item in issue_comments
            if item.comment_id == view.automated_review_trigger_comment_id
        ]
        if len(trigger_matches) != 1:
            raise CodexReviewError("governed Codex trigger comment is missing")
        trigger = trigger_matches[0]
        if marker not in trigger.body:
            raise CodexReviewError("governed Codex trigger marker is missing")
        if _actor_key(trigger.actor) != _actor_key(
            view.automated_review_trigger_actor
        ):
            raise CodexReviewError("governed Codex trigger actor changed")
        if _parse_time(trigger.created_at) != trigger_time:
            raise CodexReviewError("governed Codex trigger timestamp changed")

        ambiguous_invocations = [
            item
            for item in issue_comments
            if item.comment_id != trigger.comment_id
            and _RESERVED_CODEX_MENTION.search(item.body or "")
            and (_parse_time(item.created_at) or trigger_time) >= trigger_time
        ]
        if ambiguous_invocations:
            raise CodexReviewError(
                "additional Codex invocation detected during governed review"
            )

        matching_reviews = []
        for item in reviews:
            submitted = _parse_time(item.submitted_at)
            if (
                self._is_allowed_actor(item.actor)
                and item.state.strip().upper() == "COMMENTED"
                and item.commit_id == view.automated_review_head_sha
                and submitted is not None
                and submitted >= trigger_time
            ):
                matching_reviews.append(item)

        matching_review_ids = {item.review_id for item in matching_reviews}
        matching_comments = []
        for item in comments:
            created = _parse_time(item.created_at)
            if (
                self._is_allowed_actor(item.actor)
                and item.commit_id == view.automated_review_head_sha
                and created is not None
                and created >= trigger_time
                and item.review_id in matching_review_ids
            ):
                matching_comments.append(item)

        matching_reactions = []
        for item in reactions:
            created = _parse_time(item.created_at)
            if (
                self._is_allowed_actor(item.actor)
                and item.content == "+1"
                and created is not None
                and created >= trigger_time
            ):
                matching_reactions.append(item)

        actors = tuple(
            sorted(
                {
                    item.actor
                    for item in [*reviews, *comments, *reactions]
                    if item.actor
                }
            )
        )
        if not matching_reviews and not matching_reactions:
            return CodexReviewObservation(
                run_id=view.automated_review_run_id,
                state="RUNNING",
                matching_reviews=0,
                matching_comments=len(matching_comments),
                matching_reactions=0,
                actors=actors,
            )

        findings = [
            self._normalize_finding(item)
            for item in matching_comments
            if item.body.strip()
        ]
        result = (
            AutomatedReviewStatus.CHANGES_REQUIRED
            if findings
            else AutomatedReviewStatus.PASS
        )
        complete_codex_review(
            session,
            publication_id,
            run_id=view.automated_review_run_id,
            reviewed_head_sha=view.automated_review_head_sha,
            result=result,
            findings=findings,
            provider_review_ids=[item.review_id for item in matching_reviews],
            provider_comment_ids=[item.comment_id for item in matching_comments],
            provider_reaction_ids=[
                item.reaction_id for item in matching_reactions
            ],
        )
        return CodexReviewObservation(
            run_id=view.automated_review_run_id,
            state=result.value,
            matching_reviews=len(matching_reviews),
            matching_comments=len(matching_comments),
            matching_reactions=len(matching_reactions),
            actors=actors,
        )
