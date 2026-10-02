from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .domain import AutomatedReviewStatus, DomainError, EventType, PublicationState
from .github_api import (
    GitHubApiError,
    GitHubRepositoryGateway,
    IssueCommentSnapshot,
    PullReviewCommentSnapshot,
)
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .github_review_auth import (
    GitHubReviewAuthError,
    GitHubReviewTokenProvider,
)
from .models import GitHubWebhookDeliveryRow
from .repository import load_events
from .service import (
    claim_codex_review_trigger_dispatch,
    complete_codex_review,
    complete_codex_review_trigger_dispatch,
    fence_codex_review_trigger_dispatch,
    get_view,
    invalidate_codex_review,
    mark_codex_review_unavailable,
    release_codex_review_trigger_dispatch,
    request_codex_review,
)

_RESERVED_CODEX_MENTION = re.compile(r"(?i)(?<![A-Za-z0-9_])@codex\b")
_CODEX_USAGE_LIMIT = re.compile(
    r"(?is)reached\s+your\s+codex\s+usage\s+limits\s+for\s+code\s+reviews"
)


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
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CodexReviewError("GitHub review timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_provider_time(value: object, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise CodexReviewError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CodexReviewError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise CodexReviewError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def assert_no_ambiguous_codex_invocations(
    comments: list[IssueCommentSnapshot],
    *,
    trigger_comment_id: int,
    trigger_time: datetime,
) -> None:
    ambiguous_invocations = [
        item
        for item in comments
        if item.comment_id != trigger_comment_id
        and _RESERVED_CODEX_MENTION.search(item.body or "")
        and (_parse_time(item.created_at) or trigger_time) >= trigger_time
    ]
    if ambiguous_invocations:
        raise CodexReviewError(
            "additional Codex invocation detected during governed review"
        )


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
    def _verify_exact_pr(
        view,
        pull,
        *,
        allow_stale_head: bool = False,
        allow_merged: bool = False,
    ) -> None:
        if view.pull_request_number is None:
            raise CodexReviewError("publication has no pull request")
        if pull.number != view.pull_request_number:
            raise CodexReviewError("pull request identity mismatch")
        if pull.state.strip().lower() != "open" and not (
            allow_merged and pull.merged
        ):
            raise CodexReviewError("pull request is not open")
        if not allow_stale_head and pull.head_sha != view.remote_head_sha:
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

    @staticmethod
    def _terminal_event(session: Session, view):
        if view.automated_review_status in {
            AutomatedReviewStatus.PASS,
            AutomatedReviewStatus.CHANGES_REQUIRED,
        }:
            expected_result = view.automated_review_status.value
            matches = [
                event
                for event in load_events(session, view.publication_id)
                if event["event_type"] == EventType.CODEX_REVIEW_COMPLETED.value
                and event["payload"].get("run_id") == view.automated_review_run_id
                and event["payload"].get("head_sha") == view.automated_review_head_sha
                and event["payload"].get("result") == expected_result
            ]
        elif view.automated_review_status is AutomatedReviewStatus.UNAVAILABLE:
            matches = [
                event
                for event in load_events(session, view.publication_id)
                if event["event_type"] == EventType.CODEX_REVIEW_UNAVAILABLE.value
                and event["payload"].get("run_id") == view.automated_review_run_id
                and event["payload"].get("head_sha") == view.automated_review_head_sha
            ]
        else:
            return None
        if len(matches) != 1:
            raise CodexReviewError("Codex terminal evidence is missing or ambiguous")
        return matches[0]

    @staticmethod
    def _terminal_time(event) -> datetime | None:
        payload = event["payload"]
        field = (
            "provider_completed_at"
            if event["event_type"] == EventType.CODEX_REVIEW_COMPLETED.value
            else "provider_occurred_at"
        )
        return _parse_provider_time(payload.get(field), f"Codex {field}")

    def _deleted_issue_invocation_ids(
        self,
        session: Session,
        view,
        *,
        trigger_time: datetime,
        terminal_time: datetime | None,
    ) -> tuple[int, ...]:
        if view.pull_request_number is None:
            raise CodexReviewError("Codex pull request metadata is incomplete")

        deliveries = session.scalars(
            select(GitHubWebhookDeliveryRow).where(
                GitHubWebhookDeliveryRow.event_name == "issue_comment",
                GitHubWebhookDeliveryRow.action == "deleted",
                GitHubWebhookDeliveryRow.repository == view.repository,
                GitHubWebhookDeliveryRow.pull_request_number
                == view.pull_request_number,
            )
        )
        deleted_ids = []
        for delivery in deliveries:
            payload = delivery.payload
            repository = payload.get("repository") if isinstance(payload, dict) else None
            issue = payload.get("issue") if isinstance(payload, dict) else None
            if (
                not isinstance(repository, dict)
                or repository.get("full_name") != view.repository
                or not isinstance(issue, dict)
                or not isinstance(issue.get("pull_request"), dict)
                or issue.get("number") != view.pull_request_number
            ):
                raise CodexReviewError("deleted issue-comment evidence is incomplete")
            comment = payload.get("comment")
            if not isinstance(comment, dict):
                raise CodexReviewError("deleted issue-comment evidence is incomplete")
            comment_id = comment.get("id")
            if (
                isinstance(comment_id, bool)
                or not isinstance(comment_id, int)
                or comment_id <= 0
            ):
                raise CodexReviewError("deleted issue-comment evidence is incomplete")
            if comment_id == view.automated_review_trigger_comment_id:
                continue
            body = comment.get("body")
            if not isinstance(body, str):
                raise CodexReviewError("deleted issue-comment evidence is incomplete")
            if not _RESERVED_CODEX_MENTION.search(body):
                continue
            created_time = _parse_time(
                comment.get("created_at")
                if isinstance(comment.get("created_at"), str)
                else None
            )
            if created_time is None:
                raise CodexReviewError("deleted invocation timestamp is missing")
            if created_time < trigger_time:
                continue
            if view.automated_review_status is AutomatedReviewStatus.RUNNING:
                raise CodexReviewError(
                    "additional Codex invocation detected during governed review"
                )
            if terminal_time is None or created_time < terminal_time:
                deleted_ids.append(comment_id)
        return tuple(sorted(set(deleted_ids)))

    def _deleted_review_finding_ids(
        self,
        session: Session,
        view,
        *,
        reviews,
        trigger_time: datetime,
        terminal_event,
        terminal_time: datetime | None,
    ) -> tuple[int, ...]:
        if view.pull_request_number is None:
            raise CodexReviewError("Codex pull request metadata is incomplete")
        deliveries = session.scalars(
            select(GitHubWebhookDeliveryRow).where(
                GitHubWebhookDeliveryRow.event_name == "pull_request_review_comment",
                GitHubWebhookDeliveryRow.action == "deleted",
                GitHubWebhookDeliveryRow.repository == view.repository,
                GitHubWebhookDeliveryRow.pull_request_number
                == view.pull_request_number,
            )
        )
        deleted_ids = []
        for delivery in deliveries:
            payload = delivery.payload
            repository = payload.get("repository") if isinstance(payload, dict) else None
            pull = payload.get("pull_request") if isinstance(payload, dict) else None
            if (
                not isinstance(repository, dict)
                or repository.get("full_name") != view.repository
                or not isinstance(pull, dict)
                or pull.get("number") != view.pull_request_number
            ):
                raise CodexReviewError(
                    "deleted review-comment evidence does not match its delivery"
                )
            comment = payload.get("comment")
            if not isinstance(comment, dict):
                raise CodexReviewError("deleted review-comment evidence is incomplete")
            comment_id = comment.get("id")
            review_id = comment.get("pull_request_review_id")
            if (
                isinstance(comment_id, bool)
                or not isinstance(comment_id, int)
                or comment_id <= 0
                or isinstance(review_id, bool)
                or not isinstance(review_id, int)
                or review_id <= 0
            ):
                raise CodexReviewError("deleted review-comment evidence is incomplete")
            user = comment.get("user")
            actor = (
                _actor_key(str(user.get("login") or ""))
                if isinstance(user, dict)
                else ""
            )
            if actor not in self.allowed_actors:
                continue
            head = pull.get("head")
            payload_head = str(head.get("sha") or "").lower() if isinstance(head, dict) else ""
            commit_id = str(comment.get("commit_id") or "").lower()
            if (
                payload_head != view.automated_review_head_sha
                or commit_id != view.automated_review_head_sha
            ):
                continue
            body = comment.get("body")
            if not isinstance(body, str) or not body.strip():
                continue
            created_time = _parse_time(
                comment.get("created_at")
                if isinstance(comment.get("created_at"), str)
                else None
            )
            if created_time is None:
                raise CodexReviewError("deleted review-comment timestamp is missing")
            if created_time < trigger_time:
                continue
            parent_reviews = []
            for review in reviews:
                if (
                    review.review_id != review_id
                    or _actor_key(review.actor) != actor
                    or review.state.strip().upper() != "COMMENTED"
                    or review.commit_id != view.automated_review_head_sha
                ):
                    continue
                submitted_time = _parse_time(review.submitted_at)
                if submitted_time is None:
                    raise CodexReviewError(
                        "deleted finding parent review timestamp is missing"
                    )
                if submitted_time >= trigger_time and submitted_time <= created_time:
                    parent_reviews.append(review)
            if view.automated_review_status is AutomatedReviewStatus.RUNNING:
                raise CodexReviewError(
                    "deleted Codex finding makes the active result ambiguous"
                )
            result_payload = terminal_event["payload"] if terminal_event else {}
            recorded_review_ids = result_payload.get("provider_review_ids", [])
            correlated = review_id in recorded_review_ids or bool(parent_reviews)
            if correlated and (
                terminal_time is None or created_time < terminal_time
            ):
                deleted_ids.append(comment_id)
        return tuple(sorted(set(deleted_ids)))

    def assert_no_deleted_ambiguous_invocations(self, session: Session, view) -> None:
        if view.automated_review_status is not AutomatedReviewStatus.RUNNING:
            return
        if (
            view.automated_review_trigger_comment_id is None
            or view.automated_review_triggered_at is None
            or view.pull_request_number is None
        ):
            raise CodexReviewError("active Codex review metadata is incomplete")

        trigger_time = _parse_time(view.automated_review_triggered_at)
        if trigger_time is None:
            raise CodexReviewError("governed Codex trigger timestamp is missing")
        self._deleted_issue_invocation_ids(
            session,
            view,
            trigger_time=trigger_time,
            terminal_time=None,
        )

    def audit_terminal_deletion_evidence(
        self,
        session: Session,
        view,
    ) -> CodexReviewObservation:
        if view.automated_review_status not in {
            AutomatedReviewStatus.PASS,
            AutomatedReviewStatus.CHANGES_REQUIRED,
            AutomatedReviewStatus.UNAVAILABLE,
        }:
            return self._observation(
                view,
                view.automated_review_status.value
                if view.automated_review_status is not None
                else "NOT_RUNNING",
                (),
            )
        if self._has_invalidation(session, view):
            return self._observation(view, "INVALIDATED", ())
        if (
            view.automated_review_run_id is None
            or view.automated_review_head_sha is None
            or view.automated_review_trigger_comment_id is None
            or view.automated_review_triggered_at is None
            or view.pull_request_number is None
        ):
            raise CodexReviewError("terminal Codex review metadata is incomplete")
        trigger_time = _parse_time(view.automated_review_triggered_at)
        if trigger_time is None:
            raise CodexReviewError("governed Codex trigger timestamp is missing")
        terminal_event = self._terminal_event(session, view)
        terminal_time = self._terminal_time(terminal_event)
        deleted_invocations = self._deleted_issue_invocation_ids(
            session,
            view,
            trigger_time=trigger_time,
            terminal_time=terminal_time,
        )
        deleted_findings = self._deleted_review_finding_ids(
            session,
            view,
            reviews=(),
            trigger_time=trigger_time,
            terminal_event=terminal_event,
            terminal_time=terminal_time,
        )
        if deleted_invocations or deleted_findings:
            return self._invalidate(
                session,
                view,
                reason=(
                    "CODEX_DELETED_INVOCATION"
                    if deleted_invocations
                    else "CODEX_DELETED_FINDING"
                ),
                evidence_ids=list(deleted_invocations or deleted_findings),
                actors=(),
            )
        return self._observation(
            view,
            view.automated_review_status.value,
            (),
        )

    def request(self, session: Session, publication_id: str):
        if self.mode == "disabled":
            raise DomainError("Codex review broker is disabled")

        view = get_view(session, publication_id)
        if view.remote_head_sha is None or view.pull_request_number is None:
            raise DomainError("Codex review requires published PR metadata")

        lease_id: str | None = None
        run_id: str | None = None
        uncertain_trigger_write = False
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

            if not fence_codex_review_trigger_dispatch(
                session,
                publication_id,
                run_id=run_id,
                lease_id=lease_id,
            ):
                return get_view(session, publication_id)

            if existing:
                comment = existing[0]
            else:
                trigger_pull = self.github.pull_request(
                    locked.repository,
                    locked.pull_request_number or 0,
                    access.token,
                )
                self._verify_exact_pr(locked, trigger_pull)
                try:
                    comment = self.github.add_issue_comment(
                        locked.repository,
                        locked.pull_request_number or 0,
                        self._trigger_body(run_id, locked.remote_head_sha or ""),
                        trigger_access.token,
                    )
                except GitHubApiError:
                    uncertain_trigger_write = True
                    recovered_comments = self.github.list_issue_comments(
                        locked.repository,
                        locked.pull_request_number or 0,
                        access.token,
                    )
                    recovered = [
                        item for item in recovered_comments if marker in item.body
                    ]
                    if any(
                        _actor_key(item.actor) != _actor_key(trigger_access.login)
                        for item in recovered
                    ):
                        raise CodexReviewError(
                            "uncertain Codex trigger was emitted by an unexpected actor"
                        )
                    if len(recovered) > 1:
                        raise CodexReviewError(
                            "multiple Codex trigger comments exist after uncertain write"
                        )
                    if not recovered:
                        raise
                    comment = recovered[0]
                    uncertain_trigger_write = False
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
                and not uncertain_trigger_write
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

    def _matching_native_evidence(
        self,
        view,
        *,
        trigger_time: datetime,
        reviews,
        comments,
        reactions,
    ):
        matching_reviews = []
        evidence_times = []
        for item in reviews:
            submitted = _parse_time(item.submitted_at)
            candidate = (
                self._is_allowed_actor(item.actor)
                and item.state.strip().upper() == "COMMENTED"
                and item.commit_id == view.automated_review_head_sha
            )
            if candidate and submitted is None:
                raise CodexReviewError("Codex review result timestamp is missing")
            if candidate and submitted >= trigger_time:
                matching_reviews.append(item)
                evidence_times.append(submitted)

        matching_review_ids = {item.review_id for item in matching_reviews}
        matching_comments = []
        for item in comments:
            created = _parse_time(item.created_at)
            candidate = (
                self._is_allowed_actor(item.actor)
                and item.commit_id == view.automated_review_head_sha
                and item.review_id in matching_review_ids
            )
            if candidate and created is None:
                raise CodexReviewError("Codex finding timestamp is missing")
            if candidate and created >= trigger_time:
                matching_comments.append(item)
                evidence_times.append(created)

        matching_reactions = []
        for item in reactions:
            created = _parse_time(item.created_at)
            candidate = self._is_allowed_actor(item.actor) and item.content == "+1"
            if candidate and created is None:
                raise CodexReviewError("Codex reaction timestamp is missing")
            if candidate and created >= trigger_time:
                matching_reactions.append(item)
                evidence_times.append(created)

        return (
            matching_reviews,
            matching_comments,
            matching_reactions,
            evidence_times,
        )

    def _usage_limit_evidence(
        self,
        issue_comments,
        *,
        trigger_comment_id: int,
        trigger_time: datetime,
        comment_id: int | None,
    ):
        if comment_id is not None:
            matches = [item for item in issue_comments if item.comment_id == comment_id]
            if len(matches) != 1:
                raise CodexReviewError(
                    "Codex webhook comment receipt is missing or ambiguous"
                )
            evidence = matches[0]
            if evidence.comment_id == trigger_comment_id:
                raise CodexReviewError("Codex usage-limit evidence collides with trigger")
            created = _parse_time(evidence.created_at)
            if (
                not self._is_allowed_actor(evidence.actor)
                or created is None
                or created <= trigger_time
                or not _CODEX_USAGE_LIMIT.search(evidence.body or "")
            ):
                return None
            return evidence, created

        provider_responses = []
        for item in issue_comments:
            if item.comment_id == trigger_comment_id:
                continue
            if not self._is_allowed_actor(item.actor):
                continue
            created = _parse_time(item.created_at)
            if created is None:
                raise CodexReviewError("Codex provider response timestamp is missing")
            if created > trigger_time:
                provider_responses.append((created, item.comment_id, item))
        provider_responses.sort(key=lambda item: (item[0], item[1]))
        if not provider_responses:
            return None
        evidence_time, _evidence_id, evidence = provider_responses[0]
        if not _CODEX_USAGE_LIMIT.search(evidence.body or ""):
            return None
        return evidence, evidence_time

    @staticmethod
    def _has_invalidation(session: Session, view) -> bool:
        return any(
            event["event_type"] == EventType.CODEX_REVIEW_INVALIDATED.value
            and event["payload"].get("run_id") == view.automated_review_run_id
            and event["payload"].get("head_sha") == view.automated_review_head_sha
            for event in load_events(session, view.publication_id)
        )

    @staticmethod
    def _observation(view, state: str, actors: tuple[str, ...]) -> CodexReviewObservation:
        return CodexReviewObservation(
            run_id=view.automated_review_run_id or "",
            state=state,
            matching_reviews=0,
            matching_comments=0,
            matching_reactions=0,
            actors=actors,
        )

    def _invalidate(
        self,
        session: Session,
        view,
        *,
        reason: str,
        evidence_ids: list[int],
        actors: tuple[str, ...],
    ) -> CodexReviewObservation:
        invalidate_codex_review(
            session,
            view.publication_id,
            run_id=view.automated_review_run_id,
            reviewed_head_sha=view.automated_review_head_sha,
            reason=reason,
            evidence_ids=evidence_ids,
        )
        return self._observation(view, "INVALIDATED", actors)

    def reconcile(
        self,
        session: Session,
        publication_id: str,
        *,
        comment_id: int | None = None,
        terminalize: bool = True,
        allow_stale_head: bool = False,
        allow_merged: bool = False,
    ) -> CodexReviewObservation:
        view = get_view(session, publication_id)
        if view.automated_review_status not in {
            AutomatedReviewStatus.RUNNING,
            AutomatedReviewStatus.PASS,
            AutomatedReviewStatus.CHANGES_REQUIRED,
            AutomatedReviewStatus.UNAVAILABLE,
        }:
            raise DomainError("publication has no governed Codex review")
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

        if self._has_invalidation(session, view):
            return self._observation(view, "INVALIDATED", ())
        if allow_merged and view.automated_review_status is AutomatedReviewStatus.RUNNING:
            raise CodexReviewError("active Codex review cannot be reconciled after merge")

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
            self._verify_exact_pr(
                view,
                pull,
                allow_stale_head=allow_stale_head,
                allow_merged=allow_merged,
            )
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

        assert_no_ambiguous_codex_invocations(
            issue_comments,
            trigger_comment_id=trigger.comment_id,
            trigger_time=trigger_time,
        )
        terminal_event = self._terminal_event(session, view)
        terminal_time = (
            self._terminal_time(terminal_event)
            if terminal_event is not None
            else None
        )
        deleted_invocations = self._deleted_issue_invocation_ids(
            session,
            view,
            trigger_time=trigger_time,
            terminal_time=terminal_time,
        )
        deleted_findings = self._deleted_review_finding_ids(
            session,
            view,
            reviews=reviews,
            trigger_time=trigger_time,
            terminal_event=terminal_event,
            terminal_time=terminal_time,
        )

        actors = tuple(
            sorted(
                {
                    item.actor
                    for item in [*reviews, *comments, *reactions]
                    if item.actor
                }
            )
        )
        if deleted_invocations:
            return self._invalidate(
                session,
                view,
                reason="CODEX_DELETED_INVOCATION",
                evidence_ids=list(deleted_invocations),
                actors=actors,
            )
        if deleted_findings:
            return self._invalidate(
                session,
                view,
                reason="CODEX_DELETED_FINDING",
                evidence_ids=list(deleted_findings),
                actors=actors,
            )
        (
            matching_reviews,
            matching_comments,
            matching_reactions,
            provider_evidence_times,
        ) = self._matching_native_evidence(
            view,
            trigger_time=trigger_time,
            reviews=reviews,
            comments=comments,
            reactions=reactions,
        )
        native_time = max(provider_evidence_times) if provider_evidence_times else None
        usage_evidence = self._usage_limit_evidence(
            issue_comments,
            trigger_comment_id=trigger.comment_id,
            trigger_time=trigger_time,
            comment_id=comment_id,
        )

        findings = [
            self._normalize_finding(item)
            for item in matching_comments
            if item.body.strip()
        ]
        native_result = None
        if matching_reviews or matching_reactions:
            native_result = (
                AutomatedReviewStatus.CHANGES_REQUIRED
                if findings
                else AutomatedReviewStatus.PASS
            )
        native_ids = [
            *[item.review_id for item in matching_reviews],
            *[item.comment_id for item in matching_comments],
            *[item.reaction_id for item in matching_reactions],
        ]

        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            if usage_evidence is not None and native_result is not None:
                usage, usage_time = usage_evidence
                if native_time is None or native_time <= usage_time:
                    return self._invalidate(
                        session,
                        view,
                        reason="CODEX_PROVIDER_RESULT_CONFLICT",
                        evidence_ids=[usage.comment_id, *native_ids],
                        actors=actors,
                    )
                if not terminalize:
                    return self._observation(view, "RUNNING", actors)
            elif usage_evidence is not None:
                usage, usage_time = usage_evidence
                mark_codex_review_unavailable(
                    session,
                    publication_id,
                    run_id=view.automated_review_run_id,
                    reviewed_head_sha=view.automated_review_head_sha,
                    reason=f"CODEX_PROVIDER_USAGE_LIMIT:{usage.comment_id}",
                    provider_occurred_at=usage_time.isoformat(),
                )
                return self._observation(view, "UNAVAILABLE", actors)
            elif native_result is None or not terminalize:
                return self._observation(view, "RUNNING", actors)
        elif view.automated_review_status is AutomatedReviewStatus.UNAVAILABLE:
            if native_result is not None:
                usage, usage_time = usage_evidence or (None, None)
                if (
                    native_time is None
                    or terminal_time is None
                    or native_time <= terminal_time
                    or (usage_time is not None and native_time <= usage_time)
                ):
                    return self._invalidate(
                        session,
                        view,
                        reason="CODEX_PROVIDER_RESULT_CONFLICT",
                        evidence_ids=[
                            *([usage.comment_id] if usage is not None else []),
                            *native_ids,
                        ],
                        actors=actors,
                    )
            elif usage_evidence is not None:
                usage, usage_time = usage_evidence
                reason = terminal_event["payload"].get("reason")
                recorded_time = terminal_event["payload"].get("provider_occurred_at")
                if (
                    reason != f"CODEX_PROVIDER_USAGE_LIMIT:{usage.comment_id}"
                    or _parse_provider_time(
                        recorded_time,
                        "Codex provider unavailability timestamp",
                    )
                    != usage_time
                ):
                    return self._invalidate(
                        session,
                        view,
                        reason="CODEX_PROVIDER_RESULT_CONFLICT",
                        evidence_ids=[usage.comment_id],
                        actors=actors,
                    )
                return self._observation(view, "UNAVAILABLE", actors)
            else:
                return self._observation(view, "UNAVAILABLE", actors)
        else:
            if usage_evidence is not None:
                usage, usage_time = usage_evidence
                if terminal_time is None or usage_time >= terminal_time:
                    return self._invalidate(
                        session,
                        view,
                        reason="CODEX_PROVIDER_RESULT_CONFLICT",
                        evidence_ids=[usage.comment_id],
                        actors=actors,
                    )
            if native_result is not None:
                result_payload = terminal_event["payload"]
                result_review_ids = sorted(item.review_id for item in matching_reviews)
                result_comment_ids = sorted(item.comment_id for item in matching_comments)
                result_reaction_ids = sorted(
                    item.reaction_id for item in matching_reactions
                )
                if (
                    terminal_time is None
                    or native_time != terminal_time
                    or native_result.value != result_payload.get("result")
                    or result_review_ids != result_payload.get("provider_review_ids")
                    or result_comment_ids != result_payload.get("provider_comment_ids")
                    or result_reaction_ids != result_payload.get("provider_reaction_ids")
                ):
                    return self._invalidate(
                        session,
                        view,
                        reason="CODEX_PROVIDER_RESULT_CHANGED",
                        evidence_ids=native_ids,
                        actors=actors,
                    )
            return self._observation(
                view,
                view.automated_review_status.value,
                actors,
            )

        if native_result is None or native_time is None:
            return self._observation(view, "RUNNING", actors)

        complete_codex_review(
            session,
            publication_id,
            run_id=view.automated_review_run_id,
            reviewed_head_sha=view.automated_review_head_sha,
            result=native_result,
            findings=findings,
            provider_review_ids=[item.review_id for item in matching_reviews],
            provider_comment_ids=[item.comment_id for item in matching_comments],
            provider_reaction_ids=[
                item.reaction_id for item in matching_reactions
            ],
            provider_completed_at=native_time.isoformat(),
        )
        return CodexReviewObservation(
            run_id=view.automated_review_run_id,
            state=native_result.value,
            matching_reviews=len(matching_reviews),
            matching_comments=len(matching_comments),
            matching_reactions=len(matching_reactions),
            actors=actors,
        )
