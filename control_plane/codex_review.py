from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from .domain import AutomatedReviewStatus, DomainError, PublicationState
from .github_api import (
    GitHubApiError,
    GitHubRepositoryGateway,
    PullReviewCommentSnapshot,
    PullReviewSnapshot,
)
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .service import (
    complete_codex_review,
    get_view,
    mark_codex_review_triggered,
    mark_codex_review_unavailable,
    request_codex_review,
)

_RESERVED_CODEX_MENTION = re.compile(r"(?i)(?<![A-Za-z0-9_])@codex\b")


class CodexReviewError(RuntimeError):
    pass


def assert_no_reserved_automation_mentions(value: str) -> None:
    if _RESERVED_CODEX_MENTION.search(value or ""):
        raise DomainError("@codex is reserved for Control Plane automation")


@dataclass(frozen=True, slots=True)
class CodexReviewObservation:
    run_id: str
    state: str
    matching_reviews: int
    matching_comments: int
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
    ) -> None:
        normalized_mode = mode.strip().lower()
        if normalized_mode not in {"disabled", "advisory", "required"}:
            raise CodexReviewError("invalid Codex review mode")
        self.token_provider = token_provider
        self.github = github
        self.mode = normalized_mode
        self.allowed_actors = tuple(
            actor.strip().lower()
            for actor in allowed_actors
            if actor.strip()
        )

    @staticmethod
    def _marker(run_id: str, head_sha: str) -> str:
        return (
            "<!-- firstcontact-control-plane:codex-review "
            f"run={run_id} head={head_sha} -->"
        )

    @classmethod
    def _trigger_body(cls, run_id: str, head_sha: str) -> str:
        return f"{cls.TRIGGER_TEXT}\n\n{cls._marker(run_id, head_sha)}"

    def _review_access(self, repository: str, *, write: bool):
        permissions = {
            "issues": "write" if write else "read",
            "pull_requests": "read",
        }
        return self.token_provider.installation_access(
            repository,
            permissions=permissions,
        )

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

    def request(self, session: Session, publication_id: str):
        if self.mode == "disabled":
            raise DomainError("Codex review broker is disabled")

        view = get_view(session, publication_id)
        if view.state is not PublicationState.IN_REVIEW:
            raise DomainError("Codex review requires IN_REVIEW state")
        if view.remote_head_sha is None or view.pull_request_number is None:
            raise DomainError("Codex review requires published PR metadata")

        try:
            access = self._review_access(view.repository, write=True)
            pull = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            self._verify_exact_pr(view, pull)

            locked = request_codex_review(
                session,
                publication_id,
                mode=self.mode,
            )
            if locked.automated_review_status is not AutomatedReviewStatus.RUNNING:
                return locked
            assert locked.automated_review_run_id is not None
            run_id = locked.automated_review_run_id
            marker = self._marker(run_id, locked.remote_head_sha or "")

            existing = [
                item
                for item in self.github.list_issue_comments(
                    locked.repository,
                    locked.pull_request_number or 0,
                    access.token,
                )
                if marker in item.body
            ]
            if len(existing) > 1:
                raise CodexReviewError("multiple Codex trigger comments exist")
            if existing:
                return mark_codex_review_triggered(
                    session,
                    publication_id,
                    run_id=run_id,
                    comment_id=existing[0].comment_id,
                )

            comment = self.github.add_issue_comment(
                locked.repository,
                locked.pull_request_number or 0,
                self._trigger_body(run_id, locked.remote_head_sha or ""),
                access.token,
            )
            return mark_codex_review_triggered(
                session,
                publication_id,
                run_id=run_id,
                comment_id=comment.comment_id,
            )
        except (GitHubAuthError, GitHubApiError, CodexReviewError) as exc:
            latest = get_view(session, publication_id)
            if (
                latest.automated_review_status is AutomatedReviewStatus.RUNNING
                and latest.automated_review_run_id is not None
                and latest.automated_review_head_sha is not None
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
        body = comment.body.strip()
        return {
            "provider_comment_id": comment.comment_id,
            "provider_review_id": comment.review_id,
            "path": comment.path,
            "line": comment.line,
            "body": body[:4000],
        }

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
        ):
            raise DomainError("active Codex review metadata is incomplete")

        if not self.allowed_actors:
            raise CodexReviewError("Codex review actor allowlist is not configured")

        try:
            access = self._review_access(view.repository, write=False)
            pull = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            self._verify_exact_pr(view, pull)

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
        except (GitHubAuthError, GitHubApiError, CodexReviewError) as exc:
            raise CodexReviewError("Codex review reconciliation failed closed") from exc

        actors = tuple(
            sorted(
                {
                    item.actor
                    for item in [*reviews, *comments]
                    if item.actor
                }
            )
        )
        matching_reviews = [
            item
            for item in reviews
            if item.actor.lower() in self.allowed_actors
            and item.commit_id == view.automated_review_head_sha
        ]
        matching_review_ids = {item.review_id for item in matching_reviews}
        matching_comments = [
            item
            for item in comments
            if item.actor.lower() in self.allowed_actors
            and item.commit_id == view.automated_review_head_sha
            and (
                item.review_id is None
                or item.review_id in matching_review_ids
            )
        ]

        if not matching_reviews:
            return CodexReviewObservation(
                run_id=view.automated_review_run_id,
                state="RUNNING",
                matching_reviews=0,
                matching_comments=len(matching_comments),
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
        )
        return CodexReviewObservation(
            run_id=view.automated_review_run_id,
            state=result.value,
            matching_reviews=len(matching_reviews),
            matching_comments=len(matching_comments),
            actors=actors,
        )
