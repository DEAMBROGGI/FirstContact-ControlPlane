from __future__ import annotations

from sqlalchemy.orm import Session

from .domain import DomainError, PublicationState, PublicationView
from .github_api import GitHubApiError, GitHubRepositoryGateway, PullRequestSnapshot
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .service import (
    get_view,
    record_merge_policy_violation,
    record_merged,
)


class MergeError(RuntimeError):
    pass


class MergeCoordinator:
    def __init__(
        self,
        *,
        token_provider: GitHubAppTokenProvider,
        github: GitHubRepositoryGateway,
        merge_method: str = "merge",
    ) -> None:
        if merge_method not in {"merge", "squash", "rebase"}:
            raise ValueError("merge_method must be merge, squash, or rebase")
        self.token_provider = token_provider
        self.github = github
        self.merge_method = merge_method

    @staticmethod
    def _verify_identity(
        view: PublicationView,
        pull: PullRequestSnapshot,
    ) -> None:
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise MergeError("publication is missing governed PR metadata")
        if pull.number != view.pull_request_number:
            raise MergeError("canonical pull request number changed")
        if pull.head_sha != view.remote_head_sha:
            raise MergeError("canonical pull request head changed")
        if view.remote_branch is not None and pull.head_ref != view.remote_branch:
            raise MergeError("canonical pull request branch changed")
        if view.base_branch is not None and pull.base_ref != view.base_branch:
            raise MergeError("canonical pull request base changed")

    @staticmethod
    def _verified_merge_commit(
        pull: PullRequestSnapshot,
        *,
        merged: bool,
    ) -> str:
        if not merged or pull.merge_commit_sha is None:
            raise MergeError("GitHub merge receipt is incomplete")
        return pull.merge_commit_sha

    def _record_reconciled_pull(
        self,
        session: Session,
        publication_id: str,
        *,
        view: PublicationView,
        pull: PullRequestSnapshot,
        token: str,
    ) -> PublicationView:
        self._verify_identity(view, pull)
        merged = self.github.pull_request_merged(
            view.repository,
            pull.number,
            token,
        )
        merge_commit_sha = self._verified_merge_commit(
            pull,
            merged=merged,
        )
        assert view.pull_request_number is not None
        assert view.remote_head_sha is not None

        if view.state is PublicationState.MERGED:
            if (
                view.merge_commit_sha != merge_commit_sha
                or view.merge_source not in {"PLANE_MERGE", "GITHUB_RECONCILE"}
            ):
                raise MergeError("stored merge receipt does not match GitHub")
            return view

        if view.state is PublicationState.READY_TO_MERGE:
            return record_merged(
                session,
                publication_id,
                head_sha=view.remote_head_sha,
                pull_request_number=view.pull_request_number,
                merge_commit_sha=merge_commit_sha,
                source="GITHUB_RECONCILE",
            )

        record_merge_policy_violation(
            session,
            publication_id,
            head_sha=view.remote_head_sha,
            pull_request_number=view.pull_request_number,
            merge_commit_sha=merge_commit_sha,
        )
        raise MergeError(
            "GitHub reports a merge before Control Plane READY_TO_MERGE"
        )

    def reconcile(
        self,
        session: Session,
        publication_id: str,
    ) -> PublicationView:
        view = get_view(session, publication_id)
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise DomainError("merge reconciliation requires published PR metadata")
        try:
            access = self.token_provider.installation_access(
                view.repository,
                permissions={
                    "contents": "read",
                    "pull_requests": "read",
                },
            )
            pull = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
        except (GitHubAuthError, GitHubApiError) as exc:
            raise MergeError("GitHub merge reconciliation failed closed") from exc

        self._verify_identity(view, pull)
        merged = self.github.pull_request_merged(
            view.repository,
            view.pull_request_number,
            access.token,
        )
        if not merged:
            if view.state is PublicationState.MERGED:
                raise MergeError("Plane says MERGED but GitHub does not")
            return view
        return self._record_reconciled_pull(
            session,
            publication_id,
            view=view,
            pull=pull,
            token=access.token,
        )

    def merge(
        self,
        session: Session,
        publication_id: str,
    ) -> PublicationView:
        view = get_view(session, publication_id)
        if view.state is PublicationState.MERGED:
            return self.reconcile(session, publication_id)
        if view.state is not PublicationState.READY_TO_MERGE:
            # Readback is still authoritative enough to detect and audit an
            # out-of-band merge before rejecting this command.
            self.reconcile(session, publication_id)
            raise DomainError("merge requires READY_TO_MERGE state")
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise DomainError("merge requires published PR metadata")

        try:
            access = self.token_provider.installation_access(
                view.repository,
                permissions={
                    "contents": "write",
                    "pull_requests": "write",
                },
            )
            pull = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            self._verify_identity(view, pull)

            already_merged = self.github.pull_request_merged(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            if already_merged:
                return self._record_reconciled_pull(
                    session,
                    publication_id,
                    view=view,
                    pull=pull,
                    token=access.token,
                )
            if pull.state != "open":
                raise MergeError("canonical pull request is not open")

            merge_sha: str | None = None
            merge_error: Exception | None = None
            try:
                merge_sha = self.github.merge_pull_request(
                    view.repository,
                    view.pull_request_number,
                    expected_head_sha=view.remote_head_sha,
                    merge_method=self.merge_method,
                    token=access.token,
                )
            except GitHubApiError as exc:
                # The write may have committed remotely before the client saw
                # the response. Readback decides whether this is recoverable.
                merge_error = exc

            readback = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            self._verify_identity(view, readback)

            merged = self.github.pull_request_merged(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            if not merged or readback.merge_commit_sha is None:
                if merge_error is not None:
                    raise MergeError("GitHub merge failed closed") from merge_error
                raise MergeError("GitHub merge did not converge on readback")
            if merge_sha is not None and readback.merge_commit_sha != merge_sha:
                raise MergeError("GitHub merge receipt changed during readback")

            return record_merged(
                session,
                publication_id,
                head_sha=view.remote_head_sha,
                pull_request_number=view.pull_request_number,
                merge_commit_sha=readback.merge_commit_sha,
                source="PLANE_MERGE",
            )
        except (GitHubAuthError, GitHubApiError) as exc:
            raise MergeError("GitHub merge failed closed") from exc
