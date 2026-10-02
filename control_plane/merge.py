from __future__ import annotations

from sqlalchemy.orm import Session

from .domain import DomainError, PublicationState, PublicationView
from .github_api import (
    GitHubApiError,
    GitHubRepositoryGateway,
    PullRequestSnapshot,
)
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .service import (
    get_view,
    record_merge_policy_violation,
    record_merged,
)


class MergeError(RuntimeError):
    pass


class MergePolicyViolationRecorded(MergeError):
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
        event_commit_sha: str | None,
    ) -> str:
        if not merged:
            raise MergeError("GitHub merge receipt says pull request is not merged")
        values = []
        if pull.merge_commit_sha is not None:
            values.append(pull.merge_commit_sha)
        if event_commit_sha is not None:
            values.append(event_commit_sha)
        unique = tuple(dict.fromkeys(values))
        if not unique:
            raise MergeError(
                "GitHub merge receipt is incomplete "
                "(merged=True, no merge commit SHA evidence)"
            )
        if len(unique) != 1:
            raise MergeError("GitHub merge commit evidence is inconsistent")
        return unique[0]

    def _merge_matches_validated_candidate(
        self,
        *,
        repository: str,
        merge_commit_sha: str,
        base_sha: str,
        head_sha: str,
        tree_sha: str,
        token: str,
    ) -> bool:
        try:
            merge_commit = self.github.commit(repository, merge_commit_sha, token)
        except GitHubApiError as exc:
            raise MergeError("GitHub merge commit ancestry readback failed closed") from exc
        if merge_commit.sha != merge_commit_sha:
            raise MergeError("GitHub merge commit readback is inconsistent")
        if merge_commit.tree_sha != tree_sha:
            return False
        if merge_commit.parents in {
            (base_sha, head_sha),
            (base_sha,),
        }:
            return True
        if len(merge_commit.parents) != 1:
            return False

        try:
            candidate_comparison = self.github.compare_commits(
                repository,
                base_sha,
                head_sha,
                token,
            )
            merge_comparison = self.github.compare_commits(
                repository,
                base_sha,
                merge_commit_sha,
                token,
            )
        except GitHubApiError as exc:
            raise MergeError("GitHub merge ancestry comparison failed closed") from exc
        if (
            candidate_comparison.base_sha != base_sha
            or candidate_comparison.head_sha != head_sha
            or merge_comparison.base_sha != base_sha
            or merge_comparison.head_sha != merge_commit_sha
        ):
            raise MergeError("GitHub merge ancestry comparison is inconsistent")
        return (
            candidate_comparison.merge_base_sha == base_sha
            and candidate_comparison.behind_by == 0
            and merge_comparison.merge_base_sha == base_sha
            and merge_comparison.behind_by == 0
            and merge_comparison.ahead_by == candidate_comparison.ahead_by
        )

    def _record_reconciled_pull(
        self,
        session: Session,
        publication_id: str,
        *,
        view: PublicationView,
        pull: PullRequestSnapshot,
        merged: bool,
        token: str,
        require_validated_base: bool = False,
        human_review_eligible: bool = True,
        expected_merge_commit_sha: str | None = None,
        merge_source: str = "GITHUB_RECONCILE",
    ) -> PublicationView:
        self._verify_identity(view, pull)
        try:
            merge_event = self.github.pull_request_merge_event(
                view.repository,
                pull.number,
                token,
            )
        except GitHubApiError as exc:
            raise MergeError("GitHub merge receipt readback failed closed") from exc
        merge_commit_sha = self._verified_merge_commit(
            pull,
            merged=merged,
            event_commit_sha=(
                merge_event.commit_id
                if merge_event is not None
                else None
            ),
        )
        if (
            expected_merge_commit_sha is not None
            and merge_commit_sha != expected_merge_commit_sha
        ):
            raise MergeError("GitHub merge receipt changed during readback")
        assert view.pull_request_number is not None
        assert view.remote_head_sha is not None

        if view.state is PublicationState.MERGED:
            if (
                view.merge_commit_sha != merge_commit_sha
                or view.merge_source not in {"PLANE_MERGE", "GITHUB_RECONCILE"}
            ):
                raise MergeError("stored merge receipt does not match GitHub")
            return view

        if require_validated_base:
            candidate = view.current_candidate
            if candidate is None or view.base_branch is None:
                raise MergeError("publication base identity is incomplete")
            if candidate.head_sha != view.remote_head_sha:
                raise MergeError("validated candidate head differs from governed PR head")
            if not self._merge_matches_validated_candidate(
                repository=view.repository,
                merge_commit_sha=merge_commit_sha,
                base_sha=candidate.base_sha,
                head_sha=view.remote_head_sha,
                tree_sha=candidate.tree_sha,
                token=token,
            ):
                record_merge_policy_violation(
                    session,
                    publication_id,
                    head_sha=view.remote_head_sha,
                    pull_request_number=view.pull_request_number,
                    merge_commit_sha=merge_commit_sha,
                )
                raise MergePolicyViolationRecorded(
                    "GitHub merge commit does not match the validated candidate base and head"
                )
            if not human_review_eligible:
                record_merge_policy_violation(
                    session,
                    publication_id,
                    head_sha=view.remote_head_sha,
                    pull_request_number=view.pull_request_number,
                    merge_commit_sha=merge_commit_sha,
                )
                raise MergePolicyViolationRecorded(
                    "GitHub reports an external merge without current human approval"
                )

        if view.merge_policy_violation:
            raise MergePolicyViolationRecorded(
                "merge policy violation permanently blocks governed merge"
            )

        if view.state is PublicationState.READY_TO_MERGE:
            return record_merged(
                session,
                publication_id,
                head_sha=view.remote_head_sha,
                pull_request_number=view.pull_request_number,
                merge_commit_sha=merge_commit_sha,
                source=merge_source,
            )

        record_merge_policy_violation(
            session,
            publication_id,
            head_sha=view.remote_head_sha,
            pull_request_number=view.pull_request_number,
            merge_commit_sha=merge_commit_sha,
        )
        raise MergePolicyViolationRecorded(
            "GitHub reports a merge before Control Plane READY_TO_MERGE"
        )

    def reconcile(
        self,
        session: Session,
        publication_id: str,
        *,
        human_review_eligible: bool = True,
    ) -> PublicationView:
        view = get_view(session, publication_id)
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise DomainError("merge reconciliation requires published PR metadata")
        try:
            access = self.token_provider.installation_access(
                view.repository,
                permissions={
                    "contents": "read",
                    "issues": "read",
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
        try:
            merged = self.github.pull_request_merged(
                view.repository,
                view.pull_request_number,
                access.token,
            )
        except GitHubApiError as exc:
            raise MergeError("GitHub merge reconciliation failed closed") from exc
        if not merged:
            if view.state is PublicationState.MERGED:
                raise MergeError("Plane says MERGED but GitHub does not")
            return view
        return self._record_reconciled_pull(
            session,
            publication_id,
            view=view,
            pull=pull,
            merged=merged,
            token=access.token,
            require_validated_base=True,
            human_review_eligible=human_review_eligible,
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
                    "issues": "read",
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
                raced_pull = self.github.pull_request(
                    view.repository,
                    view.pull_request_number,
                    access.token,
                )
                self._verify_identity(view, raced_pull)
                if not raced_pull.merged:
                    raise MergeError(
                        "GitHub merged status disagrees with pull request readback"
                    )
                return self._record_reconciled_pull(
                    session,
                    publication_id,
                    view=view,
                    pull=raced_pull,
                    merged=True,
                    token=access.token,
                    require_validated_base=True,
                )
            if pull.state != "open":
                raise MergeError("canonical pull request is not open")

            candidate = view.current_candidate
            if candidate is None:
                raise MergeError("publication is missing current candidate identity")
            base_sha = self.github.ref_sha(
                view.repository,
                pull.base_ref,
                access.token,
            )
            if base_sha != candidate.base_sha:
                raise MergeError(
                    "canonical pull request base moved after candidate admission"
                )

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
            if not merged:
                if merge_error is not None:
                    raise MergeError("GitHub merge failed closed") from merge_error
                raise MergeError("GitHub merge did not converge on readback")
            if not readback.merged:
                raise MergeError(
                    "GitHub merged status disagrees with pull request readback"
                )

            return self._record_reconciled_pull(
                session,
                publication_id,
                view=view,
                pull=readback,
                merged=merged,
                token=access.token,
                require_validated_base=True,
                expected_merge_commit_sha=merge_sha,
                merge_source="PLANE_MERGE",
            )
        except (GitHubAuthError, GitHubApiError) as exc:
            raise MergeError("GitHub merge failed closed") from exc
