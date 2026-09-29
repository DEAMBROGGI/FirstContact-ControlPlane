from __future__ import annotations

from types import SimpleNamespace

import pytest

from control_plane.domain import DomainError, PublicationState, ReviewDecision, ValidationStatus
from control_plane.github_api import GitHubApiError, PullRequestSnapshot
from control_plane.merge import MergeCoordinator, MergeError
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.service import (
    create_publication,
    get_view,
    mark_remote_published,
    record_mergeability,
    record_merged,
    record_review,
    record_validation,
    submit_verified_candidate,
)


BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40
MERGE_SHA = "4" * 40
REPOSITORY = "DEAMBROGGI/FirstContact"
PR_NUMBER = 13
BRANCH = "control-plane/issue-22-canonical"


def ready_publication(session, *, issue_number: int = 220):
    source = VerifiedCandidateSource(
        bundle_sha256="a" * 64,
        byte_length=100,
        quarantine_id="a" * 64,
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
    )
    view = create_publication(session, REPOSITORY, issue_number)
    view = submit_verified_candidate(session, view.publication_id, source)
    profile = profile_for_repository(REPOSITORY)
    for index, job in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )
    view = mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch=BRANCH,
        base_branch="master",
        pull_request_number=PR_NUMBER,
    )
    view = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
    )
    return record_mergeability(
        session,
        view.publication_id,
        head_sha=HEAD,
        mergeable=True,
    )


def approved_publication(session, *, issue_number: int = 221):
    # Build a fresh publication and stop before mergeability.
    source = VerifiedCandidateSource(
        bundle_sha256="b" * 64,
        byte_length=100,
        quarantine_id="b" * 64,
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
    )
    view = create_publication(session, REPOSITORY, issue_number + 1000)
    view = submit_verified_candidate(session, view.publication_id, source)
    profile = profile_for_repository(REPOSITORY)
    for index, job in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 100:064x}",
        )
    view = mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch=BRANCH,
        base_branch="master",
        pull_request_number=PR_NUMBER,
    )
    return record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
    )


class TokenProvider:
    def __init__(self):
        self.permissions = []

    def installation_access(self, repository, *, permissions=None):
        assert repository == REPOSITORY
        self.permissions.append(permissions)
        return SimpleNamespace(token="installation-token")


class GitHub:
    def __init__(
        self,
        pulls,
        *,
        merged_statuses,
        merge_result=MERGE_SHA,
        merge_error=None,
    ):
        self.pulls = list(pulls)
        self.merged_statuses = list(merged_statuses)
        self.merge_result = merge_result
        self.merge_error = merge_error
        self.merge_calls = []

    def pull_request(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == PR_NUMBER
        assert token == "installation-token"
        if not self.pulls:
            raise AssertionError("unexpected pull_request readback")
        return self.pulls.pop(0)

    def pull_request_merged(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == PR_NUMBER
        assert token == "installation-token"
        if not self.merged_statuses:
            raise AssertionError("unexpected pull_request_merged readback")
        return self.merged_statuses.pop(0)

    def merge_pull_request(
        self,
        repository,
        number,
        *,
        expected_head_sha,
        token,
        merge_method,
    ):
        self.merge_calls.append(
            {
                "repository": repository,
                "number": number,
                "expected_head_sha": expected_head_sha,
                "token": token,
                "merge_method": merge_method,
            }
        )
        if self.merge_error is not None:
            raise self.merge_error
        return self.merge_result


def pull(*, merged: bool, head: str = HEAD, state: str | None = None, merge_sha=None):
    return PullRequestSnapshot(
        number=PR_NUMBER,
        state=state or ("closed" if merged else "open"),
        base_ref="master",
        head_ref=BRANCH,
        head_sha=head,
        merged=merged,
        merge_commit_sha=merge_sha,
    )


def test_record_merged_persists_exact_receipt_and_is_idempotent(session):
    ready = ready_publication(session)

    merged = record_merged(
        session,
        ready.publication_id,
        head_sha=HEAD,
        pull_request_number=PR_NUMBER,
        merge_commit_sha=MERGE_SHA,
        source="PLANE_MERGE",
    )

    assert merged.state is PublicationState.MERGED
    assert merged.merge_commit_sha == MERGE_SHA
    assert merged.merge_source == "PLANE_MERGE"
    assert merged.merge_policy_violation is False

    same = record_merged(
        session,
        ready.publication_id,
        head_sha=HEAD,
        pull_request_number=PR_NUMBER,
        merge_commit_sha=MERGE_SHA,
        source="PLANE_MERGE",
    )
    assert same.state is PublicationState.MERGED

    with pytest.raises(DomainError, match="receipt does not match"):
        record_merged(
            session,
            ready.publication_id,
            head_sha=HEAD,
            pull_request_number=PR_NUMBER,
            merge_commit_sha="5" * 40,
            source="PLANE_MERGE",
        )


def test_plane_merge_executes_exact_head_and_records_native_receipt(session):
    ready = ready_publication(session)
    token_provider = TokenProvider()
    github = GitHub(
        [
            pull(merged=False),
            pull(merged=True, merge_sha=MERGE_SHA),
        ],
        merged_statuses=[False, True],
    )
    coordinator = MergeCoordinator(
        token_provider=token_provider,
        github=github,
    )

    merged = coordinator.merge(session, ready.publication_id)

    assert merged.state is PublicationState.MERGED
    assert merged.merge_commit_sha == MERGE_SHA
    assert merged.merge_source == "PLANE_MERGE"
    assert github.merge_calls == [
        {
            "repository": REPOSITORY,
            "number": PR_NUMBER,
            "expected_head_sha": HEAD,
            "token": "installation-token",
            "merge_method": "merge",
        }
    ]
    assert token_provider.permissions == [
        {"contents": "write", "pull_requests": "write"}
    ]


def test_plane_merge_recovers_remote_success_after_uncertain_write(session):
    ready = ready_publication(session, issue_number=222)
    github = GitHub(
        [
            pull(merged=False),
            pull(merged=True, merge_sha=MERGE_SHA),
        ],
        merged_statuses=[False, True],
        merge_error=GitHubApiError("transport failed after write"),
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    merged = coordinator.merge(session, ready.publication_id)

    assert merged.state is PublicationState.MERGED
    assert merged.merge_commit_sha == MERGE_SHA
    assert merged.merge_source == "PLANE_MERGE"


def test_reconcile_already_merged_ready_publication(session):
    ready = ready_publication(session, issue_number=223)
    github = GitHub(
        [pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    merged = coordinator.reconcile(session, ready.publication_id)

    assert merged.state is PublicationState.MERGED
    assert merged.merge_commit_sha == MERGE_SHA
    assert merged.merge_source == "GITHUB_RECONCILE"
    assert github.merge_calls == []


def test_reconcile_non_ready_out_of_band_merge_records_violation(session):
    approved = approved_publication(session, issue_number=224)
    github = GitHub(
        [pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(MergeError, match="before Control Plane READY_TO_MERGE"):
        coordinator.reconcile(session, approved.publication_id)

    current = get_view(session, approved.publication_id)
    assert current.state is PublicationState.APPROVED
    assert current.merge_policy_violation is True
    assert current.merge_commit_sha == MERGE_SHA
    assert current.merge_source == "GITHUB_RECONCILE"


def test_merge_command_rejects_non_ready_unmerged_publication(session):
    approved = approved_publication(session, issue_number=225)
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=GitHub(
            [pull(merged=False)],
            merged_statuses=[False],
        ),
    )

    with pytest.raises(DomainError, match="READY_TO_MERGE"):
        coordinator.merge(session, approved.publication_id)

    assert get_view(session, approved.publication_id).state is PublicationState.APPROVED


def test_reconcile_rejects_stale_github_head(session):
    ready = ready_publication(session, issue_number=226)
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=GitHub(
            [pull(merged=True, head="9" * 40, merge_sha=MERGE_SHA)],
            merged_statuses=[True],
        ),
    )

    with pytest.raises(MergeError, match="head changed"):
        coordinator.reconcile(session, ready.publication_id)

    assert get_view(session, ready.publication_id).state is PublicationState.READY_TO_MERGE
