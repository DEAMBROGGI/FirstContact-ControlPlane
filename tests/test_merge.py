from __future__ import annotations

from types import SimpleNamespace

import pytest

import control_plane.remediation as remediation_module

from control_plane.domain import DomainError, PublicationState, ReviewDecision, ValidationStatus
from control_plane.github_api import GitHubApiError, PullRequestSnapshot
from control_plane.pr_findings import reconcile_pr_findings
from control_plane.merge import (
    MergeCoordinator,
    MergeError,
    MergePolicyViolationRecorded,
)
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
    _reconcile_empty_pr_findings(session, view)
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
    _reconcile_empty_pr_findings(session, view)
    return record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
    )


def _reconcile_empty_pr_findings(session, view):
    github = SimpleNamespace(
        pull_request=lambda repository, number, token: PullRequestSnapshot(
            number=view.pull_request_number,
            state="open",
            base_ref=view.base_branch,
            head_ref=view.remote_branch,
            head_sha=view.remote_head_sha,
            base_sha=BASE,
        ),
        ref_sha=lambda repository, branch, token: BASE,
        list_pull_reviews=lambda repository, number, token: [],
        list_pull_review_comments=lambda repository, number, token: [],
        list_pull_review_threads=lambda repository, number, token: [],
    )
    return reconcile_pr_findings(
        session,
        view.publication_id,
        github=github,
        token="test-installation-token",
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
        merge_events=None,
        base_shas=None,
        merge_result=MERGE_SHA,
        merge_error=None,
        merge_commit_parents=(BASE, HEAD),
        merge_commit_tree=TREE,
        merge_commit_readback=None,
        comparison_results=None,
    ):
        self.pulls = list(pulls)
        self.merged_statuses = list(merged_statuses)
        self.merge_events = list(
            merge_events
            if merge_events is not None
            else [SimpleNamespace(commit_id=MERGE_SHA)] * 4
        )
        self.base_shas = list(
            base_shas
            if base_shas is not None
            else [BASE] * 4
        )
        self.merge_result = merge_result
        self.merge_error = merge_error
        self.merge_commit_parents = merge_commit_parents
        self.merge_commit_tree = merge_commit_tree
        self.merge_commit_readback = merge_commit_readback
        self.comparison_results = list(comparison_results or [])
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

    def pull_request_merge_event(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == PR_NUMBER
        assert token == "installation-token"
        if not self.merge_events:
            raise AssertionError("unexpected pull_request_merge_event readback")
        return self.merge_events.pop(0)

    def ref_sha(self, repository, branch, token):
        assert repository == REPOSITORY
        assert branch == "master"
        assert token == "installation-token"
        if not self.base_shas:
            raise AssertionError("unexpected ref_sha readback")
        return self.base_shas.pop(0)

    def commit(self, repository, sha, token):
        assert repository == REPOSITORY
        assert token == "installation-token"
        if isinstance(self.merge_commit_readback, Exception):
            raise self.merge_commit_readback
        if self.merge_commit_readback is not None:
            return self.merge_commit_readback
        return SimpleNamespace(
            sha=sha,
            tree_sha=self.merge_commit_tree,
            parents=self.merge_commit_parents,
        )

    def compare_commits(self, repository, base_sha, head_sha, token):
        assert repository == REPOSITORY
        assert token == "installation-token"
        if not self.comparison_results:
            raise AssertionError("unexpected compare_commits readback")
        return self.comparison_results.pop(0)

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
        {
            "contents": "write",
            "issues": "read",
            "pull_requests": "write",
        }
    ]


def test_plane_merge_is_blocked_before_write_with_open_remediation(
    session,
    monkeypatch,
):
    ready = ready_publication(session)
    github = GitHub(
        [pull(merged=False)],
        merged_statuses=[False],
    )
    monkeypatch.setattr(
        remediation_module,
        "publication_has_unresolved_remediation_findings",
        lambda *_args: True,
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(DomainError, match="unresolved remediation"):
        coordinator.merge(session, ready.publication_id)

    assert github.merge_calls == []


def test_external_merge_with_open_remediation_records_policy_violation(
    session,
    monkeypatch,
):
    ready = ready_publication(session)
    github = GitHub(
        [pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
    )
    monkeypatch.setattr(
        remediation_module,
        "publication_has_unresolved_remediation_findings",
        lambda *_args: True,
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(
        MergePolicyViolationRecorded,
        match="remediation findings remained unresolved",
    ):
        coordinator.reconcile(session, ready.publication_id)

    current = get_view(session, ready.publication_id)
    assert current.state is PublicationState.READY_TO_MERGE
    assert current.merge_policy_violation is True
    assert github.merge_calls == []


def test_merge_accepts_raced_external_merge_matching_candidate_graph(session):
    ready = ready_publication(session, issue_number=233)
    github = GitHub(
        [pull(merged=False), pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
        merge_events=[SimpleNamespace(commit_id=MERGE_SHA)],
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    merged = coordinator.merge(session, ready.publication_id)

    assert merged.state is PublicationState.MERGED
    assert merged.merge_commit_sha == MERGE_SHA
    assert merged.merge_source == "GITHUB_RECONCILE"
    assert github.merge_calls == []


@pytest.mark.parametrize(
    ("merge_commit_tree", "merge_commit_parents"),
    [
        ("5" * 40, (BASE, HEAD)),
        (TREE, ("9" * 40, HEAD)),
    ],
)
def test_merge_rejects_raced_external_merge_outside_candidate_graph(
    session,
    merge_commit_tree,
    merge_commit_parents,
):
    ready = ready_publication(session, issue_number=234)
    github = GitHub(
        [pull(merged=False), pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
        merge_events=[SimpleNamespace(commit_id=MERGE_SHA)],
        merge_commit_tree=merge_commit_tree,
        merge_commit_parents=merge_commit_parents,
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(MergePolicyViolationRecorded, match="does not match"):
        coordinator.merge(session, ready.publication_id)

    current = get_view(session, ready.publication_id)
    assert current.state is PublicationState.READY_TO_MERGE
    assert current.merge_policy_violation is True
    assert current.merge_commit_sha == MERGE_SHA
    assert github.merge_calls == []


@pytest.mark.parametrize(
    ("pull_merge_sha", "event_merge_sha", "message"),
    [
        (None, None, "incomplete"),
        (MERGE_SHA, "5" * 40, "inconsistent"),
    ],
)
def test_merge_fails_closed_on_incomplete_or_ambiguous_race_receipt(
    session,
    pull_merge_sha,
    event_merge_sha,
    message,
):
    ready = ready_publication(session, issue_number=235)
    merge_event = (
        SimpleNamespace(commit_id=event_merge_sha)
        if event_merge_sha is not None
        else None
    )
    github = GitHub(
        [pull(merged=False), pull(merged=True, merge_sha=pull_merge_sha)],
        merged_statuses=[True],
        merge_events=[merge_event],
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(MergeError, match=message):
        coordinator.merge(session, ready.publication_id)

    current = get_view(session, ready.publication_id)
    assert current.state is PublicationState.READY_TO_MERGE
    assert current.merge_policy_violation is False
    assert current.merge_commit_sha is None
    assert github.merge_calls == []


@pytest.mark.parametrize(
    ("merge_method", "parents", "comparisons"),
    [
        ("merge", (BASE, HEAD), []),
        ("squash", (BASE,), []),
        (
            "rebase",
            ("5" * 40,),
            [
                SimpleNamespace(
                    base_sha=BASE,
                    head_sha=HEAD,
                    merge_base_sha=BASE,
                    ahead_by=2,
                    behind_by=0,
                ),
                SimpleNamespace(
                    base_sha=BASE,
                    head_sha=MERGE_SHA,
                    merge_base_sha=BASE,
                    ahead_by=2,
                    behind_by=0,
                ),
            ],
        ),
    ],
)
def test_plane_merge_validates_supported_merge_method_graphs(
    session,
    merge_method,
    parents,
    comparisons,
):
    ready = ready_publication(session, issue_number=236)
    github = GitHub(
        [pull(merged=False), pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[False, True],
        merge_events=[SimpleNamespace(commit_id=MERGE_SHA)],
        merge_commit_parents=parents,
        comparison_results=comparisons,
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
        merge_method=merge_method,
    )

    merged = coordinator.merge(session, ready.publication_id)

    assert merged.state is PublicationState.MERGED
    assert merged.merge_source == "PLANE_MERGE"
    assert github.merge_calls[0]["merge_method"] == merge_method
    assert github.comparison_results == []


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
        [pull(merged=True, merge_sha=None)],
        merged_statuses=[True],
        merge_events=[SimpleNamespace(commit_id=MERGE_SHA)],
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


def test_reconcile_ready_external_merge_records_violation_when_base_drifted(session):
    ready = ready_publication(session, issue_number=229)
    github = GitHub(
        [pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
        base_shas=["9" * 40],
        merge_commit_parents=("9" * 40, HEAD),
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(MergeError, match="validated candidate base and head"):
        coordinator.reconcile(session, ready.publication_id)

    current = get_view(session, ready.publication_id)
    assert current.state is PublicationState.READY_TO_MERGE
    assert current.merge_policy_violation is True
    assert current.merge_commit_sha == MERGE_SHA
    assert current.merge_source == "GITHUB_RECONCILE"


def test_reconcile_accepts_exact_merge_when_live_base_has_advanced(session):
    ready = ready_publication(session, issue_number=230)
    advanced_base = "9" * 40
    github = GitHub(
        [pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
        base_shas=[advanced_base],
        merge_commit_parents=(BASE, HEAD),
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    merged = coordinator.reconcile(session, ready.publication_id)

    assert merged.state is PublicationState.MERGED
    assert merged.merge_commit_sha == MERGE_SHA
    assert github.base_shas == [advanced_base]


def test_reconcile_accepts_rebased_commit_graph_with_exact_validated_base(session):
    ready = ready_publication(session, issue_number=231)
    github = GitHub(
        [pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
        merge_commit_parents=("5" * 40,),
        comparison_results=[
            SimpleNamespace(
                base_sha=BASE,
                head_sha=HEAD,
                merge_base_sha=BASE,
                ahead_by=2,
                behind_by=0,
            ),
            SimpleNamespace(
                base_sha=BASE,
                head_sha=MERGE_SHA,
                merge_base_sha=BASE,
                ahead_by=2,
                behind_by=0,
            ),
        ],
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    merged = coordinator.reconcile(session, ready.publication_id)

    assert merged.state is PublicationState.MERGED
    assert not github.comparison_results


@pytest.mark.parametrize(
    ("merge_commit_readback", "message"),
    [
        (GitHubApiError("incomplete commit"), "ancestry readback failed closed"),
        (
            SimpleNamespace(sha="8" * 40, tree_sha=TREE, parents=(BASE, HEAD)),
            "readback is inconsistent",
        ),
    ],
)
def test_reconcile_fails_closed_on_incomplete_or_inconsistent_commit_readback(
    session,
    merge_commit_readback,
    message,
):
    ready = ready_publication(session, issue_number=232)
    github = GitHub(
        [pull(merged=True, merge_sha=MERGE_SHA)],
        merged_statuses=[True],
        merge_commit_readback=merge_commit_readback,
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(MergeError, match=message):
        coordinator.reconcile(session, ready.publication_id)

    current = get_view(session, ready.publication_id)
    assert current.merge_policy_violation is False
    assert current.state is PublicationState.READY_TO_MERGE


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


def test_merge_command_rejects_publication_after_changes_request(session):
    ready = ready_publication(session)
    demoted = record_review(
        session,
        ready.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.CHANGES_REQUIRED,
    )
    assert demoted.state is PublicationState.CHANGES_REQUIRED
    github = GitHub(
        [pull(merged=False)],
        merged_statuses=[False],
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(DomainError, match="READY_TO_MERGE"):
        coordinator.merge(session, ready.publication_id)

    assert get_view(session, ready.publication_id).state is PublicationState.CHANGES_REQUIRED
    assert github.merge_calls == []


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


def test_policy_violation_blocks_later_readiness_and_reconcile(session):
    approved = approved_publication(session, issue_number=227)
    first = MergeCoordinator(
        token_provider=TokenProvider(),
        github=GitHub(
            [pull(merged=True, merge_sha=MERGE_SHA)],
            merged_statuses=[True],
        ),
    )

    with pytest.raises(MergeError, match="before Control Plane READY_TO_MERGE"):
        first.reconcile(session, approved.publication_id)

    violated = get_view(session, approved.publication_id)
    assert violated.state is PublicationState.APPROVED
    assert violated.merge_policy_violation is True

    with pytest.raises(
        DomainError,
        match="permanently blocks governed readiness",
    ):
        record_mergeability(
            session,
            approved.publication_id,
            head_sha=HEAD,
            mergeable=True,
        )

    second = MergeCoordinator(
        token_provider=TokenProvider(),
        github=GitHub(
            [pull(merged=True, merge_sha=MERGE_SHA)],
            merged_statuses=[True],
        ),
    )

    with pytest.raises(
        MergeError,
        match="permanently blocks governed merge",
    ):
        second.reconcile(session, approved.publication_id)

    current = get_view(session, approved.publication_id)
    assert current.state is PublicationState.APPROVED
    assert current.merge_policy_violation is True


def test_plane_merge_rejects_base_drift_after_ready(session):
    ready = ready_publication(session, issue_number=228)
    github = GitHub(
        [pull(merged=False)],
        merged_statuses=[False],
        base_shas=["9" * 40],
    )
    coordinator = MergeCoordinator(
        token_provider=TokenProvider(),
        github=github,
    )

    with pytest.raises(
        MergeError,
        match="base moved after candidate admission",
    ):
        coordinator.merge(session, ready.publication_id)

    current = get_view(session, ready.publication_id)
    assert current.state is PublicationState.READY_TO_MERGE
    assert github.merge_calls == []
