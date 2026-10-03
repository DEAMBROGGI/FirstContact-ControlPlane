import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

import control_plane.service as service_module
from control_plane.domain import (
    AutomatedReviewStatus,
    DomainError,
    EventType,
    PublicationState,
    ReviewDecision,
    ValidationStatus,
)
from control_plane.github_api import PullRequestSnapshot
from control_plane.models import CandidateRow, CandidateSourceRow, EventRow, PublicationRow
from control_plane.plane_review import (
    complete_plane_review_materialization,
    record_plane_review,
)
from control_plane.profile_registry import all_profiles, profile_for_repository
from control_plane.pr_findings import reconcile_pr_findings
from control_plane.repository import append_event, load_events
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.service import (
    create_publication,
    complete_codex_review,
    get_view,
    mark_codex_review_unavailable,
    mark_remote_published,
    record_mergeability,
    record_merged,
    record_review,
    record_validation,
    request_codex_review,
    submit_verified_candidate,
    supersede_publication,
)

BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


def source(
    *,
    digest: str = "a" * 64,
    base: str = BASE,
    head: str = HEAD,
    tree: str = TREE,
) -> VerifiedCandidateSource:
    return VerifiedCandidateSource(
        bundle_sha256=digest,
        byte_length=1234,
        quarantine_id=digest,
        base_sha=base,
        head_sha=head,
        tree_sha=tree,
    )


def admitted_publication(
    session,
    repository="DEAMBROGGI/FirstContact",
    issue_number=42,
):
    view = create_publication(session, repository, issue_number)
    view = submit_verified_candidate(session, view.publication_id, source())
    profile = profile_for_repository(repository)
    for index, job in enumerate(profile.required_jobs):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 1:064x}",
        )
    return view


def successor_source():
    return source(digest="b" * 64, base=BASE, head="4" * 40, tree="5" * 40)


def published_publication(session, issue_number=42):
    view = admitted_publication(session, issue_number=issue_number)
    view = mark_remote_published(
        session,
        view.publication_id,
        view.current_candidate.head_sha,
        branch=f"control-plane/issue-{issue_number}-canonical",
        base_branch="master",
        pull_request_number=13,
    )
    _reconcile_empty_pr_findings(session, view)
    return view


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


def pass_codex_review(session, view):
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=view.remote_head_sha,
    )
    return complete_codex_review(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=view.remote_head_sha,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[],
        provider_comment_ids=[],
    )


def raw_publication(session, repository, issue_number):
    publication_id = str(uuid.uuid4())
    session.add(
        PublicationRow(
            id=publication_id,
            repository=repository,
            issue_number=issue_number,
        )
    )
    session.flush()
    append_event(
        session,
        publication_id,
        EventType.PUBLICATION_CREATED,
        {"repository": repository, "issue_number": issue_number},
    )
    session.commit()
    return get_view(session, publication_id)


def interleave_after_first_publication_lock(session, monkeypatch, action):
    original_scalars = session.scalars
    state = {"interleaved": False}

    def run_competing_command(statement, *args, **kwargs):
        rows = list(original_scalars(statement, *args, **kwargs))
        if (
            getattr(statement, "_for_update_arg", None) is not None
            and not state["interleaved"]
        ):
            state["interleaved"] = True
            action()
        return rows

    monkeypatch.setattr(session, "scalars", run_competing_command)
    return state


def admit_current_candidate(session, publication_id):
    view = get_view(session, publication_id)
    profile = profile_for_repository(view.repository)
    for index, job in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )
    return view
def test_all_required_jobs_admit_exact_candidate(session):
    view = admitted_publication(session)
    assert view.state is PublicationState.ADMITTED
    assert view.current_candidate is not None
    assert view.current_candidate.head_sha == HEAD
    assert view.projection.issue == "In Progress"


def test_failed_required_job_returns_ready_projection(session):
    view = create_publication(session, "DEAMBROGGI/FirstContact", 43)
    view = submit_verified_candidate(session, view.publication_id, source())
    view = record_validation(
        session,
        view.publication_id,
        job_id="python-contracts",
        status=ValidationStatus.FAIL,
        evidence_sha256="a" * 64,
    )
    assert view.state is PublicationState.VALIDATION_FAILED
    assert view.projection.issue == "Ready"


def test_same_candidate_submission_is_idempotent(session):
    view = create_publication(session, "DEAMBROGGI/FirstContact", 44)
    first = submit_verified_candidate(session, view.publication_id, source())
    second = submit_verified_candidate(session, view.publication_id, source())
    assert first.current_candidate == second.current_candidate
def test_review_is_exact_remote_head_bound(session):
    view = admitted_publication(session)
    view = mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch="control-plane/issue-42-canonical",
        base_branch="master",
        pull_request_number=13,
    )
    _reconcile_empty_pr_findings(session, view)
    assert view.state is PublicationState.IN_REVIEW
    with pytest.raises(DomainError, match="stale"):
        record_review(
            session,
            view.publication_id,
            reviewed_head_sha="4" * 40,
            decision=ReviewDecision.APPROVED,
        )
    approved = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
    )
    assert approved.state is PublicationState.APPROVED
    ready = record_mergeability(
        session,
        view.publication_id,
        head_sha=HEAD,
        mergeable=True,
    )
    assert ready.state is PublicationState.READY_TO_MERGE
    assert ready.projection.project == "Review"


@pytest.mark.parametrize("was_ready", [False, True])
def test_changes_requested_revokes_approval_without_erasing_evidence(
    session,
    was_ready,
):
    view = published_publication(session)
    approved = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
    )
    if was_ready:
        approved = record_mergeability(
            session,
            view.publication_id,
            head_sha=HEAD,
            mergeable=True,
        )
        assert approved.state is PublicationState.READY_TO_MERGE
    events_before = load_events(session, view.publication_id)

    demoted = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.CHANGES_REQUIRED,
    )

    events_after = load_events(session, view.publication_id)
    review_events = [
        event
        for event in events_after
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert demoted.state is PublicationState.CHANGES_REQUIRED
    assert demoted.review_decision is ReviewDecision.CHANGES_REQUIRED
    assert events_after[:-1] == events_before
    assert [event["payload"]["decision"] for event in review_events] == [
        ReviewDecision.APPROVED.value,
        ReviewDecision.CHANGES_REQUIRED.value,
    ]
    if was_ready:
        assert demoted.mergeable is True
        assert sum(
            event["event_type"] == EventType.MERGEABILITY_RECORDED.value
            for event in events_after
        ) == 1
    else:
        assert demoted.mergeable is None

    with pytest.raises(DomainError, match="merge requires READY_TO_MERGE state"):
        record_merged(
            session,
            view.publication_id,
            head_sha=HEAD,
            pull_request_number=13,
            merge_commit_sha="9" * 40,
            source="PLANE_MERGE",
        )
    with pytest.raises(DomainError, match="review requires IN_REVIEW state"):
        record_review(
            session,
            view.publication_id,
            reviewed_head_sha=HEAD,
            decision=ReviewDecision.APPROVED,
        )
    assert get_view(session, view.publication_id).state is PublicationState.CHANGES_REQUIRED


def test_changes_required_does_not_require_codex_pass(session):
    view = published_publication(session)
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=HEAD,
    )
    assert running.automated_review_status is AutomatedReviewStatus.RUNNING

    changes = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.CHANGES_REQUIRED,
        require_codex_review=True,
    )

    assert changes.state is PublicationState.CHANGES_REQUIRED
    assert changes.automated_review_status is AutomatedReviewStatus.RUNNING


def test_reapproval_after_changes_requires_successor_and_codex_pass(session):
    first = published_publication(session, issue_number=55)
    changes = record_review(
        session,
        first.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.CHANGES_REQUIRED,
    )
    with pytest.raises(
        DomainError,
        match="required Codex review has not passed or been adjudicated",
    ):
        record_review(
            session,
            first.publication_id,
            reviewed_head_sha=HEAD,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )

    submit_verified_candidate(
        session,
        first.publication_id,
        successor_source(),
    )
    admitted = admit_current_candidate(session, first.publication_id)
    republished = mark_remote_published(
        session,
        first.publication_id,
        admitted.current_candidate.head_sha,
        branch=first.remote_branch,
        base_branch=first.base_branch,
        pull_request_number=first.pull_request_number,
    )
    _reconcile_empty_pr_findings(session, republished)
    reviewed = pass_codex_review(session, republished)
    approved = record_review(
        session,
        first.publication_id,
        reviewed_head_sha=reviewed.remote_head_sha,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )

    assert changes.state is PublicationState.CHANGES_REQUIRED
    assert reviewed.state is PublicationState.IN_REVIEW
    assert approved.state is PublicationState.APPROVED


def test_hash_chain_tamper_fails_closed(session):
    view = create_publication(session, "DEAMBROGGI/FirstContact", 45)
    event = session.query(EventRow).filter_by(publication_id=view.publication_id).first()
    event.event_hash = "f" * 64
    session.commit()
    with pytest.raises(RuntimeError, match="hash mismatch"):
        get_view(session, view.publication_id)
def test_new_candidate_only_after_rework_state(session):
    view = admitted_publication(session)
    with pytest.raises(DomainError, match="cannot be submitted"):
        submit_verified_candidate(
            session,
            view.publication_id,
            source(
                digest="b" * 64,
                base=HEAD,
                head="5" * 40,
                tree="6" * 40,
            ),
        )


def test_same_candidate_with_different_bundle_is_conflict(session):
    view = create_publication(session, "DEAMBROGGI/FirstContact", 46)
    submit_verified_candidate(session, view.publication_id, source(digest="a" * 64))
    with pytest.raises(DomainError, match="immutable candidate source conflict"):
        submit_verified_candidate(
            session,
            view.publication_id,
            source(digest="b" * 64),
        )


def test_inflight_candidate_keeps_historical_profile_contract(session):
    repository = "DEAMBROGGI/FirstContact-ControlPlane"
    v1 = next(
        profile
        for profile in all_profiles()
        if profile.repository == repository and profile.version == 1
    )
    assert profile_for_repository(repository).version > v1.version

    view = create_publication(session, repository, 47)
    candidate_id = str(uuid.uuid4())
    session.add(
        CandidateRow(
            id=candidate_id,
            publication_id=view.publication_id,
            base_sha=BASE,
            head_sha=HEAD,
            tree_sha=TREE,
            profile_id=v1.profile_id,
            profile_version=v1.version,
            profile_digest=v1.digest,
        )
    )
    session.add(
        CandidateSourceRow(
            candidate_id=candidate_id,
            bundle_sha256="a" * 64,
            byte_length=1234,
            quarantine_id="a" * 64,
            base_sha=BASE,
            head_sha=HEAD,
            tree_sha=TREE,
        )
    )
    append_event(
        session,
        view.publication_id,
        EventType.CANDIDATE_SUBMITTED,
        {
            "candidate_id": candidate_id,
            "base_sha": BASE,
            "head_sha": HEAD,
            "tree_sha": TREE,
            "profile_id": v1.profile_id,
            "profile_version": v1.version,
            "profile_digest": v1.digest,
            "source": {
                "bundle_sha256": "a" * 64,
                "byte_length": 1234,
                "quarantine_id": "a" * 64,
                "base_sha": BASE,
                "head_sha": HEAD,
                "tree_sha": TREE,
            },
        },
    )
    session.commit()

    current = get_view(session, view.publication_id)
    assert current.current_candidate.profile_version == 1

    for index, job in enumerate(v1.required_jobs, 1):
        current = record_validation(
            session,
            view.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )

    assert current.state is PublicationState.ADMITTED
    assert current.current_candidate.profile_version == 1
    admitted = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == "CANDIDATE_ADMITTED"
    ]
    assert admitted[-1]["payload"]["profile_version"] == 1
    assert admitted[-1]["payload"]["profile_digest"] == v1.digest


def test_active_validation_records_versioned_job_definition(session):
    repository = "DEAMBROGGI/FirstContact-ControlPlane"
    profile = profile_for_repository(repository)
    assert profile.version == 4
    definition = profile.definition_for("codex-review-broker")
    assert definition is not None
    assert definition.version == 2
    assert len(definition.digest) == 64

    view = create_publication(session, repository, 48)
    view = submit_verified_candidate(session, view.publication_id, source())
    record_validation(
        session,
        view.publication_id,
        job_id="codex-review-broker",
        status=ValidationStatus.PASS,
        evidence_sha256="f" * 64,
    )
    event = next(
        item
        for item in reversed(load_events(session, view.publication_id))
        if item["event_type"] == "VALIDATION_RECORDED"
    )
    recorded = event["payload"]["job_definition"]
    assert recorded["job_id"] == "codex-review-broker"
    assert recorded["version"] == 2
    assert recorded["digest"] == definition.digest
    assert recorded["implementation"] == "controlplane.pytest"


def test_control_plane_profile_versions_remain_resolvable():
    profiles = [
        profile
        for profile in all_profiles()
        if profile.repository == "DEAMBROGGI/FirstContact-ControlPlane"
    ]
    assert [profile.version for profile in profiles] == [1, 2, 3, 4]
    assert profiles[0].schema_version == 1
    assert profiles[1].schema_version == 1
    assert profiles[2].schema_version == 2
    assert profiles[3].schema_version == 2


def test_in_review_successor_candidate_resets_current_gates_and_keeps_pr_identity(session):
    first = published_publication(session)
    events_before = load_events(session, first.publication_id)

    second = submit_verified_candidate(session, first.publication_id, successor_source())

    assert second.state is PublicationState.VALIDATING
    assert second.current_candidate.head_sha == "4" * 40
    assert second.remote_head_sha == first.remote_head_sha
    assert second.remote_branch == first.remote_branch
    assert second.base_branch == first.base_branch
    assert second.pull_request_number == first.pull_request_number
    assert second.automated_review_status is None
    assert second.review_decision is None
    assert second.mergeable is None
    events_after = load_events(session, first.publication_id)
    assert events_after[:-1] == events_before


def test_changes_required_allows_successor_candidate(session):
    first = published_publication(session, issue_number=52)
    changes = record_review(
        session,
        first.publication_id,
        reviewed_head_sha=first.remote_head_sha,
        decision=ReviewDecision.CHANGES_REQUIRED,
    )
    assert changes.state is PublicationState.CHANGES_REQUIRED

    second = submit_verified_candidate(session, first.publication_id, successor_source())

    assert second.state is PublicationState.VALIDATING
    assert second.current_candidate.head_sha == "4" * 40
    assert second.remote_head_sha == first.remote_head_sha


def test_approved_successor_invalidates_codex_and_human_approval(session):
    first = published_publication(session, issue_number=53)
    reviewed = pass_codex_review(session, first)
    approved = record_review(
        session,
        first.publication_id,
        reviewed_head_sha=first.remote_head_sha,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    assert approved.state is PublicationState.APPROVED

    second = submit_verified_candidate(session, first.publication_id, successor_source())

    assert second.state is PublicationState.VALIDATING
    assert second.automated_review_status is None
    assert second.automated_review_head_sha is None
    assert second.review_decision is None
    assert second.mergeable is None


def test_ready_to_merge_successor_invalidates_mergeability_and_stale_approval(session):
    first = published_publication(session, issue_number=54)
    reviewed = pass_codex_review(session, first)
    approved = record_review(
        session,
        first.publication_id,
        reviewed_head_sha=first.remote_head_sha,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    ready = record_mergeability(
        session,
        first.publication_id,
        head_sha=first.remote_head_sha,
        mergeable=True,
    )
    assert ready.state is PublicationState.READY_TO_MERGE

    second = submit_verified_candidate(session, first.publication_id, successor_source())
    assert second.state is PublicationState.VALIDATING
    assert second.mergeable is None
    assert second.review_decision is None

    admitted = admit_current_candidate(session, first.publication_id)
    republished = mark_remote_published(
        session,
        first.publication_id,
        admitted.current_candidate.head_sha,
        branch=first.remote_branch,
        base_branch=first.base_branch,
        pull_request_number=first.pull_request_number,
    )
    _reconcile_empty_pr_findings(session, republished)
    assert republished.state is PublicationState.IN_REVIEW
    with pytest.raises(DomainError, match="stale"):
        record_review(
            session,
            first.publication_id,
            reviewed_head_sha=first.remote_head_sha,
            decision=ReviewDecision.APPROVED,
        )
    with pytest.raises(DomainError, match="mergeability"):
        record_mergeability(
            session,
            first.publication_id,
            head_sha=first.remote_head_sha,
            mergeable=True,
        )
    assert approved.review_decision is ReviewDecision.APPROVED

    codex_b = pass_codex_review(session, republished)
    approved_b = record_review(
        session,
        first.publication_id,
        reviewed_head_sha=republished.remote_head_sha,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    with pytest.raises(DomainError, match="stale head"):
        record_mergeability(
            session,
            first.publication_id,
            head_sha=first.remote_head_sha,
            mergeable=True,
        )
    ready_b = record_mergeability(
        session,
        first.publication_id,
        head_sha=republished.remote_head_sha,
        mergeable=True,
    )
    assert codex_b.automated_review_head_sha == republished.remote_head_sha
    assert approved_b.review_decision is ReviewDecision.APPROVED
    assert ready_b.state is PublicationState.READY_TO_MERGE


def test_merged_publication_rejects_successor_candidate(session):
    view = published_publication(session, issue_number=55)
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=view.remote_head_sha,
        decision=ReviewDecision.APPROVED,
    )
    record_mergeability(
        session,
        view.publication_id,
        head_sha=view.remote_head_sha,
        mergeable=True,
    )
    record_merged(
        session,
        view.publication_id,
        head_sha=view.remote_head_sha,
        pull_request_number=view.pull_request_number,
        merge_commit_sha="6" * 40,
        source="PLANE_MERGE",
    )
    assert get_view(session, view.publication_id).state is PublicationState.MERGED
    with pytest.raises(DomainError, match="MERGED publication is terminal"):
        submit_verified_candidate(session, view.publication_id, successor_source())


def test_successor_candidate_is_blocked_while_codex_review_is_running(session):
    first = published_publication(session, issue_number=56)
    running = request_codex_review(
        session,
        first.publication_id,
        mode="required",
        expected_head_sha=first.remote_head_sha,
    )

    with pytest.raises(DomainError, match="automated review is running"):
        submit_verified_candidate(session, first.publication_id, successor_source())

    current = get_view(session, first.publication_id)
    assert current.state is PublicationState.IN_REVIEW
    assert current.automated_review_status is AutomatedReviewStatus.RUNNING
    assert current.automated_review_run_id == running.automated_review_run_id

    completed = complete_codex_review(
        session,
        first.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=first.remote_head_sha,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[],
        provider_comment_ids=[],
    )
    assert completed.automated_review_status is AutomatedReviewStatus.PASS
    successor = submit_verified_candidate(session, first.publication_id, successor_source())
    assert successor.state is PublicationState.VALIDATING

def test_codex_pass_from_old_head_does_not_satisfy_successor_review(session):
    first = published_publication(session, issue_number=57)
    pass_codex_review(session, first)
    second = submit_verified_candidate(session, first.publication_id, successor_source())
    admitted = admit_current_candidate(session, first.publication_id)
    published = mark_remote_published(
        session,
        first.publication_id,
        admitted.current_candidate.head_sha,
        branch=first.remote_branch,
        base_branch=first.base_branch,
        pull_request_number=first.pull_request_number,
    )
    _reconcile_empty_pr_findings(session, published)

    assert published.automated_review_status is None
    assert published.automated_review_head_sha is None
    with pytest.raises(DomainError, match="required Codex review has not passed"):
        record_review(
            session,
            second.publication_id,
            reviewed_head_sha=published.remote_head_sha,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )


def test_create_publication_returns_single_active_aggregate(session):
    first = create_publication(session, "DEAMBROGGI/FirstContact", 58)

    repeated = create_publication(session, "DEAMBROGGI/FirstContact", 58)

    assert repeated.publication_id == first.publication_id
    assert session.query(PublicationRow).filter_by(
        repository="DEAMBROGGI/FirstContact", issue_number=58
    ).count() == 1


def test_create_publication_fails_closed_for_multiple_active_aggregates(session):
    first = create_publication(session, "DEAMBROGGI/FirstContact", 59)
    second = raw_publication(session, first.repository, first.issue_number)

    with pytest.raises(DomainError, match="multiple active publications"):
        create_publication(session, first.repository, first.issue_number)
    assert session.query(PublicationRow).filter_by(issue_number=59).count() == 2
    assert get_view(session, second.publication_id).state is PublicationState.CREATED


def test_supersession_is_idempotent_and_preserves_historical_metadata(session):
    old = published_publication(session, issue_number=60)
    successor = raw_publication(session, old.repository, old.issue_number)
    prior_events = load_events(session, old.publication_id)

    superseded = supersede_publication(
        session,
        old.publication_id,
        successor.publication_id,
        "duplicate aggregate replacement",
    )

    assert superseded.state is PublicationState.SUPERSEDED
    assert superseded.projection.issue == "Superseded"
    assert superseded.projection.pull_request == "Superseded"
    assert superseded.projection.project == "Superseded"
    assert superseded.current_candidate == old.current_candidate
    assert superseded.remote_head_sha == old.remote_head_sha
    assert superseded.remote_branch == old.remote_branch
    assert superseded.base_branch == old.base_branch
    assert superseded.pull_request_number == old.pull_request_number
    after_events = load_events(session, old.publication_id)
    assert after_events[:-1] == prior_events
    assert after_events[-1]["event_type"] == EventType.PUBLICATION_SUPERSEDED.value
    assert after_events[-1]["payload"] == {
        "successor_publication_id": successor.publication_id,
        "reason": "duplicate aggregate replacement",
    }

    repeated = supersede_publication(
        session,
        old.publication_id,
        successor.publication_id,
        "duplicate aggregate replacement",
    )
    assert repeated == superseded
    assert len(load_events(session, old.publication_id)) == len(after_events)
    assert create_publication(session, old.repository, old.issue_number).publication_id == successor.publication_id
    with pytest.raises(DomainError, match="SUPERSEDED publication"):
        submit_verified_candidate(session, old.publication_id, successor_source())


def test_historical_supersession_replay_survives_successor_supersession(session):
    original = raw_publication(session, "DEAMBROGGI/FirstContact", 68)
    successor = raw_publication(session, original.repository, original.issue_number)
    replacement = raw_publication(session, original.repository, original.issue_number)
    reason = "first replacement"

    first_result = supersede_publication(
        session,
        original.publication_id,
        successor.publication_id,
        reason,
    )
    supersede_publication(
        session,
        successor.publication_id,
        replacement.publication_id,
        "later replacement",
    )

    replay = supersede_publication(
        session,
        original.publication_id,
        successor.publication_id,
        reason,
    )

    assert replay == first_result
    assert len(
        [event for event in load_events(session, original.publication_id)
         if event["event_type"] == EventType.PUBLICATION_SUPERSEDED.value]
    ) == 1


def test_supersession_requests_ordered_row_locks_before_rereading(session, monkeypatch):
    """SQLite omits FOR UPDATE, so assert the production PostgreSQL SQL shape."""
    old = published_publication(session, issue_number=69)
    successor = raw_publication(session, old.repository, old.issue_number)
    trace = []
    original_scalars = session.scalars
    original_get_view = service_module.get_view
    original_append_event = service_module.append_event
    original_commit = session.commit

    def recording_scalars(statement, *args, **kwargs):
        if getattr(statement, "_for_update_arg", None) is not None:
            compiled = statement.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"render_postcompile": True},
            )
            trace.append(("lock", str(compiled), compiled.params))
        return original_scalars(statement, *args, **kwargs)

    def recording_get_view(db_session, publication_id):
        assert any(entry[0] == "lock" for entry in trace)
        trace.append(("read", publication_id))
        return original_get_view(db_session, publication_id)

    def recording_append_event(db_session, publication_id, event_type, payload):
        trace.append(("append", publication_id))
        return original_append_event(db_session, publication_id, event_type, payload)

    def recording_commit():
        trace.append(("commit",))
        return original_commit()

    monkeypatch.setattr(session, "scalars", recording_scalars)
    monkeypatch.setattr(session, "commit", recording_commit)
    monkeypatch.setattr(service_module, "get_view", recording_get_view)
    monkeypatch.setattr(service_module, "append_event", recording_append_event)

    superseded = supersede_publication(
        session,
        old.publication_id,
        successor.publication_id,
        "ordered lock check",
    )

    assert superseded.state is PublicationState.SUPERSEDED
    lock_index = next(index for index, entry in enumerate(trace) if entry[0] == "lock")
    lock_sql = trace[lock_index][1].upper()
    lock_params = trace[lock_index][2]
    assert "FOR UPDATE" in lock_sql
    assert "ORDER BY PUBLICATIONS.ID" in lock_sql
    expected_ids = tuple(sorted((old.publication_id, successor.publication_id)))
    assert tuple(str(value) for value in lock_params.values()) == expected_ids
    assert [entry[0] for entry in trace] == [
        "lock",
        "read",
        "read",
        "append",
        "commit",
        "read",
    ]
    assert trace[1][1] == old.publication_id
    assert trace[2][1] == successor.publication_id
    assert trace[3][1] == old.publication_id


def test_codex_running_state_serializes_candidate_submission(session):
    published = published_publication(session, issue_number=72)
    running = request_codex_review(
        session,
        published.publication_id,
        mode="required",
        expected_head_sha=published.remote_head_sha,
    )

    with pytest.raises(DomainError, match="automated review is running"):
        submit_verified_candidate(
            session,
            published.publication_id,
            successor_source(),
        )

    current = get_view(session, published.publication_id)
    assert current.state is PublicationState.IN_REVIEW
    assert current.current_candidate.head_sha == HEAD
    assert current.remote_head_sha == HEAD
    assert current.automated_review_status is AutomatedReviewStatus.RUNNING
    assert current.automated_review_run_id == running.automated_review_run_id

def test_human_approval_is_rejected_if_successor_candidate_wins_lock_race(
    session,
    monkeypatch,
):
    published = published_publication(session, issue_number=73)
    state = interleave_after_first_publication_lock(
        session,
        monkeypatch,
        lambda: submit_verified_candidate(
            session,
            published.publication_id,
            successor_source(),
        ),
    )

    with pytest.raises(DomainError, match="review requires IN_REVIEW"):
        record_review(
            session,
            published.publication_id,
            reviewed_head_sha=published.remote_head_sha,
            decision=ReviewDecision.APPROVED,
        )

    events = load_events(session, published.publication_id)
    assert state["interleaved"]
    assert not any(event["event_type"] == EventType.REVIEW_RECORDED.value for event in events)
    assert get_view(session, published.publication_id).state is PublicationState.VALIDATING


def test_mergeability_is_rejected_if_successor_candidate_wins_lock_race(
    session,
    monkeypatch,
):
    published = published_publication(session, issue_number=74)
    record_review(
        session,
        published.publication_id,
        reviewed_head_sha=published.remote_head_sha,
        decision=ReviewDecision.APPROVED,
    )
    state = interleave_after_first_publication_lock(
        session,
        monkeypatch,
        lambda: submit_verified_candidate(
            session,
            published.publication_id,
            successor_source(),
        ),
    )

    with pytest.raises(DomainError, match="mergeability is evaluated only after approval"):
        record_mergeability(
            session,
            published.publication_id,
            head_sha=published.remote_head_sha,
            mergeable=True,
        )

    events = load_events(session, published.publication_id)
    assert state["interleaved"]
    assert not any(
        event["event_type"] == EventType.MERGEABILITY_RECORDED.value
        for event in events
    )
    current = get_view(session, published.publication_id)
    assert current.state is PublicationState.VALIDATING
    assert current.mergeable is None


def test_codex_request_is_rejected_if_successor_candidate_wins_lock_race(
    session,
    monkeypatch,
):
    published = published_publication(session, issue_number=75)
    state = interleave_after_first_publication_lock(
        session,
        monkeypatch,
        lambda: submit_verified_candidate(
            session,
            published.publication_id,
            successor_source(),
        ),
    )

    with pytest.raises(DomainError, match="Codex review requires IN_REVIEW"):
        request_codex_review(
            session,
            published.publication_id,
            mode="required",
            expected_head_sha=published.remote_head_sha,
        )

    events = load_events(session, published.publication_id)
    assert state["interleaved"]
    assert not any(
        event["event_type"] == EventType.CODEX_REVIEW_REQUESTED.value
        for event in events
    )
    current = get_view(session, published.publication_id)
    assert current.current_candidate.head_sha == "4" * 40
    assert current.automated_review_status is None


def test_only_one_successor_candidate_wins_concurrent_submissions(
    session,
    monkeypatch,
):
    published = published_publication(session, issue_number=76)
    winning_source = successor_source()
    losing_source = source(digest="c" * 64, head="6" * 40, tree="7" * 40)
    state = interleave_after_first_publication_lock(
        session,
        monkeypatch,
        lambda: submit_verified_candidate(
            session,
            published.publication_id,
            winning_source,
        ),
    )

    with pytest.raises(DomainError, match="candidate cannot be submitted from VALIDATING"):
        submit_verified_candidate(session, published.publication_id, losing_source)

    events = load_events(session, published.publication_id)
    submissions = [
        event for event in events
        if event["event_type"] == EventType.CANDIDATE_SUBMITTED.value
    ]
    assert state["interleaved"]
    assert len(submissions) == 2
    assert get_view(session, published.publication_id).current_candidate.head_sha == "4" * 40


@pytest.mark.parametrize("outer_evidence", ["d" * 64, "e" * 64])
def test_same_candidate_validation_race_is_idempotent_or_rejects_conflict(
    session,
    monkeypatch,
    outer_evidence,
):
    created = create_publication(session, "DEAMBROGGI/FirstContact", 77)
    validating = submit_verified_candidate(session, created.publication_id, source())
    job_id = profile_for_repository(validating.repository).required_jobs[0]
    winning_evidence = "d" * 64
    state = interleave_after_first_publication_lock(
        session,
        monkeypatch,
        lambda: record_validation(
            session,
            created.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=winning_evidence,
        ),
    )

    if outer_evidence == winning_evidence:
        result = record_validation(
            session,
            created.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=outer_evidence,
        )
        assert result.state is PublicationState.VALIDATING
    else:
        with pytest.raises(DomainError, match="immutable validation result conflict"):
            record_validation(
                session,
                created.publication_id,
                job_id=job_id,
                status=ValidationStatus.PASS,
                evidence_sha256=outer_evidence,
            )

    validation_events = [
        event for event in load_events(session, created.publication_id)
        if event["event_type"] == EventType.VALIDATION_RECORDED.value
    ]
    assert state["interleaved"]
    assert len(validation_events) == 1
    assert validation_events[0]["payload"]["evidence_sha256"] == winning_evidence


def test_concurrent_distinct_validations_admit_candidate_once(session, monkeypatch):
    created = create_publication(session, "DEAMBROGGI/FirstContact", 78)
    validating = submit_verified_candidate(session, created.publication_id, source())
    required_jobs = profile_for_repository(validating.repository).required_jobs
    assert len(required_jobs) >= 2
    for index, job_id in enumerate(required_jobs[:-2]):
        record_validation(
            session,
            created.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 10:064x}",
        )

    first_job, second_job = required_jobs[-2:]
    state = interleave_after_first_publication_lock(
        session,
        monkeypatch,
        lambda: record_validation(
            session,
            created.publication_id,
            job_id=first_job,
            status=ValidationStatus.PASS,
            evidence_sha256="a" * 64,
        ),
    )

    admitted = record_validation(
        session,
        created.publication_id,
        job_id=second_job,
        status=ValidationStatus.PASS,
        evidence_sha256="b" * 64,
    )

    events = load_events(session, created.publication_id)
    assert state["interleaved"]
    assert admitted.state is PublicationState.ADMITTED
    assert sum(
        event["event_type"] == EventType.CANDIDATE_ADMITTED.value
        for event in events
    ) == 1
    assert len(
        [event for event in events
         if event["event_type"] == EventType.VALIDATION_RECORDED.value]
    ) == len(required_jobs)


def test_supersession_returns_concurrent_exact_winner_after_lock_reread(
    session,
    monkeypatch,
):
    """Simulate a waiting caller observing the winner after acquiring locks."""
    old = raw_publication(session, "DEAMBROGGI/FirstContact", 70)
    successor = raw_publication(session, old.repository, old.issue_number)
    payload = {
        "successor_publication_id": successor.publication_id,
        "reason": "same concurrent decision",
    }
    original_scalars = session.scalars
    injected_winner = False

    def commit_winner_before_reread(statement, *args, **kwargs):
        nonlocal injected_winner
        rows = list(original_scalars(statement, *args, **kwargs))
        if getattr(statement, "_for_update_arg", None) is not None and not injected_winner:
            injected_winner = True
            append_event(
                session,
                old.publication_id,
                EventType.PUBLICATION_SUPERSEDED,
                payload,
            )
            session.commit()
        return rows

    monkeypatch.setattr(session, "scalars", commit_winner_before_reread)

    result = supersede_publication(
        session,
        old.publication_id,
        successor.publication_id,
        "same concurrent decision",
    )

    events = load_events(session, old.publication_id)
    assert injected_winner
    assert result.state is PublicationState.SUPERSEDED
    assert len(
        [event for event in events
         if event["event_type"] == EventType.PUBLICATION_SUPERSEDED.value]
    ) == 1


def test_supersession_rejects_successor_superseded_while_waiting_for_locks(
    session,
    monkeypatch,
):
    old = raw_publication(session, "DEAMBROGGI/FirstContact", 71)
    successor = raw_publication(session, old.repository, old.issue_number)
    winner = raw_publication(session, old.repository, old.issue_number)
    original_scalars = session.scalars
    injected_winner = False

    def supersede_target_before_reread(statement, *args, **kwargs):
        nonlocal injected_winner
        rows = list(original_scalars(statement, *args, **kwargs))
        if getattr(statement, "_for_update_arg", None) is not None and not injected_winner:
            injected_winner = True
            append_event(
                session,
                successor.publication_id,
                EventType.PUBLICATION_SUPERSEDED,
                {
                    "successor_publication_id": winner.publication_id,
                    "reason": "another winner",
                },
            )
            session.commit()
        return rows

    monkeypatch.setattr(session, "scalars", supersede_target_before_reread)

    with pytest.raises(DomainError, match="successor cannot be SUPERSEDED"):
        supersede_publication(
            session,
            old.publication_id,
            successor.publication_id,
            "stale target",
        )

    assert injected_winner
    assert get_view(session, old.publication_id).state is PublicationState.CREATED
    assert not any(
        event["event_type"] == EventType.PUBLICATION_SUPERSEDED.value
        for event in load_events(session, old.publication_id)
    )


def test_supersession_rejects_other_successor_or_reason(session):
    old = raw_publication(session, "DEAMBROGGI/FirstContact", 61)
    one = raw_publication(session, old.repository, old.issue_number)
    two = raw_publication(session, old.repository, old.issue_number)
    supersede_publication(session, old.publication_id, one.publication_id, "replace")

    with pytest.raises(DomainError, match="already superseded"):
        supersede_publication(session, old.publication_id, two.publication_id, "replace")
    with pytest.raises(DomainError, match="already superseded"):
        supersede_publication(session, old.publication_id, one.publication_id, "different reason")


def test_supersession_requires_same_repository_and_issue(session):
    old = raw_publication(session, "DEAMBROGGI/FirstContact", 62)
    wrong_issue = raw_publication(session, old.repository, 63)
    wrong_repository = raw_publication(session, "another/repository", 62)

    with pytest.raises(DomainError, match="share repository and issue"):
        supersede_publication(
            session,
            old.publication_id,
            wrong_issue.publication_id,
            "wrong issue",
        )
    with pytest.raises(DomainError, match="share repository and issue"):
        supersede_publication(
            session,
            old.publication_id,
            wrong_repository.publication_id,
            "wrong repository",
        )


def test_supersession_rejects_superseded_successor_and_self_reference(session):
    old = raw_publication(session, "DEAMBROGGI/FirstContact", 64)
    successor = raw_publication(session, old.repository, old.issue_number)
    terminal = raw_publication(session, old.repository, old.issue_number)
    supersede_publication(session, successor.publication_id, terminal.publication_id, "replaced")

    with pytest.raises(DomainError, match="cannot be SUPERSEDED"):
        supersede_publication(session, old.publication_id, successor.publication_id, "bad target")
    with pytest.raises(DomainError, match="itself"):
        supersede_publication(session, old.publication_id, old.publication_id, "self")


def test_supersession_requires_both_publications_to_exist(session):
    existing = raw_publication(session, "DEAMBROGGI/FirstContact", 68)

    with pytest.raises(KeyError):
        supersede_publication(
            session,
            existing.publication_id,
            "missing-successor",
            "missing target",
        )
    with pytest.raises(KeyError):
        supersede_publication(
            session,
            "missing-publication",
            existing.publication_id,
            "missing source",
        )


def test_superseded_publication_rejects_late_codex_result(session):
    old = published_publication(session, issue_number=67)
    running = request_codex_review(
        session,
        old.publication_id,
        mode="required",
        expected_head_sha=old.remote_head_sha,
    )
    successor = raw_publication(session, old.repository, old.issue_number)
    supersede_publication(
        session,
        old.publication_id,
        successor.publication_id,
        "duplicate aggregate replacement",
    )

    with pytest.raises(DomainError, match="SUPERSEDED publication"):
        complete_codex_review(
            session,
            old.publication_id,
            run_id=running.automated_review_run_id,
            reviewed_head_sha=old.remote_head_sha,
            result=AutomatedReviewStatus.CHANGES_REQUIRED,
            findings=[],
            provider_review_ids=[],
            provider_comment_ids=[],
        )
    assert get_view(session, old.publication_id).state is PublicationState.SUPERSEDED


def test_merged_publication_cannot_be_superseded(session):
    old = published_publication(session, issue_number=65)
    approved = record_review(
        session,
        old.publication_id,
        reviewed_head_sha=old.remote_head_sha,
        decision=ReviewDecision.APPROVED,
    )
    record_mergeability(
        session,
        old.publication_id,
        head_sha=old.remote_head_sha,
        mergeable=True,
    )
    record_merged(
        session,
        old.publication_id,
        head_sha=old.remote_head_sha,
        pull_request_number=old.pull_request_number,
        merge_commit_sha="7" * 40,
        source="PLANE_MERGE",
    )
    successor = raw_publication(session, old.repository, old.issue_number)

    with pytest.raises(DomainError, match="cannot be superseded from MERGED"):
        supersede_publication(
            session,
            old.publication_id,
            successor.publication_id,
            "merged aggregate",
        )


def test_merged_is_inactive_for_canonical_publication_resolution(session):
    original = create_publication(session, "DEAMBROGGI/FirstContact", 66)
    submitted = submit_verified_candidate(session, original.publication_id, source())
    admitted = admit_current_candidate(session, submitted.publication_id)
    published = mark_remote_published(
        session,
        original.publication_id,
        admitted.current_candidate.head_sha,
        branch="control-plane/issue-66-canonical",
        base_branch="master",
        pull_request_number=66,
    )
    _reconcile_empty_pr_findings(session, published)
    approved = record_review(
        session,
        original.publication_id,
        reviewed_head_sha=published.remote_head_sha,
        decision=ReviewDecision.APPROVED,
    )
    ready = record_mergeability(
        session,
        original.publication_id,
        head_sha=published.remote_head_sha,
        mergeable=True,
    )
    assert approved.state is PublicationState.APPROVED
    record_merged(
        session,
        original.publication_id,
        head_sha=published.remote_head_sha,
        pull_request_number=published.pull_request_number,
        merge_commit_sha="8" * 40,
        source="PLANE_MERGE",
    )
    assert get_view(session, original.publication_id).state is PublicationState.MERGED
    assert ready.state is PublicationState.READY_TO_MERGE

    replacement = create_publication(session, original.repository, original.issue_number)

    assert replacement.publication_id != original.publication_id
    assert replacement.state is PublicationState.CREATED


def _mark_required_codex_unavailable(session, view):
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=view.remote_head_sha,
    )
    return mark_codex_review_unavailable(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=view.remote_head_sha,
        reason="provider unavailable for test",
    )


def _materialize_plane_fallback(
    session,
    view,
    *,
    run_id,
    reviewer_kind="FALLBACK_REVIEWER",
    comments=None,
    provider_review_id=9101,
):
    comments = [] if comments is None else comments
    record_plane_review(
        session,
        view.publication_id,
        run_id=run_id,
        reviewer_kind=reviewer_kind,
        reviewer="principal-reviewer:test",
        reviewed_head_sha=view.remote_head_sha,
        body="Exact-head Plane fallback test review.",
        comments=comments,
        idempotency_key=f"{run_id}:record",
    )
    receipts = [
        {
            "finding_id": item["finding_id"],
            "provider_comment_id": provider_review_id + index + 1,
            "provider_review_id": provider_review_id,
            "path": item["path"],
            "line": item["line"],
        }
        for index, item in enumerate(comments)
    ]
    return complete_plane_review_materialization(
        session,
        view.publication_id,
        run_id=run_id,
        provider_review_id=provider_review_id,
        receipts=receipts,
    )


def test_required_human_approval_accepts_exact_head_clean_plane_fallback(session):
    published = published_publication(session, issue_number=90)
    unavailable = _mark_required_codex_unavailable(session, published)
    materialized = _materialize_plane_fallback(
        session,
        unavailable,
        run_id="principal-review:test-required-fallback",
        provider_review_id=9201,
    )
    assert materialized["result"] == "PASS"
    assert materialized["findings_count"] == 0

    approved = record_review(
        session,
        published.publication_id,
        reviewed_head_sha=published.remote_head_sha,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )

    assert approved.state is PublicationState.APPROVED
    review_event = [
        event
        for event in load_events(session, published.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ][-1]
    assert review_event["payload"]["required_review_adjudication"] == {
        "kind": "PLANE_FALLBACK",
        "codex_run_id": unavailable.automated_review_run_id,
        "head_sha": published.remote_head_sha,
        "plane_run_id": "principal-review:test-required-fallback",
        "plane_reviewer": "principal-reviewer:test",
        "provider_review_id": 9201,
    }


def test_required_human_approval_rejects_stale_plane_fallback(session):
    first = published_publication(session, issue_number=91)
    unavailable = _mark_required_codex_unavailable(session, first)
    _materialize_plane_fallback(
        session,
        unavailable,
        run_id="principal-review:test-stale-fallback",
        provider_review_id=9301,
    )

    submit_verified_candidate(
        session,
        first.publication_id,
        successor_source(),
    )
    admitted = admit_current_candidate(session, first.publication_id)
    successor = mark_remote_published(
        session,
        first.publication_id,
        admitted.current_candidate.head_sha,
        branch=first.remote_branch,
        base_branch=first.base_branch,
        pull_request_number=first.pull_request_number,
    )
    _reconcile_empty_pr_findings(session, successor)
    _mark_required_codex_unavailable(session, successor)

    with pytest.raises(DomainError, match="required Codex review has not passed"):
        record_review(
            session,
            first.publication_id,
            reviewed_head_sha=successor.remote_head_sha,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )


def test_required_human_approval_rejects_nonclean_plane_fallback(session):
    published = published_publication(session, issue_number=92)
    unavailable = _mark_required_codex_unavailable(session, published)
    finding = {
        "finding_id": "principal:test:required-fallback-finding",
        "normalized_identity": "principal:test:required-fallback-finding:v1",
        "priority": "P1",
        "path": "control_plane/service.py",
        "line": 500,
        "side": "RIGHT",
        "body": "Test finding keeps fallback non-clean.",
    }
    materialized = _materialize_plane_fallback(
        session,
        unavailable,
        run_id="principal-review:test-nonclean-fallback",
        comments=[finding],
        provider_review_id=9401,
    )
    assert materialized["result"] == "CHANGES_REQUIRED"

    with pytest.raises(DomainError, match="required Codex review has not passed"):
        record_review(
            session,
            published.publication_id,
            reviewed_head_sha=published.remote_head_sha,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )


def test_required_human_approval_rejects_nonfallback_plane_pass(session):
    published = published_publication(session, issue_number=93)
    unavailable = _mark_required_codex_unavailable(session, published)
    materialized = _materialize_plane_fallback(
        session,
        unavailable,
        run_id="principal-review:test-principal-not-fallback",
        reviewer_kind="PRINCIPAL_REVIEWER",
        provider_review_id=9501,
    )
    assert materialized["result"] == "PASS"

    with pytest.raises(DomainError, match="required Codex review has not passed"):
        record_review(
            session,
            published.publication_id,
            reviewed_head_sha=published.remote_head_sha,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )


def test_required_human_approval_rejects_preexisting_same_head_plane_fallback(session):
    published = published_publication(session, issue_number=94)
    materialized = _materialize_plane_fallback(
        session,
        published,
        run_id="principal-review:test-preexisting-fallback",
        provider_review_id=9601,
    )
    assert materialized["result"] == "PASS"

    unavailable = _mark_required_codex_unavailable(session, published)
    assert unavailable.automated_review_status is AutomatedReviewStatus.UNAVAILABLE

    with pytest.raises(DomainError, match="required Codex review has not passed"):
        record_review(
            session,
            published.publication_id,
            reviewed_head_sha=published.remote_head_sha,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )
