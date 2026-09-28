import uuid

import pytest

from control_plane.domain import DomainError, EventType, PublicationState, ReviewDecision, ValidationStatus
from control_plane.models import CandidateRow, CandidateSourceRow, EventRow
from control_plane.profile_registry import all_profiles, profile_for_repository
from control_plane.repository import append_event, load_events
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.service import (
    create_publication,
    get_view,
    mark_remote_published,
    record_mergeability,
    record_review,
    record_validation,
    submit_verified_candidate,
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


def admitted_publication(session, repository="DEAMBROGGI/FirstContact"):
    view = create_publication(session, repository, 42)
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
    view = mark_remote_published(session, view.publication_id, HEAD)
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
    ready = record_mergeability(session, view.publication_id, True)
    assert ready.state is PublicationState.READY_TO_MERGE
    assert ready.projection.project == "Review"


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
