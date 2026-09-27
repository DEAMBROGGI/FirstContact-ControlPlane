import pytest

from control_plane.domain import DomainError, PublicationState, ReviewDecision, ValidationStatus
from control_plane.models import EventRow
from control_plane.profile_registry import profile_for_repository
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
