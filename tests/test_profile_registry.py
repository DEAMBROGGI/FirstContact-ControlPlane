from __future__ import annotations

import uuid

from control_plane.domain import (
    EventType,
    PublicationState,
    ValidationStatus,
)
from control_plane.models import CandidateRow
from control_plane.profile_registry import (
    all_profiles,
    profile_for_identity,
    profile_for_repository,
)
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.repository import append_event, load_events
from control_plane.service import (
    create_publication,
    record_validation,
    submit_verified_candidate,
)

BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


def source():
    return VerifiedCandidateSource(
        bundle_sha256="b" * 64,
        byte_length=100,
        quarantine_id="b" * 64,
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
    )


def test_active_control_plane_profile_pins_versioned_job_definitions():
    profile = profile_for_repository(
        "DEAMBROGGI/FirstContact-ControlPlane"
    )

    assert profile.version == 4
    assert profile.schema_version == 2
    assert len(profile.job_definitions) == len(profile.required_jobs)
    assert {
        item.job_id for item in profile.job_definitions
    } == set(profile.required_jobs)
    assert all(len(item.digest) == 64 for item in profile.job_definitions)


def test_historical_control_plane_profile_is_resolvable_by_exact_identity():
    historical = next(
        item
        for item in all_profiles()
        if item.repository == "DEAMBROGGI/FirstContact-ControlPlane"
        and item.version == 1
    )

    resolved = profile_for_identity(
        historical.repository,
        historical.profile_id,
        historical.version,
        historical.digest,
    )

    assert resolved == historical
    assert "codex-review-broker" not in resolved.required_jobs


def test_inflight_v1_candidate_finishes_under_its_pinned_profile(session):
    publication = create_publication(
        session,
        "DEAMBROGGI/FirstContact-ControlPlane",
        91,
    )
    historical = next(
        item
        for item in all_profiles()
        if item.repository == publication.repository
        and item.version == 1
    )
    candidate_id = str(uuid.uuid4())
    session.add(
        CandidateRow(
            id=candidate_id,
            publication_id=publication.publication_id,
            base_sha=BASE,
            head_sha=HEAD,
            tree_sha=TREE,
            profile_id=historical.profile_id,
            profile_version=historical.version,
            profile_digest=historical.digest,
        )
    )
    append_event(
        session,
        publication.publication_id,
        EventType.CANDIDATE_SUBMITTED,
        {
            "candidate_id": candidate_id,
            "base_sha": BASE,
            "head_sha": HEAD,
            "tree_sha": TREE,
            "profile_id": historical.profile_id,
            "profile_version": historical.version,
            "profile_digest": historical.digest,
        },
    )
    session.commit()

    view = None
    for index, job in enumerate(historical.required_jobs, 1):
        view = record_validation(
            session,
            publication.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )

    assert view is not None
    assert view.state is PublicationState.ADMITTED
    assert view.current_candidate.profile_version == 1


def test_active_validation_event_records_job_definition_identity(session):
    publication = create_publication(
        session,
        "DEAMBROGGI/FirstContact-ControlPlane",
        92,
    )
    view = submit_verified_candidate(
        session,
        publication.publication_id,
        source(),
    )
    record_validation(
        session,
        publication.publication_id,
        job_id="codex-review-broker",
        status=ValidationStatus.PASS,
        evidence_sha256="c" * 64,
    )

    event = next(
        item
        for item in load_events(session, publication.publication_id)
        if item["event_type"] == EventType.VALIDATION_RECORDED.value
    )
    definition = event["payload"]["job_definition"]

    assert definition["job_id"] == "codex-review-broker"
    assert definition["version"] == 2
    assert len(definition["digest"]) == 64
    assert definition["implementation"] == "controlplane.pytest"


def test_historical_v2_profile_remains_resolvable_after_v4_activation():
    historical = next(
        item
        for item in all_profiles()
        if item.repository == "DEAMBROGGI/FirstContact-ControlPlane"
        and item.version == 2
    )
    active = profile_for_repository(historical.repository)

    assert historical.version == 2
    assert historical.schema_version == 1
    assert active.version == 4
    assert profile_for_identity(
        historical.repository,
        historical.profile_id,
        historical.version,
        historical.digest,
    ) == historical


def test_previous_codex_profile_keeps_its_pinned_job_definition():
    historical = next(
        item
        for item in all_profiles()
        if item.repository == "DEAMBROGGI/FirstContact-ControlPlane"
        and item.version == 3
    )
    definition = historical.definition_for("codex-review-broker")

    assert definition is not None
    assert definition.version == 1
    assert profile_for_identity(
        historical.repository,
        historical.profile_id,
        historical.version,
        historical.digest,
    ) == historical


def test_active_codex_profile_uses_new_job_definition_version():
    active = profile_for_repository("DEAMBROGGI/FirstContact-ControlPlane")
    definition = active.definition_for("codex-review-broker")

    assert active.version == 4
    assert definition is not None
    assert definition.version == 2
