from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .domain import (
    DomainError,
    EventType,
    PublicationView,
    ReviewDecision,
    ValidationStatus,
    fold_events,
    validate_transition,
)
from .models import CandidateRow, CandidateSourceRow, PublicationRow
from .profile_registry import DeliveryProfile, profile_for_repository
from .quarantine import VerifiedCandidateSource
from .repository import append_event, load_events

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _sha(value: str, field: str) -> str:
    normalized = value.lower()
    if not _SHA_RE.fullmatch(normalized):
        raise DomainError(f"{field} must be an exact 40-hex Git SHA")
    return normalized


def _candidate_id(publication_id: str, base: str, head: str, tree: str, profile: DeliveryProfile) -> str:
    name = "|".join((publication_id, base, head, tree, profile.profile_id, str(profile.version), profile.digest))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))
def get_view(session: Session, publication_id: str) -> PublicationView:
    if session.get(PublicationRow, publication_id) is None:
        raise KeyError(publication_id)
    return fold_events(publication_id, load_events(session, publication_id))


def create_publication(session: Session, repository: str, issue_number: int) -> PublicationView:
    if issue_number <= 0:
        raise DomainError("issue_number must be positive")
    profile_for_repository(repository)
    publication_id = str(uuid.uuid4())
    session.add(PublicationRow(id=publication_id, repository=repository, issue_number=issue_number))
    session.flush()
    append_event(session, publication_id, EventType.PUBLICATION_CREATED, {
        "repository": repository,
        "issue_number": issue_number,
    })
    session.commit()
    return get_view(session, publication_id)


def _source_payload(source: VerifiedCandidateSource) -> dict[str, Any]:
    return {
        "bundle_sha256": source.bundle_sha256,
        "byte_length": source.byte_length,
        "quarantine_id": source.quarantine_id,
        "base_sha": source.base_sha,
        "head_sha": source.head_sha,
        "tree_sha": source.tree_sha,
    }


def submit_verified_candidate(
    session: Session,
    publication_id: str,
    source: VerifiedCandidateSource,
) -> PublicationView:
    view = get_view(session, publication_id)
    profile = profile_for_repository(view.repository)
    base = _sha(source.base_sha, "base_sha")
    head = _sha(source.head_sha, "head_sha")
    tree = _sha(source.tree_sha, "tree_sha")
    if not re.fullmatch(r"[0-9a-f]{64}", source.bundle_sha256):
        raise DomainError("bundle_sha256 must be exact lowercase sha256")
    if source.quarantine_id != source.bundle_sha256:
        raise DomainError("quarantine identity must equal bundle sha256")
    if source.byte_length <= 0:
        raise DomainError("candidate source byte_length must be positive")

    candidate_id = _candidate_id(publication_id, base, head, tree, profile)
    source_payload = _source_payload(source)
    payload = {
        "candidate_id": candidate_id,
        "base_sha": base,
        "head_sha": head,
        "tree_sha": tree,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "profile_digest": profile.digest,
        "source": source_payload,
    }

    existing_candidate = session.get(CandidateRow, candidate_id)
    existing_source = session.get(CandidateSourceRow, candidate_id)
    if existing_candidate is not None:
        if existing_source is None:
            raise DomainError("candidate exists without immutable verified source")
        observed = {
            "bundle_sha256": existing_source.bundle_sha256,
            "byte_length": existing_source.byte_length,
            "quarantine_id": existing_source.quarantine_id,
            "base_sha": existing_source.base_sha,
            "head_sha": existing_source.head_sha,
            "tree_sha": existing_source.tree_sha,
        }
        if observed != source_payload:
            raise DomainError("immutable candidate source conflict")
        if view.current_candidate and view.current_candidate.candidate_id == candidate_id:
            return view
        raise DomainError("candidate identity already belongs to another publication state")

    validate_transition(view, EventType.CANDIDATE_SUBMITTED, payload)
    session.add(
        CandidateRow(
            id=candidate_id,
            publication_id=publication_id,
            base_sha=base,
            head_sha=head,
            tree_sha=tree,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            profile_digest=profile.digest,
        )
    )
    session.add(
        CandidateSourceRow(
            candidate_id=candidate_id,
            bundle_sha256=source.bundle_sha256,
            byte_length=source.byte_length,
            quarantine_id=source.quarantine_id,
            base_sha=base,
            head_sha=head,
            tree_sha=tree,
        )
    )
    append_event(session, publication_id, EventType.CANDIDATE_SUBMITTED, payload)
    session.commit()
    return get_view(session, publication_id)
def _validation_results(session: Session, publication_id: str, candidate_id: str) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for event in load_events(session, publication_id):
        if event["event_type"] != EventType.VALIDATION_RECORDED.value:
            continue
        payload = event["payload"]
        if payload.get("candidate_id") == candidate_id:
            results[str(payload["job_id"])] = payload
    return results


def record_validation(
    session: Session,
    publication_id: str,
    *,
    job_id: str,
    status: ValidationStatus,
    evidence_sha256: str,
) -> PublicationView:
    view = get_view(session, publication_id)
    validate_transition(view, EventType.VALIDATION_RECORDED, {})
    if view.current_candidate is None:
        raise DomainError("validation requires a current candidate")
    profile = profile_for_repository(view.repository)
    if job_id not in profile.required_jobs:
        raise DomainError(f"job {job_id} is not required by the active profile")
    if not re.fullmatch(r"[0-9a-f]{64}", evidence_sha256.lower()):
        raise DomainError("evidence_sha256 must be 64 lowercase hex characters")
    existing = _validation_results(session, publication_id, view.current_candidate.candidate_id)
    payload = {
        "candidate_id": view.current_candidate.candidate_id,
        "job_id": job_id,
        "status": status.value,
        "evidence_sha256": evidence_sha256.lower(),
    }
    if job_id in existing:
        if existing[job_id] == payload:
            return view
        raise DomainError("immutable validation result conflict")
    append_event(session, publication_id, EventType.VALIDATION_RECORDED, payload)
    session.flush()
    results = _validation_results(session, publication_id, view.current_candidate.candidate_id)
    if any(item["status"] == ValidationStatus.FAIL.value for item in results.values()):
        append_event(session, publication_id, EventType.CANDIDATE_REJECTED, {
            "candidate_id": view.current_candidate.candidate_id,
            "reason": "REQUIRED_JOB_FAILED",
        })
    elif all(
        results.get(required, {}).get("status") == ValidationStatus.PASS.value
        for required in profile.required_jobs
    ):
        append_event(session, publication_id, EventType.CANDIDATE_ADMITTED, {
            "candidate_id": view.current_candidate.candidate_id,
            "profile_id": profile.profile_id,
            "profile_version": profile.version,
            "profile_digest": profile.digest,
        })
    session.commit()
    return get_view(session, publication_id)


def mark_remote_published(
    session: Session,
    publication_id: str,
    head_sha: str,
    *,
    branch: str | None = None,
    base_branch: str | None = None,
    pull_request_number: int | None = None,
) -> PublicationView:
    view = get_view(session, publication_id)
    payload: dict[str, Any] = {"head_sha": _sha(head_sha, "head_sha")}
    if branch is not None:
        payload["branch"] = branch
    if base_branch is not None:
        payload["base_branch"] = base_branch
    if pull_request_number is not None:
        if pull_request_number <= 0:
            raise DomainError("pull_request_number must be positive")
        payload["pull_request_number"] = pull_request_number
    validate_transition(view, EventType.REMOTE_PUBLISHED, payload)
    append_event(session, publication_id, EventType.REMOTE_PUBLISHED, payload)
    session.commit()
    return get_view(session, publication_id)
def record_review(
    session: Session,
    publication_id: str,
    *,
    reviewed_head_sha: str,
    decision: ReviewDecision,
) -> PublicationView:
    view = get_view(session, publication_id)
    payload = {
        "reviewed_head_sha": _sha(reviewed_head_sha, "reviewed_head_sha"),
        "decision": decision.value,
    }
    validate_transition(view, EventType.REVIEW_RECORDED, payload)
    append_event(session, publication_id, EventType.REVIEW_RECORDED, payload)
    session.commit()
    return get_view(session, publication_id)


def record_mergeability(session: Session, publication_id: str, mergeable: bool) -> PublicationView:
    view = get_view(session, publication_id)
    payload = {"mergeable": bool(mergeable)}
    validate_transition(view, EventType.MERGEABILITY_RECORDED, payload)
    append_event(session, publication_id, EventType.MERGEABILITY_RECORDED, payload)
    session.commit()
    return get_view(session, publication_id)


def list_publication_ids(session: Session) -> list[str]:
    return list(session.scalars(select(PublicationRow.id).order_by(PublicationRow.created_at.desc())))
