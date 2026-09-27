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
from .models import CandidateRow, PublicationRow
from .profile_registry import DeliveryProfile, profile_for_repository
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


def submit_candidate(
    session: Session,
    publication_id: str,
    *,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
) -> PublicationView:
    view = get_view(session, publication_id)
    profile = profile_for_repository(view.repository)
    base = _sha(base_sha, "base_sha")
    head = _sha(head_sha, "head_sha")
    tree = _sha(tree_sha, "tree_sha")
    candidate_id = _candidate_id(publication_id, base, head, tree, profile)
    payload = {
        "candidate_id": candidate_id,
        "base_sha": base,
        "head_sha": head,
        "tree_sha": tree,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "profile_digest": profile.digest,
    }
    if view.current_candidate and view.current_candidate.candidate_id == candidate_id:
        return view
    validate_transition(view, EventType.CANDIDATE_SUBMITTED, payload)
    session.add(CandidateRow(id=candidate_id, publication_id=publication_id, **{
        key: payload[key] for key in (
            "base_sha", "head_sha", "tree_sha", "profile_id", "profile_version", "profile_digest"
        )
    }))
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


def mark_remote_published(session: Session, publication_id: str, head_sha: str) -> PublicationView:
    view = get_view(session, publication_id)
    payload = {"head_sha": _sha(head_sha, "head_sha")}
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
