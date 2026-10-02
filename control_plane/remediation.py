from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Mapping

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .domain import (
    AutomatedReviewStatus,
    DomainError,
    EventType,
    PublicationState,
    validate_transition,
)
from .codex_findings import codex_review_body_finding_id
from .models import (
    CandidateRow,
    RemediationDispatchRow,
    PublicationRow,
    RemediationEventRow,
    RemediationWorkPackageRow,
)
from .repository import ZERO_HASH, append_event, load_events
from .service import get_view

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_RE = re.compile(r"^[0-9a-f]{64}$")
_BATCH_NAMESPACE = uuid.UUID("a68dd9c2-c23c-4e78-8b0c-9a2e0ef506bf")
_RESERVED_AUTOMATION_MENTION = re.compile(r"(?i)(?<![A-Za-z0-9_])@codex\b")


def _assert_safe_client_text(value: str, field: str) -> None:
    if _RESERVED_AUTOMATION_MENTION.search(value):
        raise DomainError(f"{field} contains a reserved automation mention")


def successor_review_is_terminal(
    status: AutomatedReviewStatus | None,
    fallback: Mapping[str, Any] | None,
) -> bool:
    if status in {
        AutomatedReviewStatus.PASS,
        AutomatedReviewStatus.CHANGES_REQUIRED,
    }:
        return True
    return (
        status is AutomatedReviewStatus.UNAVAILABLE
        and fallback is not None
        and fallback.get("provider_status") == AutomatedReviewStatus.UNAVAILABLE.value
    )


class WorkPackageState(StrEnum):
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    IMPLEMENTED = "IMPLEMENTED"
    VERIFYING = "VERIFYING"
    REWORK_REQUIRED = "REWORK_REQUIRED"
    DONE = "DONE"


class PrincipalDecision(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class RemediationFindingsOpen(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class RemediationWorkPackageView:
    work_package_id: str
    publication_id: str
    repository: str
    implementation_issue_number: int | None
    review_run: dict[str, Any]
    reviewed_head_sha: str
    state: WorkPackageState
    findings: tuple[dict[str, Any], ...]
    implementer: str | None
    candidate_id: str | None
    implementation_head_sha: str | None
    implementation_summary: str | None
    implementation_evidence_sha256: str | None
    successor_review_run_id: str | None
    successor_head_sha: str | None
    successor_fallback: dict[str, Any] | None
    principal_verification: dict[str, Any] | None
    implementation_projection: dict[str, Any] | None
    summary_comment_id: int | None
    issue_closed: bool


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_event(
    work_package_id: str,
    sequence: int,
    event_type: str,
    idempotency_key: str,
    payload: Mapping[str, Any],
    previous_hash: str,
) -> str:
    return hashlib.sha256(
        _canonical(
            {
                "work_package_id": work_package_id,
                "sequence": sequence,
                "event_type": event_type,
                "idempotency_key": idempotency_key,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        ).encode("utf-8")
    ).hexdigest()


def _event_payload(row: RemediationEventRow) -> dict[str, Any]:
    return {
        "sequence": row.sequence,
        "event_type": row.event_type,
        "idempotency_key": row.idempotency_key,
        "payload": row.payload,
        "previous_hash": row.previous_hash,
        "event_hash": row.event_hash,
        "occurred_at": row.occurred_at.isoformat(),
    }


def load_work_package_events(
    session: Session,
    work_package_id: str,
) -> list[dict[str, Any]]:
    rows = list(
        session.scalars(
            select(RemediationEventRow)
            .where(RemediationEventRow.work_package_id == work_package_id)
            .order_by(RemediationEventRow.sequence.asc())
        )
    )
    previous = ZERO_HASH
    events: list[dict[str, Any]] = []
    for expected, row in enumerate(rows, start=1):
        if row.sequence != expected or row.previous_hash != previous:
            raise RuntimeError("remediation event chain is corrupt")
        expected_hash = _hash_event(
            work_package_id,
            row.sequence,
            row.event_type,
            row.idempotency_key,
            row.payload,
            row.previous_hash,
        )
        if row.event_hash != expected_hash:
            raise RuntimeError("remediation event hash mismatch")
        events.append(_event_payload(row))
        previous = row.event_hash
    return events


def _lock_create_scope(
    session: Session,
    repository: str,
    issue_number: int | None,
) -> None:
    if session.get_bind().dialect.name != "postgresql":
        return
    key = hashlib.sha256(
        f"firstcontact-remediation-issue\0{repository}\0{issue_number}".encode()
    ).digest()[:8]
    lock_key = int.from_bytes(key, byteorder="big", signed=True)
    session.execute(
        text("SELECT pg_advisory_xact_lock(:remediation_issue_key)"),
        {"remediation_issue_key": lock_key},
    )


def _lock_work_package(session: Session, work_package_id: str) -> RemediationWorkPackageRow:
    row = session.scalar(
        select(RemediationWorkPackageRow)
        .where(RemediationWorkPackageRow.id == work_package_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise KeyError(work_package_id)
    return row


def _lock_publication_then_work_package(
    session: Session,
    work_package_id: str,
) -> RemediationWorkPackageRow:
    seed = session.get(RemediationWorkPackageRow, work_package_id)
    if seed is None:
        raise KeyError(work_package_id)
    publication = session.scalar(
        select(PublicationRow)
        .where(PublicationRow.id == seed.publication_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if publication is None:
        raise KeyError(seed.publication_id)
    return _lock_work_package(session, work_package_id)


def _append(
    session: Session,
    row: RemediationWorkPackageRow,
    *,
    event_type: str,
    idempotency_key: str,
    payload: dict[str, Any],
) -> RemediationEventRow:
    if not idempotency_key.strip() or len(idempotency_key) > 200:
        raise DomainError("idempotency_key must contain 1..200 characters")
    existing = session.scalar(
        select(RemediationEventRow).where(
            RemediationEventRow.work_package_id == row.id,
            RemediationEventRow.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.event_type != event_type or _canonical(existing.payload) != _canonical(payload):
            raise DomainError("idempotency key was already used for another command")
        return existing

    last = session.scalar(
        select(RemediationEventRow)
        .where(RemediationEventRow.work_package_id == row.id)
        .order_by(RemediationEventRow.sequence.desc())
        .limit(1)
    )
    sequence = 1 if last is None else last.sequence + 1
    previous_hash = ZERO_HASH if last is None else last.event_hash
    event_hash = _hash_event(
        row.id,
        sequence,
        event_type,
        idempotency_key,
        payload,
        previous_hash,
    )
    event = RemediationEventRow(
        work_package_id=row.id,
        sequence=sequence,
        event_type=event_type,
        idempotency_key=idempotency_key,
        payload=payload,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    session.add(event)
    session.flush()
    return event


def _finding_defaults(finding: dict[str, Any]) -> dict[str, Any]:
    thread_id = finding["source"].get("provider_thread_id")
    has_thread = thread_id is not None
    decision = finding["principal_decision"]["decision"]
    legacy_materialization = {
        "reaction": "PENDING" if has_thread and finding["desired_reaction"] != "none" else "NOT_APPLICABLE",
        "reply": "PENDING" if has_thread else "NOT_APPLICABLE",
        "resolution": "PENDING" if has_thread else "NOT_APPLICABLE",
    }
    decision_materialization = {
        "reaction": "PENDING" if has_thread and finding["desired_reaction"] != "none" else "NOT_APPLICABLE",
        "reply": "PENDING" if has_thread else "NOT_APPLICABLE",
        "resolution": (
            "PENDING"
            if has_thread and decision == PrincipalDecision.REJECTED.value
            else "NOT_APPLICABLE"
        ),
    }
    verification_materialization = {
        "reply": (
            "PENDING"
            if has_thread and decision == PrincipalDecision.ACCEPTED.value
            else "NOT_APPLICABLE"
        ),
        "resolution": (
            "PENDING"
            if has_thread and decision == PrincipalDecision.ACCEPTED.value
            else "NOT_APPLICABLE"
        ),
    }
    return {
        **finding,
        "closure_state": finding.get(
            "closure_state",
            "AWAITING_VERIFICATION"
            if decision == PrincipalDecision.ACCEPTED.value
            else "REJECTED_BY_PRINCIPAL",
        ),
        "verification": finding.get("verification"),
        "verification_history": list(finding.get("verification_history") or []),
        "materialization": {
            **legacy_materialization,
            **dict(finding.get("materialization") or {}),
        },
        "materialization_ids": dict(finding.get("materialization_ids") or {}),
        "decision_materialization": {
            **decision_materialization,
            **dict(finding.get("decision_materialization") or {}),
        },
        "decision_materialization_ids": dict(
            finding.get("decision_materialization_ids") or {}
        ),
        "verification_materialization": {
            **verification_materialization,
            **dict(finding.get("verification_materialization") or {}),
        },
        "verification_materialization_ids": dict(
            finding.get("verification_materialization_ids") or {}
        ),
    }


def _fold(work_package_id: str, row: RemediationWorkPackageRow, events: list[dict[str, Any]]) -> RemediationWorkPackageView:
    if not events or events[0]["event_type"] != "WORK_PACKAGE_CREATED":
        raise RuntimeError("remediation work package has no creation event")
    initial = events[0]["payload"]
    findings = {}
    for item in initial["findings"]:
        finding = _finding_defaults(dict(item))
        findings[item["finding_id"]] = finding
    state = WorkPackageState.READY
    implementer = None
    candidate_id = None
    implementation_head_sha = None
    implementation_summary = None
    implementation_evidence_sha256 = None
    successor_review_run_id = None
    successor_head_sha = None
    successor_fallback = None
    principal_verification = None
    implementation_projection = None
    implementation_issue_number = initial.get("implementation_issue_number")
    summary_comment_id = None
    issue_closed = False

    for event in events[1:]:
        payload = event["payload"]
        event_type = event["event_type"]
        if event_type == "IMPLEMENTATION_ISSUE_LINKED":
            linked_number = payload["issue_number"]
            if implementation_issue_number is not None and implementation_issue_number != linked_number:
                raise RuntimeError("remediation issue link changed in the event ledger")
            implementation_issue_number = linked_number
        elif event_type == "WORK_PACKAGE_CLAIMED":
            state = WorkPackageState.IN_PROGRESS
            implementer = payload["actor"]
        elif event_type == "IMPLEMENTATION_SUBMITTED":
            state = WorkPackageState.IMPLEMENTED
            candidate_id = payload["candidate_id"]
            implementation_head_sha = payload["head_sha"]
            implementation_summary = payload["summary"]
            implementation_evidence_sha256 = payload["evidence_sha256"]
            principal_verification = None
            implementation_projection = None
        elif event_type == "SUCCESSOR_REVIEW_STARTED":
            state = WorkPackageState.VERIFYING
            successor_review_run_id = payload["review_run_id"]
            successor_head_sha = payload["head_sha"]
            fallback = payload.get("fallback")
            successor_fallback = dict(fallback) if isinstance(fallback, dict) else None
            principal_verification = None
        elif event_type == "PRINCIPAL_VERIFICATION_STARTED":
            state = WorkPackageState.VERIFYING
            principal_verification = dict(payload)
        elif event_type == "REJECTED_FINDINGS_FINALIZATION_STARTED":
            state = WorkPackageState.VERIFYING
        elif event_type == "FINDING_VERIFIED":
            finding = findings[payload["finding_id"]]
            verification = {
                "outcome": payload["outcome"],
                "review_run_id": payload["review_run_id"],
                "head_sha": payload["head_sha"],
                "reviewer": payload["reviewer"],
                "evidence": payload["evidence"],
            }
            for key in (
                "provider",
                "provider_review_id",
                "reviewer_kind",
                "review_event_hash",
                "candidate_id",
                "implementation_head_sha",
            ):
                if key in payload:
                    verification[key] = payload[key]
            finding["verification_history"].append(verification)
            finding["verification"] = verification
            finding["closure_state"] = {
                "ABSENT": "VERIFIED_ABSENT",
                "PERSISTS": "PERSISTS",
                "FIXED": "FIXED",
                "NOT_FIXED": "NOT_FIXED",
            }.get(payload["outcome"], "NOT_FIXED")
        elif event_type == "WORK_PACKAGE_REWORK_REQUIRED":
            state = WorkPackageState.REWORK_REQUIRED
            if payload.get("verification_mode") != "PRINCIPAL_REVIEW":
                for finding in findings.values():
                    verification = finding.get("verification")
                    if (
                        finding["principal_decision"]["decision"]
                        == PrincipalDecision.ACCEPTED.value
                        and verification is not None
                        and verification["outcome"] == "PERSISTS"
                    ):
                        finding["verification"] = None
                        finding["closure_state"] = "AWAITING_VERIFICATION"
        elif event_type == "GITHUB_ARTIFACT_MATERIALIZED":
            finding = findings[payload["finding_id"]]
            finding["materialization"][payload["artifact"]] = "MATERIALIZED"
            finding["materialization_ids"][payload["artifact"]] = payload["remote_id"]
        elif event_type in {
            "DECISION_ARTIFACT_MATERIALIZED",
            "VERIFICATION_ARTIFACT_MATERIALIZED",
        }:
            finding = findings[payload["finding_id"]]
            if event_type == "DECISION_ARTIFACT_MATERIALIZED":
                finding["decision_materialization"][payload["artifact"]] = "MATERIALIZED"
                finding["decision_materialization_ids"][payload["artifact"]] = payload[
                    "remote_id"
                ]
            else:
                finding["verification_materialization"][payload["artifact"]] = "MATERIALIZED"
                finding["verification_materialization_ids"][payload["artifact"]] = payload[
                    "remote_id"
                ]
        elif event_type == "WORK_PACKAGE_SUMMARY_MATERIALIZED":
            summary_comment_id = payload["comment_id"]
        elif event_type == "IMPLEMENTATION_PROJECTION_MATERIALIZED":
            implementation_projection = {
                "candidate_id": payload["candidate_id"],
                "head_sha": payload["head_sha"],
                "issue_comment_id": payload["issue_comment_id"],
                "pull_request_comment_id": payload["pull_request_comment_id"],
            }
        elif event_type == "IMPLEMENTATION_ISSUE_CLOSED":
            issue_closed = True
        elif event_type == "WORK_PACKAGE_COMPLETED":
            state = WorkPackageState.DONE

    if row.implementation_issue_number != implementation_issue_number:
        raise RuntimeError("remediation issue-link index differs from the event ledger")

    return RemediationWorkPackageView(
        work_package_id=work_package_id,
        publication_id=row.publication_id,
        repository=row.repository,
        implementation_issue_number=implementation_issue_number,
        review_run=initial["review_run"],
        reviewed_head_sha=row.reviewed_head_sha,
        state=state,
        findings=tuple(findings.values()),
        implementer=implementer,
        candidate_id=candidate_id,
        implementation_head_sha=implementation_head_sha,
        implementation_summary=implementation_summary,
        implementation_evidence_sha256=implementation_evidence_sha256,
        successor_review_run_id=successor_review_run_id,
        successor_head_sha=successor_head_sha,
        successor_fallback=successor_fallback,
        principal_verification=principal_verification,
        implementation_projection=implementation_projection,
        summary_comment_id=summary_comment_id,
        issue_closed=issue_closed,
    )


def get_work_package(session: Session, work_package_id: str) -> RemediationWorkPackageView:
    row = session.get(RemediationWorkPackageRow, work_package_id)
    if row is None:
        raise KeyError(work_package_id)
    return _fold(work_package_id, row, load_work_package_events(session, work_package_id))


def _artifact_ready(finding: Mapping[str, Any], phase: str, artifact: str) -> bool:
    phase_state = finding.get(phase, {}).get(artifact)
    if phase_state in {"MATERIALIZED", "NOT_APPLICABLE"}:
        return True
    return finding.get("materialization", {}).get(artifact) in {
        "MATERIALIZED",
        "NOT_APPLICABLE",
    }


def finding_is_terminal(finding: Mapping[str, Any]) -> bool:
    decision = finding["principal_decision"]["decision"]
    closure_state = finding.get("closure_state")
    has_thread = finding["source"].get("provider_thread_id") is not None
    if decision == PrincipalDecision.REJECTED.value:
        if closure_state != "REJECTED_BY_PRINCIPAL":
            return False
        return not has_thread or all(
            _artifact_ready(finding, "decision_materialization", artifact)
            for artifact in (
                "reaction",
                "reply",
                "resolution",
            )
            if artifact != "reaction" or finding["desired_reaction"] != "none"
        )
    if decision != PrincipalDecision.ACCEPTED.value or closure_state not in {
        "FIXED",
        "VERIFIED_ABSENT",
    }:
        return False
    if not has_thread:
        return True
    return (
        _artifact_ready(finding, "decision_materialization", "reaction")
        if finding["desired_reaction"] != "none"
        else True
    ) and _artifact_ready(
        finding,
        "decision_materialization",
        "reply",
    ) and _artifact_ready(
        finding,
        "verification_materialization",
        "reply",
    ) and _artifact_ready(
        finding,
        "verification_materialization",
        "resolution",
    )


def publication_has_unresolved_remediation_findings(
    session: Session,
    publication_id: str,
) -> bool:
    package_ids = session.scalars(
        select(RemediationWorkPackageRow.id)
        .where(RemediationWorkPackageRow.publication_id == publication_id)
        .order_by(RemediationWorkPackageRow.created_at, RemediationWorkPackageRow.id)
    )
    for work_package_id in package_ids:
        view = get_work_package(session, work_package_id)
        if view.state is WorkPackageState.DONE:
            continue
        if any(not finding_is_terminal(finding) for finding in view.findings):
            return True
    return False


def remediation_watch_action(
    session: Session,
    publication_id: str,
) -> tuple[str, str] | None:
    if not publication_has_unresolved_remediation_findings(session, publication_id):
        return None
    package_ids = session.scalars(
        select(RemediationWorkPackageRow.id)
        .where(RemediationWorkPackageRow.publication_id == publication_id)
        .order_by(RemediationWorkPackageRow.created_at, RemediationWorkPackageRow.id)
    )
    for work_package_id in package_ids:
        view = get_work_package(session, work_package_id)
        if view.state is WorkPackageState.DONE:
            continue
        unresolved = [finding for finding in view.findings if not finding_is_terminal(finding)]
        needs_implementation = any(
            finding["principal_decision"]["decision"] == PrincipalDecision.ACCEPTED.value
            and finding.get("closure_state")
            in {"AWAITING_VERIFICATION", "NOT_FIXED", "PERSISTS"}
            for finding in unresolved
        )
        if needs_implementation and view.state in {
            WorkPackageState.READY,
            WorkPackageState.IN_PROGRESS,
            WorkPackageState.REWORK_REQUIRED,
        }:
            return "IMPLEMENTER", "REMEDIATE_FINDINGS"
        if needs_implementation and view.state in {
            WorkPackageState.IMPLEMENTED,
            WorkPackageState.VERIFYING,
        }:
            return "PRINCIPAL_REVIEWER", "REVIEW_REMEDIATION_FIXES"
    return "CONTROL_PLANE", "MATERIALIZE_REMEDIATION"


def _validate_governed_published_candidate(
    session: Session,
    view: RemediationWorkPackageView,
) -> CandidateRow:
    if view.candidate_id is None or view.implementation_head_sha is None:
        raise DomainError("implementation candidate identity is incomplete")
    candidate = session.get(CandidateRow, view.candidate_id)
    if (
        candidate is None
        or candidate.publication_id != view.publication_id
        or candidate.head_sha != view.implementation_head_sha
    ):
        raise DomainError("implementation candidate does not belong to this publication and head")

    active_candidate_id = None
    active_admitted = False
    exact_submission_seen = False
    published = False
    for event in load_events(session, view.publication_id):
        payload = event["payload"]
        event_type = event["event_type"]
        if event_type == EventType.CANDIDATE_SUBMITTED.value:
            active_candidate_id = payload.get("candidate_id")
            active_admitted = False
            if active_candidate_id == candidate.id:
                exact_submission_seen = all(
                    payload.get(key) == value
                    for key, value in (
                        ("base_sha", candidate.base_sha),
                        ("head_sha", candidate.head_sha),
                        ("tree_sha", candidate.tree_sha),
                        ("profile_id", candidate.profile_id),
                        ("profile_version", candidate.profile_version),
                        ("profile_digest", candidate.profile_digest),
                    )
                )
        elif event_type == EventType.CANDIDATE_ADMITTED.value:
            if active_candidate_id == candidate.id:
                active_admitted = all(
                    payload.get(key) == value
                    for key, value in (
                        ("candidate_id", candidate.id),
                        ("profile_id", candidate.profile_id),
                        ("profile_version", candidate.profile_version),
                        ("profile_digest", candidate.profile_digest),
                    )
                )
        elif event_type == EventType.CANDIDATE_REJECTED.value:
            if active_candidate_id == candidate.id:
                active_admitted = False
        elif event_type == EventType.REMOTE_PUBLISHED.value:
            if (
                active_candidate_id == candidate.id
                and active_admitted
                and payload.get("head_sha") == candidate.head_sha
            ):
                published = True
    if not exact_submission_seen or not published:
        raise DomainError("implementation candidate was not admitted and governed-published")
    return candidate


def _principal_review_evidence(
    session: Session,
    publication_id: str,
    *,
    review_run_id: str,
    head_sha: str,
) -> dict[str, Any]:
    events = load_events(session, publication_id)
    recorded = [
        event
        for event in events
        if event["event_type"] == EventType.PLANE_REVIEW_RECORDED.value
        and event["payload"].get("run_id") == review_run_id
    ]
    materialized = [
        event
        for event in events
        if event["event_type"] == EventType.PLANE_REVIEW_MATERIALIZED.value
        and event["payload"].get("run_id") == review_run_id
    ]
    if len(recorded) != 1 or len(materialized) != 1:
        raise DomainError("exact immutable Principal PLANE_REVIEW evidence is required")
    recorded_payload = recorded[0]["payload"]
    materialized_event = materialized[0]
    payload = materialized_event["payload"]
    if (
        payload.get("provider") != "PLANE_REVIEW"
        or payload.get("reviewer_kind") != "PRINCIPAL_REVIEWER"
        or not isinstance(payload.get("reviewer"), str)
        or not payload["reviewer"].strip()
        or payload.get("run_id") != review_run_id
        or payload.get("head_sha") != head_sha
        or recorded_payload.get("provider") != "PLANE_REVIEW"
        or recorded_payload.get("reviewer_kind") != "PRINCIPAL_REVIEWER"
        or recorded_payload.get("reviewer") != payload.get("reviewer")
        or recorded_payload.get("run_id") != review_run_id
        or recorded_payload.get("head_sha") != head_sha
    ):
        raise DomainError("Principal PLANE_REVIEW identity does not match the requested run and head")

    provider_review_ids = payload.get("provider_review_ids")
    findings = payload.get("findings")
    provider_comment_ids = payload.get("provider_comment_ids")
    recorded_comments = recorded_payload.get("comments")
    if (
        not isinstance(provider_review_ids, list)
        or len(provider_review_ids) != 1
        or not isinstance(provider_review_ids[0], int)
        or isinstance(provider_review_ids[0], bool)
        or provider_review_ids[0] <= 0
        or not isinstance(findings, list)
        or not isinstance(provider_comment_ids, list)
        or not isinstance(recorded_comments, list)
        or payload.get("findings_count") != len(findings)
        or payload.get("result") != ("CHANGES_REQUIRED" if findings else "PASS")
        or provider_comment_ids != [item.get("provider_comment_id") for item in findings]
        or len({item.get("finding_id") for item in findings}) != len(findings)
    ):
        raise DomainError("Principal PLANE_REVIEW provider receipt is inconsistent")
    recorded_by_id = {
        item.get("finding_id"): item
        for item in recorded_comments
        if isinstance(item, dict)
    }
    if len(recorded_by_id) != len(recorded_comments) or len(recorded_by_id) != len(findings):
        raise DomainError("Principal PLANE_REVIEW source findings are inconsistent")
    for item in findings:
        source = recorded_by_id.get(item.get("finding_id"))
        if (
            source is None
            or item.get("provider_review_id") != provider_review_ids[0]
            or item.get("path") != source.get("path")
            or item.get("line") != source.get("line")
            or item.get("side") != source.get("side")
            or item.get("body") != source.get("body")
            or item.get("normalized_identity") != source.get("normalized_identity")
            or item.get("priority") != source.get("priority")
        ):
            raise DomainError("Principal PLANE_REVIEW finding receipt changed")
    return {
        "review_run_id": review_run_id,
        "provider": "PLANE_REVIEW",
        "provider_review_id": provider_review_ids[0],
        "head_sha": head_sha,
        "reviewer_kind": "PRINCIPAL_REVIEWER",
        "reviewer": payload["reviewer"],
        "review_event_hash": materialized_event["event_hash"],
    }


def _finding_needs_principal_verification(finding: Mapping[str, Any]) -> bool:
    return (
        finding["principal_decision"]["decision"] == PrincipalDecision.ACCEPTED.value
        and finding.get("closure_state")
        in {"AWAITING_VERIFICATION", "NOT_FIXED", "PERSISTS"}
    )


def begin_principal_verification(
    session: Session,
    work_package_id: str,
    *,
    review_run_id: str,
    head_sha: str,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_publication_then_work_package(session, work_package_id)
    normalized_run_id = review_run_id.strip()
    normalized_head_sha = head_sha.lower()
    if not normalized_run_id or len(normalized_run_id) > 160:
        raise DomainError("Principal review run id is invalid")
    _assert_safe_client_text(normalized_run_id, "Principal review run id")
    if not _SHA_RE.fullmatch(normalized_head_sha):
        raise DomainError("Principal review head must be an exact 40-hex Git SHA")

    current = get_work_package(session, work_package_id)
    if current.implementation_head_sha != normalized_head_sha:
        raise DomainError("Principal review head does not match the implementation head")
    _validate_governed_published_candidate(session, current)
    evidence = _principal_review_evidence(
        session,
        row.publication_id,
        review_run_id=normalized_run_id,
        head_sha=normalized_head_sha,
    )
    if current.principal_verification is not None:
        existing_binding = current.principal_verification
        if (
            existing_binding.get("review_run_id") == normalized_run_id
            and existing_binding.get("head_sha") == normalized_head_sha
            and existing_binding.get("review_event_hash")
            == evidence["review_event_hash"]
            and existing_binding.get("candidate_id") == current.candidate_id
        ):
            duplicate = _command_duplicate(
                session,
                row,
                event_type="PRINCIPAL_VERIFICATION_STARTED",
                idempotency_key=idempotency_key,
                payload=existing_binding,
            )
            if duplicate is not None:
                return duplicate
            if current.state is WorkPackageState.VERIFYING:
                session.commit()
                return current
        raise DomainError("work package is already bound to another Principal verification")
    if current.state is not WorkPackageState.IMPLEMENTED:
        raise DomainError("Principal verification can only start from IMPLEMENTED")
    pending_ids = sorted(
        finding["finding_id"]
        for finding in current.findings
        if _finding_needs_principal_verification(finding)
    )
    if not pending_ids:
        raise DomainError("work package has no accepted findings awaiting Principal verification")
    payload = {
        **evidence,
        "candidate_id": current.candidate_id,
        "finding_ids": pending_ids,
    }
    duplicate = _command_duplicate(
        session,
        row,
        event_type="PRINCIPAL_VERIFICATION_STARTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    _append(
        session,
        row,
        event_type="PRINCIPAL_VERIFICATION_STARTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def _find_source_review(
    session: Session,
    publication_id: str,
    review_run_id: str,
    reviewed_head_sha: str,
    provider_review_id: int | None,
) -> dict[str, Any] | None:
    from .repository import load_events

    providers = {
        "CODEX_REVIEW_COMPLETED": "CODEX_CODE_REVIEW",
        "PLANE_REVIEW_MATERIALIZED": "PLANE_REVIEW",
    }
    for event in load_events(session, publication_id):
        event_type = event["event_type"]
        provider = providers.get(event_type)
        if provider is None:
            continue
        payload = event["payload"]
        if (
            payload.get("run_id") != review_run_id
            or payload.get("head_sha") != reviewed_head_sha
        ):
            continue
        if payload.get("result") not in {"PASS", "CHANGES_REQUIRED"}:
            continue
        if payload.get("provider") not in {None, provider}:
            raise DomainError("source review provider evidence is inconsistent")

        provider_review_ids = payload.get("provider_review_ids")
        provider_comment_ids = payload.get("provider_comment_ids")
        findings = payload.get("findings")
        if (
            not isinstance(provider_review_ids, list)
            or not isinstance(provider_comment_ids, list)
            or not isinstance(findings, list)
            or payload.get("findings_count") != len(findings)
        ):
            raise DomainError("source review finding ledger is inconsistent")
        if len(set(provider_review_ids)) != len(provider_review_ids) or len(
            set(provider_comment_ids)
        ) != len(provider_comment_ids):
            raise DomainError("source review finding ledger contains duplicate ids")

        source_comments: dict[int, dict[str, Any]] = {}
        source_body_findings: dict[str, dict[str, Any]] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                raise DomainError("source review finding ledger is inconsistent")
            source_kind = finding.get("source_kind", "INLINE_COMMENT")
            if source_kind == "REVIEW_BODY":
                try:
                    review_id = int(finding["provider_review_id"])
                    priority = str(finding["priority"]).upper()
                    title = str(finding["title"]).strip()
                    body = str(finding["body"])
                    provider_finding_id = str(finding["provider_finding_id"])
                    finding_id = str(finding["finding_id"])
                    normalized_identity = str(finding["normalized_identity"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise DomainError(
                        "source review body finding ledger is inconsistent"
                    ) from exc
                expected_id = codex_review_body_finding_id(
                    run_id=review_run_id,
                    head_sha=reviewed_head_sha,
                    review_id=review_id,
                    priority=priority,
                    title=title,
                    body=body,
                )
                body_digest = str(finding.get("provider_body_sha256") or "")
                if (
                    review_id <= 0
                    or review_id not in provider_review_ids
                    or priority not in {"P0", "P1", "P2", "P3", "P4"}
                    or not title
                    or len(body) > 4000
                    or finding.get("provider_comment_id") is not None
                    or provider_finding_id != expected_id
                    or finding_id != expected_id
                    or normalized_identity != expected_id
                    or not _EVIDENCE_RE.fullmatch(body_digest)
                    or provider_finding_id in source_body_findings
                ):
                    raise DomainError(
                        "source review body finding ledger is inconsistent"
                    )
                source_body_findings[provider_finding_id] = finding
                continue
            if source_kind != "INLINE_COMMENT":
                raise DomainError("source review finding kind is unsupported")
            try:
                comment_id = int(finding["provider_comment_id"])
                review_id = int(finding["provider_review_id"])
            except (KeyError, TypeError, ValueError) as exc:
                raise DomainError("source review finding ledger is inconsistent") from exc
            if (
                comment_id <= 0
                or review_id <= 0
                or comment_id in source_comments
                or review_id not in provider_review_ids
                or comment_id not in provider_comment_ids
            ):
                raise DomainError("source review finding ledger is inconsistent")
            source_comments[comment_id] = finding
        if set(source_comments) != set(provider_comment_ids):
            raise DomainError("source review provider comments do not match its findings")
        if provider_review_id is not None and provider_review_id not in provider_review_ids:
            continue
        return {
            "event_type": event_type,
            "provider": provider,
            **payload,
        }
    return None


def _validate_review_findings(
    findings: list[dict[str, Any]],
    *,
    source_review: dict[str, Any],
    review_provider: str,
) -> None:
    source_provider = str(source_review.get("provider") or "")
    if review_provider != source_provider:
        raise DomainError("source review provider does not match the completed review")
    if source_provider not in {"CODEX_CODE_REVIEW", "PLANE_REVIEW"}:
        raise DomainError("source review provider is unsupported")

    trusted_comments = {
        int(item["provider_comment_id"]): item
        for item in source_review["findings"]
        if item.get("source_kind", "INLINE_COMMENT") == "INLINE_COMMENT"
    }
    trusted_body_findings = {
        str(item["provider_finding_id"]): item
        for item in source_review["findings"]
        if item.get("source_kind") == "REVIEW_BODY"
    }
    submitted_comments: list[tuple[int, int]] = []
    submitted_body_findings: list[tuple[int, str]] = []
    for finding in findings:
        source = finding["source"]
        kind = source["kind"]
        if kind == "CONTROL_PLANE":
            if (
                source["provider"] != "CONTROL_PLANE"
                or source["provider_review_id"] is not None
                or source["provider_thread_id"] is not None
                or source.get("provider_finding_id") is not None
            ):
                raise DomainError("internal findings require the explicit Control Plane source")
            continue
        if kind == "PROVIDER_REVIEW_BODY":
            review_id = source["provider_review_id"]
            provider_finding_id = source.get("provider_finding_id")
            trusted = trusted_body_findings.get(str(provider_finding_id or ""))
            if (
                source["provider"] != source_provider
                or review_id is None
                or source["provider_thread_id"] is not None
                or trusted is None
                or int(trusted["provider_review_id"]) != review_id
            ):
                raise DomainError(
                    "provider body finding is not owned by the source review run"
                )
            expected_id = str(trusted["finding_id"])
            expected_identity = str(trusted["normalized_identity"])
            expected_priority = str(trusted["priority"]).upper()
            if finding["priority"] != expected_priority:
                raise DomainError(
                    "provider body finding priority differs from the source review"
                )
            if (
                finding["finding_id"] != expected_id
                or finding["normalized_identity"] != expected_identity
            ):
                raise DomainError(
                    "provider body finding identity differs from the source review"
                )
            finding["source"].update(
                {
                    "provider_finding_id": expected_id,
                    "path": None,
                    "line": None,
                    "side": None,
                    "title": str(trusted["title"]),
                    "body": str(trusted.get("body", ""))[:4000],
                }
            )
            submitted_body_findings.append((review_id, expected_id))
            continue
        if kind != "PROVIDER_THREAD":
            raise DomainError("finding source kind is unsupported")

        review_id = source["provider_review_id"]
        comment_id = source["provider_thread_id"]
        if (
            source["provider"] != source_provider
            or review_id is None
            or comment_id is None
        ):
            raise DomainError("provider finding does not match the source review provider")

        trusted = trusted_comments.get(comment_id)
        if trusted is None or int(trusted["provider_review_id"]) != review_id:
            raise DomainError("provider finding is not owned by the source review run")

        if source_provider == "CODEX_CODE_REVIEW":
            expected_id = f"codex:{review_id}:{comment_id}"
            expected_identity = f"codex:review-{review_id}:comment-{comment_id}"
        else:
            expected_id = str(trusted.get("finding_id") or "")
            expected_identity = str(trusted.get("normalized_identity") or "")
            expected_priority = str(trusted.get("priority") or "").upper()
            expected_reviewer = str(source_review.get("reviewer") or "").strip()
            if not expected_reviewer or expected_priority not in {
                "P0",
                "P1",
                "P2",
                "P3",
                "P4",
            }:
                raise DomainError("Plane review source authority is incomplete")
            if finding["priority"] != expected_priority:
                raise DomainError(
                    "Plane review finding priority differs from the source review"
                )
            principal_decision = finding["principal_decision"]
            if (
                principal_decision["actor"] != expected_reviewer
                or principal_decision["decision"]
                != PrincipalDecision.ACCEPTED.value
            ):
                raise DomainError(
                    "Plane review Principal Reviewer decision differs from the source review"
                )

        if (
            finding["finding_id"] != expected_id
            or finding["normalized_identity"] != expected_identity
        ):
            raise DomainError("provider finding identity differs from the source review")

        finding["source"].update(
            {
                "path": trusted.get("path"),
                "line": trusted.get("line"),
                "side": trusted.get("side"),
                "body": str(trusted.get("body", ""))[:4000],
            }
        )
        submitted_comments.append((review_id, comment_id))

    if len(submitted_comments) != len(set(submitted_comments)):
        raise DomainError("duplicate provider finding in Principal Reviewer decision set")

    expected_comments = {
        (int(item["provider_review_id"]), int(item["provider_comment_id"]))
        for item in source_review["findings"]
        if item.get("source_kind", "INLINE_COMMENT") == "INLINE_COMMENT"
    }
    expected_body_findings = {
        (int(item["provider_review_id"]), str(item["provider_finding_id"]))
        for item in source_review["findings"]
        if item.get("source_kind") == "REVIEW_BODY"
    }
    if (
        set(submitted_comments) != expected_comments
        or len(submitted_body_findings) != len(set(submitted_body_findings))
        or set(submitted_body_findings) != expected_body_findings
    ):
        raise DomainError(
            "Principal Reviewer decision set must include every source provider finding exactly once"
        )


def _normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not findings or len(findings) > 200:
        raise DomainError("work package requires 1..200 findings")
    normalized = []
    seen: set[str] = set()
    for item in findings:
        finding_id = str(item.get("finding_id", "")).strip()
        identity = str(item.get("normalized_identity", "")).strip()
        priority = str(item.get("priority", "")).upper()
        source = item.get("source")
        decision = item.get("principal_decision")
        desired_reaction = str(item.get("desired_reaction", "")).lower()
        if not finding_id or len(finding_id) > 200 or not identity or len(identity) > 500:
            raise DomainError("finding identity is required and bounded")
        if finding_id in seen:
            raise DomainError("duplicate finding identity")
        seen.add(finding_id)
        if priority not in {"P0", "P1", "P2", "P3", "P4"}:
            raise DomainError("finding priority is invalid")
        if not isinstance(source, dict) or not source.get("kind"):
            raise DomainError("finding source is required")
        if not isinstance(decision, dict):
            raise DomainError("Principal Reviewer decision is required")
        try:
            decision_value = PrincipalDecision(str(decision.get("decision", "")).upper())
        except ValueError as exc:
            raise DomainError("Principal Reviewer decision is invalid") from exc
        reason = str(decision.get("reason") or "").strip()
        actor = str(decision.get("actor", "")).strip()
        for field_name, value in (
            ("finding id", finding_id),
            ("finding identity", identity),
            ("Principal Reviewer actor", actor),
            ("Principal Reviewer reason", reason),
            ("finding source kind", str(source.get("kind", ""))),
            ("finding source provider", str(source.get("provider", ""))),
        ):
            _assert_safe_client_text(value, field_name)
        if not actor or len(actor) > 200:
            raise DomainError("Principal Reviewer decision actor is required and bounded")
        if decision_value is PrincipalDecision.REJECTED and not reason:
            raise DomainError("rejected finding requires a reason")
        if decision_value is PrincipalDecision.ACCEPTED and desired_reaction not in {"+1", "none"}:
            raise DomainError("accepted finding reaction must be +1 or none")
        if decision_value is PrincipalDecision.REJECTED and desired_reaction not in {"-1", "none"}:
            raise DomainError("rejected finding reaction must be -1 or none")
        provider_thread_id = source.get("provider_thread_id")
        if provider_thread_id is not None and int(provider_thread_id) <= 0:
            raise DomainError("provider thread id must be positive")
        if provider_thread_id is None and desired_reaction != "none":
            raise DomainError("finding without a provider thread cannot request a reaction")
        provider_review_id = source.get("provider_review_id")
        if provider_review_id is not None and int(provider_review_id) <= 0:
            raise DomainError("provider review id must be positive")
        provider_finding_id = source.get("provider_finding_id")
        if source.get("kind") == "PROVIDER_REVIEW_BODY":
            if (
                provider_thread_id is not None
                or provider_review_id is None
                or not isinstance(provider_finding_id, str)
                or not provider_finding_id
                or len(provider_finding_id) > 200
            ):
                raise DomainError("provider review body identity is invalid")
        elif provider_finding_id is not None:
            raise DomainError("provider finding id is only valid for review-body findings")
        normalized_source = {
            "kind": str(source["kind"]),
            "provider": str(source.get("provider", "")),
            "provider_review_id": int(provider_review_id) if provider_review_id is not None else None,
            "provider_thread_id": int(provider_thread_id) if provider_thread_id is not None else None,
        }
        if provider_finding_id is not None:
            normalized_source["provider_finding_id"] = provider_finding_id
        normalized.append(
            {
                "finding_id": finding_id,
                "normalized_identity": identity,
                "priority": priority,
                "source": normalized_source,
                "principal_decision": {
                    "decision": decision_value.value,
                    "actor": actor,
                    "reason": reason or None,
                },
                "desired_reaction": desired_reaction,
            }
        )
    return sorted(normalized, key=lambda item: item["finding_id"])


def create_work_package(
    session: Session,
    *,
    publication_id: str,
    implementation_issue_number: int | None,
    review_run_id: str,
    review_provider: str,
    provider_review_id: int | None,
    reviewed_head_sha: str,
    findings: list[dict[str, Any]],
    idempotency_key: str,
) -> RemediationWorkPackageView:
    if implementation_issue_number is not None and implementation_issue_number <= 0:
        raise DomainError("implementation issue number must be positive")
    if not review_run_id.strip() or len(review_run_id) > 160:
        raise DomainError("review run id is invalid")
    if not review_provider.strip() or len(review_provider) > 100:
        raise DomainError("review provider is invalid")
    _assert_safe_client_text(review_run_id, "review run id")
    _assert_safe_client_text(review_provider, "review provider")
    head = reviewed_head_sha.lower()
    if not _SHA_RE.fullmatch(head):
        raise DomainError("reviewed_head_sha must be an exact 40-hex Git SHA")
    if provider_review_id is not None and provider_review_id <= 0:
        raise DomainError("provider review id must be positive")
    normalized_findings = _normalize_findings(findings)
    work_package_id = str(
        uuid.uuid5(
            _BATCH_NAMESPACE,
            f"{publication_id}|{review_run_id}|{implementation_issue_number or 'pending'}",
        )
    )
    publication_row = session.scalar(
        select(PublicationRow)
        .where(PublicationRow.id == publication_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if publication_row is None:
        raise KeyError(publication_id)
    _lock_create_scope(
        session,
        publication_row.repository,
        implementation_issue_number,
    )
    if implementation_issue_number is not None:
        linked_issue = session.scalar(
            select(RemediationWorkPackageRow).where(
                RemediationWorkPackageRow.repository == publication_row.repository,
                RemediationWorkPackageRow.implementation_issue_number
                == implementation_issue_number,
            )
        )
        if linked_issue is not None and linked_issue.id != work_package_id:
            raise DomainError("implementation issue is already linked to another work package")
    source_review = _find_source_review(
        session,
        publication_id,
        review_run_id,
        head,
        provider_review_id,
    )
    if source_review is None:
        raise DomainError("source review run is missing or does not match the exact head")
    _validate_review_findings(
        normalized_findings,
        source_review=source_review,
        review_provider=review_provider.strip(),
    )
    payload = {
        "publication_id": publication_id,
        "implementation_issue_number": implementation_issue_number,
        "review_run": {
            "run_id": review_run_id,
            "provider": review_provider.strip(),
            "provider_review_id": provider_review_id,
            "head_sha": head,
        },
        "findings": [
            _finding_defaults(finding)
            for finding in normalized_findings
        ],
    }
    existing_row = session.get(RemediationWorkPackageRow, work_package_id)
    if existing_row is not None:
        events = load_work_package_events(session, work_package_id)
        if not events or _canonical(events[0]["payload"]) != _canonical(payload):
            raise DomainError("work package identity already exists with different content")
        session.commit()
        return _fold(work_package_id, existing_row, events)

    view = get_view(session, publication_id)
    if view.remote_head_sha != head:
        raise DomainError("reviewed head is not the current published head")

    row = RemediationWorkPackageRow(
        id=work_package_id,
        publication_id=publication_id,
        repository=publication_row.repository,
        review_run_id=review_run_id,
        reviewed_head_sha=head,
        implementation_issue_number=implementation_issue_number,
    )
    session.add(row)
    session.flush()
    _append(
        session,
        row,
        event_type="WORK_PACKAGE_CREATED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def record_implementation_issue_linked(
    session: Session,
    work_package_id: str,
    *,
    issue_number: int,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    if issue_number <= 0:
        raise DomainError("implementation issue number must be positive")
    row = _lock_work_package(session, work_package_id)
    payload = {"issue_number": issue_number}
    duplicate = _command_duplicate(
        session,
        row,
        event_type="IMPLEMENTATION_ISSUE_LINKED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if row.implementation_issue_number is not None:
        if row.implementation_issue_number == issue_number:
            session.commit()
            return get_work_package(session, work_package_id)
        raise DomainError("work package is already linked to another implementation issue")
    linked = session.scalar(
        select(RemediationWorkPackageRow).where(
            RemediationWorkPackageRow.repository == row.repository,
            RemediationWorkPackageRow.implementation_issue_number == issue_number,
        )
    )
    if linked is not None and linked.id != row.id:
        raise DomainError("implementation issue is already linked to another work package")
    row.implementation_issue_number = issue_number
    _append(
        session,
        row,
        event_type="IMPLEMENTATION_ISSUE_LINKED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def _command_duplicate(
    session: Session,
    row: RemediationWorkPackageRow,
    *,
    event_type: str,
    idempotency_key: str,
    payload: dict[str, Any],
) -> RemediationWorkPackageView | None:
    existing = session.scalar(
        select(RemediationEventRow).where(
            RemediationEventRow.work_package_id == row.id,
            RemediationEventRow.idempotency_key == idempotency_key,
        )
    )
    if existing is None:
        return None
    if existing.event_type != event_type or _canonical(existing.payload) != _canonical(payload):
        raise DomainError("idempotency key was already used for another command")
    session.commit()
    return get_work_package(session, row.id)


def claim_work_package(
    session: Session,
    work_package_id: str,
    *,
    actor: str,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    payload = {"actor": actor.strip()}
    duplicate = _command_duplicate(
        session,
        row,
        event_type="WORK_PACKAGE_CLAIMED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    view = get_work_package(session, work_package_id)
    if view.state is WorkPackageState.IN_PROGRESS and view.implementer == payload["actor"]:
        session.commit()
        return view
    if view.state not in {WorkPackageState.READY, WorkPackageState.REWORK_REQUIRED}:
        raise DomainError("work package can only be claimed from READY or REWORK_REQUIRED")
    if view.implementation_issue_number is None:
        raise DomainError("implementation issue must be linked before the package can be claimed")
    if not payload["actor"] or len(payload["actor"]) > 200:
        raise DomainError("claim actor is required and bounded")
    _append(
        session,
        row,
        event_type="WORK_PACKAGE_CLAIMED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def submit_implementation(
    session: Session,
    work_package_id: str,
    *,
    candidate_id: str,
    head_sha: str,
    summary: str,
    evidence_sha256: str,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    payload = {
        "candidate_id": candidate_id,
        "head_sha": head_sha.lower(),
        "summary": summary.strip(),
        "evidence_sha256": evidence_sha256.lower(),
    }
    duplicate = _command_duplicate(
        session,
        row,
        event_type="IMPLEMENTATION_SUBMITTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    view = get_work_package(session, work_package_id)
    if view.state is WorkPackageState.IMPLEMENTED:
        if (
            view.candidate_id == candidate_id
            and view.implementation_head_sha == payload["head_sha"]
            and view.implementation_summary == payload["summary"]
            and view.implementation_evidence_sha256 == payload["evidence_sha256"]
        ):
            session.commit()
            return view
        raise DomainError("work package already has a different implementation submission")
    if view.state is not WorkPackageState.IN_PROGRESS:
        raise DomainError("implementation can only be submitted from IN_PROGRESS")
    if not candidate_id or len(candidate_id) > 36:
        raise DomainError("candidate id is invalid")
    if not _SHA_RE.fullmatch(payload["head_sha"]):
        raise DomainError("implementation head must be an exact 40-hex Git SHA")
    if not _EVIDENCE_RE.fullmatch(payload["evidence_sha256"]):
        raise DomainError("implementation evidence must be a SHA-256 digest")
    if not payload["summary"] or len(payload["summary"]) > 4000:
        raise DomainError("implementation summary must contain 1..4000 characters")
    _assert_safe_client_text(payload["summary"], "implementation summary")
    candidate = session.get(CandidateRow, candidate_id)
    publication = get_view(session, row.publication_id)
    if (
        candidate is None
        or candidate.publication_id != row.publication_id
        or publication.current_candidate is None
        or publication.current_candidate.candidate_id != candidate_id
        or publication.current_candidate.head_sha != payload["head_sha"]
    ):
        raise DomainError("implementation submission does not match the current publication candidate")
    _append(
        session,
        row,
        event_type="IMPLEMENTATION_SUBMITTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def mark_implementation_rework_required(
    session: Session,
    work_package_id: str,
    *,
    reason: str,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    bounded_reason = reason.strip()
    if not bounded_reason or len(bounded_reason) > 1000:
        raise DomainError("implementation rework reason is required and bounded")
    _assert_safe_client_text(bounded_reason, "implementation rework reason")
    view = get_work_package(session, work_package_id)
    payload = {
        "reason": bounded_reason,
        "candidate_id": view.candidate_id,
        "implementation_head_sha": view.implementation_head_sha,
    }
    duplicate = _command_duplicate(
        session,
        row,
        event_type="WORK_PACKAGE_REWORK_REQUIRED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if view.state is WorkPackageState.REWORK_REQUIRED:
        session.commit()
        return view
    if view.state is not WorkPackageState.IMPLEMENTED:
        raise DomainError("implementation rework requires IMPLEMENTED state")
    _append(
        session,
        row,
        event_type="WORK_PACKAGE_REWORK_REQUIRED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def begin_successor_verification(
    session: Session,
    work_package_id: str,
    *,
    review_run_id: str,
    head_sha: str,
    idempotency_key: str,
    fallback_reviewer: str | None = None,
    fallback_reason: str | None = None,
) -> RemediationWorkPackageView:
    row = _lock_publication_then_work_package(session, work_package_id)
    normalized_reviewer = fallback_reviewer.strip() if fallback_reviewer is not None else None
    normalized_reason = fallback_reason.strip() if fallback_reason is not None else None
    if (normalized_reviewer is None) != (normalized_reason is None):
        raise DomainError("fallback reviewer and reason must be supplied together")
    if normalized_reviewer is not None:
        if not normalized_reviewer or len(normalized_reviewer) > 200:
            raise DomainError("fallback reviewer is required and bounded")
        if not normalized_reason or len(normalized_reason) > 1000:
            raise DomainError("fallback reason is required and bounded")
        _assert_safe_client_text(normalized_reviewer, "fallback reviewer")
        _assert_safe_client_text(normalized_reason, "fallback reason")

    fallback = (
        {
            "reviewer": normalized_reviewer,
            "reason": normalized_reason,
            "provider_status": AutomatedReviewStatus.UNAVAILABLE.value,
        }
        if normalized_reviewer is not None
        else None
    )
    payload = {
        "review_run_id": review_run_id,
        "head_sha": head_sha.lower(),
        "fallback": fallback,
    }
    duplicate = _command_duplicate(
        session,
        row,
        event_type="SUCCESSOR_REVIEW_STARTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    view = get_work_package(session, work_package_id)
    if view.state is WorkPackageState.VERIFYING:
        if (
            view.successor_review_run_id == review_run_id
            and view.successor_head_sha == payload["head_sha"]
            and view.successor_fallback == fallback
        ):
            session.commit()
            return view
        raise DomainError("work package is already bound to another successor review")
    if view.state is not WorkPackageState.IMPLEMENTED:
        raise DomainError("successor verification can only start from IMPLEMENTED")
    if not _SHA_RE.fullmatch(payload["head_sha"]):
        raise DomainError("successor head must be an exact 40-hex Git SHA")

    publication = get_view(session, row.publication_id)
    exact_binding = (
        payload["head_sha"] != row.reviewed_head_sha
        and payload["head_sha"] == view.implementation_head_sha
        and publication.current_candidate is not None
        and publication.current_candidate.candidate_id == view.candidate_id
        and publication.current_candidate.head_sha == view.implementation_head_sha
        and publication.remote_head_sha == payload["head_sha"]
        and publication.automated_review_head_sha == payload["head_sha"]
        and publication.automated_review_run_id == review_run_id
    )
    provider_terminal = publication.automated_review_status in {
        AutomatedReviewStatus.PASS,
        AutomatedReviewStatus.CHANGES_REQUIRED,
    }
    if not exact_binding or not successor_review_is_terminal(
        publication.automated_review_status,
        fallback,
    ):
        raise DomainError("successor review is not complete for the exact published head")
    if provider_terminal and fallback is not None:
        raise DomainError("fallback is only valid when the provider review is unavailable")

    _append(
        session,
        row,
        event_type="SUCCESSOR_REVIEW_STARTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def begin_rejected_findings_finalization(
    session: Session,
    work_package_id: str,
    *,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_publication_then_work_package(session, work_package_id)
    payload = {
        "review_run_id": row.review_run_id,
        "head_sha": row.reviewed_head_sha,
    }
    duplicate = _command_duplicate(
        session,
        row,
        event_type="REJECTED_FINDINGS_FINALIZATION_STARTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    view = get_work_package(session, work_package_id)
    if view.state is WorkPackageState.VERIFYING:
        if view.successor_review_run_id is None and view.successor_head_sha is None:
            session.commit()
            return view
        raise DomainError("work package is bound to a successor review")
    if view.state is not WorkPackageState.READY:
        raise DomainError("rejected findings can finalize only from READY")
    if not view.findings or any(
        finding["principal_decision"]["decision"] != PrincipalDecision.REJECTED.value
        for finding in view.findings
    ):
        raise DomainError("decision-only finalization requires all findings to be rejected")
    publication = get_view(session, row.publication_id)
    if (
        publication.remote_head_sha != row.reviewed_head_sha
        or publication.automated_review_head_sha != row.reviewed_head_sha
        or publication.automated_review_run_id != row.review_run_id
        or publication.automated_review_status
        not in {AutomatedReviewStatus.PASS, AutomatedReviewStatus.CHANGES_REQUIRED}
    ):
        raise DomainError("principal decisions are no longer current for the reviewed head")
    _append(
        session,
        row,
        event_type="REJECTED_FINDINGS_FINALIZATION_STARTED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def _verify_principal_finding(
    session: Session,
    work_package_id: str,
    *,
    finding_id: str,
    outcome: str,
    reviewer: str,
    evidence: str,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    current = get_work_package(session, work_package_id)
    binding = current.principal_verification
    finding = next(
        (item for item in current.findings if item["finding_id"] == finding_id),
        None,
    )
    if finding is None:
        raise DomainError("finding does not belong to this work package")
    if finding["principal_decision"]["decision"] != PrincipalDecision.ACCEPTED.value:
        raise DomainError("only accepted findings require Principal verification")
    if binding is None or finding_id not in binding.get("finding_ids", []):
        raise DomainError("finding is not part of the active Principal verification")
    normalized_outcome = outcome.upper()
    if normalized_outcome not in {"FIXED", "NOT_FIXED"}:
        raise DomainError("Principal finding outcome must be FIXED or NOT_FIXED")
    normalized_reviewer = reviewer.strip()
    normalized_evidence = evidence.strip()
    _assert_safe_client_text(normalized_reviewer, "finding verification reviewer")
    _assert_safe_client_text(normalized_evidence, "finding verification evidence")
    if normalized_reviewer != binding.get("reviewer"):
        raise DomainError("finding verifier does not match the Principal PLANE_REVIEW identity")
    if not normalized_evidence or len(normalized_evidence) > 4000:
        raise DomainError("verification evidence is required and bounded")
    if not idempotency_key.strip() or len(idempotency_key) > 200:
        raise DomainError("idempotency_key must contain 1..200 characters")

    _validate_governed_published_candidate(session, current)
    evidence_binding = _principal_review_evidence(
        session,
        row.publication_id,
        review_run_id=str(binding["review_run_id"]),
        head_sha=str(binding["head_sha"]),
    )
    if any(binding.get(key) != evidence_binding.get(key) for key in evidence_binding):
        raise DomainError("Principal verification evidence changed after it was started")
    payload = {
        "finding_id": finding_id,
        "outcome": normalized_outcome,
        "review_run_id": binding["review_run_id"],
        "head_sha": binding["head_sha"],
        "reviewer": normalized_reviewer,
        "evidence": normalized_evidence,
        "provider": binding["provider"],
        "provider_review_id": binding["provider_review_id"],
        "reviewer_kind": binding["reviewer_kind"],
        "review_event_hash": binding["review_event_hash"],
        "candidate_id": binding["candidate_id"],
        "implementation_head_sha": current.implementation_head_sha,
    }
    duplicate = _command_duplicate(
        session,
        row,
        event_type="FINDING_VERIFIED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if current.state is not WorkPackageState.VERIFYING:
        raise DomainError("Principal findings can only be verified during VERIFYING")
    prior = finding.get("verification")
    if prior is not None:
        same_review = (
            prior.get("review_run_id") == binding["review_run_id"]
            and prior.get("head_sha") == binding["head_sha"]
        )
        if same_review:
            if all(prior.get(key) == value for key, value in payload.items()):
                session.commit()
                return current
            raise DomainError("finding already has a different result for this Principal review")
        if prior.get("outcome") in {"FIXED", "ABSENT"}:
            raise DomainError("a fixed finding cannot be reopened by a later verification")
        if prior.get("outcome") not in {"NOT_FIXED", "PERSISTS"}:
            raise DomainError("finding already has a different verification result")

    _append(
        session,
        row,
        event_type="FINDING_VERIFIED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    updated = get_work_package(session, work_package_id)
    verification = updated.principal_verification
    assert verification is not None
    cycle_findings = {
        item["finding_id"]: item
        for item in updated.findings
        if item["finding_id"] in verification["finding_ids"]
    }
    if all(
        item.get("verification") is not None
        and item["verification"].get("review_run_id")
        == verification["review_run_id"]
        and item["verification"].get("head_sha") == verification["head_sha"]
        for item in cycle_findings.values()
    ):
        not_fixed_ids = sorted(
            finding_key
            for finding_key, item in cycle_findings.items()
            if item["verification"]["outcome"] == "NOT_FIXED"
        )
        if not_fixed_ids:
            fixed_ids = sorted(set(cycle_findings) - set(not_fixed_ids))
            _append(
                session,
                row,
                event_type="WORK_PACKAGE_REWORK_REQUIRED",
                idempotency_key=(
                    f"auto-principal-rework:{verification['review_run_id']}:"
                    f"{verification['head_sha']}"
                ),
                payload={
                    "review_run_id": verification["review_run_id"],
                    "head_sha": verification["head_sha"],
                    "implementation_head_sha": verification["head_sha"],
                    "candidate_id": verification["candidate_id"],
                    "principal_review_event_hash": verification["review_event_hash"],
                    "verification_mode": "PRINCIPAL_REVIEW",
                    "persistent_finding_ids": not_fixed_ids,
                    "fixed_finding_ids": fixed_ids,
                },
            )
    session.commit()
    return get_work_package(session, work_package_id)


def verify_finding(
    session: Session,
    work_package_id: str,
    *,
    finding_id: str,
    outcome: str,
    reviewer: str,
    evidence: str,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    if outcome.upper() in {"FIXED", "NOT_FIXED"}:
        return _verify_principal_finding(
            session,
            work_package_id,
            finding_id=finding_id,
            outcome=outcome,
            reviewer=reviewer,
            evidence=evidence,
            idempotency_key=idempotency_key,
        )
    row = _lock_work_package(session, work_package_id)
    current = get_work_package(session, work_package_id)
    finding = next((item for item in current.findings if item["finding_id"] == finding_id), None)
    if finding is None:
        raise DomainError("finding does not belong to this work package")
    if finding["principal_decision"]["decision"] != PrincipalDecision.ACCEPTED.value:
        raise DomainError("only accepted findings require successor verification")
    normalized_outcome = outcome.upper()
    if normalized_outcome not in {"ABSENT", "PERSISTS"}:
        raise DomainError("finding verification outcome must be ABSENT or PERSISTS")
    stable_request = {
        "finding_id": finding_id,
        "outcome": normalized_outcome,
        "reviewer": reviewer.strip(),
        "evidence": evidence.strip(),
    }
    _assert_safe_client_text(stable_request["reviewer"], "finding verification reviewer")
    _assert_safe_client_text(stable_request["evidence"], "finding verification evidence")
    if current.successor_fallback is not None:
        authorized_reviewer = str(current.successor_fallback.get("reviewer", "")).strip()
        if (
            not authorized_reviewer
            or stable_request["reviewer"] != authorized_reviewer
        ):
            raise DomainError(
                "finding verification reviewer does not match the authorized fallback reviewer"
            )
    existing = session.scalar(
        select(RemediationEventRow).where(
            RemediationEventRow.work_package_id == row.id,
            RemediationEventRow.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.event_type != "FINDING_VERIFIED" or any(
            existing.payload.get(key) != value
            for key, value in stable_request.items()
        ):
            raise DomainError("idempotency key was already used for another command")
        session.commit()
        return get_work_package(session, work_package_id)
    if current.state is not WorkPackageState.VERIFYING:
        raise DomainError("findings can only be verified during VERIFYING")
    payload = {
        **stable_request,
        "review_run_id": current.successor_review_run_id,
        "head_sha": current.successor_head_sha,
    }
    if not payload["review_run_id"] or not payload["head_sha"]:
        raise DomainError("successor review binding is required for finding verification")
    if not idempotency_key.strip() or len(idempotency_key) > 200:
        raise DomainError("idempotency_key must contain 1..200 characters")
    duplicate = _command_duplicate(
        session,
        row,
        event_type="FINDING_VERIFIED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if not payload["reviewer"] or len(payload["reviewer"]) > 200:
        raise DomainError("verification reviewer is required and bounded")
    if not payload["evidence"] or len(payload["evidence"]) > 4000:
        raise DomainError("verification evidence is required and bounded")
    prior = finding.get("verification")
    if prior is not None:
        if prior == {
            "outcome": payload["outcome"],
            "review_run_id": payload["review_run_id"],
            "head_sha": payload["head_sha"],
            "reviewer": payload["reviewer"],
            "evidence": payload["evidence"],
        }:
            session.commit()
            return current
        raise DomainError("finding already has a different verification result")
    _append(
        session,
        row,
        event_type="FINDING_VERIFIED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    updated = get_work_package(session, work_package_id)
    accepted_findings = [
        item
        for item in updated.findings
        if item["principal_decision"]["decision"] == PrincipalDecision.ACCEPTED.value
    ]
    if accepted_findings and all(item["verification"] is not None for item in accepted_findings):
        persistent_ids = sorted(
            item["finding_id"]
            for item in accepted_findings
            if item["verification"]["outcome"] == "PERSISTS"
        )
        if persistent_ids:
            absent_ids = sorted(
                item["finding_id"]
                for item in accepted_findings
                if item["verification"]["outcome"] == "ABSENT"
            )
            run_id = updated.successor_review_run_id
            assert run_id is not None
            _append(
                session,
                row,
                event_type="WORK_PACKAGE_REWORK_REQUIRED",
                idempotency_key=f"auto-rework:{run_id}",
                payload={
                    "review_run_id": run_id,
                    "head_sha": updated.successor_head_sha,
                    "implementation_head_sha": updated.implementation_head_sha,
                    "persistent_finding_ids": persistent_ids,
                    "absent_finding_ids": absent_ids,
                },
            )
    session.commit()
    return get_work_package(session, work_package_id)


def record_github_artifact(
    session: Session,
    work_package_id: str,
    *,
    finding_id: str,
    artifact: str,
    remote_id: int | str,
    idempotency_key: str,
    phase: str | None = None,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    view = get_work_package(session, work_package_id)
    finding = next((item for item in view.findings if item["finding_id"] == finding_id), None)
    if finding is None:
        raise DomainError("finding does not belong to this work package")
    if artifact not in {"reaction", "reply", "resolution"}:
        raise DomainError("GitHub artifact type is invalid")
    if finding["source"].get("provider_thread_id") is None:
        raise DomainError("internal findings do not have GitHub thread artifacts")
    if artifact == "reaction" and finding["desired_reaction"] == "none":
        raise DomainError("finding decision does not request a reaction")
    if phase not in {None, "decision", "verification"}:
        raise DomainError("GitHub finding artifact phase is invalid")
    if phase is None:
        if view.state is not WorkPackageState.VERIFYING:
            raise DomainError("legacy GitHub finding artifacts can only be recorded during VERIFYING")
        if finding["closure_state"] not in {"VERIFIED_ABSENT", "REJECTED_BY_PRINCIPAL"}:
            raise DomainError("finding closure evidence is required before thread materialization")
        event_type = "GITHUB_ARTIFACT_MATERIALIZED"
        artifact_state = finding["materialization"]
        artifact_ids = finding["materialization_ids"]
    elif phase == "decision":
        if view.state is WorkPackageState.DONE:
            raise DomainError("decision artifacts cannot change after work-package completion")
        if artifact == "resolution" and (
            finding["principal_decision"]["decision"] != PrincipalDecision.REJECTED.value
        ):
            raise DomainError("accepted provider threads remain open during adjudication")
        event_type = "DECISION_ARTIFACT_MATERIALIZED"
        artifact_state = finding["decision_materialization"]
        artifact_ids = finding["decision_materialization_ids"]
    else:
        if (
            view.state not in {WorkPackageState.VERIFYING, WorkPackageState.REWORK_REQUIRED}
            or finding["principal_decision"]["decision"] != PrincipalDecision.ACCEPTED.value
            or finding.get("verification", {}).get("outcome") != "FIXED"
            or artifact not in {"reply", "resolution"}
        ):
            raise DomainError("verification artifacts require an accepted FIXED finding")
        event_type = "VERIFICATION_ARTIFACT_MATERIALIZED"
        artifact_state = finding["verification_materialization"]
        artifact_ids = finding["verification_materialization_ids"]
    if isinstance(remote_id, int) and remote_id <= 0:
        raise DomainError("GitHub materialization id must be positive")
    payload = {"finding_id": finding_id, "artifact": artifact, "remote_id": remote_id}
    duplicate = _command_duplicate(
        session,
        row,
        event_type=event_type,
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if artifact_state[artifact] == "MATERIALIZED":
        if artifact_ids.get(artifact) == remote_id:
            session.commit()
            return view
        raise DomainError("GitHub artifact already has a different materialization")
    _append(
        session,
        row,
        event_type=event_type,
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def record_implementation_projection(
    session: Session,
    work_package_id: str,
    *,
    candidate_id: str,
    head_sha: str,
    issue_comment_id: int,
    pull_request_comment_id: int,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    view = get_work_package(session, work_package_id)
    payload = {
        "candidate_id": candidate_id,
        "head_sha": head_sha.lower(),
        "issue_comment_id": issue_comment_id,
        "pull_request_comment_id": pull_request_comment_id,
    }
    if (
        view.state
        not in {
            WorkPackageState.IMPLEMENTED,
            WorkPackageState.VERIFYING,
            WorkPackageState.REWORK_REQUIRED,
            WorkPackageState.DONE,
        }
        or view.candidate_id != payload["candidate_id"]
        or view.implementation_head_sha != payload["head_sha"]
        or issue_comment_id <= 0
        or pull_request_comment_id <= 0
        or issue_comment_id == pull_request_comment_id
    ):
        raise DomainError("implementation projection does not match its submitted candidate")
    duplicate = _command_duplicate(
        session,
        row,
        event_type="IMPLEMENTATION_PROJECTION_MATERIALIZED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if view.implementation_projection == payload:
        session.commit()
        return view
    _append(
        session,
        row,
        event_type="IMPLEMENTATION_PROJECTION_MATERIALIZED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def record_summary_comment(
    session: Session,
    work_package_id: str,
    *,
    comment_id: int,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    view = get_work_package(session, work_package_id)
    if view.state is not WorkPackageState.VERIFYING or comment_id <= 0:
        raise DomainError("work package summary comment cannot be recorded yet")
    if any(not finding_is_terminal(finding) for finding in view.findings):
        raise DomainError("all finding verification and thread artifacts must finish first")
    payload = {"comment_id": comment_id}
    duplicate = _command_duplicate(
        session,
        row,
        event_type="WORK_PACKAGE_SUMMARY_MATERIALIZED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if view.summary_comment_id is not None:
        if view.summary_comment_id == comment_id:
            session.commit()
            return view
        raise DomainError("work package already has a different summary comment")
    _append(
        session,
        row,
        event_type="WORK_PACKAGE_SUMMARY_MATERIALIZED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_package(session, work_package_id)


def record_issue_closed(
    session: Session,
    work_package_id: str,
    *,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_work_package(session, work_package_id)
    view = get_work_package(session, work_package_id)
    if (
        view.state not in {WorkPackageState.VERIFYING, WorkPackageState.DONE}
        or view.summary_comment_id is None
        or view.implementation_issue_number is None
    ):
        raise DomainError("implementation issue cannot close before authoritative completion readiness")
    payload: dict[str, Any] = {"issue_number": view.implementation_issue_number}
    duplicate = _command_duplicate(
        session,
        row,
        event_type="IMPLEMENTATION_ISSUE_CLOSED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if not view.issue_closed:
        _append(
            session,
            row,
            event_type="IMPLEMENTATION_ISSUE_CLOSED",
            idempotency_key=idempotency_key,
            payload=payload,
        )
    session.commit()
    return get_work_package(session, work_package_id)


def complete_work_package(
    session: Session,
    work_package_id: str,
    *,
    idempotency_key: str,
) -> RemediationWorkPackageView:
    row = _lock_publication_then_work_package(session, work_package_id)
    view = get_work_package(session, work_package_id)
    payload: dict[str, Any] = {"implementation_issue_number": view.implementation_issue_number}
    duplicate = _command_duplicate(
        session,
        row,
        event_type="WORK_PACKAGE_COMPLETED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    if duplicate is not None:
        return duplicate
    if view.state is WorkPackageState.DONE:
        session.commit()
        return view
    if view.state is not WorkPackageState.VERIFYING:
        raise DomainError("work package can only complete after verification")
    if view.summary_comment_id is None or any(
        not finding_is_terminal(finding) for finding in view.findings
    ):
        raise DomainError("work package findings are not fully closed")

    publication = get_view(session, row.publication_id)
    if view.principal_verification is not None:
        _validate_governed_published_candidate(session, view)
        evidence_binding = _principal_review_evidence(
            session,
            row.publication_id,
            review_run_id=view.principal_verification["review_run_id"],
            head_sha=view.principal_verification["head_sha"],
        )
        if any(
            view.principal_verification.get(key) != value
            for key, value in evidence_binding.items()
        ):
            raise DomainError("work package Principal verification evidence changed")
    else:
        expected_run_id = view.successor_review_run_id or row.review_run_id
        expected_head_sha = view.successor_head_sha or row.reviewed_head_sha
        terminal_review = successor_review_is_terminal(
            publication.automated_review_status,
            view.successor_fallback if view.successor_review_run_id is not None else None,
        )
        if (
            publication.remote_head_sha != expected_head_sha
            or publication.automated_review_head_sha != expected_head_sha
            or publication.automated_review_run_id != expected_run_id
            or not terminal_review
        ):
            raise DomainError("work package completion is stale for the current review/head")

    _append(
        session,
        row,
        event_type="WORK_PACKAGE_COMPLETED",
        idempotency_key=idempotency_key,
        payload=payload,
    )

    # A decision-only package (all provider findings rejected by the Principal
    # Reviewer) has no successor review. Preserve the provider's original
    # CHANGES_REQUIRED evidence while explicitly restoring same-head Human
    # Review eligibility after the package is fully materialized and closed.
    if view.successor_review_run_id is None and view.principal_verification is None:
        clearance = {
            "run_id": row.review_run_id,
            "head_sha": row.reviewed_head_sha,
            "work_package_id": work_package_id,
        }
        validate_transition(publication, EventType.REMEDIATION_CLEARED, clearance)
        append_event(session, row.publication_id, EventType.REMEDIATION_CLEARED, clearance)

    session.commit()
    return get_work_package(session, work_package_id)


def work_package_events(session: Session, work_package_id: str) -> list[dict[str, Any]]:
    if session.get(RemediationWorkPackageRow, work_package_id) is None:
        raise KeyError(work_package_id)
    return load_work_package_events(session, work_package_id)


def claim_github_artifact_dispatch(
    session: Session,
    work_package_id: str,
    *,
    artifact_key: str,
    lease_id: str,
    lease_seconds: int = 60,
) -> bool:
    if not artifact_key.strip() or len(artifact_key) > 300:
        raise DomainError("artifact dispatch key is invalid")
    if not lease_id.strip() or len(lease_id) > 36:
        raise DomainError("artifact dispatch lease id is invalid")
    _lock_work_package(session, work_package_id)
    dispatch = session.scalar(
        select(RemediationDispatchRow)
        .where(
            RemediationDispatchRow.work_package_id == work_package_id,
            RemediationDispatchRow.artifact_key == artifact_key,
        )
        .with_for_update()
    )
    now = datetime.now(timezone.utc)
    if dispatch is not None and dispatch.lease_expires_at is not None:
        expires_at = dispatch.lease_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at > now:
            session.commit()
            return False
    if dispatch is None:
        dispatch = RemediationDispatchRow(
            work_package_id=work_package_id,
            artifact_key=artifact_key,
            lease_id=lease_id,
            lease_expires_at=now + timedelta(seconds=lease_seconds),
        )
        session.add(dispatch)
    else:
        dispatch.lease_id = lease_id
        dispatch.lease_expires_at = now + timedelta(seconds=lease_seconds)
    session.commit()
    return True


def fence_github_artifact_dispatch(
    session: Session,
    work_package_id: str,
    *,
    artifact_key: str,
    lease_id: str,
    lease_seconds: int = 60,
) -> bool:
    """Hold package + dispatch row locks across the final remote artifact write.

    This converts the expiring recovery lease into an actual mutation fence:
    ownership may expire during discovery, but a stale worker cannot write after
    another worker has reclaimed the dispatch.
    """
    _lock_work_package(session, work_package_id)
    dispatch = session.scalar(
        select(RemediationDispatchRow)
        .where(
            RemediationDispatchRow.work_package_id == work_package_id,
            RemediationDispatchRow.artifact_key == artifact_key,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if dispatch is None or dispatch.lease_id != lease_id:
        session.commit()
        return False
    dispatch.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)
    session.flush()
    return True


def release_github_artifact_dispatch(
    session: Session,
    work_package_id: str,
    *,
    artifact_key: str,
    lease_id: str,
) -> None:
    dispatch = session.scalar(
        select(RemediationDispatchRow)
        .where(
            RemediationDispatchRow.work_package_id == work_package_id,
            RemediationDispatchRow.artifact_key == artifact_key,
        )
        .with_for_update()
    )
    if dispatch is not None and dispatch.lease_id == lease_id:
        dispatch.lease_id = None
        dispatch.lease_expires_at = None
    session.commit()
