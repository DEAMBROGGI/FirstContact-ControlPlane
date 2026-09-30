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

from .domain import DomainError
from .models import WorkDependencyRow, WorkItemEventRow, WorkItemRow
from .repository import ZERO_HASH

_CONTEXT_NAMESPACE = uuid.UUID("abf32b46-34a6-40b2-a86a-2b8734ad192e")
_EVIDENCE_RE = re.compile(r"^[0-9a-f]{64}$")
_MIN_LEASE_SECONDS = 60
_MAX_LEASE_SECONDS = 24 * 60 * 60


class WorkState(StrEnum):
    BACKLOG = "BACKLOG"
    BLOCKED = "BLOCKED"
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    REVIEW = "REVIEW"
    DONE = "DONE"
    SUSPENDED = "SUSPENDED"


class NextRole(StrEnum):
    PLANNER = "PLANNER"
    IMPLEMENTER = "IMPLEMENTER"
    REVIEWER = "REVIEWER"
    NONE = "NONE"


class NextAction(StrEnum):
    WAIT_RELEASE = "WAIT_RELEASE"
    WAIT_DEPENDENCIES = "WAIT_DEPENDENCIES"
    CLAIM_WORK = "CLAIM_WORK"
    IMPLEMENT = "IMPLEMENT"
    WAIT_REVIEW = "WAIT_REVIEW"
    DONE = "DONE"
    SUSPENDED = "SUSPENDED"


@dataclass(frozen=True, slots=True)
class WorkItemView:
    work_item_id: str
    repository: str
    issue_number: int
    parent_work_item_id: str | None
    required_for_parent: bool
    executable: bool
    priority: int
    topology_order: int
    rank: int
    context_version: int
    context_digest: str
    context: dict[str, Any]
    state: WorkState
    released: bool
    suspended: bool
    implementer: str | None
    claim_lease_id: str | None
    claim_expires_at: str | None
    implementation_summary: str | None
    implementation_evidence_sha256: str | None
    dependencies: tuple[str, ...]
    required_children: tuple[str, ...]
    blockers: tuple[str, ...]
    next_role: NextRole
    next_action: NextAction


@dataclass(frozen=True, slots=True)
class _LocalState:
    context_version: int
    context_digest: str
    context: dict[str, Any]
    released: bool
    suspended: bool
    implementer: str | None
    claim_lease_id: str | None
    claim_expires_at: datetime | None
    implementation_summary: str | None
    implementation_evidence_sha256: str | None
    implemented: bool
    completed: bool


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_text(value: str, field: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise DomainError(f"{field} must contain 1..{maximum} characters")
    return normalized


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _lease_seconds(value: int) -> int:
    if value < _MIN_LEASE_SECONDS or value > _MAX_LEASE_SECONDS:
        raise DomainError(
            f"claim lease must be between {_MIN_LEASE_SECONDS} and {_MAX_LEASE_SECONDS} seconds"
        )
    return value


def _parse_lease_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("work claim lease timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("work claim lease timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeError("work claim lease timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _context_payload(context: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    normalized = json.loads(_canonical(dict(context)))
    raw = _canonical(normalized).encode("utf-8")
    if len(raw) > 64 * 1024:
        raise DomainError("work context exceeds 64 KiB")
    return normalized, hashlib.sha256(raw).hexdigest()


def _hash_event(
    work_item_id: str,
    sequence: int,
    event_type: str,
    idempotency_key: str,
    payload: Mapping[str, Any],
    previous_hash: str,
) -> str:
    return hashlib.sha256(
        _canonical(
            {
                "work_item_id": work_item_id,
                "sequence": sequence,
                "event_type": event_type,
                "idempotency_key": idempotency_key,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        ).encode("utf-8")
    ).hexdigest()


def _event_payload(row: WorkItemEventRow) -> dict[str, Any]:
    return {
        "sequence": row.sequence,
        "event_type": row.event_type,
        "idempotency_key": row.idempotency_key,
        "payload": row.payload,
        "previous_hash": row.previous_hash,
        "event_hash": row.event_hash,
        "occurred_at": row.occurred_at.isoformat(),
    }


def load_work_item_events(
    session: Session,
    work_item_id: str,
) -> list[dict[str, Any]]:
    if session.get(WorkItemRow, work_item_id) is None:
        raise KeyError(work_item_id)
    rows = list(
        session.scalars(
            select(WorkItemEventRow)
            .where(WorkItemEventRow.work_item_id == work_item_id)
            .order_by(WorkItemEventRow.sequence.asc())
        )
    )
    previous = ZERO_HASH
    events: list[dict[str, Any]] = []
    for expected, row in enumerate(rows, start=1):
        if row.sequence != expected or row.previous_hash != previous:
            raise RuntimeError("work-item event chain is corrupt")
        digest = _hash_event(
            work_item_id,
            row.sequence,
            row.event_type,
            row.idempotency_key,
            row.payload,
            row.previous_hash,
        )
        if digest != row.event_hash:
            raise RuntimeError("work-item event hash mismatch")
        events.append(_event_payload(row))
        previous = row.event_hash
    return events


def _lock_create_scope(session: Session, repository: str, issue_number: int) -> None:
    if session.get_bind().dialect.name != "postgresql":
        return
    key = hashlib.sha256(
        f"firstcontact-work-create\0{repository}\0{issue_number}".encode("utf-8")
    ).digest()[:8]
    session.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": int.from_bytes(key, byteorder="big", signed=True)},
    )


def _lock_scheduler_scope(session: Session, repository: str) -> None:
    if session.get_bind().dialect.name != "postgresql":
        return
    key = hashlib.sha256(
        f"firstcontact-work-scheduler\0{repository}".encode("utf-8")
    ).digest()[:8]
    session.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": int.from_bytes(key, byteorder="big", signed=True)},
    )


def _lock_work_item(session: Session, work_item_id: str) -> WorkItemRow:
    row = session.scalar(
        select(WorkItemRow)
        .where(WorkItemRow.id == work_item_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise KeyError(work_item_id)
    return row


def _event_by_idempotency(
    session: Session,
    idempotency_key: str,
) -> WorkItemEventRow | None:
    return session.scalar(
        select(WorkItemEventRow).where(
            WorkItemEventRow.idempotency_key == idempotency_key
        )
    )


def _append(
    session: Session,
    row: WorkItemRow,
    *,
    event_type: str,
    idempotency_key: str,
    payload: dict[str, Any],
) -> WorkItemEventRow:
    key = _safe_text(idempotency_key, "idempotency_key", 200)
    existing = _event_by_idempotency(session, key)
    if existing is not None:
        if (
            existing.work_item_id != row.id
            or existing.event_type != event_type
            or _canonical(existing.payload) != _canonical(payload)
        ):
            raise DomainError("idempotency key was already used for another work command")
        return existing

    last = session.scalar(
        select(WorkItemEventRow)
        .where(WorkItemEventRow.work_item_id == row.id)
        .order_by(WorkItemEventRow.sequence.desc())
        .limit(1)
    )
    sequence = 1 if last is None else last.sequence + 1
    previous_hash = ZERO_HASH if last is None else last.event_hash
    event_hash = _hash_event(
        row.id,
        sequence,
        event_type,
        key,
        payload,
        previous_hash,
    )
    event = WorkItemEventRow(
        work_item_id=row.id,
        sequence=sequence,
        event_type=event_type,
        idempotency_key=key,
        payload=payload,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    session.add(event)
    session.flush()
    return event


def _fold_local(session: Session, work_item_id: str) -> _LocalState:
    row = session.get(WorkItemRow, work_item_id)
    if row is None:
        raise KeyError(work_item_id)
    events = load_work_item_events(session, work_item_id)
    if not events or events[0]["event_type"] != "WORK_CREATED":
        raise RuntimeError("work-item ledger is missing its creation event")

    created = events[0]["payload"]
    if not isinstance(created, dict):
        raise RuntimeError("work-item creation payload is invalid")
    ledger_context = created.get("context")
    if not isinstance(ledger_context, dict):
        raise RuntimeError("work-item ledger is missing versioned context")
    normalized_context, observed_digest = _context_payload(ledger_context)

    expected_created = {
        "repository": row.repository,
        "issue_number": row.issue_number,
        "parent_work_item_id": row.parent_work_item_id,
        "required_for_parent": row.required_for_parent,
        "executable": row.executable,
        "priority": row.priority,
        "rank": row.rank,
        "context_version": row.context_version,
        "context_digest": row.context_digest,
        "context": normalized_context,
    }
    if _canonical(created) != _canonical(expected_created):
        raise RuntimeError("work-item immutable identity differs from its ledger")
    if observed_digest != row.context_digest:
        raise RuntimeError("work-item ledger context digest is invalid")
    if normalized_context != row.context_data:
        raise RuntimeError("work-item context projection differs from its ledger")

    released = False
    suspended = False
    implementer: str | None = None
    claim_lease_id: str | None = None
    claim_expires_at: datetime | None = None
    implementation_summary: str | None = None
    implementation_evidence: str | None = None
    implemented = False
    completed = False

    for event in events:
        event_type = event["event_type"]
        payload = event["payload"]
        if event_type == "WORK_RELEASED":
            released = True
        elif event_type == "WORK_SUSPENDED":
            suspended = True
        elif event_type == "WORK_RESUMED":
            suspended = False
        elif event_type == "WORK_CLAIMED":
            implementer = str(payload["actor"])
            claim_lease_id = str(payload["lease_id"])
            claim_expires_at = _parse_lease_time(payload["lease_expires_at"])
        elif event_type == "WORK_CLAIM_RENEWED":
            if implementer != str(payload["actor"]):
                raise RuntimeError("work claim renewal actor differs from active claim")
            if claim_lease_id != str(payload["lease_id"]):
                raise RuntimeError("work claim renewal lease differs from active claim")
            claim_expires_at = _parse_lease_time(payload["lease_expires_at"])
        elif event_type == "WORK_CLAIM_RELEASED":
            implementer = None
            claim_lease_id = None
            claim_expires_at = None
        elif event_type == "WORK_IMPLEMENTATION_COMPLETED":
            implemented = True
            implementation_summary = str(payload["summary"])
            implementation_evidence = str(payload["evidence_sha256"])
        elif event_type == "WORK_COMPLETED":
            completed = True
        elif event_type in {"WORK_CREATED", "WORK_DEPENDENCY_ADDED"}:
            continue
        else:
            raise RuntimeError(f"unknown work-item event type: {event_type}")

    if (
        implementer is not None
        and not implemented
        and not completed
        and claim_expires_at is not None
        and claim_expires_at <= _utcnow()
    ):
        implementer = None
        claim_lease_id = None
        claim_expires_at = None

    return _LocalState(
        context_version=row.context_version,
        context_digest=row.context_digest,
        context=normalized_context,
        released=released,
        suspended=suspended,
        implementer=implementer,
        claim_lease_id=claim_lease_id,
        claim_expires_at=claim_expires_at,
        implementation_summary=implementation_summary,
        implementation_evidence_sha256=implementation_evidence,
        implemented=implemented,
        completed=completed,
    )


def _dependency_ids(session: Session, work_item_id: str) -> tuple[str, ...]:
    materialized = tuple(
        session.scalars(
            select(WorkDependencyRow.depends_on_work_item_id)
            .where(WorkDependencyRow.work_item_id == work_item_id)
            .order_by(WorkDependencyRow.depends_on_work_item_id.asc())
        )
    )
    ledger = tuple(
        sorted(
            str(event["payload"]["depends_on_work_item_id"])
            for event in load_work_item_events(session, work_item_id)
            if event["event_type"] == "WORK_DEPENDENCY_ADDED"
        )
    )
    if materialized != ledger:
        raise RuntimeError("work dependency projection differs from its ledger")
    return materialized


def _required_child_ids(session: Session, work_item_id: str) -> tuple[str, ...]:
    parent = session.get(WorkItemRow, work_item_id)
    if parent is None:
        raise KeyError(work_item_id)
    children: list[str] = []
    candidates = list(
        session.scalars(
            select(WorkItemRow)
            .where(WorkItemRow.repository == parent.repository)
            .order_by(WorkItemRow.id.asc())
        )
    )
    for candidate in candidates:
        events = load_work_item_events(session, candidate.id)
        if not events or events[0]["event_type"] != "WORK_CREATED":
            raise RuntimeError("work-item ledger is missing its creation event")
        created = events[0]["payload"]
        if (
            created.get("parent_work_item_id") == work_item_id
            and created.get("required_for_parent") is True
        ):
            children.append(candidate.id)
    return tuple(children)


def _next_for(
    state: WorkState,
    *,
    blockers: tuple[str, ...],
) -> tuple[NextRole, NextAction]:
    if state is WorkState.BACKLOG:
        return NextRole.PLANNER, NextAction.WAIT_RELEASE
    if state is WorkState.BLOCKED:
        return NextRole.PLANNER, NextAction.WAIT_DEPENDENCIES
    if state is WorkState.READY:
        return NextRole.IMPLEMENTER, NextAction.CLAIM_WORK
    if state is WorkState.IN_PROGRESS:
        return NextRole.IMPLEMENTER, NextAction.IMPLEMENT
    if state is WorkState.REVIEW:
        return NextRole.REVIEWER, NextAction.WAIT_REVIEW
    if state is WorkState.SUSPENDED:
        return NextRole.PLANNER, NextAction.SUSPENDED
    if state is WorkState.DONE:
        return NextRole.NONE, NextAction.DONE
    raise RuntimeError(f"unsupported work state: {state}; blockers={blockers}")


def _view(
    session: Session,
    row: WorkItemRow,
    *,
    memo: dict[str, WorkItemView],
    stack: set[str],
    topology_orders: dict[str, int],
) -> WorkItemView:
    if row.id in memo:
        return memo[row.id]
    if row.id in stack:
        raise RuntimeError("work graph contains a blocking cycle")
    stack.add(row.id)
    try:
        local = _fold_local(session, row.id)
        dependencies = _dependency_ids(session, row.id)
        children = _required_child_ids(session, row.id)
        blockers: list[str] = []

        for dependency_id in dependencies:
            dependency = session.get(WorkItemRow, dependency_id)
            if dependency is None:
                raise RuntimeError("work dependency points to a missing work item")
            dependency_view = _view(
                session,
                dependency,
                memo=memo,
                stack=stack,
                topology_orders=topology_orders,
            )
            if dependency_view.state is not WorkState.DONE:
                blockers.append(f"dependency:{dependency_id}")

        for child_id in children:
            child = session.get(WorkItemRow, child_id)
            if child is None:
                raise RuntimeError("required child points to a missing work item")
            child_view = _view(
                session,
                child,
                memo=memo,
                stack=stack,
                topology_orders=topology_orders,
            )
            if child_view.state is not WorkState.DONE:
                blockers.append(f"child:{child_id}")

        if local.completed:
            state = WorkState.DONE
        elif local.suspended:
            state = WorkState.SUSPENDED
        elif local.implemented:
            state = WorkState.REVIEW
        elif local.implementer is not None:
            state = WorkState.IN_PROGRESS
        elif blockers:
            state = WorkState.BLOCKED
        elif not local.released:
            state = WorkState.BACKLOG
        elif row.executable:
            state = WorkState.READY
        else:
            state = WorkState.REVIEW

        blocker_tuple = tuple(sorted(blockers))
        next_role, next_action = _next_for(state, blockers=blocker_tuple)
        view = WorkItemView(
            work_item_id=row.id,
            repository=row.repository,
            issue_number=row.issue_number,
            parent_work_item_id=row.parent_work_item_id,
            required_for_parent=row.required_for_parent,
            executable=row.executable,
            priority=row.priority,
            topology_order=topology_orders[row.id],
            rank=row.rank,
            context_version=local.context_version,
            context_digest=local.context_digest,
            context=dict(local.context),
            state=state,
            released=local.released,
            suspended=local.suspended,
            implementer=local.implementer,
            claim_lease_id=local.claim_lease_id,
            claim_expires_at=(
                local.claim_expires_at.isoformat()
                if local.claim_expires_at is not None
                else None
            ),
            implementation_summary=local.implementation_summary,
            implementation_evidence_sha256=local.implementation_evidence_sha256,
            dependencies=dependencies,
            required_children=children,
            blockers=blocker_tuple,
            next_role=next_role,
            next_action=next_action,
        )
        memo[row.id] = view
        return view
    finally:
        stack.remove(row.id)


def get_work_item(session: Session, work_item_id: str) -> WorkItemView:
    row = session.get(WorkItemRow, work_item_id)
    if row is None:
        raise KeyError(work_item_id)
    return _view(
        session,
        row,
        memo={},
        stack=set(),
        topology_orders=_topology_orders(session, row.repository),
    )


def get_work_item_by_issue(
    session: Session,
    repository: str,
    issue_number: int,
) -> WorkItemView:
    row = session.scalar(
        select(WorkItemRow).where(
            WorkItemRow.repository == repository,
            WorkItemRow.issue_number == issue_number,
        )
    )
    if row is None:
        raise KeyError(f"{repository}#{issue_number}")
    return get_work_item(session, row.id)


def list_work_items(
    session: Session,
    repository: str,
) -> list[WorkItemView]:
    rows = list(
        session.scalars(
            select(WorkItemRow)
            .where(WorkItemRow.repository == repository)
        )
    )
    topology_orders = _topology_orders(session, repository)
    memo: dict[str, WorkItemView] = {}
    views = [
        _view(
            session,
            row,
            memo=memo,
            stack=set(),
            topology_orders=topology_orders,
        )
        for row in rows
    ]
    return sorted(
        views,
        key=lambda view: (
            view.priority,
            view.topology_order,
            view.rank,
            view.work_item_id,
        ),
    )


def create_work_item(
    session: Session,
    *,
    repository: str,
    issue_number: int,
    context: Mapping[str, Any],
    priority: int = 2,
    rank: int = 0,
    parent_work_item_id: str | None = None,
    required_for_parent: bool = True,
    executable: bool = True,
    released: bool = True,
) -> WorkItemView:
    normalized_repository = _safe_text(repository, "repository", 200)
    if "/" not in normalized_repository:
        raise DomainError("repository must be owner/name")
    if issue_number <= 0:
        raise DomainError("issue_number must be positive")
    if priority < 0 or priority > 4:
        raise DomainError("priority must be between 0 and 4")
    if rank < 0:
        raise DomainError("rank must be non-negative")

    normalized_context, context_digest = _context_payload(context)
    _lock_create_scope(session, normalized_repository, issue_number)

    existing = session.scalar(
        select(WorkItemRow).where(
            WorkItemRow.repository == normalized_repository,
            WorkItemRow.issue_number == issue_number,
        )
    )
    if existing is not None:
        expected = {
            "parent_work_item_id": parent_work_item_id,
            "required_for_parent": bool(required_for_parent),
            "executable": bool(executable),
            "priority": priority,
            "rank": rank,
            "context_version": 1,
            "context_digest": context_digest,
            "context_data": normalized_context,
        }
        actual = {
            "parent_work_item_id": existing.parent_work_item_id,
            "required_for_parent": existing.required_for_parent,
            "executable": existing.executable,
            "priority": existing.priority,
            "rank": existing.rank,
            "context_version": existing.context_version,
            "context_digest": existing.context_digest,
            "context_data": existing.context_data,
        }
        if _canonical(expected) != _canonical(actual):
            raise DomainError("work item already exists with different immutable identity")
        view = get_work_item(session, existing.id)
        if released and not view.released:
            return release_work_item(
                session,
                existing.id,
                idempotency_key=f"work:create-release:{existing.id}",
            )
        return view

    if parent_work_item_id is not None:
        try:
            parent = _lock_work_item(session, parent_work_item_id)
        except KeyError as exc:
            raise DomainError("parent work item does not exist") from exc
        if parent.repository != normalized_repository:
            raise DomainError("parent work item must belong to the same repository")
        if required_for_parent:
            parent_view = get_work_item(session, parent.id)
            if parent_view.state in {
                WorkState.IN_PROGRESS,
                WorkState.REVIEW,
                WorkState.DONE,
            }:
                raise DomainError(
                    "required child cannot be added after parent implementation starts"
                )

    work_item_id = str(
        uuid.uuid5(
            _CONTEXT_NAMESPACE,
            f"{normalized_repository}\0{issue_number}",
        )
    )
    row = WorkItemRow(
        id=work_item_id,
        repository=normalized_repository,
        issue_number=issue_number,
        parent_work_item_id=parent_work_item_id,
        required_for_parent=bool(required_for_parent),
        executable=bool(executable),
        priority=priority,
        rank=rank,
        context_version=1,
        context_digest=context_digest,
        context_data=normalized_context,
    )
    session.add(row)
    session.flush()

    _append(
        session,
        row,
        event_type="WORK_CREATED",
        idempotency_key=f"work:create:{work_item_id}",
        payload={
            "repository": normalized_repository,
            "issue_number": issue_number,
            "parent_work_item_id": parent_work_item_id,
            "required_for_parent": bool(required_for_parent),
            "executable": bool(executable),
            "priority": priority,
            "rank": rank,
            "context_version": 1,
            "context_digest": context_digest,
            "context": normalized_context,
        },
    )
    if released:
        _append(
            session,
            row,
            event_type="WORK_RELEASED",
            idempotency_key=f"work:create-release:{work_item_id}",
            payload={"reason": "CREATED_RELEASED"},
        )
    session.commit()
    return get_work_item(session, work_item_id)


def release_work_item(
    session: Session,
    work_item_id: str,
    *,
    idempotency_key: str,
) -> WorkItemView:
    payload = {"reason": "EXPLICIT_RELEASE"}
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.work_item_id != work_item_id
            or existing.event_type != "WORK_RELEASED"
            or _canonical(existing.payload) != _canonical(payload)
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, work_item_id)

    row = _lock_work_item(session, work_item_id)
    view = get_work_item(session, row.id)
    if view.released:
        raise DomainError("work item is already released")
    if view.state in {WorkState.IN_PROGRESS, WorkState.REVIEW, WorkState.DONE}:
        raise DomainError("work item cannot be released from its current state")
    _append(
        session,
        row,
        event_type="WORK_RELEASED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_item(session, row.id)


def _blocking_graph(session: Session, repository: str) -> dict[str, set[str]]:
    rows = list(
        session.scalars(
            select(WorkItemRow).where(WorkItemRow.repository == repository)
        )
    )
    graph = {row.id: set() for row in rows}
    for edge in session.scalars(
        select(WorkDependencyRow).join(
            WorkItemRow,
            WorkItemRow.id == WorkDependencyRow.work_item_id,
        ).where(WorkItemRow.repository == repository)
    ):
        graph.setdefault(edge.work_item_id, set()).add(edge.depends_on_work_item_id)
    for row in rows:
        events = load_work_item_events(session, row.id)
        if not events or events[0]["event_type"] != "WORK_CREATED":
            raise RuntimeError("work-item ledger is missing its creation event")
        created = events[0]["payload"]
        parent_id = created.get("parent_work_item_id")
        if parent_id is not None and created.get("required_for_parent") is True:
            graph.setdefault(str(parent_id), set()).add(row.id)
    return graph


def _path_exists(graph: dict[str, set[str]], start: str, target: str) -> bool:
    pending = [start]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(graph.get(current, ()))
    return False


def _topology_orders(session: Session, repository: str) -> dict[str, int]:
    graph = _blocking_graph(session, repository)
    memo: dict[str, int] = {}
    visiting: set[str] = set()

    def depth(work_item_id: str) -> int:
        if work_item_id in memo:
            return memo[work_item_id]
        if work_item_id in visiting:
            raise RuntimeError("work graph contains a blocking cycle")
        visiting.add(work_item_id)
        try:
            blockers = graph.get(work_item_id, set())
            value = 0 if not blockers else 1 + max(depth(item) for item in blockers)
            memo[work_item_id] = value
            return value
        finally:
            visiting.remove(work_item_id)

    for work_item_id in sorted(graph):
        depth(work_item_id)
    return memo


def add_dependency(
    session: Session,
    work_item_id: str,
    depends_on_work_item_id: str,
    *,
    idempotency_key: str,
) -> WorkItemView:
    if work_item_id == depends_on_work_item_id:
        raise DomainError("work item cannot depend on itself")

    seed = session.get(WorkItemRow, work_item_id)
    if seed is None:
        raise KeyError(work_item_id)

    # Dependency mutations share the repository transaction lock with claim-next.
    # The repository lock must be acquired before the target row lock so opposite
    # concurrent edges cannot each validate against the same pre-write graph, and
    # so graph mutation and claim paths preserve one lock ordering.
    _lock_scheduler_scope(session, seed.repository)

    row = _lock_work_item(session, work_item_id)
    dependency = session.get(WorkItemRow, depends_on_work_item_id)
    if dependency is None:
        raise DomainError("dependency work item does not exist")
    if dependency.repository != row.repository:
        raise DomainError("hard dependency must belong to the same repository")

    current = get_work_item(session, row.id)
    if current.state in {WorkState.IN_PROGRESS, WorkState.REVIEW, WorkState.DONE}:
        raise DomainError("hard dependencies cannot change after implementation starts")

    existing = session.scalar(
        select(WorkDependencyRow).where(
            WorkDependencyRow.work_item_id == row.id,
            WorkDependencyRow.depends_on_work_item_id == dependency.id,
        )
    )
    if existing is not None:
        session.commit()
        return get_work_item(session, row.id)

    graph = _blocking_graph(session, row.repository)
    if _path_exists(graph, dependency.id, row.id):
        raise DomainError("hard dependency would create a blocking cycle")

    session.add(
        WorkDependencyRow(
            work_item_id=row.id,
            depends_on_work_item_id=dependency.id,
        )
    )
    _append(
        session,
        row,
        event_type="WORK_DEPENDENCY_ADDED",
        idempotency_key=idempotency_key,
        payload={"depends_on_work_item_id": dependency.id},
    )
    session.commit()
    return get_work_item(session, row.id)


def suspend_work_item(
    session: Session,
    work_item_id: str,
    *,
    actor: str,
    reason: str,
    idempotency_key: str,
) -> WorkItemView:
    payload = {
        "actor": _safe_text(actor, "actor", 200),
        "reason": _safe_text(reason, "reason", 1000),
    }
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.work_item_id != work_item_id
            or existing.event_type != "WORK_SUSPENDED"
            or _canonical(existing.payload) != _canonical(payload)
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, work_item_id)

    row = _lock_work_item(session, work_item_id)
    view = get_work_item(session, row.id)
    if view.state is WorkState.DONE:
        raise DomainError("completed work cannot be suspended")
    if view.state is WorkState.SUSPENDED:
        raise DomainError("work item is already suspended")
    _append(
        session,
        row,
        event_type="WORK_SUSPENDED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_item(session, row.id)


def resume_work_item(
    session: Session,
    work_item_id: str,
    *,
    actor: str,
    idempotency_key: str,
) -> WorkItemView:
    payload = {"actor": _safe_text(actor, "actor", 200)}
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.work_item_id != work_item_id
            or existing.event_type != "WORK_RESUMED"
            or _canonical(existing.payload) != _canonical(payload)
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, work_item_id)

    row = _lock_work_item(session, work_item_id)
    view = get_work_item(session, row.id)
    if view.state is not WorkState.SUSPENDED:
        raise DomainError("work item is not suspended")
    _append(
        session,
        row,
        event_type="WORK_RESUMED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_item(session, row.id)


def _claim_locked(
    session: Session,
    row: WorkItemRow,
    *,
    actor: str,
    idempotency_key: str,
    lease_seconds: int,
) -> WorkItemView:
    normalized_actor = _safe_text(actor, "actor", 200)
    lease_seconds = _lease_seconds(lease_seconds)
    view = get_work_item(session, row.id)
    if view.state is not WorkState.READY:
        raise DomainError(f"work item is not READY: {view.state.value}")
    if not row.executable:
        raise DomainError("non-executable work item cannot be claimed")
    lease_id = str(uuid.uuid4())
    lease_expires_at = (_utcnow() + timedelta(seconds=lease_seconds)).isoformat()
    _append(
        session,
        row,
        event_type="WORK_CLAIMED",
        idempotency_key=idempotency_key,
        payload={
            "actor": normalized_actor,
            "lease_id": lease_id,
            "lease_expires_at": lease_expires_at,
        },
    )
    session.commit()
    return get_work_item(session, row.id)


def claim_work_item(
    session: Session,
    work_item_id: str,
    *,
    actor: str,
    idempotency_key: str,
    lease_seconds: int = 4 * 60 * 60,
) -> WorkItemView:
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.event_type != "WORK_CLAIMED"
            or str(existing.payload.get("actor")) != actor.strip()
            or existing.work_item_id != work_item_id
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, existing.work_item_id)
    row = _lock_work_item(session, work_item_id)
    return _claim_locked(
        session,
        row,
        actor=actor,
        idempotency_key=idempotency_key,
        lease_seconds=lease_seconds,
    )


def next_work(
    session: Session,
    repository: str,
) -> WorkItemView | None:
    for view in list_work_items(session, repository):
        if view.executable and view.state is WorkState.READY:
            return view
    return None


def claim_next_work(
    session: Session,
    repository: str,
    *,
    actor: str,
    idempotency_key: str,
    lease_seconds: int = 4 * 60 * 60,
) -> WorkItemView | None:
    normalized_repository = _safe_text(repository, "repository", 200)
    normalized_actor = _safe_text(actor, "actor", 200)
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.event_type != "WORK_CLAIMED"
            or str(existing.payload.get("actor")) != normalized_actor
        ):
            raise DomainError("idempotency key was already used for another work command")
        view = get_work_item(session, existing.work_item_id)
        if view.repository != normalized_repository:
            raise DomainError("claim-next idempotency key belongs to another repository")
        return view

    _lock_scheduler_scope(session, normalized_repository)
    for candidate in list_work_items(session, normalized_repository):
        if not candidate.executable or candidate.state is not WorkState.READY:
            continue
        row = _lock_work_item(session, candidate.work_item_id)
        candidate = get_work_item(session, row.id)
        if candidate.state is not WorkState.READY:
            continue
        return _claim_locked(
            session,
            row,
            actor=normalized_actor,
            idempotency_key=idempotency_key,
            lease_seconds=lease_seconds,
        )
    session.commit()
    return None


def renew_claim(
    session: Session,
    work_item_id: str,
    *,
    actor: str,
    idempotency_key: str,
    lease_seconds: int = 4 * 60 * 60,
) -> WorkItemView:
    normalized_actor = _safe_text(actor, "actor", 200)
    lease_seconds = _lease_seconds(lease_seconds)

    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.work_item_id != work_item_id
            or existing.event_type != "WORK_CLAIM_RENEWED"
            or str(existing.payload.get("actor")) != normalized_actor
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, work_item_id)

    row = _lock_work_item(session, work_item_id)
    view = get_work_item(session, row.id)
    if view.state is not WorkState.IN_PROGRESS:
        raise DomainError("claim can be renewed only while IN_PROGRESS")
    if view.implementer != normalized_actor:
        raise DomainError("only the current implementer can renew the claim")
    if view.claim_lease_id is None or view.claim_expires_at is None:
        raise RuntimeError("active work claim is missing lease identity")

    lease_expires_at = (_utcnow() + timedelta(seconds=lease_seconds)).isoformat()
    _append(
        session,
        row,
        event_type="WORK_CLAIM_RENEWED",
        idempotency_key=idempotency_key,
        payload={
            "actor": normalized_actor,
            "lease_id": view.claim_lease_id,
            "lease_expires_at": lease_expires_at,
        },
    )
    session.commit()
    return get_work_item(session, row.id)


def release_claim(
    session: Session,
    work_item_id: str,
    *,
    actor: str,
    reason: str,
    idempotency_key: str,
) -> WorkItemView:
    payload = {
        "actor": _safe_text(actor, "actor", 200),
        "reason": _safe_text(reason, "reason", 1000),
    }
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.work_item_id != work_item_id
            or existing.event_type != "WORK_CLAIM_RELEASED"
            or _canonical(existing.payload) != _canonical(payload)
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, work_item_id)

    row = _lock_work_item(session, work_item_id)
    view = get_work_item(session, row.id)
    if view.state is not WorkState.IN_PROGRESS:
        raise DomainError("claim can be released only from IN_PROGRESS")
    if view.implementer != payload["actor"]:
        raise DomainError("only the current implementer can release the claim")
    _append(
        session,
        row,
        event_type="WORK_CLAIM_RELEASED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_item(session, row.id)


def submit_work_implementation(
    session: Session,
    work_item_id: str,
    *,
    actor: str,
    summary: str,
    evidence_sha256: str,
    idempotency_key: str,
) -> WorkItemView:
    evidence = evidence_sha256.lower()
    if not _EVIDENCE_RE.fullmatch(evidence):
        raise DomainError("implementation evidence must be a 64-hex SHA-256")
    payload = {
        "actor": _safe_text(actor, "actor", 200),
        "summary": _safe_text(summary, "summary", 4000),
        "evidence_sha256": evidence,
    }
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.work_item_id != work_item_id
            or existing.event_type != "WORK_IMPLEMENTATION_COMPLETED"
            or _canonical(existing.payload) != _canonical(payload)
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, work_item_id)

    row = _lock_work_item(session, work_item_id)
    view = get_work_item(session, row.id)
    if view.state is not WorkState.IN_PROGRESS:
        raise DomainError("implementation requires IN_PROGRESS work")
    if view.implementer != payload["actor"]:
        raise DomainError("implementation actor is not the current implementer")
    _append(
        session,
        row,
        event_type="WORK_IMPLEMENTATION_COMPLETED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_item(session, row.id)


def complete_work_item(
    session: Session,
    work_item_id: str,
    *,
    actor: str,
    evidence: str,
    idempotency_key: str,
) -> WorkItemView:
    payload = {
        "actor": _safe_text(actor, "actor", 200),
        "evidence": _safe_text(evidence, "evidence", 4000),
    }
    existing = _event_by_idempotency(session, idempotency_key)
    if existing is not None:
        if (
            existing.work_item_id != work_item_id
            or existing.event_type != "WORK_COMPLETED"
            or _canonical(existing.payload) != _canonical(payload)
        ):
            raise DomainError("idempotency key was already used for another work command")
        return get_work_item(session, work_item_id)

    row = _lock_work_item(session, work_item_id)
    view = get_work_item(session, row.id)
    if view.state is WorkState.DONE:
        raise DomainError("work item is already complete")
    if view.state is not WorkState.REVIEW:
        raise DomainError("work item can complete only from REVIEW")
    _append(
        session,
        row,
        event_type="WORK_COMPLETED",
        idempotency_key=idempotency_key,
        payload=payload,
    )
    session.commit()
    return get_work_item(session, row.id)
