from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .domain import EventType
from .models import EventRow, PublicationRow

ZERO_HASH = "0" * 64


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_event_hash(
    publication_id: str,
    sequence: int,
    event_type: str,
    payload: Mapping[str, Any],
    previous_hash: str,
) -> str:
    preimage = canonical_json({
        "publication_id": publication_id,
        "sequence": sequence,
        "event_type": event_type,
        "payload": payload,
        "previous_hash": previous_hash,
    }).encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()
def append_event(
    session: Session,
    publication_id: str,
    event_type: EventType,
    payload: Mapping[str, Any],
) -> EventRow:
    publication = session.scalar(
        select(PublicationRow)
        .where(PublicationRow.id == publication_id)
        .with_for_update()
    )
    if publication is None:
        raise KeyError(publication_id)
    last = session.scalar(
        select(EventRow)
        .where(EventRow.publication_id == publication_id)
        .order_by(EventRow.sequence.desc())
        .limit(1)
    )
    sequence = 1 if last is None else last.sequence + 1
    previous_hash = ZERO_HASH if last is None else last.event_hash
    normalized = dict(payload)
    digest = compute_event_hash(
        publication_id,
        sequence,
        event_type.value,
        normalized,
        previous_hash,
    )
    row = EventRow(
        publication_id=publication_id,
        sequence=sequence,
        event_type=event_type.value,
        payload=normalized,
        previous_hash=previous_hash,
        event_hash=digest,
    )
    session.add(row)
    session.flush()
    return row
def load_events(session: Session, publication_id: str) -> list[dict[str, Any]]:
    rows = list(
        session.scalars(
            select(EventRow)
            .where(EventRow.publication_id == publication_id)
            .order_by(EventRow.sequence.asc())
        )
    )
    previous = ZERO_HASH
    events: list[dict[str, Any]] = []
    for expected_sequence, row in enumerate(rows, start=1):
        if row.sequence != expected_sequence:
            raise RuntimeError("event sequence gap detected")
        if row.previous_hash != previous:
            raise RuntimeError("event previous-hash mismatch")
        expected_hash = compute_event_hash(
            publication_id,
            row.sequence,
            row.event_type,
            row.payload,
            row.previous_hash,
        )
        if row.event_hash != expected_hash:
            raise RuntimeError("event hash mismatch")
        events.append({
            "sequence": row.sequence,
            "event_type": row.event_type,
            "payload": row.payload,
            "previous_hash": row.previous_hash,
            "event_hash": row.event_hash,
            "occurred_at": row.occurred_at.isoformat(),
        })
        previous = row.event_hash
    return events
