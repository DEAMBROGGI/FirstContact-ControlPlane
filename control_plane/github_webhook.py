from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .domain import AutomatedReviewStatus, DomainError, PublicationState
from .models import GitHubWebhookDeliveryRow, PublicationRow, ReviewWatchRow
from .profile_registry import profile_for_repository
from .service import get_view, required_review_adjudication

_SUPPORTED_EVENTS = frozenset(
    {
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "pull_request",
        "push",
        "check_run",
        "status",
    }
)
_DELIVERY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
_EVENT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_SHA256_SIGNATURE_RE = re.compile(r"^sha256=([0-9a-f]{64})$")


class GitHubWebhookError(RuntimeError):
    pass


class GitHubWebhookAuthError(GitHubWebhookError):
    pass


@dataclass(frozen=True, slots=True)
class WebhookDeliveryView:
    delivery_id: str
    body_sha256: str
    event_name: str
    action: str | None
    repository: str
    pull_request_number: int | None
    state: str
    attempt_count: int
    last_error: str | None
    received_at: str
    processed_at: str | None


@dataclass(frozen=True, slots=True)
class ReviewWatchView:
    publication_id: str
    repository: str
    pull_request_number: int
    watched_head_sha: str
    review_run_id: str | None
    provider: str | None
    trigger_comment_id: int | None
    expected_actors: tuple[str, ...]
    state: str
    next_role: str
    next_action: str
    last_delivery_id: str | None
    last_reconciled_at: str | None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_actor(value: str) -> str:
    return value.strip().lower()


def _delivery_view(row: GitHubWebhookDeliveryRow) -> WebhookDeliveryView:
    return WebhookDeliveryView(
        delivery_id=row.delivery_id,
        body_sha256=row.body_sha256,
        event_name=row.event_name,
        action=row.action,
        repository=row.repository,
        pull_request_number=row.pull_request_number,
        state=row.state,
        attempt_count=row.attempt_count,
        last_error=row.last_error,
        received_at=row.received_at.isoformat(),
        processed_at=row.processed_at.isoformat() if row.processed_at else None,
    )


def _watch_view(row: ReviewWatchRow) -> ReviewWatchView:
    return ReviewWatchView(
        publication_id=row.publication_id,
        repository=row.repository,
        pull_request_number=row.pull_request_number,
        watched_head_sha=row.watched_head_sha,
        review_run_id=row.review_run_id,
        provider=row.provider,
        trigger_comment_id=row.trigger_comment_id,
        expected_actors=tuple(str(item) for item in (row.expected_actors or [])),
        state=row.state,
        next_role=row.next_role,
        next_action=row.next_action,
        last_delivery_id=row.last_delivery_id,
        last_reconciled_at=(
            row.last_reconciled_at.isoformat()
            if row.last_reconciled_at is not None
            else None
        ),
    )


def webhook_payload(payload: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if maximum_bytes <= 0:
        raise GitHubWebhookError("webhook payload limit must be positive")
    if not payload or len(payload) > maximum_bytes:
        raise GitHubWebhookError("GitHub webhook payload is empty or exceeds the limit")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubWebhookError("GitHub webhook payload is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise GitHubWebhookError("GitHub webhook payload root must be an object")
    return parsed


def verify_webhook_signature(
    payload: bytes,
    signature: str | None,
    *,
    secret: str,
) -> None:
    if not secret:
        raise GitHubWebhookAuthError("GitHub webhook secret is not configured")
    raw = (signature or "").strip().lower()
    match = _SHA256_SIGNATURE_RE.fullmatch(raw)
    if match is None:
        raise GitHubWebhookAuthError("GitHub webhook signature is missing or invalid")
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(match.group(1), expected):
        raise GitHubWebhookAuthError("GitHub webhook signature did not verify")


def _repository_from_payload(payload: Mapping[str, Any]) -> str:
    repository = payload.get("repository")
    if not isinstance(repository, Mapping):
        raise GitHubWebhookError("GitHub webhook repository identity is missing")
    full_name = str(repository.get("full_name") or "").strip()
    if "/" not in full_name or len(full_name) > 200:
        raise GitHubWebhookError("GitHub webhook repository identity is invalid")
    # Registration/profile lookup is the repository allowlist.
    profile_for_repository(full_name)
    return full_name


def _pull_request_number(payload: Mapping[str, Any]) -> int | None:
    pull = payload.get("pull_request")
    if isinstance(pull, Mapping):
        try:
            number = int(pull.get("number"))
        except (TypeError, ValueError):
            number = 0
        if number > 0:
            return number

    issue = payload.get("issue")
    if isinstance(issue, Mapping) and isinstance(issue.get("pull_request"), Mapping):
        try:
            number = int(issue.get("number"))
        except (TypeError, ValueError):
            number = 0
        if number > 0:
            return number
    return None


def persist_webhook_delivery(
    session: Session,
    *,
    delivery_id: str,
    event_name: str,
    signature: str | None,
    body: bytes,
    secret: str,
    maximum_bytes: int,
) -> WebhookDeliveryView:
    """Persist one verified delivery before any publication/domain processing."""

    verify_webhook_signature(body, signature, secret=secret)
    payload = webhook_payload(body, maximum_bytes=maximum_bytes)

    normalized_delivery = delivery_id.strip()
    normalized_event = event_name.strip()
    if _DELIVERY_RE.fullmatch(normalized_delivery) is None:
        raise GitHubWebhookError("GitHub delivery id is missing or invalid")
    if _EVENT_RE.fullmatch(normalized_event) is None:
        raise GitHubWebhookError("GitHub event name is missing or invalid")

    repository = _repository_from_payload(payload)
    action_value = payload.get("action")
    action = None if action_value is None else str(action_value).strip()[:80] or None
    pull_number = _pull_request_number(payload)
    digest = hashlib.sha256(body).hexdigest()

    existing = session.get(GitHubWebhookDeliveryRow, normalized_delivery)
    if existing is not None:
        same = (
            existing.body_sha256 == digest
            and existing.event_name == normalized_event
            and existing.repository == repository
            and existing.action == action
            and existing.pull_request_number == pull_number
            and existing.payload == payload
        )
        if not same:
            raise DomainError("GitHub delivery id was reused with conflicting evidence")
        session.commit()
        return _delivery_view(existing)

    row = GitHubWebhookDeliveryRow(
        delivery_id=normalized_delivery,
        body_sha256=digest,
        event_name=normalized_event,
        action=action,
        repository=repository,
        pull_request_number=pull_number,
        payload=payload,
        state="PENDING" if normalized_event in _SUPPORTED_EVENTS else "IGNORED",
        attempt_count=0,
        last_error=None,
        processed_at=None,
    )
    session.add(row)
    session.commit()
    return _delivery_view(row)


def get_webhook_delivery(session: Session, delivery_id: str) -> WebhookDeliveryView:
    row = session.get(GitHubWebhookDeliveryRow, delivery_id)
    if row is None:
        raise KeyError(delivery_id)
    return _delivery_view(row)


def list_pending_delivery_ids(session: Session) -> tuple[str, ...]:
    return tuple(
        session.scalars(
            select(GitHubWebhookDeliveryRow.delivery_id)
            .where(GitHubWebhookDeliveryRow.state == "PENDING")
            .order_by(GitHubWebhookDeliveryRow.received_at, GitHubWebhookDeliveryRow.delivery_id)
        )
    )


def _derive_next(session: Session, publication_id: str) -> tuple[str, str]:
    view = get_view(session, publication_id)

    if view.state is PublicationState.MERGED:
        return "NONE", "DONE"
    if view.merge_policy_violation:
        return "CONTROL_PLANE", "BLOCKED"
    if view.state is PublicationState.READY_TO_MERGE:
        return "CONTROL_PLANE", "MERGE"
    if view.state is PublicationState.APPROVED:
        return "CONTROL_PLANE", "CHECK_MERGEABILITY"
    if view.state is PublicationState.CHANGES_REQUIRED:
        return "IMPLEMENTER", "REMEDIATE_FINDINGS"

    adjudication = required_review_adjudication(session, publication_id)
    if adjudication is not None:
        return "HUMAN_REVIEWER", "WAIT_HUMAN_REVIEW"

    if view.automated_review_status is AutomatedReviewStatus.RUNNING:
        return "PROVIDER", "WAIT_PROVIDER"
    if view.automated_review_status is AutomatedReviewStatus.UNAVAILABLE:
        return "PRINCIPAL_REVIEWER", "PRINCIPAL_FALLBACK"
    if view.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED:
        return "IMPLEMENTER", "REMEDIATE_FINDINGS"
    if view.automated_review_status is AutomatedReviewStatus.PASS:
        return "HUMAN_REVIEWER", "WAIT_HUMAN_REVIEW"
    if view.state is PublicationState.IN_REVIEW:
        return "PROVIDER", "WAIT_PROVIDER"
    return "CONTROL_PLANE", "BLOCKED"


def sync_review_watch(
    session: Session,
    publication_id: str,
    *,
    expected_actors: tuple[str, ...] = (),
    last_delivery_id: str | None = None,
    state: str | None = None,
) -> ReviewWatchView:
    view = get_view(session, publication_id)
    if (
        view.pull_request_number is None
        or view.remote_head_sha is None
        or view.remote_branch is None
    ):
        raise DomainError("review watch requires published PR metadata")

    actors = tuple(
        sorted(
            {
                _normalize_actor(actor)
                for actor in expected_actors
                if actor.strip()
            }
        )
    )
    next_role, next_action = _derive_next(session, publication_id)
    provider = "CODEX" if view.automated_review_run_id is not None else None

    row = session.get(ReviewWatchRow, publication_id)
    if row is None:
        row = ReviewWatchRow(
            publication_id=publication_id,
            repository=view.repository,
            pull_request_number=view.pull_request_number,
            watched_head_sha=view.remote_head_sha,
            review_run_id=view.automated_review_run_id,
            provider=provider,
            trigger_comment_id=view.automated_review_trigger_comment_id,
            expected_actors=list(actors),
            state=state or ("DONE" if view.state is PublicationState.MERGED else "ACTIVE"),
            next_role=next_role,
            next_action=next_action,
            last_delivery_id=last_delivery_id,
            last_reconciled_at=_utcnow(),
        )
        session.add(row)
    else:
        if row.repository != view.repository or row.pull_request_number != view.pull_request_number:
            raise DomainError("review watch identity conflicts with publication")
        head_changed = row.watched_head_sha != view.remote_head_sha
        row.watched_head_sha = view.remote_head_sha
        row.review_run_id = view.automated_review_run_id
        row.provider = provider
        row.trigger_comment_id = view.automated_review_trigger_comment_id
        if actors:
            row.expected_actors = list(actors)
        if state is not None:
            row.state = state
        elif head_changed:
            row.state = "ACTIVE"
        elif view.state is PublicationState.MERGED:
            row.state = "DONE"
        row.next_role = next_role
        row.next_action = next_action
        if last_delivery_id is not None:
            row.last_delivery_id = last_delivery_id
        row.last_reconciled_at = _utcnow()

    session.commit()
    return _watch_view(row)


def get_review_watch(session: Session, publication_id: str) -> ReviewWatchView:
    row = session.get(ReviewWatchRow, publication_id)
    if row is None:
        raise KeyError(publication_id)
    return _watch_view(row)


def publication_for_pull(
    session: Session,
    repository: str,
    pull_request_number: int,
) -> str | None:
    if pull_request_number <= 0:
        return None
    candidates: list[str] = []
    rows = list(
        session.scalars(
            select(PublicationRow)
            .where(PublicationRow.repository == repository)
            .order_by(PublicationRow.created_at.desc())
        )
    )
    for row in rows:
        view = get_view(session, row.id)
        if view.pull_request_number == pull_request_number:
            candidates.append(row.id)
    if len(candidates) > 1:
        raise DomainError("multiple publications are bound to the same canonical PR")
    return candidates[0] if candidates else None


def delivery_payload(session: Session, delivery_id: str) -> dict[str, Any]:
    row = session.get(GitHubWebhookDeliveryRow, delivery_id)
    if row is None:
        raise KeyError(delivery_id)
    return dict(row.payload)


def mark_delivery_processed(
    session: Session,
    delivery_id: str,
    *,
    state: str = "PROCESSED",
    error: str | None = None,
) -> WebhookDeliveryView:
    row = session.get(GitHubWebhookDeliveryRow, delivery_id)
    if row is None:
        raise KeyError(delivery_id)
    row.attempt_count += 1
    row.state = state
    row.last_error = error[:1000] if error else None
    row.processed_at = _utcnow() if state in {"PROCESSED", "IGNORED"} else None
    session.commit()
    return _delivery_view(row)


def mark_delivery_retry(
    session: Session,
    delivery_id: str,
    error: str,
) -> WebhookDeliveryView:
    row = session.get(GitHubWebhookDeliveryRow, delivery_id)
    if row is None:
        raise KeyError(delivery_id)
    row.attempt_count += 1
    row.state = "PENDING"
    row.last_error = error[:1000]
    session.commit()
    return _delivery_view(row)


def watch_payload(view: ReviewWatchView) -> dict[str, Any]:
    return asdict(view)
