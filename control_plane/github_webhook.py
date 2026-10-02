from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Mapping

from sqlalchemy import and_, event, or_, select, text, update
from sqlalchemy.orm import Session

from .codex_review import (
    CodexReviewBroker,
    CodexReviewError,
    assert_no_ambiguous_codex_invocations,
)
from .domain import (
    AutomatedReviewStatus,
    DomainError,
    EventType,
    PublicationState,
    ReviewDecision,
)
from .github_api import GitHubApiError, GitHubRepositoryGateway, PullRequestSnapshot
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .merge import MergeCoordinator, MergeError, MergePolicyViolationRecorded
from .models import (
    GitHubWebhookDeliveryClaimRow,
    GitHubWebhookDeliveryRow,
    PublicationRow,
    ReviewWatchRow,
)
from .profile_registry import ProfileError, profile_for_repository
from .repository import load_events
from .service import (
    clear_human_review_block,
    get_view,
    record_mergeability,
    record_review,
    required_review_adjudication,
)

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
_BLOCKED_WATCH_STATES = frozenset({"STALE", "CLOSED_UNMERGED"})
_DELIVERY_CLAIM_LEASE_SECONDS = 300
_DELIVERY_CLAIM_SESSION_KEY = "github_webhook_delivery_claim"
_DELIVERY_CLAIM_RELEASE_KEY = "github_webhook_delivery_claim_release"


class GitHubWebhookError(RuntimeError):
    pass


class GitHubWebhookAuthError(GitHubWebhookError):
    pass


class GitHubWebhookDeliveryClaimLost(RuntimeError):
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


def _lock_delivery_scope(session: Session, delivery_id: str) -> None:
    """Serialize first-write/replay decisions for one GitHub delivery id."""

    if session.get_bind().dialect.name != "postgresql":
        return
    key = hashlib.sha256(
        ("firstcontact-github-webhook-delivery\0" + delivery_id).encode("utf-8")
    ).digest()[:8]
    lock_key = int.from_bytes(key, byteorder="big", signed=True)
    session.execute(
        text("SELECT pg_advisory_xact_lock(:webhook_delivery_key)"),
        {"webhook_delivery_key": lock_key},
    )


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
    try:
        profile_for_repository(full_name)
    except ProfileError as exc:
        raise GitHubWebhookError("GitHub webhook repository is not registered") from exc
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

    check_run = payload.get("check_run")
    if isinstance(check_run, Mapping):
        pull_requests = check_run.get("pull_requests")
        if isinstance(pull_requests, list):
            numbers: set[int] = set()
            for pull in pull_requests:
                if not isinstance(pull, Mapping):
                    continue
                try:
                    number = int(pull.get("number"))
                except (TypeError, ValueError):
                    continue
                if number > 0:
                    numbers.add(number)
            if len(numbers) == 1:
                return next(iter(numbers))
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

    if maximum_bytes <= 0:
        raise GitHubWebhookError("webhook payload limit must be positive")
    if not body or len(body) > maximum_bytes:
        raise GitHubWebhookError("GitHub webhook payload is empty or exceeds the limit")
    verify_webhook_signature(body, signature, secret=secret)
    payload = webhook_payload(body, maximum_bytes=maximum_bytes)

    normalized_delivery = delivery_id.strip()
    normalized_event = event_name.strip()
    if _DELIVERY_RE.fullmatch(normalized_delivery) is None:
        raise GitHubWebhookError("GitHub delivery id is missing or invalid")
    if _EVENT_RE.fullmatch(normalized_event) is None:
        raise GitHubWebhookError("GitHub event name is missing or invalid")

    _lock_delivery_scope(session, normalized_delivery)

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
    session.add(
        GitHubWebhookDeliveryClaimRow(
            delivery_id=normalized_delivery,
            owner_id=None,
            generation=0,
            lease_expires_at=None,
        )
    )
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


def list_pending_delivery_ids_for_startup(
    session: Session,
    *,
    limit: int,
) -> tuple[str, ...]:
    return tuple(
        session.scalars(
            select(GitHubWebhookDeliveryRow.delivery_id)
            .where(GitHubWebhookDeliveryRow.state == "PENDING")
            .order_by(
                GitHubWebhookDeliveryRow.attempt_count,
                GitHubWebhookDeliveryRow.received_at,
                GitHubWebhookDeliveryRow.delivery_id,
            )
            .limit(limit)
        )
    )


def _derive_next(
    session: Session,
    publication_id: str,
    *,
    codex_review_mode: str = "required",
) -> tuple[str, str]:
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
        if codex_review_mode.strip().lower() == "advisory":
            return "HUMAN_REVIEWER", "WAIT_HUMAN_REVIEW"
        return "IMPLEMENTER", "REMEDIATE_FINDINGS"
    if view.automated_review_status is AutomatedReviewStatus.PASS:
        return "HUMAN_REVIEWER", "WAIT_HUMAN_REVIEW"
    if view.state is PublicationState.IN_REVIEW:
        if (
            codex_review_mode.strip().lower() == "disabled"
            and view.automated_review_run_id is None
        ):
            return "HUMAN_REVIEWER", "WAIT_HUMAN_REVIEW"
        return "PROVIDER", "WAIT_PROVIDER"
    return "CONTROL_PLANE", "BLOCKED"


def _governed_watch_generation_advanced(
    session: Session,
    publication_id: str,
    *,
    watched_head_sha: str,
    remote_head_sha: str,
) -> bool:
    """Return whether verified REMOTE_PUBLISHED events advance this watch.

    The event chain must terminate at the current governed remote head.
    """
    current_head = watched_head_sha
    advanced = False
    for event in load_events(session, publication_id):
        if event["event_type"] != EventType.REMOTE_PUBLISHED.value:
            continue
        payload = event["payload"]
        published_head = payload.get("head_sha")
        if (
            payload.get("previous_head_sha") == current_head
            and isinstance(published_head, str)
            and published_head != current_head
        ):
            current_head = published_head
            advanced = True
    return advanced and current_head == remote_head_sha


def sync_review_watch(
    session: Session,
    publication_id: str,
    *,
    expected_actors: tuple[str, ...] = (),
    last_delivery_id: str | None = None,
    state: str | None = None,
    codex_review_mode: str = "required",
    reactivate_closed_unmerged: bool = False,
) -> ReviewWatchView:
    if reactivate_closed_unmerged:
        session.scalar(
            select(PublicationRow)
            .where(PublicationRow.id == publication_id)
            .with_for_update()
        )
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
    if reactivate_closed_unmerged:
        row = session.scalar(
            select(ReviewWatchRow)
            .where(ReviewWatchRow.publication_id == publication_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    else:
        row = session.get(ReviewWatchRow, publication_id)
    generation_advanced = bool(
        row is not None
        and row.watched_head_sha != view.remote_head_sha
        and _governed_watch_generation_advanced(
            session,
            publication_id,
            watched_head_sha=row.watched_head_sha,
            remote_head_sha=view.remote_head_sha,
        )
    )
    if state is not None:
        effective_state = state
    elif (
        reactivate_closed_unmerged
        and row is not None
        and row.state == "CLOSED_UNMERGED"
        and row.watched_head_sha == view.remote_head_sha
        and not view.merge_policy_violation
    ):
        effective_state = "ACTIVE"
    else:
        effective_state = (
            None
            if generation_advanced
            else (row.state if row is not None else None)
        )
    if view.state is PublicationState.MERGED:
        next_role, next_action = _derive_next(
            session,
            publication_id,
            codex_review_mode=codex_review_mode,
        )
    elif effective_state in _BLOCKED_WATCH_STATES:
        next_role, next_action = "CONTROL_PLANE", "BLOCKED"
    else:
        next_role, next_action = _derive_next(
            session,
            publication_id,
            codex_review_mode=codex_review_mode,
        )
    provider = "CODEX" if view.automated_review_run_id is not None else None

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
            state=effective_state or ("DONE" if view.state is PublicationState.MERGED else "ACTIVE"),
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
        row.expected_actors = list(actors)
        if state is not None:
            row.state = state
        elif (
            reactivate_closed_unmerged
            and effective_state == "ACTIVE"
            and row.state == "CLOSED_UNMERGED"
        ):
            row.state = "ACTIVE"
        elif head_changed:
            # A prior generation stays stale unless the append-only publication
            # history proves that Plane governed and published this new head.
            row.state = (
                "ACTIVE"
                if generation_advanced or effective_state not in _BLOCKED_WATCH_STATES
                else effective_state
            )
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
    claim = _current_delivery_claim(session, delivery_id)
    if claim is None:
        raise GitHubWebhookDeliveryClaimLost(
            "only the active webhook delivery owner may finalize a receipt"
        )
    if state not in {"PROCESSED", "IGNORED"}:
        raise GitHubWebhookError("webhook delivery terminal state is invalid")
    _renew_delivery_claim(session, claim)
    row = session.get(GitHubWebhookDeliveryRow, delivery_id)
    if row is None:
        raise KeyError(delivery_id)
    if row.state in {"PROCESSED", "IGNORED"}:
        return _delivery_view(row)
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
    if row.state in {"PROCESSED", "IGNORED"}:
        raise GitHubWebhookError("a terminal webhook delivery cannot be retried")
    claim = _current_delivery_claim(session, delivery_id)
    now = _utcnow()
    claim_update = update(GitHubWebhookDeliveryClaimRow).where(
        GitHubWebhookDeliveryClaimRow.delivery_id == delivery_id
    )
    if claim is not None:
        claim_update = claim_update.where(
            GitHubWebhookDeliveryClaimRow.owner_id == claim.owner_id,
            GitHubWebhookDeliveryClaimRow.generation == claim.generation,
            GitHubWebhookDeliveryClaimRow.lease_expires_at > now,
        )
    else:
        claim_update = claim_update.where(
            or_(
                and_(
                    GitHubWebhookDeliveryClaimRow.owner_id.is_(None),
                    GitHubWebhookDeliveryClaimRow.lease_expires_at.is_(None),
                ),
                and_(
                    GitHubWebhookDeliveryClaimRow.owner_id.is_not(None),
                    GitHubWebhookDeliveryClaimRow.lease_expires_at.is_not(None),
                    GitHubWebhookDeliveryClaimRow.lease_expires_at <= now,
                ),
            )
        )
    result = session.execute(
        claim_update.values(owner_id=None, lease_expires_at=None)
    )
    if result.rowcount != 1:
        raise GitHubWebhookDeliveryClaimLost(
            "retry cannot release a webhook delivery owned by another worker"
        )
    if claim is not None:
        session.info[_DELIVERY_CLAIM_RELEASE_KEY] = delivery_id
    row.attempt_count += 1
    row.state = "PENDING"
    row.last_error = error[:1000]
    row.processed_at = None
    try:
        session.commit()
    finally:
        if claim is not None:
            session.info.pop(_DELIVERY_CLAIM_RELEASE_KEY, None)
    return _delivery_view(row)


def watch_payload(view: ReviewWatchView) -> dict[str, Any]:
    return asdict(view)


class GitHubWebhookDeferred(GitHubWebhookError):
    """Evidence is valid but a prerequisite is not yet authoritative."""


@dataclass(frozen=True, slots=True)
class WebhookProcessResult:
    delivery_id: str | None
    publication_id: str | None
    outcome: str
    next_role: str
    next_action: str
    watch_state: str | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class WebhookDeliveryClaim:
    delivery_id: str
    owner_id: str
    generation: int


def _current_delivery_claim(
    session: Session,
    delivery_id: str,
) -> WebhookDeliveryClaim | None:
    claim = session.info.get(_DELIVERY_CLAIM_SESSION_KEY)
    if isinstance(claim, WebhookDeliveryClaim) and claim.delivery_id == delivery_id:
        return claim
    return None


def _renew_delivery_claim(
    session: Session,
    claim: WebhookDeliveryClaim,
) -> None:
    now = _utcnow()
    result = session.execute(
        update(GitHubWebhookDeliveryClaimRow)
        .where(
            GitHubWebhookDeliveryClaimRow.delivery_id == claim.delivery_id,
            GitHubWebhookDeliveryClaimRow.owner_id == claim.owner_id,
            GitHubWebhookDeliveryClaimRow.generation == claim.generation,
            GitHubWebhookDeliveryClaimRow.lease_expires_at > now,
        )
        .values(
            lease_expires_at=now
            + timedelta(seconds=_DELIVERY_CLAIM_LEASE_SECONDS)
        )
    )
    if result.rowcount != 1:
        raise GitHubWebhookDeliveryClaimLost(
            "webhook delivery processing claim expired or was fenced"
        )


def _acquire_delivery_claim(
    session: Session,
    delivery_id: str,
) -> WebhookDeliveryClaim | None:
    owner_id = str(uuid.uuid4())
    now = _utcnow()
    result = session.execute(
        update(GitHubWebhookDeliveryClaimRow)
        .where(
            GitHubWebhookDeliveryClaimRow.delivery_id == delivery_id,
            or_(
                and_(
                    GitHubWebhookDeliveryClaimRow.owner_id.is_(None),
                    GitHubWebhookDeliveryClaimRow.lease_expires_at.is_(None),
                ),
                and_(
                    GitHubWebhookDeliveryClaimRow.owner_id.is_not(None),
                    GitHubWebhookDeliveryClaimRow.lease_expires_at.is_not(None),
                    GitHubWebhookDeliveryClaimRow.lease_expires_at <= now,
                ),
            ),
        )
        .values(
            owner_id=owner_id,
            generation=GitHubWebhookDeliveryClaimRow.generation + 1,
            lease_expires_at=now
            + timedelta(seconds=_DELIVERY_CLAIM_LEASE_SECONDS),
        )
    )
    if result.rowcount != 1:
        session.rollback()
        return None
    generation = session.scalar(
        select(GitHubWebhookDeliveryClaimRow.generation).where(
            GitHubWebhookDeliveryClaimRow.delivery_id == delivery_id,
            GitHubWebhookDeliveryClaimRow.owner_id == owner_id,
        )
    )
    if generation is None:
        session.rollback()
        raise GitHubWebhookDeliveryClaimLost(
            "webhook delivery claim readback is incomplete"
        )
    session.commit()
    return WebhookDeliveryClaim(
        delivery_id=delivery_id,
        owner_id=owner_id,
        generation=int(generation),
    )


def _processing_delivery_result(delivery_id: str) -> WebhookProcessResult:
    return WebhookProcessResult(
        delivery_id=delivery_id,
        publication_id=None,
        outcome="PROCESSING",
        next_role="CONTROL_PLANE",
        next_action="RETRY",
        watch_state=None,
    )


def _claim_delivery_processing(method):
    @wraps(method)
    def wrapped(gateway, session: Session, delivery_id: str):
        row = session.get(GitHubWebhookDeliveryRow, delivery_id)
        if row is None or row.state in {"PROCESSED", "IGNORED"}:
            return method(gateway, session, delivery_id)

        current_claim = session.info.get(_DELIVERY_CLAIM_SESSION_KEY)
        if isinstance(current_claim, WebhookDeliveryClaim):
            if current_claim.delivery_id == delivery_id:
                return _processing_delivery_result(delivery_id)
            raise GitHubWebhookError(
                "one database session cannot process multiple webhook deliveries"
            )

        claim = _acquire_delivery_claim(session, delivery_id)
        if claim is None:
            session.expire_all()
            latest = session.get(GitHubWebhookDeliveryRow, delivery_id)
            if latest is not None and latest.state in {"PROCESSED", "IGNORED"}:
                return method(gateway, session, delivery_id)
            return _processing_delivery_result(delivery_id)

        session.info[_DELIVERY_CLAIM_SESSION_KEY] = claim

        def renew_before_commit(active_session: Session) -> None:
            if active_session.info.get(_DELIVERY_CLAIM_RELEASE_KEY) == delivery_id:
                return
            if active_session.info.get(_DELIVERY_CLAIM_SESSION_KEY) == claim:
                _renew_delivery_claim(active_session, claim)

        event.listen(session, "before_commit", renew_before_commit)
        try:
            return method(gateway, session, delivery_id)
        except GitHubWebhookDeliveryClaimLost:
            session.rollback()
            return _processing_delivery_result(delivery_id)
        finally:
            event.remove(session, "before_commit", renew_before_commit)
            if session.info.get(_DELIVERY_CLAIM_SESSION_KEY) == claim:
                session.info.pop(_DELIVERY_CLAIM_SESSION_KEY, None)
            session.info.pop(_DELIVERY_CLAIM_RELEASE_KEY, None)

    return wrapped


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubWebhookError("GitHub evidence timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _required_adjudication_time(
    session: Session,
    publication_id: str,
    adjudication: Mapping[str, Any],
) -> datetime:
    kind = adjudication.get("kind")
    run_id = adjudication.get("codex_run_id")
    head_sha = adjudication.get("head_sha")

    def matches(event: Mapping[str, Any]) -> bool:
        payload = event["payload"]
        if kind == "CODEX_PASS":
            return (
                event["event_type"] == EventType.CODEX_REVIEW_COMPLETED.value
                and payload.get("run_id") == run_id
                and payload.get("head_sha") == head_sha
                and payload.get("result") == AutomatedReviewStatus.PASS.value
            )
        if kind == "REMEDIATION_CLEARED":
            return (
                event["event_type"] == EventType.REMEDIATION_CLEARED.value
                and payload.get("run_id") == run_id
                and payload.get("head_sha") == head_sha
            )
        if kind == "PLANE_FALLBACK":
            return (
                event["event_type"] == EventType.PLANE_REVIEW_MATERIALIZED.value
                and payload.get("run_id") == adjudication.get("plane_run_id")
                and payload.get("head_sha") == head_sha
                and payload.get("provider") == "PLANE_REVIEW"
                and payload.get("reviewer_kind") == "FALLBACK_REVIEWER"
                and payload.get("reviewer") == adjudication.get("plane_reviewer")
                and payload.get("result") == "PASS"
                and payload.get("findings_count") == 0
                and payload.get("findings") == []
                and payload.get("provider_review_ids")
                == [adjudication.get("provider_review_id")]
                and payload.get("provider_comment_ids") == []
            )
        return False

    events = [
        event
        for event in load_events(session, publication_id)
        if matches(event)
    ]
    if len(events) != 1:
        raise GitHubWebhookError(
            "required review adjudication timestamp is missing or ambiguous"
        )
    adjudicated_at = _parse_time(events[0].get("occurred_at"))
    if kind == "CODEX_PASS":
        provider_time = events[0]["payload"].get("provider_completed_at")
        if not isinstance(provider_time, str) or not provider_time.strip():
            raise GitHubWebhookError(
                "Codex provider completion timestamp is missing"
            )
        adjudicated_at = _parse_time(provider_time)
    if adjudicated_at is None:
        raise GitHubWebhookError("required review adjudication timestamp is missing")
    return adjudicated_at


def _issue_comment_id(row: GitHubWebhookDeliveryRow) -> int | None:
    raw_comment = row.payload.get("comment")
    if not isinstance(raw_comment, Mapping):
        return None
    try:
        comment_id = int(raw_comment.get("id"))
    except (TypeError, ValueError):
        return None
    return comment_id if comment_id > 0 else None


class GitHubWebhookGateway:
    """Durable wake-up gateway that always re-reads GitHub before domain mutation."""

    def __init__(
        self,
        *,
        token_provider: GitHubAppTokenProvider,
        github: GitHubRepositoryGateway,
        codex_review_mode: str,
        codex_actors: tuple[str, ...],
        human_review_actors: tuple[str, ...],
        webhook_secret: str | None,
        maximum_payload_bytes: int,
    ) -> None:
        self.token_provider = token_provider
        self.github = github
        self.codex_review_mode = codex_review_mode.strip().lower()
        self.codex_actors = tuple(
            sorted({_normalize_actor(value) for value in codex_actors if value.strip()})
        )
        self.human_review_actors = tuple(
            sorted({_normalize_actor(value) for value in human_review_actors if value.strip()})
        )
        self.webhook_secret = webhook_secret
        self.maximum_payload_bytes = maximum_payload_bytes

    @property
    def expected_actors(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.codex_actors) | set(self.human_review_actors)))

    def _sync_review_watch(
        self,
        session: Session,
        publication_id: str,
        *,
        expected_actors: tuple[str, ...] = (),
        last_delivery_id: str | None = None,
        state: str | None = None,
        reactivate_closed_unmerged: bool = False,
    ) -> ReviewWatchView:
        return sync_review_watch(
            session,
            publication_id,
            expected_actors=expected_actors,
            last_delivery_id=last_delivery_id,
            state=state,
            codex_review_mode=self.codex_review_mode,
            reactivate_closed_unmerged=reactivate_closed_unmerged,
        )

    def _requires_codex_adjudication(self, view) -> bool:
        return (
            self.codex_review_mode == "required"
            or view.automated_review_mode == "required"
        )

    @staticmethod
    def _normalized_wakeup_sha(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower()
        if len(normalized) != 40 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            return None
        return normalized

    def _resolve_wakeup_publication(
        self,
        session: Session,
        row: GitHubWebhookDeliveryRow,
    ) -> tuple[str | None, str]:
        candidates: set[str] = set()
        if row.event_name == "check_run":
            check_run = row.payload.get("check_run")
            if not isinstance(check_run, Mapping):
                return None, "NO_GOVERNED_TARGET"
            head_sha = self._normalized_wakeup_sha(check_run.get("head_sha"))
            pull_requests = check_run.get("pull_requests")
            if head_sha is None or not isinstance(pull_requests, list):
                return None, "NO_GOVERNED_TARGET"
            pull_numbers: set[int] = set()
            for pull in pull_requests:
                if not isinstance(pull, Mapping):
                    continue
                raw_number = pull.get("number")
                if isinstance(raw_number, bool):
                    continue
                try:
                    number = int(raw_number)
                except (TypeError, ValueError):
                    continue
                if number > 0:
                    pull_numbers.add(number)

            for number in pull_numbers:
                try:
                    publication_id = publication_for_pull(
                        session,
                        row.repository,
                        number,
                    )
                except DomainError:
                    return None, "AMBIGUOUS_GOVERNED_TARGET"
                if publication_id is None:
                    continue
                view = get_view(session, publication_id)
                watch = session.get(ReviewWatchRow, publication_id)
                if (
                    view.repository == row.repository
                    and view.pull_request_number == number
                    and view.remote_head_sha == head_sha
                    and watch is not None
                    and watch.repository == row.repository
                    and watch.pull_request_number == number
                    and watch.watched_head_sha == head_sha
                ):
                    candidates.add(publication_id)
        else:
            head_sha = self._normalized_wakeup_sha(row.payload.get("sha"))
            if head_sha is None:
                return None, "NO_GOVERNED_TARGET"
            watches = session.scalars(
                select(ReviewWatchRow).where(
                    ReviewWatchRow.repository == row.repository,
                    ReviewWatchRow.watched_head_sha == head_sha,
                )
            )
            for watch in watches:
                view = get_view(session, watch.publication_id)
                try:
                    canonical_publication_id = publication_for_pull(
                        session,
                        row.repository,
                        watch.pull_request_number,
                    )
                except DomainError:
                    return None, "AMBIGUOUS_GOVERNED_TARGET"
                if (
                    canonical_publication_id == watch.publication_id
                    and view.repository == row.repository
                    and view.pull_request_number == watch.pull_request_number
                    and view.remote_head_sha == head_sha
                    and watch.repository == row.repository
                ):
                    candidates.add(watch.publication_id)

        if len(candidates) > 1:
            return None, "AMBIGUOUS_GOVERNED_TARGET"
        if not candidates:
            return None, "NO_GOVERNED_TARGET"
        return next(iter(candidates)), "GOVERNED_TARGET"

    def ingest(
        self,
        session: Session,
        *,
        delivery_id: str,
        event_name: str,
        signature: str | None,
        body: bytes,
    ) -> WebhookDeliveryView:
        if not self.webhook_secret:
            raise GitHubWebhookAuthError(
                "GitHub webhook secret is not configured"
            )
        return persist_webhook_delivery(
            session,
            delivery_id=delivery_id,
            event_name=event_name,
            signature=signature,
            body=body,
            secret=self.webhook_secret,
            maximum_bytes=self.maximum_payload_bytes,
        )

    def _access(self, repository: str):
        return self.token_provider.installation_access(
            repository,
            permissions={
                "contents": "read",
                "issues": "read",
                "pull_requests": "read",
            },
        )

    @staticmethod
    def _verify_pull_identity(view, pull) -> None:
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise GitHubWebhookError("publication has no canonical PR identity")
        if pull.number != view.pull_request_number:
            raise GitHubWebhookError("canonical pull request number changed")
        if view.remote_branch is not None and pull.head_ref != view.remote_branch:
            raise GitHubWebhookError("canonical pull request branch changed")
        if view.base_branch is not None and pull.base_ref != view.base_branch:
            raise GitHubWebhookError("canonical pull request base changed")

    def _read_pull(self, view, token: str):
        assert view.pull_request_number is not None
        pull = self.github.pull_request(
            view.repository,
            view.pull_request_number,
            token,
        )
        self._verify_pull_identity(view, pull)
        return pull

    def _base_is_current(
        self,
        session: Session,
        publication_id: str,
        *,
        token: str,
        last_delivery_id: str | None = None,
    ) -> bool:
        view = get_view(session, publication_id)
        candidate = view.current_candidate
        if candidate is None or view.base_branch is None:
            raise GitHubWebhookError("publication base identity is incomplete")
        current_base = self.github.ref_sha(
            view.repository,
            view.base_branch,
            token,
        )
        if current_base == candidate.base_sha:
            existing_watch = session.get(ReviewWatchRow, publication_id)
            if existing_watch is not None and existing_watch.state == "STALE":
                if existing_watch.watched_head_sha != view.remote_head_sha:
                    refreshed_watch = self._sync_review_watch(
                        session,
                        publication_id,
                        expected_actors=self.expected_actors,
                        last_delivery_id=last_delivery_id,
                    )
                    return refreshed_watch.state != "STALE"
                if (
                    existing_watch.next_role != "CONTROL_PLANE"
                    or existing_watch.next_action != "BLOCKED"
                ):
                    self._sync_review_watch(
                        session,
                        publication_id,
                        expected_actors=self.expected_actors,
                        last_delivery_id=last_delivery_id,
                        state="STALE",
                    )
                return False
            return True
        self._sync_review_watch(
            session,
            publication_id,
            expected_actors=self.expected_actors,
            last_delivery_id=last_delivery_id,
            state="STALE",
        )
        return False

    def assert_review_write_current(
        self,
        session: Session,
        publication_id: str,
    ) -> None:
        """Fail closed before accepting a direct Human Review write."""
        pull = self._assert_live_head_and_base(
            session,
            publication_id,
            action="human review",
        )
        if pull.merged:
            raise DomainError(
                "human review is blocked because the canonical PR is already merged"
            )

    def assert_mergeability_write_current(
        self,
        session: Session,
        publication_id: str,
        *,
        head_sha: str,
    ) -> PullRequestSnapshot:
        """Return GitHub's current mergeability only for the exact live head/base."""
        pull = self._assert_live_head_and_base(
            session,
            publication_id,
            action="mergeability",
        )
        if pull.head_sha != head_sha:
            raise DomainError("mergeability evidence head is stale")
        if pull.merged:
            raise DomainError(
                "mergeability is blocked because the canonical PR is already merged"
            )
        return pull

    def _assert_live_head_and_base(
        self,
        session: Session,
        publication_id: str,
        *,
        action: str,
    ) -> PullRequestSnapshot:
        view = get_view(session, publication_id)
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise GitHubWebhookError("publication is not published")

        try:
            access = self._access(view.repository)
            pull = self._read_pull(view, access.token)
        except (GitHubAuthError, GitHubApiError) as exc:
            raise GitHubWebhookError(
                f"GitHub {action} write readback failed closed"
            ) from exc

        if pull.state.strip().lower() == "closed" and not pull.merged:
            self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                state="CLOSED_UNMERGED",
            )
            raise DomainError(
                f"{action} is blocked because the canonical PR is closed unmerged"
            )

        if pull.head_sha != view.remote_head_sha:
            self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                state="STALE",
            )
            raise DomainError(
                f"{action} is blocked because the published PR head is stale"
            )

        if not self._base_is_current(
            session,
            publication_id,
            token=access.token,
        ):
            raise DomainError(
                f"{action} is blocked because the publication base is stale"
            )
        return pull

    def _codex_broker(self) -> CodexReviewBroker:
        return CodexReviewBroker(
            token_provider=self.token_provider,
            github=self.github,
            mode=self.codex_review_mode,
            allowed_actors=self.codex_actors,
            trigger_user=None,
        )

    def _reconcile_codex_unavailability_only(
        self,
        session: Session,
        publication_id: str,
        *,
        token: str,
        comment_id: int | None = None,
    ) -> bool:
        """Close only a correlated provider usage-limit run; never run the broker."""
        view = get_view(session, publication_id)
        if view.automated_review_status is not AutomatedReviewStatus.RUNNING:
            return False
        try:
            observation = self._codex_broker().reconcile(
                session,
                publication_id,
                comment_id=comment_id,
                terminalize=False,
                allow_stale_head=True,
            )
            return observation.state in {"UNAVAILABLE", "INVALIDATED"}
        except (
            CodexReviewError,
            DomainError,
            GitHubApiError,
            GitHubAuthError,
            GitHubWebhookError,
        ):
            # A stale wake-up cannot complete a provider result before the
            # authoritative head/base fence.
            return False

    def _reconcile_codex(
        self,
        session: Session,
        publication_id: str,
        *,
        token: str,
        comment_id: int | None = None,
        allow_merged: bool = False,
        include_provider_evidence: bool = False,
    ) -> str:
        view = get_view(session, publication_id)
        if view.automated_review_status not in {
            AutomatedReviewStatus.RUNNING,
            AutomatedReviewStatus.PASS,
            AutomatedReviewStatus.CHANGES_REQUIRED,
            AutomatedReviewStatus.UNAVAILABLE,
        }:
            return "CODEX_NOT_RUNNING"
        if (
            view.automated_review_status is not AutomatedReviewStatus.RUNNING
            and not include_provider_evidence
        ):
            observation = self._codex_broker().audit_terminal_deletion_evidence(
                session,
                view,
            )
        else:
            observation = self._codex_broker().reconcile(
                session,
                publication_id,
                comment_id=comment_id,
                allow_merged=allow_merged,
            )
        return "CODEX_" + observation.state

    def _effective_human_review_decisions(
        self,
        reviews,
        *,
        head_sha: str,
    ) -> dict[str, tuple[datetime, Any]]:
        latest_by_actor = {}
        ambiguous_actors = set()
        candidates = []
        decision_states = {
            "APPROVED",
            "CHANGES_REQUESTED",
            "REQUEST_CHANGES",
            "DISMISSED",
        }
        for item in reviews:
            actor = _normalize_actor(item.actor)
            if actor not in self.human_review_actors or item.commit_id != head_sha:
                continue
            review_state = item.state.strip().upper()
            if review_state not in decision_states:
                continue
            submitted_at = _parse_time(item.submitted_at)
            if submitted_at is None:
                ambiguous_actors.add(actor)
                continue
            candidates.append((submitted_at, item.review_id, actor, item))

        if ambiguous_actors:
            raise GitHubWebhookError(
                "human review decision timestamp is missing or ambiguous"
            )

        candidates.sort(key=lambda item: (item[0], item[1], item[2]))
        timestamp_decisions = {}
        for submitted_at, review_id, actor, item in candidates:
            key = (actor, submitted_at)
            decision = (review_id, item.state.strip().upper())
            previous = timestamp_decisions.get(key)
            if previous is not None and previous != decision:
                raise GitHubWebhookError(
                    "human review decision timestamp is ambiguous"
                )
            timestamp_decisions[key] = decision

        for submitted_at, review_id, actor, item in candidates:
            latest_by_actor[actor] = (submitted_at, review_id, item)
        return {
            actor: (submitted_at, item)
            for actor, (submitted_at, _review_id, item) in latest_by_actor.items()
        }

    @staticmethod
    def _active_human_approvals(
        effective_reviews: Mapping[str, tuple[datetime, Any]],
        *,
        submitted_after: datetime | None = None,
    ):
        return tuple(
            item
            for actor in sorted(effective_reviews)
            for submitted_at, item in (effective_reviews[actor],)
            if item.state.strip().upper() == "APPROVED"
            and (submitted_after is None or submitted_at > submitted_after)
        )

    def _dismissed_recorded_approval_id(
        self,
        session: Session,
        publication_id: str,
        reviews,
        *,
        head_sha: str,
    ) -> int | None:
        approval_payload = next(
            (
                event["payload"]
                for event in reversed(load_events(session, publication_id))
                if event["event_type"] == EventType.REVIEW_RECORDED.value
                and event["payload"].get("decision")
                == ReviewDecision.APPROVED.value
                and event["payload"].get("reviewed_head_sha") == head_sha
            ),
            None,
        )
        if approval_payload is None:
            return None

        review_id = approval_payload.get("github_review_id")
        if isinstance(review_id, bool) or not isinstance(review_id, int) or review_id <= 0:
            return None
        matches = [item for item in reviews if item.review_id == review_id]
        if len(matches) != 1:
            return None

        receipt = matches[0]
        if (
            _normalize_actor(receipt.actor) not in self.human_review_actors
            or receipt.commit_id != head_sha
            or receipt.state.strip().upper() != "DISMISSED"
        ):
            return None
        return review_id

    def _effective_active_human_approvals(
        self,
        reviews,
        *,
        head_sha: str,
        submitted_after: datetime | None = None,
    ):
        effective_reviews = self._effective_human_review_decisions(
            reviews,
            head_sha=head_sha,
        )
        return self._active_human_approvals(
            effective_reviews,
            submitted_after=submitted_after,
        )

    def _effective_active_human_approvals_after_adjudication(
        self,
        session: Session,
        publication_id: str,
        view,
        reviews,
        effective_reviews=None,
    ):
        submitted_after = None
        if self._requires_codex_adjudication(view):
            adjudication = required_review_adjudication(session, publication_id)
            if adjudication is None:
                return ()
            submitted_after = _required_adjudication_time(
                session,
                publication_id,
                adjudication,
            )
        if effective_reviews is None:
            effective_reviews = self._effective_human_review_decisions(
                reviews,
                head_sha=view.remote_head_sha,
            )
        return self._active_human_approvals(
            effective_reviews,
            submitted_after=submitted_after,
        )

    @staticmethod
    def _recorded_human_changes_event(
        session: Session,
        publication_id: str,
        *,
        head_sha: str,
    ):
        for event in reversed(load_events(session, publication_id)):
            if (
                event["event_type"] == EventType.REVIEW_RECORDED.value
                and event["payload"].get("reviewed_head_sha") == head_sha
            ):
                if (
                    event["payload"].get("decision")
                    == ReviewDecision.CHANGES_REQUIRED.value
                ):
                    return event
                return None
        return None

    def _clear_human_review_block(
        self,
        session: Session,
        publication_id: str,
        *,
        view,
        blocker_event,
        reviews,
        effective_reviews,
    ) -> bool:
        blocker_payload = blocker_event["payload"]
        blocking_review_id = blocker_payload.get("github_review_id")
        if (
            isinstance(blocking_review_id, bool)
            or not isinstance(blocking_review_id, int)
            or blocking_review_id <= 0
        ):
            return False
        blocking_reviews = [
            item
            for item in reviews
            if item.review_id == blocking_review_id
            and item.commit_id == view.remote_head_sha
        ]
        if len(blocking_reviews) != 1:
            return False
        blocking_review = blocking_reviews[0]
        actor = _normalize_actor(blocking_review.actor)
        if actor not in self.human_review_actors:
            return False
        effective = effective_reviews.get(actor)
        if effective is None:
            return False
        blocking_time = _parse_time(blocking_review.submitted_at)
        if blocking_time is None:
            return False
        clearing_time, clearing_review = effective
        clearing_state = clearing_review.state.strip().upper()
        if clearing_state not in {"APPROVED", "DISMISSED"}:
            return False
        if clearing_review.review_id == blocking_review_id:
            if clearing_state != "DISMISSED":
                return False
        elif clearing_time <= blocking_time:
            return False

        clear_human_review_block(
            session,
            publication_id,
            reviewed_head_sha=view.remote_head_sha,
            cleared_review_event_sequence=blocker_event["sequence"],
            blocking_review_id=blocking_review_id,
            clearing_review_id=clearing_review.review_id,
            clearing_review_state=clearing_state,
        )
        return True

    def _human_review_from_payload(
        self,
        session: Session,
        publication_id: str,
        *,
        payload: Mapping[str, Any],
        token: str,
    ) -> str:
        raw_review = payload.get("review")
        if not isinstance(raw_review, Mapping):
            return "NO_HUMAN_REVIEW"
        try:
            review_id = int(raw_review.get("id"))
        except (TypeError, ValueError):
            return "NO_HUMAN_REVIEW"
        if review_id <= 0:
            return "NO_HUMAN_REVIEW"

        view = get_view(session, publication_id)
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise GitHubWebhookError("human review publication metadata is incomplete")

        reviews = self.github.list_pull_reviews(
            view.repository,
            view.pull_request_number,
            token,
        )
        matches = [item for item in reviews if item.review_id == review_id]
        if len(matches) != 1:
            raise GitHubWebhookError("human review receipt is missing or ambiguous")

        receipt = matches[0]
        actor = _normalize_actor(receipt.actor)
        if actor not in self.human_review_actors:
            return "NON_HUMAN_REVIEW_ACTOR"
        if receipt.commit_id != view.remote_head_sha:
            return "STALE_HUMAN_REVIEW"
        review_state = receipt.state.strip().upper()
        if review_state not in {
            "APPROVED",
            "CHANGES_REQUESTED",
            "REQUEST_CHANGES",
            "DISMISSED",
        }:
            return "NON_DECISION_HUMAN_REVIEW"

        if (
            view.state is PublicationState.IN_REVIEW
            and receipt.state.strip().upper() == ReviewDecision.APPROVED.value
            and self._requires_codex_adjudication(view)
            and required_review_adjudication(session, publication_id) is None
        ):
            raise GitHubWebhookDeferred(
                "human review is waiting for required automated/fallback adjudication"
            )

        outcome = self._reconcile_human_from_github(
            session,
            publication_id,
            token=token,
        )
        if (
            review_state == ReviewDecision.APPROVED.value
            and view.state in {
                PublicationState.APPROVED,
                PublicationState.READY_TO_MERGE,
            }
            and outcome == "HUMAN_APPROVAL_REMAINS"
        ):
            recorded_approval = next(
                (
                    event
                    for event in reversed(load_events(session, publication_id))
                    if event["event_type"] == EventType.REVIEW_RECORDED.value
                    and event["payload"].get("reviewed_head_sha")
                    == view.remote_head_sha
                    and event["payload"].get("decision")
                    == ReviewDecision.APPROVED.value
                ),
                None,
            )
            if (
                recorded_approval is not None
                and recorded_approval["payload"].get("github_review_id")
                == receipt.review_id
            ):
                return "HUMAN_APPROVED_ALREADY_RECORDED"
        return outcome

    def _mergeability_if_ready(
        self,
        session: Session,
        publication_id: str,
        *,
        pull,
        token: str,
        last_delivery_id: str | None = None,
    ) -> str:
        view = get_view(session, publication_id)
        if pull.merged:
            return "PULL_MERGED"
        if pull.state.strip().lower() == "closed" and not pull.merged:
            self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=last_delivery_id,
                state="CLOSED_UNMERGED",
            )
            return "PULL_CLOSED_UNMERGED"
        if view.state is not PublicationState.APPROVED:
            return "MERGEABILITY_NOT_ELIGIBLE"
        if pull.head_sha != view.remote_head_sha:
            return "STALE_MERGEABILITY"
        if not self._base_is_current(
            session,
            publication_id,
            token=token,
            last_delivery_id=last_delivery_id,
        ):
            return "STALE_BASE"
        if pull.mergeable is None:
            return "MERGEABILITY_PENDING"
        record_mergeability(
            session,
            publication_id,
            head_sha=pull.head_sha,
            mergeable=pull.mergeable,
        )
        return "MERGEABILITY_RECORDED"

    def _reconcile_human_from_github(
        self,
        session: Session,
        publication_id: str,
        *,
        token: str,
    ) -> str:
        view = get_view(session, publication_id)
        if not self.human_review_actors:
            return "HUMAN_ACTOR_ALLOWLIST_EMPTY"
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise GitHubWebhookError("human review publication metadata is incomplete")
        reviews = self.github.list_pull_reviews(
            view.repository,
            view.pull_request_number,
            token,
        )
        effective_reviews = self._effective_human_review_decisions(
            reviews,
            head_sha=view.remote_head_sha,
        )
        active_changes = [
            (submitted_at, item)
            for submitted_at, item in effective_reviews.values()
            if item.state.strip().upper() in {
                "CHANGES_REQUESTED",
                "REQUEST_CHANGES",
            }
        ]
        active_changes.sort(
            key=lambda entry: (
                entry[0],
                entry[1].review_id,
                _normalize_actor(entry[1].actor),
            )
        )
        active_approvals = self._effective_active_human_approvals_after_adjudication(
            session,
            publication_id,
            view,
            reviews,
            effective_reviews=effective_reviews,
        )
        required_codex_findings = (
            view.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
            and self._requires_codex_adjudication(view)
        )
        cleared_human_block = False

        if view.state is PublicationState.CHANGES_REQUIRED:
            if (
                required_codex_findings
                or view.review_decision is not ReviewDecision.CHANGES_REQUIRED
            ):
                return "HUMAN_NOT_ELIGIBLE"
            if active_changes:
                return "HUMAN_CHANGES_REQUIRED_ALREADY_RECORDED"
            blocker_event = self._recorded_human_changes_event(
                session,
                publication_id,
                head_sha=view.remote_head_sha,
            )
            if blocker_event is None or not self._clear_human_review_block(
                session,
                publication_id,
                view=view,
                blocker_event=blocker_event,
                reviews=reviews,
                effective_reviews=effective_reviews,
            ):
                return "HUMAN_CHANGES_REQUIRED_ALREADY_RECORDED"
            view = get_view(session, publication_id)
            cleared_human_block = True

        if active_changes:
            if view.state not in {
                PublicationState.IN_REVIEW,
                PublicationState.APPROVED,
                PublicationState.READY_TO_MERGE,
            }:
                return "HUMAN_NOT_ELIGIBLE"
            selected = active_changes[-1][1]
            record_review(
                session,
                publication_id,
                reviewed_head_sha=selected.commit_id,
                decision=ReviewDecision.CHANGES_REQUIRED,
                require_codex_review=self._requires_codex_adjudication(view),
                github_review_id=selected.review_id,
            )
            return "HUMAN_CHANGES_REQUIRED"

        if view.state is PublicationState.IN_REVIEW:
            if active_approvals:
                selected = max(
                    active_approvals,
                    key=lambda item: (
                        _parse_time(item.submitted_at),
                        item.review_id,
                        _normalize_actor(item.actor),
                    ),
                )
                record_review(
                    session,
                    publication_id,
                    reviewed_head_sha=selected.commit_id,
                    decision=ReviewDecision.APPROVED,
                    require_codex_review=self._requires_codex_adjudication(view),
                    github_review_id=selected.review_id,
                )
                return "HUMAN_APPROVED"
            if self._requires_codex_adjudication(view):
                adjudication = required_review_adjudication(
                    session,
                    publication_id,
                )
                if adjudication is None:
                    return "HUMAN_NOT_ELIGIBLE"
                if self._active_human_approvals(effective_reviews):
                    return "STALE_HUMAN_REVIEW"
            return (
                "HUMAN_REVIEW_CLEARED"
                if cleared_human_block
                else "HUMAN_REVIEW_NOT_FOUND"
            )

        if view.state in {
            PublicationState.APPROVED,
            PublicationState.READY_TO_MERGE,
        }:
            if active_approvals:
                return "HUMAN_APPROVAL_REMAINS"

            dismissed_recorded_approval_id = self._dismissed_recorded_approval_id(
                session,
                publication_id,
                reviews,
                head_sha=view.remote_head_sha,
            )
            record_review(
                session,
                publication_id,
                reviewed_head_sha=view.remote_head_sha,
                decision=ReviewDecision.CHANGES_REQUIRED,
                require_codex_review=self._requires_codex_adjudication(view),
                github_review_id=dismissed_recorded_approval_id,
            )
            if dismissed_recorded_approval_id is not None:
                view = get_view(session, publication_id)
                blocker_event = self._recorded_human_changes_event(
                    session,
                    publication_id,
                    head_sha=view.remote_head_sha,
                )
                if blocker_event is not None and self._clear_human_review_block(
                    session,
                    publication_id,
                    view=view,
                    blocker_event=blocker_event,
                    reviews=reviews,
                    effective_reviews=effective_reviews,
                ):
                    return "HUMAN_REVIEW_CLEARED"
            return "HUMAN_CHANGES_REQUIRED"

        return "HUMAN_NOT_ELIGIBLE"

    def authorize_merge(
        self,
        session: Session,
        publication_id: str,
    ) -> None:
        """Refresh authoritative review state and fence blocked generations."""
        self.reconcile_publication(
            session,
            publication_id,
            require_authoritative_codex_evidence=True,
        )
        view = get_view(session, publication_id)
        watch = get_review_watch(session, publication_id)
        if (
            watch.state in _BLOCKED_WATCH_STATES
            or (
                watch.next_role == "CONTROL_PLANE"
                and watch.next_action == "BLOCKED"
            )
        ):
            raise DomainError("governed merge is blocked by the current ReviewWatch")
        if view.state is not PublicationState.READY_TO_MERGE:
            raise DomainError(
                "merge requires READY_TO_MERGE after authoritative review reconciliation"
            )

    def _reconcile_external_merge(
        self,
        session: Session,
        publication_id: str,
    ) -> None:
        view = get_view(session, publication_id)
        if view.automated_review_status in {
            AutomatedReviewStatus.PASS,
            AutomatedReviewStatus.CHANGES_REQUIRED,
            AutomatedReviewStatus.UNAVAILABLE,
        }:
            self._reconcile_codex(
                session,
                publication_id,
                token=self._access(view.repository).token,
                allow_merged=True,
                include_provider_evidence=True,
            )
            view = get_view(session, publication_id)
        human_review_eligible = False
        if view.state is PublicationState.READY_TO_MERGE:
            outcome = self._reconcile_human_from_github(
                session,
                publication_id,
                token=self._access(view.repository).token,
            )
            current = get_view(session, publication_id)
            human_review_eligible = (
                current.state is PublicationState.READY_TO_MERGE
                and outcome == "HUMAN_APPROVAL_REMAINS"
            )
        MergeCoordinator(
            token_provider=self.token_provider,
            github=self.github,
        ).reconcile(
            session,
            publication_id,
            human_review_eligible=human_review_eligible,
        )

    def reconcile_publication(
        self,
        session: Session,
        publication_id: str,
        *,
        last_delivery_id: str | None = None,
        require_authoritative_codex_evidence: bool = False,
    ) -> WebhookProcessResult:
        view = get_view(session, publication_id)
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise GitHubWebhookError("publication is not published")

        try:
            access = self._access(view.repository)
            pull = self._read_pull(view, access.token)
        except (GitHubAuthError, GitHubApiError) as exc:
            raise GitHubWebhookError("GitHub review readback failed closed") from exc

        if pull.state.strip().lower() == "closed" and not pull.merged:
            watch = self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=last_delivery_id,
                state="CLOSED_UNMERGED",
            )
            return WebhookProcessResult(
                delivery_id=last_delivery_id,
                publication_id=publication_id,
                outcome="PULL_CLOSED_UNMERGED",
                next_role="CONTROL_PLANE",
                next_action="BLOCKED",
                watch_state=watch.state,
            )

        if pull.merged and pull.head_sha != view.remote_head_sha:
            watch = self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=last_delivery_id,
                state="STALE",
            )
            return WebhookProcessResult(
                delivery_id=last_delivery_id,
                publication_id=publication_id,
                outcome="STALE_HEAD",
                next_role="CONTROL_PLANE",
                next_action="BLOCKED",
                watch_state=watch.state,
            )

        if pull.merged:
            merge_outcome = "RECONCILED"
            try:
                self._reconcile_external_merge(session, publication_id)
            except MergePolicyViolationRecorded:
                merge_outcome = "MERGE_POLICY_VIOLATION"
            except (MergeError, DomainError) as exc:
                raise GitHubWebhookError(
                    "merge reconciliation failed closed"
                ) from exc
            watch = self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=last_delivery_id,
            )
            return WebhookProcessResult(
                delivery_id=last_delivery_id,
                publication_id=publication_id,
                outcome=merge_outcome,
                next_role=watch.next_role,
                next_action=watch.next_action,
                watch_state=watch.state,
            )

        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            self._reconcile_codex_unavailability_only(
                session,
                publication_id,
                token=access.token,
            )
        view = get_view(session, publication_id)

        if pull.head_sha != view.remote_head_sha:
            watch = self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=last_delivery_id,
                state="STALE",
            )
            return WebhookProcessResult(
                delivery_id=last_delivery_id,
                publication_id=publication_id,
                outcome="STALE_HEAD",
                next_role="CONTROL_PLANE",
                next_action="BLOCKED",
                watch_state=watch.state,
            )

        if not self._base_is_current(
            session,
            publication_id,
            token=access.token,
            last_delivery_id=last_delivery_id,
        ):
            watch = get_review_watch(session, publication_id)
            return WebhookProcessResult(
                delivery_id=last_delivery_id,
                publication_id=publication_id,
                outcome="STALE_BASE",
                next_role="CONTROL_PLANE",
                next_action="BLOCKED",
                watch_state=watch.state,
            )

        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            self._reconcile_codex(
                session,
                publication_id,
                token=access.token,
            )
        elif view.automated_review_status in {
            AutomatedReviewStatus.PASS,
            AutomatedReviewStatus.CHANGES_REQUIRED,
            AutomatedReviewStatus.UNAVAILABLE,
        }:
            self._reconcile_codex(
                session,
                publication_id,
                token=access.token,
                include_provider_evidence=require_authoritative_codex_evidence,
            )

        self._reconcile_human_from_github(
            session,
            publication_id,
            token=access.token,
        )

        view = get_view(session, publication_id)
        pull = self._read_pull(view, access.token)

        if view.state is PublicationState.APPROVED and not pull.merged:
            self._mergeability_if_ready(
                session,
                publication_id,
                pull=pull,
                token=access.token,
                last_delivery_id=last_delivery_id,
            )

        view = get_view(session, publication_id)
        merge_outcome = "RECONCILED"
        if pull.merged or view.state is PublicationState.MERGED:
            try:
                MergeCoordinator(
                    token_provider=self.token_provider,
                    github=self.github,
                ).reconcile(session, publication_id)
            except MergePolicyViolationRecorded:
                merge_outcome = "MERGE_POLICY_VIOLATION"
            except (MergeError, DomainError) as exc:
                raise GitHubWebhookError("merge reconciliation failed closed") from exc

        view = get_view(session, publication_id)
        watch_row = session.get(ReviewWatchRow, publication_id)
        reactivate_closed_unmerged = (
            pull.state.strip().lower() == "open"
            and not pull.merged
            and pull.head_sha == view.remote_head_sha
            and watch_row is not None
            and watch_row.state == "CLOSED_UNMERGED"
            and watch_row.watched_head_sha == view.remote_head_sha
            and view.state is not PublicationState.MERGED
            and not view.merge_policy_violation
        )
        watch = self._sync_review_watch(
            session,
            publication_id,
            expected_actors=self.expected_actors,
            last_delivery_id=last_delivery_id,
            reactivate_closed_unmerged=reactivate_closed_unmerged,
        )
        return WebhookProcessResult(
            delivery_id=last_delivery_id,
            publication_id=publication_id,
            outcome=merge_outcome,
            next_role=watch.next_role,
            next_action=watch.next_action,
            watch_state=watch.state,
        )

    def _process_pull_delivery(
        self,
        session: Session,
        publication_id: str,
        row: GitHubWebhookDeliveryRow,
        *,
        token: str,
    ) -> str:
        view = get_view(session, publication_id)
        pull = self._read_pull(view, token)
        comment_id = (
            _issue_comment_id(row)
            if row.event_name == "issue_comment" and row.action != "deleted"
            else None
        )

        if pull.state.strip().lower() == "closed" and not pull.merged:
            self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=row.delivery_id,
                state="CLOSED_UNMERGED",
            )
            return "PULL_CLOSED_UNMERGED"

        if pull.merged and pull.head_sha != view.remote_head_sha:
            self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=row.delivery_id,
                state="STALE",
            )
            return "STALE_HEAD"

        if pull.merged:
            try:
                self._reconcile_external_merge(session, publication_id)
            except MergePolicyViolationRecorded:
                return "MERGE_POLICY_VIOLATION"
            except (MergeError, DomainError) as exc:
                error = (
                    "closed PR reconciliation failed closed"
                    if row.event_name == "pull_request" and row.action == "closed"
                    else "merged PR reconciliation failed closed"
                )
                raise GitHubWebhookError(
                    error
                ) from exc
            return (
                "PULL_CLOSED_RECONCILED"
                if row.event_name == "pull_request" and row.action == "closed"
                else "PULL_MERGED_RECONCILED"
            )

        codex_unavailable = False
        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            codex_unavailable = self._reconcile_codex_unavailability_only(
                session,
                publication_id,
                token=token,
                comment_id=comment_id,
            )
            view = get_view(session, publication_id)

        if row.event_name == "pull_request" and row.action == "closed":
            try:
                MergeCoordinator(
                    token_provider=self.token_provider,
                    github=self.github,
                ).reconcile(session, publication_id)
            except MergePolicyViolationRecorded:
                return "MERGE_POLICY_VIOLATION"
            except (MergeError, DomainError) as exc:
                raise GitHubWebhookError("closed PR reconciliation failed closed") from exc
            return "PULL_CLOSED_RECONCILED"

        if row.event_name == "pull_request" and row.action == "synchronize":
            if pull.head_sha != view.remote_head_sha:
                self._sync_review_watch(
                    session,
                    publication_id,
                    expected_actors=self.expected_actors,
                    last_delivery_id=row.delivery_id,
                    state="STALE",
                )
                return "STALE_HEAD"

        if pull.head_sha != view.remote_head_sha:
            self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=row.delivery_id,
                state="STALE",
            )
            return "STALE_HEAD"

        if not self._base_is_current(
            session,
            publication_id,
            token=token,
            last_delivery_id=row.delivery_id,
        ):
            return "STALE_BASE"

        view = get_view(session, publication_id)
        if view.automated_review_status in {
            AutomatedReviewStatus.PASS,
            AutomatedReviewStatus.CHANGES_REQUIRED,
            AutomatedReviewStatus.UNAVAILABLE,
        }:
            self._reconcile_codex(
                session,
                publication_id,
                token=token,
                include_provider_evidence=False,
            )

        if row.event_name == "pull_request" and row.action == "synchronize":
            return "SYNCHRONIZE_MATCHED"

        if row.event_name == "issue_comment":
            if codex_unavailable:
                return "CODEX_UNAVAILABLE"
            raw_comment = row.payload.get("comment")
            actor = ""
            if isinstance(raw_comment, Mapping):
                user = raw_comment.get("user")
                if isinstance(user, Mapping):
                    actor = _normalize_actor(str(user.get("login") or ""))
            if actor not in self.codex_actors and row.action != "deleted":
                return "ISSUE_COMMENT_OBSERVED"
            return self._reconcile_codex(
                session,
                publication_id,
                token=token,
                comment_id=comment_id,
                include_provider_evidence=True,
            )

        if row.event_name == "pull_request_review":
            raw_review = row.payload.get("review")
            actor = ""
            if isinstance(raw_review, Mapping):
                user = raw_review.get("user")
                if isinstance(user, Mapping):
                    actor = _normalize_actor(str(user.get("login") or ""))

            if actor in self.codex_actors:
                return self._reconcile_codex(
                    session,
                    publication_id,
                    token=token,
                    include_provider_evidence=True,
                )
            return self._human_review_from_payload(
                session,
                publication_id,
                payload=row.payload,
                token=token,
            )

        if row.event_name == "pull_request_review_comment":
            raw_comment = row.payload.get("comment")
            actor = ""
            if isinstance(raw_comment, Mapping):
                user = raw_comment.get("user")
                if isinstance(user, Mapping):
                    actor = _normalize_actor(str(user.get("login") or ""))
            if actor in self.codex_actors:
                return self._reconcile_codex(
                    session,
                    publication_id,
                    token=token,
                    include_provider_evidence=True,
                )
            return "REVIEW_COMMENT_OBSERVED"

        if row.event_name == "pull_request":
            return "PULL_OBSERVED"

        return "EVENT_OBSERVED"

    def _process_push(
        self,
        session: Session,
        row: GitHubWebhookDeliveryRow,
    ) -> str:
        raw_ref = str(row.payload.get("ref") or "")
        if not raw_ref.startswith("refs/heads/"):
            return "PUSH_IGNORED_REF"
        branch = raw_ref.removeprefix("refs/heads/")

        try:
            access = self._access(row.repository)
            current_sha = self.github.ref_sha(
                row.repository,
                branch,
                access.token,
            )
        except (GitHubAuthError, GitHubApiError) as exc:
            raise GitHubWebhookError("push ref readback failed closed") from exc

        stale = 0
        recovered = 0
        watches = list(
            session.scalars(
                select(ReviewWatchRow).where(
                    ReviewWatchRow.repository == row.repository,
                    ReviewWatchRow.state.in_({"ACTIVE", "STALE"}),
                )
            )
        )
        for watch_row in watches:
            view = get_view(session, watch_row.publication_id)
            candidate = view.current_candidate
            if (
                view.base_branch != branch
                or candidate is None
                or view.state is PublicationState.MERGED
            ):
                continue

            if current_sha is None or candidate.base_sha != current_sha:
                watch_row.state = "STALE"
                watch_row.next_role = "CONTROL_PLANE"
                watch_row.next_action = "BLOCKED"
                watch_row.last_delivery_id = row.delivery_id
                watch_row.last_reconciled_at = _utcnow()
                stale += 1
                continue

            if watch_row.state != "STALE":
                continue
            if watch_row.watched_head_sha != view.remote_head_sha:
                stale += 1
                continue
            if view.merge_policy_violation:
                stale += 1
                continue

            pull = self._read_pull(view, access.token)
            if (
                pull.head_sha != view.remote_head_sha
                or pull.state.strip().lower() != "open"
                or pull.merged
            ):
                watch_row.state = "STALE"
                watch_row.next_role = "CONTROL_PLANE"
                watch_row.next_action = "BLOCKED"
                watch_row.last_delivery_id = row.delivery_id
                watch_row.last_reconciled_at = _utcnow()
                stale += 1
                continue

            if watch_row.state == "STALE":
                watch_row.state = "ACTIVE"
                watch_row.next_role, watch_row.next_action = _derive_next(
                    session,
                    watch_row.publication_id,
                    codex_review_mode=self.codex_review_mode,
                )
                watch_row.last_delivery_id = row.delivery_id
                watch_row.last_reconciled_at = _utcnow()
                recovered += 1

        session.commit()
        return f"BASE_PUSH_STALE:{stale}:RECOVERED:{recovered}"

    @_claim_delivery_processing
    def process_delivery(
        self,
        session: Session,
        delivery_id: str,
    ) -> WebhookProcessResult:
        row = session.scalar(
            select(GitHubWebhookDeliveryRow)
            .where(GitHubWebhookDeliveryRow.delivery_id == delivery_id)
            .execution_options(populate_existing=True)
        )
        if row is None:
            raise KeyError(delivery_id)

        if row.state in {"PROCESSED", "IGNORED"}:
            publication_id = None
            if row.event_name not in {"check_run", "status"}:
                publication_id = (
                    publication_for_pull(
                        session,
                        row.repository,
                        row.pull_request_number,
                    )
                    if row.pull_request_number is not None
                    else None
                )
            watch = (
                session.get(ReviewWatchRow, publication_id)
                if publication_id is not None
                else None
            )
            return WebhookProcessResult(
                delivery_id=row.delivery_id,
                publication_id=publication_id,
                outcome=row.state,
                next_role=watch.next_role if watch else "NONE",
                next_action=watch.next_action if watch else "DONE",
                watch_state=watch.state if watch else None,
            )

        if row.event_name not in _SUPPORTED_EVENTS:
            mark_delivery_processed(session, delivery_id, state="IGNORED")
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=None,
                outcome="UNSUPPORTED_EVENT",
                next_role="NONE",
                next_action="DONE",
                watch_state=None,
            )

        if row.event_name == "push":
            try:
                outcome = self._process_push(session, row)
            except (
                DomainError,
                GitHubAuthError,
                GitHubApiError,
                GitHubWebhookError,
            ) as exc:
                session.rollback()
                mark_delivery_retry(session, delivery_id, str(exc))
                raise
            mark_delivery_processed(session, delivery_id)
            stale_count = 0
            if outcome.startswith("BASE_PUSH_STALE:"):
                try:
                    stale_count = int(outcome.split(":", 2)[1])
                except (IndexError, TypeError, ValueError):
                    raise GitHubWebhookError("base push reconciliation result is malformed")
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=None,
                outcome=outcome,
                next_role="CONTROL_PLANE",
                next_action="BLOCKED" if stale_count > 0 else "DONE",
                watch_state=None,
            )

        if row.event_name in {"check_run", "status"}:
            publication_id, target_outcome = self._resolve_wakeup_publication(
                session,
                row,
            )
            if publication_id is None:
                mark_delivery_processed(session, delivery_id, state="IGNORED")
                ambiguous = target_outcome == "AMBIGUOUS_GOVERNED_TARGET"
                return WebhookProcessResult(
                    delivery_id=delivery_id,
                    publication_id=None,
                    outcome=target_outcome,
                    next_role="CONTROL_PLANE" if ambiguous else "NONE",
                    next_action="BLOCKED" if ambiguous else "DONE",
                    watch_state=None,
                )
        elif row.pull_request_number is None:
            mark_delivery_processed(session, delivery_id, state="IGNORED")
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=None,
                outcome="NO_PULL_REQUEST",
                next_role="NONE",
                next_action="DONE",
                watch_state=None,
            )

        else:
            publication_id = publication_for_pull(
                session,
                row.repository,
                row.pull_request_number,
            )
            if publication_id is None:
                mark_delivery_processed(session, delivery_id, state="IGNORED")
                return WebhookProcessResult(
                    delivery_id=delivery_id,
                    publication_id=None,
                    outcome="UNMANAGED_PULL_REQUEST",
                    next_role="NONE",
                    next_action="DONE",
                    watch_state=None,
                )

        try:
            access = self._access(row.repository)
            outcome = self._process_pull_delivery(
                session,
                publication_id,
                row,
                token=access.token,
            )
            latest = get_view(session, publication_id)
            if (
                latest.state is PublicationState.APPROVED
                and outcome not in {
                    "PULL_CLOSED_UNMERGED",
                    "MERGE_POLICY_VIOLATION",
                    "STALE_HEAD",
                    "STALE_BASE",
                }
            ):
                latest_pull = self._read_pull(latest, access.token)
                mergeability_outcome = self._mergeability_if_ready(
                    session,
                    publication_id,
                    pull=latest_pull,
                    token=access.token,
                    last_delivery_id=delivery_id,
                )
                if mergeability_outcome != "MERGEABILITY_NOT_ELIGIBLE":
                    outcome = outcome + "+" + mergeability_outcome
            stale_outcome = outcome in {"STALE_HEAD", "STALE_BASE"} or outcome.endswith("+STALE_BASE")
            reactivate_closed_unmerged = (
                row.event_name == "pull_request"
                and row.action == "reopened"
                and not stale_outcome
                and outcome != "PULL_CLOSED_UNMERGED"
            )
            watch = self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=delivery_id,
                state=("STALE" if stale_outcome else None),
                reactivate_closed_unmerged=reactivate_closed_unmerged,
            )
            mark_delivery_processed(session, delivery_id)
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=publication_id,
                outcome=outcome,
                next_role="CONTROL_PLANE" if stale_outcome else watch.next_role,
                next_action="BLOCKED" if stale_outcome else watch.next_action,
                watch_state=watch.state,
            )
        except GitHubWebhookDeferred as exc:
            watch = self._sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=delivery_id,
            )
            mark_delivery_retry(session, delivery_id, str(exc))
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=publication_id,
                outcome="DEFERRED",
                next_role=watch.next_role,
                next_action=watch.next_action,
                watch_state=watch.state,
            )
        except (
            DomainError,
            GitHubAuthError,
            GitHubApiError,
            CodexReviewError,
            GitHubWebhookError,
        ) as exc:
            mark_delivery_retry(session, delivery_id, str(exc))
            raise

    def reconcile_pending(self, session: Session) -> tuple[WebhookProcessResult, ...]:
        results = []
        for delivery_id in list_pending_delivery_ids(session):
            try:
                results.append(self.process_delivery(session, delivery_id))
            except (
                DomainError,
                GitHubAuthError,
                GitHubApiError,
                CodexReviewError,
                GitHubWebhookError,
            ) as exc:
                session.rollback()
                results.append(
                    WebhookProcessResult(
                        delivery_id=delivery_id,
                        publication_id=None,
                        outcome="FAILED_PENDING",
                        next_role="CONTROL_PLANE",
                        next_action="RETRY",
                        watch_state=None,
                        error=str(exc)[:1000],
                    )
                )
        return tuple(results)

    def reconcile_pending_best_effort(
        self,
        session: Session,
        *,
        limit: int = 100,
    ) -> tuple[WebhookProcessResult, ...]:
        if limit <= 0:
            raise GitHubWebhookError("pending reconciliation limit must be positive")
        results = []
        for delivery_id in list_pending_delivery_ids_for_startup(
            session,
            limit=limit,
        ):
            try:
                results.append(self.process_delivery(session, delivery_id))
            except (
                DomainError,
                GitHubAuthError,
                GitHubApiError,
                CodexReviewError,
                GitHubWebhookError,
            ):
                # process_delivery persists retry evidence before raising. One bad
                # delivery must not prevent later durable inbox entries from resuming.
                continue
        return tuple(results)
