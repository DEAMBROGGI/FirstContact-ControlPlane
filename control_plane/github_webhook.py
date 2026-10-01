from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .codex_review import CodexReviewBroker, CodexReviewError
from .domain import AutomatedReviewStatus, DomainError, PublicationState, ReviewDecision
from .github_api import GitHubApiError, GitHubRepositoryGateway, PullRequestSnapshot
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .merge import MergeCoordinator, MergeError
from .models import GitHubWebhookDeliveryRow, PublicationRow, ReviewWatchRow
from .profile_registry import ProfileError, profile_for_repository
from .service import (
    get_view,
    mark_codex_review_unavailable,
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
    row = session.get(ReviewWatchRow, publication_id)
    effective_state = state if state is not None else (row.state if row is not None else None)
    if effective_state == "STALE":
        next_role, next_action = "CONTROL_PLANE", "BLOCKED"
    else:
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
        if actors:
            row.expected_actors = list(actors)
        if state is not None:
            row.state = state
        elif head_changed:
            # A changed head is not evidence that a stale base recovered. Only
            # the authoritative base-push readback may clear a STALE watch.
            row.state = "STALE" if effective_state == "STALE" else "ACTIVE"
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


_CODEX_USAGE_LIMIT_RE = re.compile(
    r"(?is)reached\s+your\s+codex\s+usage\s+limits\s+for\s+code\s+reviews"
)


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


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError as exc:
        raise GitHubWebhookError("GitHub evidence timestamp is invalid") from exc


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
                if (
                    existing_watch.watched_head_sha != view.remote_head_sha
                    or existing_watch.next_role != "CONTROL_PLANE"
                    or existing_watch.next_action != "BLOCKED"
                ):
                    sync_review_watch(
                        session,
                        publication_id,
                        expected_actors=self.expected_actors,
                        last_delivery_id=last_delivery_id,
                        state="STALE",
                    )
                return False
            return True
        sync_review_watch(
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
        self._assert_live_head_and_base(session, publication_id, action="human review")

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

        if pull.head_sha != view.remote_head_sha:
            sync_review_watch(
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

    def _maybe_mark_codex_unavailable_from_comment(
        self,
        session: Session,
        publication_id: str,
        *,
        comment_id: int | None,
        token: str,
    ) -> bool:
        view = get_view(session, publication_id)
        if (
            view.automated_review_status is not AutomatedReviewStatus.RUNNING
            or view.automated_review_run_id is None
            or view.automated_review_head_sha is None
            or view.automated_review_triggered_at is None
            or view.pull_request_number is None
        ):
            return False

        trigger_time = _parse_time(view.automated_review_triggered_at)
        if trigger_time is None:
            raise GitHubWebhookError("governed Codex trigger timestamp is missing")
        comments = self.github.list_issue_comments(
            view.repository,
            view.pull_request_number,
            token,
        )
        trigger_matches = [
            item
            for item in comments
            if item.comment_id == view.automated_review_trigger_comment_id
        ]
        if len(trigger_matches) != 1:
            raise GitHubWebhookError("governed Codex trigger receipt is missing or ambiguous")
        trigger = trigger_matches[0]
        if _normalize_actor(trigger.actor) != _normalize_actor(
            view.automated_review_trigger_actor or ""
        ):
            raise GitHubWebhookError("governed Codex trigger actor changed")
        if _parse_time(trigger.created_at) != trigger_time:
            raise GitHubWebhookError("governed Codex trigger timestamp changed")
        marker = (
            "<!-- firstcontact-control-plane:codex-review "
            f"run={view.automated_review_run_id} "
            f"head={view.automated_review_head_sha} -->"
        )
        if marker not in (trigger.body or ""):
            raise GitHubWebhookError("governed Codex trigger marker changed")

        if comment_id is not None:
            evidence_matches = [
                item for item in comments if item.comment_id == comment_id
            ]
            if len(evidence_matches) != 1:
                raise GitHubWebhookError(
                    "Codex webhook comment receipt is missing or ambiguous"
                )
            evidence = evidence_matches[0]
            if evidence.comment_id == view.automated_review_trigger_comment_id:
                raise GitHubWebhookError(
                    "Codex usage-limit evidence collides with trigger"
                )
            evidence_time = _parse_time(evidence.created_at)
            if (
                _normalize_actor(evidence.actor) not in self.codex_actors
                or evidence_time is None
                or evidence_time <= trigger_time
                or not _CODEX_USAGE_LIMIT_RE.search(evidence.body or "")
            ):
                return False
        else:
            provider_responses: list[tuple[datetime, int, Any]] = []
            for item in comments:
                if item.comment_id == view.automated_review_trigger_comment_id:
                    continue
                if _normalize_actor(item.actor) not in self.codex_actors:
                    continue
                created = _parse_time(item.created_at)
                if created is None:
                    raise GitHubWebhookError(
                        "Codex provider response timestamp is missing"
                    )
                if created > trigger_time:
                    provider_responses.append((created, item.comment_id, item))

            provider_responses.sort(key=lambda item: (item[0], item[1]))
            if any(
                earlier[1] == later[1]
                for earlier, later in zip(
                    provider_responses,
                    provider_responses[1:],
                )
            ):
                raise GitHubWebhookError(
                    "Codex provider response receipt is ambiguous"
                )
            if not provider_responses:
                return False

            evidence = provider_responses[0][2]
            if not _CODEX_USAGE_LIMIT_RE.search(evidence.body or ""):
                return False

        mark_codex_review_unavailable(
            session,
            publication_id,
            run_id=view.automated_review_run_id,
            reviewed_head_sha=view.automated_review_head_sha,
            reason=f"CODEX_PROVIDER_USAGE_LIMIT:{evidence.comment_id}",
        )
        return True

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
            return self._maybe_mark_codex_unavailable_from_comment(
                session,
                publication_id,
                comment_id=comment_id,
                token=token,
            )
        except (
            CodexReviewError,
            DomainError,
            GitHubApiError,
            GitHubAuthError,
            GitHubWebhookError,
        ):
            # Stale evidence cannot safely complete the run. The caller still
            # applies the authoritative stale-head/base fence and blocks review.
            return False

    def _reconcile_codex(
        self,
        session: Session,
        publication_id: str,
        *,
        token: str,
        comment_id: int | None = None,
    ) -> str:
        if self._maybe_mark_codex_unavailable_from_comment(
            session,
            publication_id,
            comment_id=comment_id,
            token=token,
        ):
            return "CODEX_UNAVAILABLE"

        view = get_view(session, publication_id)
        if view.automated_review_status is not AutomatedReviewStatus.RUNNING:
            return "CODEX_NOT_RUNNING"

        observation = self._codex_broker().reconcile(session, publication_id)
        return "CODEX_" + observation.state

    def _latest_human_review(
        self,
        view,
        *,
        token: str,
    ):
        if not self.human_review_actors:
            return None
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise GitHubWebhookError("human review publication metadata is incomplete")

        reviews = self.github.list_pull_reviews(
            view.repository,
            view.pull_request_number,
            token,
        )
        candidates = [
            item
            for item in reviews
            if _normalize_actor(item.actor) in self.human_review_actors
            and item.commit_id == view.remote_head_sha
            and item.state.strip().upper() in {
                "APPROVED",
                "CHANGES_REQUESTED",
                "REQUEST_CHANGES",
            }
            and item.submitted_at is not None
        ]
        if not candidates:
            return None

        candidates.sort(
            key=lambda item: (
                _parse_time(item.submitted_at)
                or datetime.min.replace(tzinfo=timezone.utc),
                item.review_id,
            )
        )
        selected = candidates[-1]
        decision = (
            ReviewDecision.APPROVED
            if selected.state.strip().upper() == "APPROVED"
            else ReviewDecision.CHANGES_REQUIRED
        )
        return selected, decision

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
        if receipt.state.strip().upper() not in {
            "APPROVED",
            "CHANGES_REQUESTED",
            "REQUEST_CHANGES",
        }:
            return "NON_DECISION_HUMAN_REVIEW"

        if (
            view.state is PublicationState.IN_REVIEW
            and required_review_adjudication(session, publication_id) is None
        ):
            raise GitHubWebhookDeferred(
                "human review is waiting for required automated/fallback adjudication"
            )

        return self._reconcile_human_from_github(
            session,
            publication_id,
            token=token,
        )

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
        latest = self._latest_human_review(view, token=token)
        if latest is None:
            return "HUMAN_REVIEW_NOT_FOUND"

        selected, decision = latest

        if view.state is not PublicationState.IN_REVIEW:
            if (
                view.review_decision is decision
                and view.remote_head_sha == selected.commit_id
                and view.state in {
                    PublicationState.APPROVED,
                    PublicationState.READY_TO_MERGE,
                    PublicationState.MERGED,
                    PublicationState.CHANGES_REQUIRED,
                }
            ):
                return "HUMAN_" + decision.value + "_ALREADY_RECORDED"
            return "HUMAN_NOT_ELIGIBLE"

        if required_review_adjudication(session, publication_id) is None:
            return "HUMAN_NOT_ELIGIBLE"

        record_review(
            session,
            publication_id,
            reviewed_head_sha=selected.commit_id,
            decision=decision,
            require_codex_review=(self.codex_review_mode == "required"),
        )
        return "HUMAN_" + decision.value

    def reconcile_publication(
        self,
        session: Session,
        publication_id: str,
        *,
        last_delivery_id: str | None = None,
    ) -> WebhookProcessResult:
        view = get_view(session, publication_id)
        if view.pull_request_number is None or view.remote_head_sha is None:
            raise GitHubWebhookError("publication is not published")

        try:
            access = self._access(view.repository)
            pull = self._read_pull(view, access.token)
        except (GitHubAuthError, GitHubApiError) as exc:
            raise GitHubWebhookError("GitHub review readback failed closed") from exc

        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            self._reconcile_codex_unavailability_only(
                session,
                publication_id,
                token=access.token,
            )
        view = get_view(session, publication_id)

        if pull.head_sha != view.remote_head_sha:
            watch = sync_review_watch(
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

        self._reconcile_human_from_github(
            session,
            publication_id,
            token=access.token,
        )

        view = get_view(session, publication_id)
        pull = self._read_pull(view, access.token)

        if view.state is PublicationState.APPROVED:
            self._mergeability_if_ready(
                session,
                publication_id,
                pull=pull,
                token=access.token,
                last_delivery_id=last_delivery_id,
            )

        view = get_view(session, publication_id)
        if pull.merged or view.state is PublicationState.MERGED:
            try:
                MergeCoordinator(
                    token_provider=self.token_provider,
                    github=self.github,
                ).reconcile(session, publication_id)
            except (MergeError, DomainError) as exc:
                raise GitHubWebhookError("merge reconciliation failed closed") from exc

        watch = sync_review_watch(
            session,
            publication_id,
            expected_actors=self.expected_actors,
            last_delivery_id=last_delivery_id,
        )
        return WebhookProcessResult(
            delivery_id=last_delivery_id,
            publication_id=publication_id,
            outcome="RECONCILED",
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

        codex_unavailable = False
        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            comment_id = (
                _issue_comment_id(row)
                if row.event_name == "issue_comment"
                else None
            )
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
            except (MergeError, DomainError) as exc:
                raise GitHubWebhookError("closed PR reconciliation failed closed") from exc
            return "PULL_CLOSED_RECONCILED"

        if row.event_name == "pull_request" and row.action == "synchronize":
            if pull.head_sha != view.remote_head_sha:
                sync_review_watch(
                    session,
                    publication_id,
                    expected_actors=self.expected_actors,
                    last_delivery_id=row.delivery_id,
                    state="STALE",
                )
                return "STALE_HEAD"

        if pull.head_sha != view.remote_head_sha:
            sync_review_watch(
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

        if row.event_name == "pull_request" and row.action == "synchronize":
            return "SYNCHRONIZE_MATCHED"

        if row.event_name == "issue_comment":
            comment_id = _issue_comment_id(row)
            if codex_unavailable:
                return "CODEX_UNAVAILABLE"
            return self._reconcile_codex(
                session,
                publication_id,
                token=token,
                comment_id=comment_id,
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
                )
            return self._human_review_from_payload(
                session,
                publication_id,
                payload=row.payload,
                token=token,
            )

        if row.event_name == "pull_request_review_comment":
            view = get_view(session, publication_id)
            if view.automated_review_status is AutomatedReviewStatus.RUNNING:
                return self._reconcile_codex(
                    session,
                    publication_id,
                    token=token,
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
                or current_sha is None
                or view.state is PublicationState.MERGED
            ):
                continue

            if candidate.base_sha != current_sha:
                watch_row.state = "STALE"
                watch_row.next_role = "CONTROL_PLANE"
                watch_row.next_action = "BLOCKED"
                watch_row.last_delivery_id = row.delivery_id
                watch_row.last_reconciled_at = _utcnow()
                stale += 1
                continue

            if (
                watch_row.state == "STALE"
                and watch_row.watched_head_sha == view.remote_head_sha
            ):
                watch_row.state = "ACTIVE"
                watch_row.next_role, watch_row.next_action = _derive_next(
                    session,
                    watch_row.publication_id,
                )
                watch_row.last_delivery_id = row.delivery_id
                watch_row.last_reconciled_at = _utcnow()
                recovered += 1

        session.commit()
        return f"BASE_PUSH_STALE:{stale}:RECOVERED:{recovered}"

    def process_delivery(
        self,
        session: Session,
        delivery_id: str,
    ) -> WebhookProcessResult:
        row = session.scalar(
            select(GitHubWebhookDeliveryRow)
            .where(GitHubWebhookDeliveryRow.delivery_id == delivery_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if row is None:
            raise KeyError(delivery_id)

        if row.state in {"PROCESSED", "IGNORED"}:
            publication_id = (
                publication_for_pull(session, row.repository, row.pull_request_number)
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
            outcome = self._process_push(session, row)
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

        if row.pull_request_number is None:
            mark_delivery_processed(session, delivery_id, state="IGNORED")
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=None,
                outcome="NO_PULL_REQUEST",
                next_role="NONE",
                next_action="DONE",
                watch_state=None,
            )

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
            if latest.state is PublicationState.APPROVED:
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
            watch = sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=delivery_id,
                state=("STALE" if stale_outcome else None),
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
            mark_delivery_retry(session, delivery_id, str(exc))
            watch = sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=delivery_id,
            )
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
            results.append(self.process_delivery(session, delivery_id))
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
        for delivery_id in list_pending_delivery_ids(session)[:limit]:
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
