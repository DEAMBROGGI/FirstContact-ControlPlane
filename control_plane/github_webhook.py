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

from .codex_review import CodexReviewBroker, CodexReviewError
from .domain import AutomatedReviewStatus, DomainError, PublicationState, ReviewDecision
from .github_api import GitHubApiError, GitHubRepositoryGateway
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .merge import MergeCoordinator, MergeError
from .models import GitHubWebhookDeliveryRow, PublicationRow, ReviewWatchRow
from .profile_registry import profile_for_repository
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
        webhook_secret: str,
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
        comments = self.github.list_issue_comments(
            view.repository,
            view.pull_request_number,
            token,
        )
        matches = []
        for item in comments:
            if comment_id is not None and item.comment_id != comment_id:
                continue
            created = _parse_time(item.created_at)
            if (
                _normalize_actor(item.actor) in self.codex_actors
                and created is not None
                and trigger_time is not None
                and created >= trigger_time
                and _CODEX_USAGE_LIMIT_RE.search(item.body or "")
            ):
                matches.append(item)

        if len(matches) > 1:
            raise GitHubWebhookError("Codex usage-limit evidence is ambiguous")
        if not matches:
            return False

        evidence = matches[0]
        if evidence.comment_id == view.automated_review_trigger_comment_id:
            raise GitHubWebhookError("Codex usage-limit evidence collides with trigger")

        mark_codex_review_unavailable(
            session,
            publication_id,
            run_id=view.automated_review_run_id,
            reviewed_head_sha=view.automated_review_head_sha,
            reason=f"CODEX_PROVIDER_USAGE_LIMIT:{evidence.comment_id}",
        )
        return True

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

        review = matches[0]
        actor = _normalize_actor(review.actor)
        if actor not in self.human_review_actors:
            return "NON_HUMAN_REVIEW_ACTOR"
        if review.commit_id != view.remote_head_sha:
            return "STALE_HUMAN_REVIEW"

        state = review.state.strip().upper()
        if state == "APPROVED":
            decision = ReviewDecision.APPROVED
        elif state in {"CHANGES_REQUESTED", "REQUEST_CHANGES"}:
            decision = ReviewDecision.CHANGES_REQUIRED
        else:
            return "NON_DECISION_HUMAN_REVIEW"

        try:
            record_review(
                session,
                publication_id,
                reviewed_head_sha=review.commit_id,
                decision=decision,
                require_codex_review=(self.codex_review_mode == "required"),
            )
        except DomainError as exc:
            raise GitHubWebhookDeferred(str(exc)) from exc
        return "HUMAN_" + decision.value

    def _mergeability_if_ready(
        self,
        session: Session,
        publication_id: str,
        *,
        pull,
    ) -> str:
        view = get_view(session, publication_id)
        if view.state is not PublicationState.APPROVED:
            return "MERGEABILITY_NOT_ELIGIBLE"
        if pull.head_sha != view.remote_head_sha:
            return "STALE_MERGEABILITY"
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
        if (
            view.state is not PublicationState.IN_REVIEW
            or required_review_adjudication(session, publication_id) is None
            or view.pull_request_number is None
            or view.remote_head_sha is None
        ):
            return "HUMAN_NOT_ELIGIBLE"
        if not self.human_review_actors:
            return "HUMAN_ACTOR_ALLOWLIST_EMPTY"

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
            return "HUMAN_REVIEW_NOT_FOUND"

        candidates.sort(
            key=lambda item: (_parse_time(item.submitted_at) or datetime.min.replace(tzinfo=timezone.utc), item.review_id)
        )
        selected = candidates[-1]
        decision = (
            ReviewDecision.APPROVED
            if selected.state.strip().upper() == "APPROVED"
            else ReviewDecision.CHANGES_REQUIRED
        )
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
            return "SYNCHRONIZE_MATCHED"

        if pull.head_sha != view.remote_head_sha:
            sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=row.delivery_id,
                state="STALE",
            )
            return "STALE_HEAD"

        if row.event_name == "issue_comment":
            raw_comment = row.payload.get("comment")
            comment_id = None
            if isinstance(raw_comment, Mapping):
                try:
                    comment_id = int(raw_comment.get("id"))
                except (TypeError, ValueError):
                    comment_id = None
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

        if row.event_name == "pull_request" and row.action == "closed":
            try:
                MergeCoordinator(
                    token_provider=self.token_provider,
                    github=self.github,
                ).reconcile(session, publication_id)
            except (MergeError, DomainError) as exc:
                raise GitHubWebhookError("closed PR reconciliation failed closed") from exc
            return "PULL_CLOSED_RECONCILED"

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
        watches = list(
            session.scalars(
                select(ReviewWatchRow).where(
                    ReviewWatchRow.repository == row.repository,
                    ReviewWatchRow.state == "ACTIVE",
                )
            )
        )
        for watch_row in watches:
            view = get_view(session, watch_row.publication_id)
            candidate = view.current_candidate
            if (
                view.base_branch == branch
                and candidate is not None
                and current_sha is not None
                and candidate.base_sha != current_sha
                and view.state is not PublicationState.MERGED
            ):
                watch_row.state = "STALE"
                watch_row.next_role = "CONTROL_PLANE"
                watch_row.next_action = "BLOCKED"
                watch_row.last_delivery_id = row.delivery_id
                watch_row.last_reconciled_at = _utcnow()
                stale += 1
        session.commit()
        return f"BASE_PUSH_STALE:{stale}"

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
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=None,
                outcome=outcome,
                next_role="CONTROL_PLANE",
                next_action="BLOCKED" if "STALE:" in outcome and not outcome.endswith(":0") else "DONE",
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
            watch = sync_review_watch(
                session,
                publication_id,
                expected_actors=self.expected_actors,
                last_delivery_id=delivery_id,
                state=("STALE" if outcome == "STALE_HEAD" else None),
            )
            mark_delivery_processed(session, delivery_id)
            return WebhookProcessResult(
                delivery_id=delivery_id,
                publication_id=publication_id,
                outcome=outcome,
                next_role=watch.next_role if outcome != "STALE_HEAD" else "CONTROL_PLANE",
                next_action=watch.next_action if outcome != "STALE_HEAD" else "BLOCKED",
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
        except (GitHubAuthError, GitHubApiError, CodexReviewError, GitHubWebhookError) as exc:
            mark_delivery_retry(session, delivery_id, str(exc))
            raise

    def reconcile_pending(self, session: Session) -> tuple[WebhookProcessResult, ...]:
        results = []
        for delivery_id in list_pending_delivery_ids(session):
            results.append(self.process_delivery(session, delivery_id))
        return tuple(results)
