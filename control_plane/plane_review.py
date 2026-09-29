from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .domain import AutomatedReviewStatus, DomainError, EventType, PublicationState
from .github_api import GitHubApiError, GitHubRepositoryGateway
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .models import PublicationRow
from .repository import append_event, load_events
from .service import get_view

_PROVIDER = "PLANE_REVIEW"
_RUN_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RESERVED_AUTOMATION_MENTION = re.compile(r"(?i)(?<![A-Za-z0-9_])@codex\b")
_ALLOWED_REVIEWER_KINDS = {"PRINCIPAL_REVIEWER", "FALLBACK_REVIEWER"}


class PlaneReviewError(RuntimeError):
    pass


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_text(value: str, field: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise DomainError(f"{field} is required and bounded")
    if _RESERVED_AUTOMATION_MENTION.search(normalized):
        raise DomainError(f"{field} contains a reserved automation mention")
    return normalized


def _lock_publication(session: Session, publication_id: str) -> None:
    row = session.scalar(
        select(PublicationRow)
        .where(PublicationRow.id == publication_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise KeyError(publication_id)


def _event_for_run(
    session: Session,
    publication_id: str,
    event_type: EventType,
    run_id: str,
) -> dict[str, Any] | None:
    matches = [
        event["payload"]
        for event in load_events(session, publication_id)
        if event["event_type"] == event_type.value
        and event["payload"].get("run_id") == run_id
    ]
    if len(matches) > 1:
        raise DomainError("Plane review ledger contains duplicate run events")
    return matches[0] if matches else None


def _normalize_comments(comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(comments) > 200:
        raise DomainError("Plane review supports at most 200 findings")
    normalized: list[dict[str, Any]] = []
    finding_ids: set[str] = set()
    identities: set[str] = set()
    positions: set[tuple[str, int, str]] = set()
    for raw in comments:
        finding_id = _safe_text(str(raw.get("finding_id") or ""), "finding id", 200)
        identity = _safe_text(
            str(raw.get("normalized_identity") or ""),
            "finding normalized identity",
            500,
        )
        priority = str(raw.get("priority") or "").strip().upper()
        path = _safe_text(str(raw.get("path") or ""), "finding path", 500)
        body = _safe_text(str(raw.get("body") or ""), "finding body", 4000)
        side = str(raw.get("side") or "").strip().upper()
        line = raw.get("line")
        if priority not in {"P0", "P1", "P2", "P3", "P4"}:
            raise DomainError("finding priority is invalid")
        if side not in {"LEFT", "RIGHT"}:
            raise DomainError("finding side must be LEFT or RIGHT")
        if not isinstance(line, int) or line <= 0:
            raise DomainError("finding line must be a positive integer")
        if finding_id in finding_ids or identity in identities:
            raise DomainError("Plane review finding identity is duplicated")
        position = (path, line, side)
        if position in positions:
            raise DomainError("Plane review contains duplicate inline positions")
        finding_ids.add(finding_id)
        identities.add(identity)
        positions.add(position)
        normalized.append(
            {
                "finding_id": finding_id,
                "normalized_identity": identity,
                "priority": priority,
                "path": path,
                "line": line,
                "side": side,
                "body": body,
            }
        )
    return sorted(normalized, key=lambda item: item["finding_id"])


def record_plane_review(
    session: Session,
    publication_id: str,
    *,
    run_id: str,
    reviewer_kind: str,
    reviewer: str,
    reviewed_head_sha: str,
    body: str,
    comments: list[dict[str, Any]],
    idempotency_key: str,
) -> dict[str, Any]:
    normalized_run = run_id.strip()
    if not _RUN_RE.fullmatch(normalized_run):
        raise DomainError("Plane review run id is invalid")
    normalized_kind = reviewer_kind.strip().upper()
    if normalized_kind not in _ALLOWED_REVIEWER_KINDS:
        raise DomainError("Plane review reviewer kind is invalid")
    normalized_reviewer = _safe_text(reviewer, "Plane review reviewer", 200)
    normalized_body = _safe_text(body, "Plane review body", 4000)
    normalized_key = _safe_text(idempotency_key, "Plane review idempotency key", 200)
    head = reviewed_head_sha.lower()
    if not _SHA_RE.fullmatch(head):
        raise DomainError("Plane review head must be an exact 40-hex Git SHA")
    normalized_comments = _normalize_comments(comments)

    payload = {
        "run_id": normalized_run,
        "provider": _PROVIDER,
        "reviewer_kind": normalized_kind,
        "reviewer": normalized_reviewer,
        "head_sha": head,
        "body": normalized_body,
        "comments": normalized_comments,
        "idempotency_key": normalized_key,
    }

    _lock_publication(session, publication_id)
    view = get_view(session, publication_id)
    if (
        view.state is not PublicationState.IN_REVIEW
        or view.remote_head_sha != head
        or view.pull_request_number is None
    ):
        raise DomainError("Plane review must target the current published PR head")
    if view.automated_review_status is AutomatedReviewStatus.RUNNING:
        raise DomainError("Plane review cannot start while automated review is running")

    for event in load_events(session, publication_id):
        if event["event_type"] != EventType.PLANE_REVIEW_RECORDED.value:
            continue
        prior = event["payload"]
        if (
            prior.get("run_id") == normalized_run
            or prior.get("idempotency_key") == normalized_key
        ):
            if _canonical(prior) != _canonical(payload):
                raise DomainError("Plane review run/idempotency identity conflicts")
            session.commit()
            return prior

    if _event_for_run(
        session,
        publication_id,
        EventType.PLANE_REVIEW_MATERIALIZED,
        normalized_run,
    ) is not None:
        raise DomainError("Plane review materialization exists without matching recorded review")

    append_event(session, publication_id, EventType.PLANE_REVIEW_RECORDED, payload)
    session.commit()
    return payload


def complete_plane_review_materialization(
    session: Session,
    publication_id: str,
    *,
    run_id: str,
    provider_review_id: int,
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    _lock_publication(session, publication_id)
    recorded = _event_for_run(
        session,
        publication_id,
        EventType.PLANE_REVIEW_RECORDED,
        run_id,
    )
    if recorded is None:
        raise DomainError("Plane review must be recorded before materialization")
    existing = _event_for_run(
        session,
        publication_id,
        EventType.PLANE_REVIEW_MATERIALIZED,
        run_id,
    )

    view = get_view(session, publication_id)
    if (
        view.state is not PublicationState.IN_REVIEW
        or view.remote_head_sha != recorded["head_sha"]
        or view.pull_request_number is None
    ):
        raise DomainError("Plane review materialization is stale for the current PR head")
    if view.automated_review_status is AutomatedReviewStatus.RUNNING:
        raise DomainError("Plane review materialization is locked by automated review")
    if provider_review_id <= 0:
        raise DomainError("Plane review provider review id must be positive")

    by_finding: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        finding_id = str(receipt.get("finding_id") or "")
        comment_id = receipt.get("provider_comment_id")
        review_id = receipt.get("provider_review_id")
        if (
            finding_id in by_finding
            or not isinstance(comment_id, int)
            or comment_id <= 0
            or review_id != provider_review_id
        ):
            raise DomainError("Plane review materialization receipts are inconsistent")
        by_finding[finding_id] = receipt

    recorded_findings = {item["finding_id"]: item for item in recorded["comments"]}
    if set(by_finding) != set(recorded_findings):
        raise DomainError("Plane review materialization receipts do not match recorded findings")

    findings = []
    for finding_id in sorted(recorded_findings):
        source = recorded_findings[finding_id]
        receipt = by_finding[finding_id]
        if (
            receipt.get("path") != source["path"]
            or receipt.get("line") != source["line"]
        ):
            raise DomainError("Plane review GitHub receipt position differs from recorded finding")
        findings.append(
            {
                "finding_id": source["finding_id"],
                "normalized_identity": source["normalized_identity"],
                "priority": source["priority"],
                "provider_comment_id": int(receipt["provider_comment_id"]),
                "provider_review_id": provider_review_id,
                "path": source["path"],
                "line": source["line"],
                "side": source["side"],
                "body": source["body"],
            }
        )

    payload = {
        "run_id": recorded["run_id"],
        "provider": _PROVIDER,
        "reviewer_kind": recorded["reviewer_kind"],
        "reviewer": recorded["reviewer"],
        "head_sha": recorded["head_sha"],
        "result": "CHANGES_REQUIRED" if findings else "PASS",
        "findings_count": len(findings),
        "findings": findings,
        "provider_review_ids": [provider_review_id],
        "provider_comment_ids": [
            int(item["provider_comment_id"]) for item in findings
        ],
    }
    if existing is not None:
        if _canonical(existing) != _canonical(payload):
            raise DomainError("Plane review materialization conflicts with existing receipt")
        session.commit()
        return existing

    append_event(session, publication_id, EventType.PLANE_REVIEW_MATERIALIZED, payload)
    session.commit()
    return payload


class PlaneReviewPublisher:
    def __init__(
        self,
        *,
        token_provider: GitHubAppTokenProvider,
        github: GitHubRepositoryGateway,
    ) -> None:
        self.token_provider = token_provider
        self.github = github

    @staticmethod
    def _review_marker(run_id: str, head_sha: str) -> str:
        return (
            "<!-- firstcontact-control-plane:plane-review "
            f"run={run_id} head={head_sha} -->"
        )

    @staticmethod
    def _finding_marker(run_id: str, finding_id: str) -> str:
        key = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:24]
        return (
            "<!-- firstcontact-control-plane:plane-review-finding "
            f"run={run_id} finding={key} -->"
        )

    def _recover(
        self,
        *,
        repository: str,
        pull_number: int,
        head_sha: str,
        run_id: str,
        comments: list[dict[str, Any]],
        token: str,
        bot_login: str,
    ) -> tuple[int, list[dict[str, Any]]] | None:
        review_marker = self._review_marker(run_id, head_sha)
        reviews = [
            item
            for item in self.github.list_pull_reviews(repository, pull_number, token)
            if review_marker in item.body
        ]
        if len(reviews) > 1:
            raise PlaneReviewError("multiple GitHub reviews match one Plane review run")
        if not reviews:
            return None
        review = reviews[0]
        if (
            review.actor.strip().lower() != bot_login.strip().lower()
            or review.commit_id != head_sha
            or review.state.strip().upper() != "COMMENTED"
        ):
            raise PlaneReviewError("existing Plane review identity is ambiguous")

        remote_comments = self.github.list_pull_review_comments(
            repository,
            pull_number,
            token,
        )
        receipts: list[dict[str, Any]] = []
        for source in comments:
            marker = self._finding_marker(run_id, source["finding_id"])
            matches = [
                item
                for item in remote_comments
                if marker in item.body
            ]
            if len(matches) != 1:
                raise PlaneReviewError(
                    "Plane review finding comment readback is missing or ambiguous"
                )
            item = matches[0]
            if (
                item.actor.strip().lower() != bot_login.strip().lower()
                or item.review_id != review.review_id
                or item.commit_id != head_sha
                or item.path != source["path"]
                or item.line != source["line"]
            ):
                raise PlaneReviewError("Plane review finding receipt identity changed")
            receipts.append(
                {
                    "finding_id": source["finding_id"],
                    "provider_review_id": review.review_id,
                    "provider_comment_id": item.comment_id,
                    "path": item.path,
                    "line": item.line,
                }
            )
        return review.review_id, receipts

    def materialize(
        self,
        session: Session,
        publication_id: str,
        run_id: str,
    ) -> dict[str, Any]:
        recorded = _event_for_run(
            session,
            publication_id,
            EventType.PLANE_REVIEW_RECORDED,
            run_id,
        )
        if recorded is None:
            raise DomainError("Plane review run is not recorded")
        existing = _event_for_run(
            session,
            publication_id,
            EventType.PLANE_REVIEW_MATERIALIZED,
            run_id,
        )
        if existing is not None:
            return existing

        view = get_view(session, publication_id)
        if (
            view.state is not PublicationState.IN_REVIEW
            or view.remote_head_sha != recorded["head_sha"]
            or view.pull_request_number is None
        ):
            raise PlaneReviewError("Plane review is stale for the current published PR")
        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            raise PlaneReviewError("Plane review is locked by an active automated review")

        try:
            access = self.token_provider.installation_access(
                view.repository,
                permissions={"pull_requests": "write"},
            )
            bot_login = self.token_provider.bot_login()
            pull = self.github.pull_request(
                view.repository,
                view.pull_request_number,
                access.token,
            )
            if (
                pull.number != view.pull_request_number
                or pull.state != "open"
                or pull.head_sha != recorded["head_sha"]
                or pull.head_ref != view.remote_branch
                or pull.base_ref != view.base_branch
            ):
                raise PlaneReviewError("canonical pull request changed before Plane review")

            recovered = self._recover(
                repository=view.repository,
                pull_number=view.pull_request_number,
                head_sha=recorded["head_sha"],
                run_id=run_id,
                comments=recorded["comments"],
                token=access.token,
                bot_login=bot_login,
            )
            if recovered is None:
                wire_comments = [
                    {
                        "path": item["path"],
                        "line": item["line"],
                        "side": item["side"],
                        "body": (
                            f"{item['body']}\n\n"
                            f"{self._finding_marker(run_id, item['finding_id'])}"
                        ),
                    }
                    for item in recorded["comments"]
                ]
                review_body = (
                    f"{recorded['body']}\n\n"
                    f"{self._review_marker(run_id, recorded['head_sha'])}"
                )
                try:
                    self.github.create_pull_review(
                        view.repository,
                        view.pull_request_number,
                        commit_id=recorded["head_sha"],
                        body=review_body,
                        comments=wire_comments,
                        token=access.token,
                    )
                except GitHubApiError:
                    pass

                recovered = self._recover(
                    repository=view.repository,
                    pull_number=view.pull_request_number,
                    head_sha=recorded["head_sha"],
                    run_id=run_id,
                    comments=recorded["comments"],
                    token=access.token,
                    bot_login=bot_login,
                )
                if recovered is None:
                    raise PlaneReviewError(
                        "Plane review write could not be recovered from GitHub"
                    )

            review_id, receipts = recovered
            return complete_plane_review_materialization(
                session,
                publication_id,
                run_id=run_id,
                provider_review_id=review_id,
                receipts=receipts,
            )
        except (GitHubApiError, GitHubAuthError) as exc:
            raise PlaneReviewError("Plane review publication failed closed") from exc
