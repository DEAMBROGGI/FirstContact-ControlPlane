from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .domain import DomainError
from .models import (
    CandidateRow,
    PRFindingReconciliationRow,
    PublicationRow,
    RemediationWorkPackageRow,
)
from .service import get_view

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha(value: Any, name: str, *, optional: bool = False) -> str | None:
    if optional and value in (None, ""):
        return None
    if not isinstance(value, str):
        raise DomainError(f"GitHub {name} is missing or invalid")
    normalized = value.lower()
    if not _SHA_RE.fullmatch(normalized):
        raise DomainError(f"GitHub {name} is missing or invalid")
    return normalized


def _datetime_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _validate_snapshot(row: PRFindingReconciliationRow) -> dict[str, Any]:
    evidence = row.evidence
    if not isinstance(evidence, dict):
        raise DomainError("PR finding reconciliation evidence is corrupt")
    bound_fields = {
        "reconciliation_id": row.id,
        "publication_id": row.publication_id,
        "sequence": row.sequence,
        "repository": row.repository,
        "pull_request_number": row.pull_request_number,
        "remote_head_sha": row.remote_head_sha,
        "remote_branch": row.remote_branch,
        "base_branch": row.base_branch,
        "base_sha": row.base_sha,
        "observed_at": _datetime_iso(row.observed_at),
    }
    if any(evidence.get(key) != value for key, value in bound_fields.items()):
        raise DomainError("PR finding reconciliation binding is corrupt")
    if (
        not _DIGEST_RE.fullmatch(row.evidence_sha256)
        or _digest(evidence) != row.evidence_sha256
        or not isinstance(evidence.get("threads"), list)
    ):
        raise DomainError("PR finding reconciliation digest or inventory is corrupt")
    return evidence


def _reconciliation_rows(
    session: Session,
    publication_id: str,
) -> list[PRFindingReconciliationRow]:
    rows = list(
        session.scalars(
            select(PRFindingReconciliationRow)
            .where(PRFindingReconciliationRow.publication_id == publication_id)
            .order_by(PRFindingReconciliationRow.sequence.asc())
        )
    )
    for expected_sequence, row in enumerate(rows, start=1):
        if row.sequence != expected_sequence:
            raise DomainError("PR finding reconciliation sequence is corrupt")
        _validate_snapshot(row)
    return rows


def latest_reconciliation(
    session: Session,
    publication_id: str,
) -> PRFindingReconciliationRow | None:
    rows = _reconciliation_rows(session, publication_id)
    return rows[-1] if rows else None


def reconciliation_receipt(
    session: Session,
    reconciliation_id: str,
) -> tuple[PRFindingReconciliationRow, dict[str, Any]]:
    row = session.get(PRFindingReconciliationRow, reconciliation_id)
    if row is None:
        raise KeyError(reconciliation_id)
    rows = _reconciliation_rows(session, row.publication_id)
    if row not in rows:
        raise DomainError("PR finding reconciliation receipt is not in its ledger")
    return row, _validate_snapshot(row)


def current_reconciliation(
    session: Session,
    publication_id: str,
) -> PRFindingReconciliationRow | None:
    view = get_view(session, publication_id)
    row = latest_reconciliation(session, publication_id)
    if row is None:
        return None
    candidate = view.current_candidate
    if (
        candidate is None
        or row.publication_id != publication_id
        or row.repository != view.repository
        or row.pull_request_number != view.pull_request_number
        or row.remote_head_sha != view.remote_head_sha
        or row.remote_branch != view.remote_branch
        or row.base_branch != view.base_branch
        or row.base_sha != candidate.base_sha
    ):
        return None
    return row


def reconciliation_payload(row: PRFindingReconciliationRow) -> dict[str, Any]:
    evidence = _validate_snapshot(row)
    return {
        **evidence,
        "evidence_sha256": row.evidence_sha256,
    }


def _provider_ids(value: Any, name: str) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise DomainError(f"GitHub {name} identity is missing")
    ids: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise DomainError(f"GitHub {name} identity is invalid")
        ids.append(item)
    if len(ids) != len(set(ids)):
        raise DomainError(f"GitHub {name} identity is duplicated")
    return tuple(ids)


def _ownership_by_thread(
    session: Session,
    publication_id: str,
    threads: list[dict[str, Any]],
) -> dict[str, list[tuple[str, str]]]:
    from .remediation import get_work_package

    thread_by_id = {thread["thread_node_id"]: thread for thread in threads}
    thread_by_comment = {
        comment_id: thread["thread_node_id"]
        for thread in threads
        for comment_id in thread["comment_ids"]
    }
    owners: dict[str, set[tuple[str, str]]] = {
        thread_id: set() for thread_id in thread_by_id
    }
    package_ids = session.scalars(
        select(RemediationWorkPackageRow.id)
        .where(RemediationWorkPackageRow.publication_id == publication_id)
        .order_by(RemediationWorkPackageRow.created_at, RemediationWorkPackageRow.id)
    )
    for work_package_id in package_ids:
        package = get_work_package(session, work_package_id)
        if package.publication_id != publication_id:
            raise DomainError("remediation finding ownership is corrupt")
        for finding in package.findings:
            source = finding.get("source")
            if not isinstance(source, dict):
                raise DomainError("remediation finding source is corrupt")
            provider_comment_id = source.get("provider_thread_id")
            provider_thread_node_id = source.get("provider_thread_node_id")
            matched_thread_id = None
            if provider_thread_node_id is not None:
                if not isinstance(provider_thread_node_id, str):
                    raise DomainError("remediation thread node identity is corrupt")
                thread = thread_by_id.get(provider_thread_node_id)
                if thread is not None:
                    if provider_comment_id not in thread["comment_ids"]:
                        raise DomainError("remediation thread comment ownership is ambiguous")
                    matched_thread_id = provider_thread_node_id
            if provider_comment_id is not None:
                if isinstance(provider_comment_id, bool) or not isinstance(
                    provider_comment_id, int
                ):
                    raise DomainError("remediation thread comment identity is corrupt")
                comment_thread_id = thread_by_comment.get(provider_comment_id)
                if (
                    matched_thread_id is not None
                    and comment_thread_id != matched_thread_id
                ):
                    raise DomainError("remediation thread comment ownership is ambiguous")
                if (
                    provider_thread_node_id is not None
                    and comment_thread_id is not None
                    and provider_thread_node_id != comment_thread_id
                ):
                    raise DomainError("remediation thread node ownership is ambiguous")
                if comment_thread_id is not None:
                    matched_thread_id = comment_thread_id
            if matched_thread_id is not None:
                owners[matched_thread_id].add(
                    (work_package_id, str(finding.get("finding_id") or ""))
                )

    result: dict[str, list[tuple[str, str]]] = {}
    for thread_id, finding_owners in owners.items():
        if len(finding_owners) > 1:
            raise DomainError("GitHub review thread has ambiguous Plane ownership")
        result[thread_id] = sorted(finding_owners)
    return result


def _review_comment_evidence(
    *,
    github: Any,
    repository: str,
    pull_number: int,
    token: str,
) -> tuple[list[dict[str, Any]], int]:
    reviews = github.list_pull_reviews(repository, pull_number, token)
    comments = github.list_pull_review_comments(repository, pull_number, token)
    provider_threads = github.list_pull_review_threads(repository, pull_number, token)
    if not isinstance(reviews, list) or not isinstance(comments, list) or not isinstance(
        provider_threads, list
    ):
        raise DomainError("GitHub review evidence is malformed")

    reviews_by_id: dict[int, Any] = {}
    for review in reviews:
        review_id = getattr(review, "review_id", None)
        actor = getattr(review, "actor", None)
        state = getattr(review, "state", None)
        if (
            isinstance(review_id, bool)
            or not isinstance(review_id, int)
            or review_id <= 0
            or not isinstance(actor, str)
            or not actor.strip()
            or not isinstance(state, str)
            or not state.strip()
            or review_id in reviews_by_id
        ):
            raise DomainError("GitHub review receipt is missing or ambiguous")
        _sha(getattr(review, "commit_id", None), "reviewed commit", optional=True)
        reviews_by_id[review_id] = review

    comments_by_id: dict[int, Any] = {}
    for comment in comments:
        comment_id = getattr(comment, "comment_id", None)
        actor = getattr(comment, "actor", None)
        body = getattr(comment, "body", None)
        path = getattr(comment, "path", None)
        line = getattr(comment, "line", None)
        side = getattr(comment, "side", None)
        if (
            isinstance(comment_id, bool)
            or not isinstance(comment_id, int)
            or comment_id <= 0
            or not isinstance(actor, str)
            or not actor.strip()
            or not isinstance(body, str)
            or not isinstance(path, str)
            or not path.strip()
            or (
                line is not None
                and (
                    isinstance(line, bool)
                    or not isinstance(line, int)
                    or line <= 0
                )
            )
            or (side is not None and not isinstance(side, str))
            or comment_id in comments_by_id
        ):
            raise DomainError("GitHub review comment receipt is missing or ambiguous")
        _sha(getattr(comment, "commit_id", None), "comment commit", optional=True)
        if side is not None and side.strip().upper() not in {"LEFT", "RIGHT"}:
            raise DomainError("GitHub review comment side is invalid")
        comments_by_id[comment_id] = comment

    thread_evidence: list[dict[str, Any]] = []
    all_thread_comment_ids: set[int] = set()
    thread_ids: set[str] = set()
    unresolved_threads = 0
    for provider_thread in provider_threads:
        thread_id = getattr(provider_thread, "thread_node_id", None)
        is_resolved = getattr(provider_thread, "is_resolved", None)
        try:
            comment_ids = _provider_ids(
                getattr(provider_thread, "comment_ids", None),
                "thread comment",
            )
            root_comment_id = getattr(provider_thread, "root_comment_id", None)
        except DomainError:
            raise
        if (
            not isinstance(thread_id, str)
            or not thread_id.strip()
            or thread_id in thread_ids
            or not isinstance(is_resolved, bool)
            or root_comment_id != comment_ids[0]
        ):
            raise DomainError("GitHub review thread identity is missing or ambiguous")
        thread_ids.add(thread_id)
        if any(comment_id not in comments_by_id for comment_id in comment_ids):
            raise DomainError("GitHub review thread comment receipt is missing")
        if all_thread_comment_ids.intersection(comment_ids):
            raise DomainError("GitHub review comment is owned by multiple threads")
        all_thread_comment_ids.update(comment_ids)

        root_comment = comments_by_id[root_comment_id]
        if getattr(root_comment, "in_reply_to_id", None) is not None:
            raise DomainError("GitHub review thread root comment is ambiguous")
        review_id = getattr(root_comment, "review_id", None)
        if isinstance(review_id, bool) or not isinstance(review_id, int) or review_id <= 0:
            raise DomainError("GitHub review thread source review is missing")
        review = reviews_by_id.get(review_id)
        if review is None:
            raise DomainError("GitHub review thread source review receipt is missing")
        source_actor = root_comment.actor.strip()
        review_actor = review.actor.strip()
        if source_actor.casefold() != review_actor.casefold():
            raise DomainError("GitHub review thread source actor is ambiguous")
        for comment_id in comment_ids[1:]:
            parent_id = getattr(comments_by_id[comment_id], "in_reply_to_id", None)
            if parent_id is not None and parent_id not in comment_ids:
                raise DomainError("GitHub review thread reply ownership is ambiguous")

        if is_resolved:
            continue
        unresolved_threads += 1
        body = root_comment.body
        body_digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        reviewed_head = _sha(
            getattr(review, "commit_id", None),
            "source reviewed head",
            optional=True,
        )
        comment_head = _sha(
            getattr(root_comment, "commit_id", None),
            "source comment head",
            optional=True,
        )
        line = root_comment.line
        side = root_comment.side
        if line is not None and line <= 0:
            raise DomainError("GitHub review comment line is invalid")
        if side is not None and side.strip().upper() not in {"LEFT", "RIGHT"}:
            raise DomainError("GitHub review comment side is invalid")
        thread_evidence.append(
            {
                "thread_node_id": thread_id,
                "is_resolved": False,
                "comment_ids": list(comment_ids),
                "root_comment_id": root_comment_id,
                "provider_review_id": review_id,
                "source_actor": source_actor,
                "source_review_actor": review_actor,
                "source_review_state": str(review.state).strip().upper(),
                "source_reviewed_head_sha": reviewed_head,
                "source_comment_commit_sha": comment_head,
                "path": root_comment.path,
                "line": line,
                "side": side.strip().upper() if side is not None else None,
                "body": body[:4000],
                "body_sha256": body_digest,
            }
        )

    if all_thread_comment_ids != set(comments_by_id):
        raise DomainError("GitHub pull review comment ownership is incomplete")
    thread_evidence.sort(
        key=lambda item: (item["root_comment_id"], item["thread_node_id"])
    )
    return thread_evidence, unresolved_threads


def reconcile_pr_findings(
    session: Session,
    publication_id: str,
    *,
    github: Any,
    token: str,
) -> dict[str, Any]:
    publication = session.scalar(
        select(PublicationRow)
        .where(PublicationRow.id == publication_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if publication is None:
        raise KeyError(publication_id)
    view = get_view(session, publication_id)
    candidate_identity = view.current_candidate
    if (
        publication.repository != view.repository
        or view.pull_request_number is None
        or view.remote_head_sha is None
        or view.remote_branch is None
        or view.base_branch is None
        or candidate_identity is None
        or candidate_identity.head_sha != view.remote_head_sha
    ):
        raise DomainError("PR finding reconciliation requires current governed PR metadata")
    candidate = session.get(CandidateRow, candidate_identity.candidate_id)
    if (
        candidate is None
        or candidate.publication_id != publication_id
        or candidate.base_sha != candidate_identity.base_sha
        or candidate.head_sha != candidate_identity.head_sha
        or candidate.tree_sha != candidate_identity.tree_sha
        or candidate.profile_id != candidate_identity.profile_id
        or candidate.profile_version != candidate_identity.profile_version
        or candidate.profile_digest != candidate_identity.profile_digest
    ):
        raise DomainError("current candidate identity is corrupt")

    pull = github.pull_request(
        view.repository,
        view.pull_request_number,
        token,
    )
    if (
        pull.number != view.pull_request_number
        or pull.head_ref != view.remote_branch
        or pull.base_ref != view.base_branch
        or pull.head_sha.lower() != view.remote_head_sha
    ):
        raise DomainError("canonical PR identity or head drifted during reconciliation")
    pull_base_sha = _sha(pull.base_sha, "pull request base SHA")
    remote_base_sha = _sha(
        github.ref_sha(view.repository, view.base_branch, token),
        "base branch SHA",
    )
    if (
        pull_base_sha != candidate.base_sha
        or remote_base_sha != candidate.base_sha
    ):
        raise DomainError("canonical PR base drifted from the admitted candidate")

    open_threads, unresolved_count = _review_comment_evidence(
        github=github,
        repository=view.repository,
        pull_number=view.pull_request_number,
        token=token,
    )
    owners = _ownership_by_thread(session, publication_id, open_threads)
    for thread in open_threads:
        finding_owners = owners[thread["thread_node_id"]]
        if finding_owners:
            work_package_id, finding_id = finding_owners[0]
            thread["classification"] = "TRACKED"
            thread["work_package_id"] = work_package_id
            thread["finding_id"] = finding_id
        else:
            thread["classification"] = "ORPHAN"

    current_view = get_view(session, publication_id)
    final_pull = github.pull_request(
        current_view.repository,
        current_view.pull_request_number,
        token,
    )
    final_base_sha = _sha(
        github.ref_sha(current_view.repository, current_view.base_branch, token),
        "base branch SHA",
    )
    if (
        current_view.remote_head_sha != view.remote_head_sha
        or current_view.remote_branch != view.remote_branch
        or current_view.base_branch != view.base_branch
        or current_view.pull_request_number != view.pull_request_number
        or final_pull.number != view.pull_request_number
        or final_pull.head_ref != view.remote_branch
        or final_pull.base_ref != view.base_branch
        or final_pull.head_sha.lower() != view.remote_head_sha
        or _sha(final_pull.base_sha, "pull request base SHA") != candidate.base_sha
        or final_base_sha != candidate.base_sha
    ):
        raise DomainError("canonical PR identity or base drifted during reconciliation")

    latest = latest_reconciliation(session, publication_id)
    sequence = 1 if latest is None else latest.sequence + 1
    observed_at = datetime.now(timezone.utc)
    reconciliation_id = str(uuid.uuid4())
    evidence = {
        "reconciliation_id": reconciliation_id,
        "publication_id": publication_id,
        "sequence": sequence,
        "repository": view.repository,
        "pull_request_number": view.pull_request_number,
        "remote_head_sha": view.remote_head_sha,
        "remote_branch": view.remote_branch,
        "base_branch": view.base_branch,
        "base_sha": candidate.base_sha,
        "observed_at": observed_at.isoformat(),
        "unresolved_thread_count": unresolved_count,
        "threads": open_threads,
    }
    row = PRFindingReconciliationRow(
        id=reconciliation_id,
        publication_id=publication_id,
        sequence=sequence,
        repository=view.repository,
        pull_request_number=view.pull_request_number,
        remote_head_sha=view.remote_head_sha,
        remote_branch=view.remote_branch,
        base_branch=view.base_branch,
        base_sha=candidate.base_sha,
        observed_at=observed_at,
        evidence=evidence,
        evidence_sha256=_digest(evidence),
    )
    session.add(row)
    session.commit()
    return reconciliation_payload(row)