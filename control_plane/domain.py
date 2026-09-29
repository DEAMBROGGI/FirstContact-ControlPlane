from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping


class DomainError(ValueError):
    pass


class PublicationState(StrEnum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    ADMITTED = "ADMITTED"
    IN_REVIEW = "IN_REVIEW"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"
    APPROVED = "APPROVED"
    READY_TO_MERGE = "READY_TO_MERGE"
    MERGED = "MERGED"
    SUPERSEDED = "SUPERSEDED"


class EventType(StrEnum):
    PUBLICATION_CREATED = "PUBLICATION_CREATED"
    CANDIDATE_SUBMITTED = "CANDIDATE_SUBMITTED"
    VALIDATION_RECORDED = "VALIDATION_RECORDED"
    CANDIDATE_ADMITTED = "CANDIDATE_ADMITTED"
    CANDIDATE_REJECTED = "CANDIDATE_REJECTED"
    REMOTE_PUBLISHED = "REMOTE_PUBLISHED"
    CODEX_REVIEW_REQUESTED = "CODEX_REVIEW_REQUESTED"
    CODEX_REVIEW_TRIGGERED = "CODEX_REVIEW_TRIGGERED"
    CODEX_REVIEW_COMPLETED = "CODEX_REVIEW_COMPLETED"
    CODEX_REVIEW_UNAVAILABLE = "CODEX_REVIEW_UNAVAILABLE"
    PLANE_REVIEW_RECORDED = "PLANE_REVIEW_RECORDED"
    PLANE_REVIEW_MATERIALIZED = "PLANE_REVIEW_MATERIALIZED"
    REMEDIATION_CLEARED = "REMEDIATION_CLEARED"
    REVIEW_RECORDED = "REVIEW_RECORDED"
    MERGEABILITY_RECORDED = "MERGEABILITY_RECORDED"
    MERGED = "MERGED"
    MERGE_POLICY_VIOLATION = "MERGE_POLICY_VIOLATION"
    PUBLICATION_SUPERSEDED = "PUBLICATION_SUPERSEDED"
class ValidationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


class ReviewDecision(StrEnum):
    APPROVED = "APPROVED"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"


class AutomatedReviewStatus(StrEnum):
    RUNNING = "RUNNING"
    PASS = "PASS"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    candidate_id: str
    base_sha: str
    head_sha: str
    tree_sha: str
    profile_id: str
    profile_version: int
    profile_digest: str


@dataclass(frozen=True, slots=True)
class LifecycleProjection:
    issue: str
    pull_request: str
    project: str


@dataclass(frozen=True, slots=True)
class PublicationView:
    publication_id: str
    repository: str
    issue_number: int
    state: PublicationState
    current_candidate: CandidateIdentity | None
    remote_head_sha: str | None
    remote_branch: str | None
    base_branch: str | None
    pull_request_number: int | None
    automated_reviewer: str | None
    automated_review_run_id: str | None
    automated_review_status: AutomatedReviewStatus | None
    automated_review_head_sha: str | None
    automated_review_trigger_comment_id: int | None
    automated_review_trigger_actor: str | None
    automated_review_triggered_at: str | None
    automated_review_mode: str | None
    automated_review_findings_count: int
    remediation_cleared_review_run_id: str | None
    remediation_cleared_head_sha: str | None
    review_decision: ReviewDecision | None
    mergeable: bool | None
    merge_commit_sha: str | None
    merge_source: str | None
    merge_policy_violation: bool
    projection: LifecycleProjection


def desired_projection(state: PublicationState) -> LifecycleProjection:
    if state is PublicationState.SUPERSEDED:
        status = "Superseded"
    elif state in {PublicationState.VALIDATION_FAILED, PublicationState.CHANGES_REQUIRED}:
        status = "Ready"
    elif state in {
        PublicationState.IN_REVIEW,
        PublicationState.APPROVED,
        PublicationState.READY_TO_MERGE,
    }:
        status = "Review"
    elif state is PublicationState.MERGED:
        status = "Done"
    else:
        status = "In Progress"
    return LifecycleProjection(issue=status, pull_request=status, project=status)
def _candidate(payload: Mapping[str, Any]) -> CandidateIdentity:
    return CandidateIdentity(
        candidate_id=str(payload["candidate_id"]),
        base_sha=str(payload["base_sha"]),
        head_sha=str(payload["head_sha"]),
        tree_sha=str(payload["tree_sha"]),
        profile_id=str(payload["profile_id"]),
        profile_version=int(payload["profile_version"]),
        profile_digest=str(payload["profile_digest"]),
    )


def fold_events(
    publication_id: str,
    events: Iterable[Mapping[str, Any]],
) -> PublicationView:
    repository = ""
    issue_number = 0
    state: PublicationState | None = None
    candidate: CandidateIdentity | None = None
    remote_head: str | None = None
    remote_branch: str | None = None
    base_branch: str | None = None
    pull_request_number: int | None = None
    automated_reviewer: str | None = None
    automated_review_run_id: str | None = None
    automated_review_status: AutomatedReviewStatus | None = None
    automated_review_head_sha: str | None = None
    automated_review_trigger_comment_id: int | None = None
    automated_review_trigger_actor: str | None = None
    automated_review_triggered_at: str | None = None
    automated_review_mode: str | None = None
    automated_review_findings_count = 0
    remediation_cleared_review_run_id: str | None = None
    remediation_cleared_head_sha: str | None = None
    review_decision: ReviewDecision | None = None
    mergeable: bool | None = None
    merge_commit_sha: str | None = None
    merge_source: str | None = None
    merge_policy_violation = False

    for event in events:
        event_type = EventType(event["event_type"])
        payload = event["payload"]
        if state in {PublicationState.MERGED, PublicationState.SUPERSEDED}:
            raise DomainError("event follows terminal publication state")
        if event_type is EventType.PUBLICATION_CREATED:
            repository = str(payload["repository"])
            issue_number = int(payload["issue_number"])
            state = PublicationState.CREATED
        elif event_type is EventType.CANDIDATE_SUBMITTED:
            candidate = _candidate(payload)
            state = PublicationState.VALIDATING
            automated_reviewer = None
            automated_review_run_id = None
            automated_review_status = None
            automated_review_head_sha = None
            automated_review_trigger_comment_id = None
            automated_review_trigger_actor = None
            automated_review_triggered_at = None
            automated_review_mode = None
            automated_review_findings_count = 0
            remediation_cleared_review_run_id = None
            remediation_cleared_head_sha = None
            review_decision = None
            mergeable = None
        elif event_type is EventType.CANDIDATE_ADMITTED:
            state = PublicationState.ADMITTED
        elif event_type is EventType.CANDIDATE_REJECTED:
            state = PublicationState.VALIDATION_FAILED
        elif event_type is EventType.REMOTE_PUBLISHED:
            remote_head = str(payload["head_sha"])
            remote_branch = (
                str(payload["branch"])
                if payload.get("branch") is not None
                else remote_branch
            )
            base_branch = (
                str(payload["base_branch"])
                if payload.get("base_branch") is not None
                else base_branch
            )
            pull_request_number = (
                int(payload["pull_request_number"])
                if payload.get("pull_request_number") is not None
                else pull_request_number
            )
            automated_reviewer = None
            automated_review_run_id = None
            automated_review_status = None
            automated_review_head_sha = None
            automated_review_trigger_comment_id = None
            automated_review_trigger_actor = None
            automated_review_triggered_at = None
            automated_review_mode = None
            automated_review_findings_count = 0
            remediation_cleared_review_run_id = None
            remediation_cleared_head_sha = None
            state = PublicationState.IN_REVIEW
        elif event_type is EventType.CODEX_REVIEW_REQUESTED:
            automated_reviewer = "CODEX_CODE_REVIEW"
            automated_review_run_id = str(payload["run_id"])
            automated_review_status = AutomatedReviewStatus.RUNNING
            automated_review_head_sha = str(payload["head_sha"])
            automated_review_mode = str(payload["mode"])
            automated_review_trigger_comment_id = None
            automated_review_trigger_actor = None
            automated_review_triggered_at = None
            automated_review_findings_count = 0
            remediation_cleared_review_run_id = None
            remediation_cleared_head_sha = None
        elif event_type is EventType.CODEX_REVIEW_TRIGGERED:
            automated_review_trigger_comment_id = int(payload["comment_id"])
            automated_review_trigger_actor = (
                str(payload["actor"])
                if payload.get("actor") is not None
                else None
            )
            automated_review_triggered_at = (
                str(payload["created_at"])
                if payload.get("created_at") is not None
                else None
            )
        elif event_type is EventType.CODEX_REVIEW_COMPLETED:
            automated_review_status = AutomatedReviewStatus(payload["result"])
            automated_review_findings_count = int(payload.get("findings_count", 0))
            automated_reviewer = None
            if (
                automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
                and automated_review_mode == "required"
            ):
                state = PublicationState.CHANGES_REQUIRED
        elif event_type is EventType.CODEX_REVIEW_UNAVAILABLE:
            automated_review_status = AutomatedReviewStatus.UNAVAILABLE
            automated_reviewer = None
        elif event_type is EventType.REMEDIATION_CLEARED:
            remediation_cleared_review_run_id = str(payload["run_id"])
            remediation_cleared_head_sha = str(payload["head_sha"])
            state = PublicationState.IN_REVIEW
        elif event_type is EventType.REVIEW_RECORDED:
            review_decision = ReviewDecision(payload["decision"])
            state = (
                PublicationState.APPROVED
                if review_decision is ReviewDecision.APPROVED
                else PublicationState.CHANGES_REQUIRED
            )
        elif event_type is EventType.MERGEABILITY_RECORDED:
            mergeable = bool(payload["mergeable"])
            state = PublicationState.READY_TO_MERGE if mergeable else PublicationState.APPROVED
        elif event_type is EventType.MERGED:
            merge_commit_sha = str(payload["merge_commit_sha"])
            merge_source = str(payload["source"])
            state = PublicationState.MERGED
        elif event_type is EventType.MERGE_POLICY_VIOLATION:
            merge_policy_violation = True
            merge_commit_sha = str(payload["merge_commit_sha"])
            merge_source = str(payload["source"])
        elif event_type is EventType.PUBLICATION_SUPERSEDED:
            state = PublicationState.SUPERSEDED

    if state is None:
        raise DomainError("publication has no creation event")
    return PublicationView(
        publication_id=publication_id,
        repository=repository,
        issue_number=issue_number,
        state=state,
        current_candidate=candidate,
        remote_head_sha=remote_head,
        remote_branch=remote_branch,
        base_branch=base_branch,
        pull_request_number=pull_request_number,
        automated_reviewer=automated_reviewer,
        automated_review_run_id=automated_review_run_id,
        automated_review_status=automated_review_status,
        automated_review_head_sha=automated_review_head_sha,
        automated_review_trigger_comment_id=automated_review_trigger_comment_id,
        automated_review_trigger_actor=automated_review_trigger_actor,
        automated_review_triggered_at=automated_review_triggered_at,
        automated_review_mode=automated_review_mode,
        automated_review_findings_count=automated_review_findings_count,
        remediation_cleared_review_run_id=remediation_cleared_review_run_id,
        remediation_cleared_head_sha=remediation_cleared_head_sha,
        review_decision=review_decision,
        mergeable=mergeable,
        merge_commit_sha=merge_commit_sha,
        merge_source=merge_source,
        merge_policy_violation=merge_policy_violation,
        projection=desired_projection(state),
    )
def _required_review_adjudication_matches(
    view: PublicationView,
    payload: Mapping[str, Any],
) -> bool:
    evidence = payload.get("required_review_adjudication")
    if not isinstance(evidence, Mapping):
        return False
    run_id = view.automated_review_run_id
    head_sha = view.remote_head_sha
    if (
        not run_id
        or not head_sha
        or view.automated_review_head_sha != head_sha
        or evidence.get("codex_run_id") != run_id
        or evidence.get("head_sha") != head_sha
    ):
        return False

    kind = evidence.get("kind")
    if kind == "CODEX_PASS":
        return view.automated_review_status is AutomatedReviewStatus.PASS

    if kind == "REMEDIATION_CLEARED":
        return (
            view.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
            and view.remediation_cleared_review_run_id == run_id
            and view.remediation_cleared_head_sha == head_sha
        )

    if kind == "PLANE_FALLBACK":
        provider_review_id = evidence.get("provider_review_id")
        return (
            view.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
            and isinstance(evidence.get("plane_run_id"), str)
            and bool(str(evidence.get("plane_run_id") or "").strip())
            and isinstance(evidence.get("plane_reviewer"), str)
            and bool(str(evidence.get("plane_reviewer") or "").strip())
            and isinstance(provider_review_id, int)
            and provider_review_id > 0
        )

    return False


def _is_exact_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(char in "0123456789abcdef" for char in value)
    )


def validate_transition(
    view: PublicationView,
    event_type: EventType,
    payload: Mapping[str, Any],
) -> None:
    state = view.state
    if state is PublicationState.SUPERSEDED and event_type is not EventType.PUBLICATION_SUPERSEDED:
        raise DomainError(
            f"{event_type.value} cannot mutate a SUPERSEDED publication"
        )
    if (
        state is PublicationState.MERGED
        and event_type is not EventType.PUBLICATION_SUPERSEDED
    ):
        raise DomainError("MERGED publication is terminal")
    if event_type is EventType.CANDIDATE_SUBMITTED:
        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            raise DomainError("candidate cannot be submitted while automated review is running")
        if state not in {
            PublicationState.CREATED,
            PublicationState.VALIDATION_FAILED,
            PublicationState.IN_REVIEW,
            PublicationState.CHANGES_REQUIRED,
            PublicationState.APPROVED,
            PublicationState.READY_TO_MERGE,
        }:
            raise DomainError(f"candidate cannot be submitted from {state}")
        return
    if event_type is EventType.VALIDATION_RECORDED:
        if state is not PublicationState.VALIDATING:
            raise DomainError("validation result requires VALIDATING state")
        return
    if event_type is EventType.CANDIDATE_ADMITTED:
        if state is not PublicationState.VALIDATING:
            raise DomainError("candidate admission requires VALIDATING state")
        return
    if event_type is EventType.CANDIDATE_REJECTED:
        if state not in {PublicationState.VALIDATING, PublicationState.ADMITTED}:
            raise DomainError("candidate rejection requires VALIDATING or ADMITTED state")
        if view.current_candidate is None or payload.get("candidate_id") != view.current_candidate.candidate_id:
            raise DomainError("candidate rejection must target the current candidate")
        if state is PublicationState.ADMITTED and payload.get("reason") != "REMOTE_BASE_MOVED_AFTER_ADMISSION":
            raise DomainError("admitted candidate rejection reason is invalid")
        return
    if event_type is EventType.REMOTE_PUBLISHED:
        if state is not PublicationState.ADMITTED or view.current_candidate is None:
            raise DomainError("remote publication requires an admitted candidate")
        if payload.get("head_sha") != view.current_candidate.head_sha:
            raise DomainError("published head must equal admitted candidate head")
        if view.remote_head_sha is not None:
            if payload.get("previous_head_sha") != view.remote_head_sha:
                raise DomainError("successor publication must name the governed prior head")
            if not view.remote_branch or not view.base_branch or view.pull_request_number is None:
                raise DomainError("successor publication requires complete prior PR metadata")
            if payload.get("branch") != view.remote_branch:
                raise DomainError("successor publication must reuse the governed branch")
            if payload.get("base_branch") != view.base_branch:
                raise DomainError("successor publication must reuse the governed base branch")
            if payload.get("pull_request_number") != view.pull_request_number:
                raise DomainError("successor publication must reuse the governed pull request")
        return
    if event_type is EventType.CODEX_REVIEW_REQUESTED:
        if state is not PublicationState.IN_REVIEW:
            raise DomainError("Codex review requires IN_REVIEW state")
        if view.remote_head_sha is None or view.pull_request_number is None:
            raise DomainError("Codex review requires published PR metadata")
        if payload.get("head_sha") != view.remote_head_sha:
            raise DomainError("Codex review head is stale")
        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            if (
                payload.get("run_id") == view.automated_review_run_id
                and payload.get("head_sha") == view.automated_review_head_sha
            ):
                return
            raise DomainError("automated review is already assigned")
        return
    if event_type is EventType.CODEX_REVIEW_TRIGGERED:
        if view.automated_review_status is not AutomatedReviewStatus.RUNNING:
            raise DomainError("Codex trigger requires active review")
        if payload.get("run_id") != view.automated_review_run_id:
            raise DomainError("Codex trigger run is stale")
        return
    if event_type in {
        EventType.CODEX_REVIEW_COMPLETED,
        EventType.CODEX_REVIEW_UNAVAILABLE,
    }:
        if view.automated_review_status is not AutomatedReviewStatus.RUNNING:
            raise DomainError("Codex result requires active review")
        if payload.get("run_id") != view.automated_review_run_id:
            raise DomainError("Codex result run is stale")
        if payload.get("head_sha") != view.automated_review_head_sha:
            raise DomainError("Codex result head is stale")
        if event_type is EventType.CODEX_REVIEW_COMPLETED:
            result = AutomatedReviewStatus(payload["result"])
            if result not in {
                AutomatedReviewStatus.PASS,
                AutomatedReviewStatus.CHANGES_REQUIRED,
            }:
                raise DomainError("invalid Codex review result")
        return
    if event_type is EventType.REMEDIATION_CLEARED:
        if state is not PublicationState.CHANGES_REQUIRED:
            raise DomainError("remediation clearance requires CHANGES_REQUIRED state")
        if view.automated_review_status is not AutomatedReviewStatus.CHANGES_REQUIRED:
            raise DomainError("remediation clearance requires a completed changes-required review")
        if payload.get("run_id") != view.automated_review_run_id:
            raise DomainError("remediation clearance review run is stale")
        if payload.get("head_sha") != view.automated_review_head_sha or payload.get("head_sha") != view.remote_head_sha:
            raise DomainError("remediation clearance head is stale")
        return
    if event_type is EventType.REVIEW_RECORDED:
        if state is not PublicationState.IN_REVIEW:
            raise DomainError("review requires IN_REVIEW state")
        if view.automated_review_status is AutomatedReviewStatus.RUNNING:
            raise DomainError("human review is locked by automated reviewer")
        if (
            payload.get("decision") == ReviewDecision.APPROVED.value
            and view.automated_review_mode == "required"
            and not _required_review_adjudication_matches(view, payload)
        ):
            raise DomainError("required Codex review has not passed or been adjudicated")
        if payload.get("reviewed_head_sha") != view.remote_head_sha:
            raise DomainError("reviewed head is stale")
        ReviewDecision(payload["decision"])
        return
    if event_type is EventType.MERGEABILITY_RECORDED:
        if state is not PublicationState.APPROVED:
            raise DomainError("mergeability is evaluated only after approval")
        if view.remote_head_sha is None or payload.get("head_sha") != view.remote_head_sha:
            raise DomainError("mergeability result is bound to a stale head")
        return
    if event_type is EventType.MERGED:
        if state is not PublicationState.READY_TO_MERGE:
            raise DomainError("merge requires READY_TO_MERGE state")
        if (
            view.remote_head_sha is None
            or payload.get("head_sha") != view.remote_head_sha
        ):
            raise DomainError("merge receipt head is stale")
        if (
            view.pull_request_number is None
            or payload.get("pull_request_number") != view.pull_request_number
        ):
            raise DomainError("merge receipt pull request is stale")
        if not _is_exact_sha(payload.get("merge_commit_sha")):
            raise DomainError("merge commit SHA is invalid")
        if payload.get("source") not in {"PLANE_MERGE", "GITHUB_RECONCILE"}:
            raise DomainError("merge receipt source is invalid")
        return
    if event_type is EventType.MERGE_POLICY_VIOLATION:
        if (
            view.remote_head_sha is None
            or payload.get("head_sha") != view.remote_head_sha
        ):
            raise DomainError("merge policy violation head is stale")
        if (
            view.pull_request_number is None
            or payload.get("pull_request_number") != view.pull_request_number
        ):
            raise DomainError("merge policy violation pull request is stale")
        if not _is_exact_sha(payload.get("merge_commit_sha")):
            raise DomainError("merge policy violation commit SHA is invalid")
        if payload.get("source") != "GITHUB_RECONCILE":
            raise DomainError("merge policy violation source is invalid")
        return
    if event_type is EventType.PUBLICATION_SUPERSEDED:
        if state in {PublicationState.MERGED, PublicationState.SUPERSEDED}:
            raise DomainError(f"publication cannot be superseded from {state}")
        successor_id = payload.get("successor_publication_id")
        reason = payload.get("reason")
        if not successor_id or not isinstance(reason, str) or not reason.strip():
            raise DomainError("publication supersession requires successor and reason")
        return
    raise DomainError(f"unsupported transition event: {event_type}")
