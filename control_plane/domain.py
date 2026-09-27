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


class EventType(StrEnum):
    PUBLICATION_CREATED = "PUBLICATION_CREATED"
    CANDIDATE_SUBMITTED = "CANDIDATE_SUBMITTED"
    VALIDATION_RECORDED = "VALIDATION_RECORDED"
    CANDIDATE_ADMITTED = "CANDIDATE_ADMITTED"
    CANDIDATE_REJECTED = "CANDIDATE_REJECTED"
    REMOTE_PUBLISHED = "REMOTE_PUBLISHED"
    REVIEW_RECORDED = "REVIEW_RECORDED"
    MERGEABILITY_RECORDED = "MERGEABILITY_RECORDED"
    MERGED = "MERGED"
class ValidationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


class ReviewDecision(StrEnum):
    APPROVED = "APPROVED"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"


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
    review_decision: ReviewDecision | None
    mergeable: bool | None
    projection: LifecycleProjection


def desired_projection(state: PublicationState) -> LifecycleProjection:
    if state in {PublicationState.VALIDATION_FAILED, PublicationState.CHANGES_REQUIRED}:
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
    review_decision: ReviewDecision | None = None
    mergeable: bool | None = None

    for event in events:
        event_type = EventType(event["event_type"])
        payload = event["payload"]
        if event_type is EventType.PUBLICATION_CREATED:
            repository = str(payload["repository"])
            issue_number = int(payload["issue_number"])
            state = PublicationState.CREATED
        elif event_type is EventType.CANDIDATE_SUBMITTED:
            candidate = _candidate(payload)
            state = PublicationState.VALIDATING
            review_decision = None
            mergeable = None
        elif event_type is EventType.CANDIDATE_ADMITTED:
            state = PublicationState.ADMITTED
        elif event_type is EventType.CANDIDATE_REJECTED:
            state = PublicationState.VALIDATION_FAILED
        elif event_type is EventType.REMOTE_PUBLISHED:
            remote_head = str(payload["head_sha"])
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
            state = PublicationState.MERGED

    if state is None:
        raise DomainError("publication has no creation event")
    return PublicationView(
        publication_id=publication_id,
        repository=repository,
        issue_number=issue_number,
        state=state,
        current_candidate=candidate,
        remote_head_sha=remote_head,
        review_decision=review_decision,
        mergeable=mergeable,
        projection=desired_projection(state),
    )
def validate_transition(
    view: PublicationView,
    event_type: EventType,
    payload: Mapping[str, Any],
) -> None:
    state = view.state
    if event_type is EventType.CANDIDATE_SUBMITTED:
        if state not in {
            PublicationState.CREATED,
            PublicationState.VALIDATION_FAILED,
            PublicationState.CHANGES_REQUIRED,
        }:
            raise DomainError(f"candidate cannot be submitted from {state}")
        return
    if event_type is EventType.VALIDATION_RECORDED:
        if state is not PublicationState.VALIDATING:
            raise DomainError("validation result requires VALIDATING state")
        return
    if event_type in {EventType.CANDIDATE_ADMITTED, EventType.CANDIDATE_REJECTED}:
        if state is not PublicationState.VALIDATING:
            raise DomainError("admission result requires VALIDATING state")
        return
    if event_type is EventType.REMOTE_PUBLISHED:
        if state is not PublicationState.ADMITTED or view.current_candidate is None:
            raise DomainError("remote publication requires an admitted candidate")
        if payload.get("head_sha") != view.current_candidate.head_sha:
            raise DomainError("published head must equal admitted candidate head")
        return
    if event_type is EventType.REVIEW_RECORDED:
        if state is not PublicationState.IN_REVIEW:
            raise DomainError("review requires IN_REVIEW state")
        if payload.get("reviewed_head_sha") != view.remote_head_sha:
            raise DomainError("reviewed head is stale")
        ReviewDecision(payload["decision"])
        return
    if event_type is EventType.MERGEABILITY_RECORDED:
        if state is not PublicationState.APPROVED:
            raise DomainError("mergeability is evaluated only after approval")
        return
    if event_type is EventType.MERGED:
        if state is not PublicationState.READY_TO_MERGE:
            raise DomainError("merge requires READY_TO_MERGE state")
        return
    raise DomainError(f"unsupported transition event: {event_type}")
