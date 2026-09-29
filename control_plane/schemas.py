from typing import Any

from pydantic import BaseModel, Field

from .domain import ReviewDecision, ValidationStatus


class CreatePublicationRequest(BaseModel):
    repository: str
    issue_number: int = Field(gt=0)


class ValidationResultRequest(BaseModel):
    job_id: str
    status: ValidationStatus
    evidence_sha256: str


class ReviewRequest(BaseModel):
    reviewed_head_sha: str
    decision: ReviewDecision


class MergeabilityRequest(BaseModel):
    head_sha: str
    mergeable: bool


class CreateRemediationWorkPackageRequest(BaseModel):
    publication_id: str
    implementation_issue_number: int | None = Field(default=None, gt=0)
    review_run_id: str = Field(min_length=1, max_length=160)
    review_provider: str = Field(min_length=1, max_length=100)
    provider_review_id: int | None = Field(default=None, gt=0)
    reviewed_head_sha: str
    findings: list[dict[str, Any]] = Field(min_length=1, max_length=200)
    idempotency_key: str = Field(min_length=1, max_length=200)


class ClaimRemediationWorkPackageRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=200)
    idempotency_key: str = Field(min_length=1, max_length=200)


class SubmitRemediationImplementationRequest(BaseModel):
    candidate_id: str = Field(min_length=1, max_length=36)
    head_sha: str
    summary: str = Field(min_length=1, max_length=4000)
    evidence_sha256: str
    idempotency_key: str = Field(min_length=1, max_length=200)


class StartSuccessorVerificationRequest(BaseModel):
    review_run_id: str = Field(min_length=1, max_length=160)
    head_sha: str
    idempotency_key: str = Field(min_length=1, max_length=200)
    fallback_reviewer: str | None = Field(default=None, min_length=1, max_length=200)
    fallback_reason: str | None = Field(default=None, min_length=1, max_length=1000)


class VerifyRemediationFindingRequest(BaseModel):
    outcome: str
    reviewer: str = Field(min_length=1, max_length=200)
    evidence: str = Field(min_length=1, max_length=4000)
    idempotency_key: str = Field(min_length=1, max_length=200)


class IdempotencyRequest(BaseModel):
    idempotency_key: str = Field(min_length=1, max_length=200)
