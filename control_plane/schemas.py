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
