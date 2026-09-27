from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import settings
from .db import get_session, init_db
from .domain import DomainError
from .profile_registry import all_profiles
from .quarantine import CandidateQuarantineError, GitCandidateQuarantine
from .repository import load_events
from .schemas import (
    CreatePublicationRequest,
    MergeabilityRequest,
    PublishedRequest,
    ReviewRequest,
    ValidationResultRequest,
)
from .service import (
    create_publication,
    get_view,
    list_publication_ids,
    mark_remote_published,
    record_mergeability,
    record_review,
    record_validation,
    submit_verified_candidate,
)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="FirstContact Control Plane", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
def require_token(x_control_plane_token: str | None = Header(default=None)) -> None:
    if x_control_plane_token != settings.internal_token:
        raise HTTPException(status_code=401, detail="invalid control-plane token")


def get_quarantine() -> GitCandidateQuarantine:
    return GitCandidateQuarantine(
        settings.quarantine_root,
        max_bundle_bytes=settings.max_candidate_bundle_bytes,
    )


def _payload(view):
    data = asdict(view)
    data["state"] = view.state.value
    if view.review_decision is not None:
        data["review_decision"] = view.review_decision.value
    return data


def _conflict(exc: Exception) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


@app.get("/api/v1/health")
def health():
    return {"status": "PASS", "publisher_mode": settings.publisher_mode}


@app.get("/api/v1/profiles")
def profiles():
    return [asdict(profile) for profile in all_profiles()]
@app.get("/api/v1/publications")
def publications(session: Session = Depends(get_session)):
    return [_payload(get_view(session, publication_id)) for publication_id in list_publication_ids(session)]


@app.post("/api/v1/publications", dependencies=[Depends(require_token)])
def publications_create(request: CreatePublicationRequest, session: Session = Depends(get_session)):
    try:
        return _payload(create_publication(session, request.repository, request.issue_number))
    except DomainError as exc:
        raise _conflict(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/publications/{publication_id}")
def publication_get(publication_id: str, session: Session = Depends(get_session)):
    try:
        return _payload(get_view(session, publication_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc


@app.get("/api/v1/publications/{publication_id}/events")
def publication_events(publication_id: str, session: Session = Depends(get_session)):
    try:
        get_view(session, publication_id)
        return load_events(session, publication_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
@app.post(
    "/api/v1/publications/{publication_id}/candidate-bundle",
    dependencies=[Depends(require_token)],
)
def candidate_bundle_submit(
    publication_id: str,
    bundle: UploadFile = File(...),
    session: Session = Depends(get_session),
    quarantine: GitCandidateQuarantine = Depends(get_quarantine),
):
    try:
        source = quarantine.import_stream(bundle.file)
        return _payload(submit_verified_candidate(session, publication_id, source))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except CandidateQuarantineError as exc:
        detail = str(exc)
        status = 413 if "size limit" in detail else 422
        raise HTTPException(status_code=status, detail=detail) from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post("/api/v1/internal/publications/{publication_id}/validations", dependencies=[Depends(require_token)])
def validation_record(publication_id: str, request: ValidationResultRequest, session: Session = Depends(get_session)):
    try:
        return _payload(record_validation(
            session,
            publication_id,
            job_id=request.job_id,
            status=request.status,
            evidence_sha256=request.evidence_sha256,
        ))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
@app.post("/api/v1/internal/publications/{publication_id}/published", dependencies=[Depends(require_token)])
def publication_mark_published(publication_id: str, request: PublishedRequest, session: Session = Depends(get_session)):
    if settings.publisher_mode != "simulated":
        raise HTTPException(status_code=503, detail="publisher is disabled")
    try:
        return _payload(mark_remote_published(session, publication_id, request.head_sha))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post("/api/v1/publications/{publication_id}/reviews", dependencies=[Depends(require_token)])
def review_record(publication_id: str, request: ReviewRequest, session: Session = Depends(get_session)):
    try:
        return _payload(record_review(
            session,
            publication_id,
            reviewed_head_sha=request.reviewed_head_sha,
            decision=request.decision,
        ))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
@app.post("/api/v1/internal/publications/{publication_id}/mergeability", dependencies=[Depends(require_token)])
def mergeability_record(publication_id: str, request: MergeabilityRequest, session: Session = Depends(get_session)):
    try:
        return _payload(record_mergeability(session, publication_id, request.mergeable))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
