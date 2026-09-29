from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .codex_review import CodexReviewBroker, CodexReviewError
from .config import settings
from .db import get_session, init_db
from .domain import DomainError
from .github_api import GitHubRepositoryGateway
from .github_app import GitHubAppTokenProvider
from .github_review_auth import GitHubReviewTokenProvider
from .profile_registry import all_profiles
from .publisher import GitHubPublisher, PublicationError
from .quarantine import CandidateQuarantineError, GitCandidateQuarantine
from .remediation_materializer import (
    GitHubRemediationMaterializer,
    RemediationMaterializationError,
)
from .repository import load_events
from .schemas import (
    CreatePublicationRequest,
    CreateRemediationWorkPackageRequest,
    ClaimRemediationWorkPackageRequest,
    IdempotencyRequest,
    MergeabilityRequest,
    ReviewRequest,
    StartSuccessorVerificationRequest,
    SubmitRemediationImplementationRequest,
    ValidationResultRequest,
    VerifyRemediationFindingRequest,
)
from .remediation import (
    begin_rejected_findings_finalization,
    begin_successor_verification,
    claim_work_package,
    create_work_package,
    get_work_package,
    submit_implementation,
    verify_finding,
    work_package_events,
)
from .service import (
    create_publication,
    get_view,
    list_publication_ids,
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


def get_publisher(
    quarantine: GitCandidateQuarantine = Depends(get_quarantine),
):
    if settings.publisher_mode != "github-app":
        raise HTTPException(status_code=503, detail="publisher is disabled")
    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    try:
        yield GitHubPublisher(
            token_provider=token_provider,
            github=github,
            quarantine=quarantine,
        )
    finally:
        token_provider.close()
        github.close()


def get_codex_review_broker():
    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    actors = tuple(
        value.strip()
        for value in settings.codex_review_actors.split(",")
        if value.strip()
    )
    trigger_user = GitHubReviewTokenProvider(
        token=settings.codex_review_user_token,
        expected_login=settings.codex_review_trigger_login,
        github=github,
    )
    try:
        yield CodexReviewBroker(
            token_provider=token_provider,
            github=github,
            mode=settings.codex_review_mode,
            allowed_actors=actors,
            trigger_user=trigger_user,
        )
    finally:
        token_provider.close()
        github.close()


def get_remediation_materializer():
    project_token = settings.remediation_project_token.get_secret_value().strip()
    thread_token = settings.remediation_thread_token.get_secret_value().strip()
    codex_trigger_token = settings.codex_review_user_token.get_secret_value().strip()
    configured = [value for value in (project_token, thread_token, codex_trigger_token) if value]
    if len(configured) != len(set(configured)):
        raise HTTPException(
            status_code=503,
            detail="remediation credential configuration is invalid",
        )
    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    try:
        yield GitHubRemediationMaterializer(
            token_provider=token_provider,
            github=github,
            project_number=settings.remediation_project_number,
            project_lifecycle_field=settings.remediation_project_lifecycle_field,
            project_token=settings.remediation_project_token,
            review_thread_token=settings.remediation_thread_token,
        )
    finally:
        token_provider.close()
        github.close()


def _payload(view):
    data = asdict(view)
    data["state"] = view.state.value
    if view.review_decision is not None:
        data["review_decision"] = view.review_decision.value
    if view.automated_review_status is not None:
        data["automated_review_status"] = view.automated_review_status.value
    return data


def _work_package_payload(view):
    data = asdict(view)
    data["state"] = view.state.value
    return data


def _conflict(exc: Exception) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


@app.get("/api/v1/health")
def health():
    return {
        "status": "PASS",
        "publisher_mode": settings.publisher_mode,
        "codex_review_mode": settings.codex_review_mode,
    }


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
@app.post(
    "/api/v1/internal/publications/{publication_id}/publish",
    dependencies=[Depends(require_token)],
)
def publication_publish(
    publication_id: str,
    session: Session = Depends(get_session),
    publisher: GitHubPublisher = Depends(get_publisher),
):
    try:
        return _payload(publisher.publish(session, publication_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except PublicationError as exc:
        raise HTTPException(status_code=502, detail="publication failed closed") from exc



@app.post(
    "/api/v1/internal/publications/{publication_id}/codex-review/request",
    dependencies=[Depends(require_token)],
)
def codex_review_request(
    publication_id: str,
    session: Session = Depends(get_session),
    broker: CodexReviewBroker = Depends(get_codex_review_broker),
):
    if settings.codex_review_mode.strip().lower() == "disabled":
        raise HTTPException(status_code=503, detail="Codex review broker is disabled")
    try:
        return _payload(broker.request(session, publication_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except CodexReviewError as exc:
        raise HTTPException(status_code=502, detail="Codex review failed closed") from exc


@app.post(
    "/api/v1/internal/publications/{publication_id}/codex-review/reconcile",
    dependencies=[Depends(require_token)],
)
def codex_review_reconcile(
    publication_id: str,
    session: Session = Depends(get_session),
    broker: CodexReviewBroker = Depends(get_codex_review_broker),
):
    try:
        observation = broker.reconcile(session, publication_id)
        return {
            "observation": asdict(observation),
            "publication": _payload(get_view(session, publication_id)),
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except CodexReviewError as exc:
        raise HTTPException(status_code=502, detail="Codex review reconciliation failed closed") from exc


@app.post("/api/v1/publications/{publication_id}/reviews", dependencies=[Depends(require_token)])
def review_record(publication_id: str, request: ReviewRequest, session: Session = Depends(get_session)):
    try:
        return _payload(record_review(
            session,
            publication_id,
            reviewed_head_sha=request.reviewed_head_sha,
            decision=request.decision,
            require_codex_review=(
                settings.codex_review_mode.strip().lower() == "required"
            ),
        ))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
@app.post("/api/v1/internal/publications/{publication_id}/mergeability", dependencies=[Depends(require_token)])
def mergeability_record(publication_id: str, request: MergeabilityRequest, session: Session = Depends(get_session)):
    try:
        return _payload(
            record_mergeability(
                session,
                publication_id,
                head_sha=request.head_sha,
                mergeable=request.mergeable,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/internal/remediation/work-packages",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_create(
    request: CreateRemediationWorkPackageRequest,
    session: Session = Depends(get_session),
    materializer: GitHubRemediationMaterializer = Depends(get_remediation_materializer),
):
    try:
        view = create_work_package(
            session,
            publication_id=request.publication_id,
            implementation_issue_number=request.implementation_issue_number,
            review_run_id=request.review_run_id,
            review_provider=request.review_provider,
            provider_review_id=request.provider_review_id,
            reviewed_head_sha=request.reviewed_head_sha,
            findings=request.findings,
            idempotency_key=request.idempotency_key,
        )
        if request.implementation_issue_number is None:
            view = materializer.ensure_implementation_issue(
                session,
                view.work_package_id,
            )
        return _work_package_payload(view)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except RemediationMaterializationError as exc:
        raise HTTPException(
            status_code=502,
            detail="remediation work package projection failed closed",
        ) from exc


@app.get(
    "/api/v1/internal/remediation/work-packages/{work_package_id}",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_get(
    work_package_id: str,
    session: Session = Depends(get_session),
):
    try:
        return _work_package_payload(get_work_package(session, work_package_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc


@app.get(
    "/api/v1/internal/remediation/work-packages/{work_package_id}/events",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_events(
    work_package_id: str,
    session: Session = Depends(get_session),
):
    try:
        return work_package_events(session, work_package_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc


@app.post(
    "/api/v1/internal/remediation/work-packages/{work_package_id}/claim",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_claim(
    work_package_id: str,
    request: ClaimRemediationWorkPackageRequest,
    session: Session = Depends(get_session),
    materializer: GitHubRemediationMaterializer = Depends(get_remediation_materializer),
):
    try:
        view = claim_work_package(
            session,
            work_package_id,
            actor=request.actor,
            idempotency_key=request.idempotency_key,
        )
        return _work_package_payload(
            materializer.sync_issue_projection(session, view.work_package_id)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except RemediationMaterializationError as exc:
        raise HTTPException(
            status_code=502,
            detail="remediation status projection failed closed",
        ) from exc


@app.post(
    "/api/v1/internal/remediation/work-packages/{work_package_id}/implementation",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_submit_implementation(
    work_package_id: str,
    request: SubmitRemediationImplementationRequest,
    session: Session = Depends(get_session),
    materializer: GitHubRemediationMaterializer = Depends(get_remediation_materializer),
):
    try:
        view = submit_implementation(
            session,
            work_package_id,
            candidate_id=request.candidate_id,
            head_sha=request.head_sha,
            summary=request.summary,
            evidence_sha256=request.evidence_sha256,
            idempotency_key=request.idempotency_key,
        )
        return _work_package_payload(
            materializer.sync_issue_projection(session, view.work_package_id)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except RemediationMaterializationError as exc:
        raise HTTPException(
            status_code=502,
            detail="remediation status projection failed closed",
        ) from exc


@app.post(
    "/api/v1/internal/remediation/work-packages/{work_package_id}/successor-review",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_start_verification(
    work_package_id: str,
    request: StartSuccessorVerificationRequest,
    session: Session = Depends(get_session),
    materializer: GitHubRemediationMaterializer = Depends(get_remediation_materializer),
):
    try:
        view = begin_successor_verification(
            session,
            work_package_id,
            review_run_id=request.review_run_id,
            head_sha=request.head_sha,
            idempotency_key=request.idempotency_key,
            fallback_reviewer=request.fallback_reviewer,
            fallback_reason=request.fallback_reason,
        )
        return _work_package_payload(
            materializer.sync_issue_projection(session, view.work_package_id)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except RemediationMaterializationError as exc:
        raise HTTPException(
            status_code=502,
            detail="remediation status projection failed closed",
        ) from exc


@app.post(
    "/api/v1/internal/remediation/work-packages/{work_package_id}/rejected-finalization",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_start_rejected_finalization(
    work_package_id: str,
    request: IdempotencyRequest,
    session: Session = Depends(get_session),
    materializer: GitHubRemediationMaterializer = Depends(get_remediation_materializer),
):
    try:
        view = begin_rejected_findings_finalization(
            session,
            work_package_id,
            idempotency_key=request.idempotency_key,
        )
        return _work_package_payload(
            materializer.sync_issue_projection(session, view.work_package_id)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except RemediationMaterializationError as exc:
        raise HTTPException(
            status_code=502,
            detail="remediation status projection failed closed",
        ) from exc


@app.post(
    "/api/v1/internal/remediation/work-packages/{work_package_id}/findings/{finding_id}/verification",
    dependencies=[Depends(require_token)],
)
def remediation_finding_verify(
    work_package_id: str,
    finding_id: str,
    request: VerifyRemediationFindingRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_package_payload(
            verify_finding(
                session,
                work_package_id,
                finding_id=finding_id,
                outcome=request.outcome,
                reviewer=request.reviewer,
                evidence=request.evidence,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/internal/remediation/work-packages/{work_package_id}/materialize",
    dependencies=[Depends(require_token)],
)
def remediation_work_package_materialize(
    work_package_id: str,
    session: Session = Depends(get_session),
    materializer: GitHubRemediationMaterializer = Depends(get_remediation_materializer),
):
    try:
        return _work_package_payload(
            materializer.materialize(session, work_package_id)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except RemediationMaterializationError as exc:
        raise HTTPException(
            status_code=502,
            detail="remediation materialization failed closed",
        ) from exc
