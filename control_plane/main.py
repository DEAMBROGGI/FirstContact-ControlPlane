from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from .codex_review import CodexReviewBroker, CodexReviewError
from .config import settings
from .db import SessionLocal, get_session, init_db
from .domain import DomainError
from .github_api import GitHubApiError, GitHubRepositoryGateway
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .github_review_auth import GitHubReviewTokenProvider
from .github_webhook import (
    GitHubWebhookAuthError,
    GitHubWebhookError,
    GitHubWebhookGateway,
    get_webhook_delivery,
    get_review_watch,
    sync_review_watch,
)
from .merge import MergeCoordinator, MergeError, MergePolicyViolationRecorded
from .profile_registry import all_profiles
from .publisher import GitHubPublisher, PublicationError
from .plane_review import (
    PlaneReviewError,
    PlaneReviewPublisher,
    record_plane_review,
)
from .quarantine import CandidateQuarantineError, GitCandidateQuarantine
from .remediation_materializer import (
    GitHubRemediationMaterializer,
    RemediationMaterializationError,
)
from .repository import load_events
from .schemas import (
    AddWorkDependencyRequest,
    ClaimNextWorkRequest,
    ClaimWorkItemRequest,
    CompleteWorkItemRequest,
    CreatePublicationRequest,
    CreateWorkItemRequest,
    CreateRemediationWorkPackageRequest,
    ClaimRemediationWorkPackageRequest,
    IdempotencyRequest,
    MergeabilityRequest,
    PlaneReviewRequest,
    ReviewRequest,
    ReleaseWorkClaimRequest,
    RenewWorkClaimRequest,
    ResumeWorkItemRequest,
    StartSuccessorVerificationRequest,
    SubmitRemediationImplementationRequest,
    SubmitWorkImplementationRequest,
    SuspendWorkItemRequest,
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
from .work import (
    WorkItemView,
    add_dependency,
    claim_next_work,
    claim_work_item,
    complete_work_item,
    create_work_item,
    get_work_item,
    load_work_item_events,
    next_work,
    release_claim,
    release_work_item,
    renew_claim,
    resume_work_item,
    submit_work_implementation,
    suspend_work_item,
)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    _startup_reconcile_pending_webhooks()
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


def get_merge_coordinator():
    if settings.publisher_mode != "github-app":
        raise HTTPException(status_code=503, detail="merge coordinator is disabled")
    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    try:
        yield MergeCoordinator(
            token_provider=token_provider,
            github=github,
        )
    finally:
        token_provider.close()
        github.close()


def _configured_actors(raw: str) -> tuple[str, ...]:
    return tuple(
        value.strip()
        for value in raw.split(",")
        if value.strip()
    )


def _startup_reconcile_pending_webhooks() -> int:
    if settings.publisher_mode != "github-app":
        return 0
    webhook_secret = settings.github_webhook_secret.get_secret_value().strip()
    if not webhook_secret:
        return 0
    limit = settings.github_webhook_startup_reconcile_limit
    if limit <= 0:
        return 0

    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    session = SessionLocal()
    try:
        gateway = GitHubWebhookGateway(
            token_provider=token_provider,
            github=github,
            codex_review_mode=settings.codex_review_mode,
            codex_actors=_configured_actors(settings.codex_review_actors),
            human_review_actors=_configured_actors(settings.human_review_actors),
            webhook_secret=webhook_secret,
            maximum_payload_bytes=settings.github_webhook_max_payload_bytes,
        )
        return len(
            gateway.reconcile_pending_best_effort(
                session,
                limit=limit,
            )
        )
    finally:
        session.close()
        token_provider.close()
        github.close()


def get_codex_review_broker():
    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    actors = _configured_actors(settings.codex_review_actors)
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


def _github_webhook_gateway(*, webhook_secret: str | None):
    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    try:
        yield GitHubWebhookGateway(
            token_provider=token_provider,
            github=github,
            codex_review_mode=settings.codex_review_mode,
            codex_actors=_configured_actors(settings.codex_review_actors),
            human_review_actors=_configured_actors(settings.human_review_actors),
            webhook_secret=webhook_secret,
            maximum_payload_bytes=settings.github_webhook_max_payload_bytes,
        )
    finally:
        token_provider.close()
        github.close()


def get_github_authoritative_gateway():
    if settings.publisher_mode != "github-app":
        raise HTTPException(status_code=503, detail="GitHub webhook gateway is disabled")
    yield from _github_webhook_gateway(webhook_secret=None)


def get_github_webhook_gateway():
    if settings.publisher_mode != "github-app":
        raise HTTPException(status_code=503, detail="GitHub webhook gateway is disabled")
    webhook_secret = settings.github_webhook_secret.get_secret_value().strip()
    if not webhook_secret:
        raise HTTPException(status_code=503, detail="GitHub webhook secret is not configured")
    yield from _github_webhook_gateway(webhook_secret=webhook_secret)


def get_plane_review_publisher():
    if settings.publisher_mode != "github-app":
        raise HTTPException(status_code=503, detail="Plane review publisher is disabled")
    token_provider = GitHubAppTokenProvider(
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        api_url=settings.github_api_url,
    )
    github = GitHubRepositoryGateway(api_url=settings.github_api_url)
    try:
        yield PlaneReviewPublisher(
            token_provider=token_provider,
            github=github,
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


def _work_item_payload(view: WorkItemView):
    data = asdict(view)
    data["state"] = view.state.value
    data["next_role"] = view.next_role.value
    data["next_action"] = view.next_action.value
    return data


def _sync_publication_watch(session: Session, publication_id: str):
    view = get_view(session, publication_id)
    if view.pull_request_number is None or view.remote_head_sha is None:
        return None
    return sync_review_watch(
        session,
        publication_id,
        expected_actors=(
            *_configured_actors(settings.codex_review_actors),
            *_configured_actors(settings.human_review_actors),
        ),
        codex_review_mode=settings.codex_review_mode,
    )


def _conflict(exc: Exception) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


async def _read_limited_webhook_body(request: Request, maximum_bytes: int) -> bytes:
    if maximum_bytes <= 0:
        raise HTTPException(status_code=400, detail="webhook payload limit is invalid")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_bytes = int(content_length)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="webhook content length is invalid",
            ) from exc
        if declared_bytes < 0:
            raise HTTPException(
                status_code=400,
                detail="webhook content length is invalid",
            )
        if declared_bytes > maximum_bytes:
            raise HTTPException(status_code=413, detail="webhook payload is too large")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum_bytes:
            raise HTTPException(status_code=413, detail="webhook payload is too large")
        body.extend(chunk)
    return bytes(body)


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


@app.post("/api/v1/internal/work-items", dependencies=[Depends(require_token)])
def work_item_create(
    request: CreateWorkItemRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            create_work_item(
                session,
                repository=request.repository,
                issue_number=request.issue_number,
                context=request.context,
                priority=request.priority,
                rank=request.rank,
                parent_work_item_id=request.parent_work_item_id,
                required_for_parent=request.required_for_parent,
                executable=request.executable,
                released=request.released,
            )
        )
    except (DomainError, ValueError) as exc:
        raise _conflict(exc) from exc


@app.get("/api/v1/work-items/{work_item_id}", dependencies=[Depends(require_token)])
def work_item_get(
    work_item_id: str,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(get_work_item(session, work_item_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc


@app.get(
    "/api/v1/work-items/{work_item_id}/events",
    dependencies=[Depends(require_token)],
)
def work_item_event_list(
    work_item_id: str,
    session: Session = Depends(get_session),
):
    try:
        return load_work_item_events(session, work_item_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc


@app.post(
    "/api/v1/internal/work-items/{work_item_id}/dependencies",
    dependencies=[Depends(require_token)],
)
def work_item_dependency_add(
    work_item_id: str,
    request: AddWorkDependencyRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            add_dependency(
                session,
                work_item_id,
                request.depends_on_work_item_id,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.get("/api/v1/work/next", dependencies=[Depends(require_token)])
def work_next(
    repository: str,
    session: Session = Depends(get_session),
):
    try:
        view = next_work(session, repository)
        return None if view is None else _work_item_payload(view)
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post("/api/v1/work/claim-next", dependencies=[Depends(require_token)])
def work_claim_next(
    request: ClaimNextWorkRequest,
    session: Session = Depends(get_session),
):
    try:
        view = claim_next_work(
            session,
            request.repository,
            actor=request.actor,
            idempotency_key=request.idempotency_key,
            lease_seconds=settings.work_claim_lease_seconds,
        )
        return None if view is None else _work_item_payload(view)
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/work-items/{work_item_id}/claim",
    dependencies=[Depends(require_token)],
)
def work_item_claim(
    work_item_id: str,
    request: ClaimWorkItemRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            claim_work_item(
                session,
                work_item_id,
                actor=request.actor,
                idempotency_key=request.idempotency_key,
                lease_seconds=settings.work_claim_lease_seconds,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/work-items/{work_item_id}/implementation",
    dependencies=[Depends(require_token)],
)
def work_item_implementation(
    work_item_id: str,
    request: SubmitWorkImplementationRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            submit_work_implementation(
                session,
                work_item_id,
                actor=request.actor,
                summary=request.summary,
                evidence_sha256=request.evidence_sha256,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/internal/work-items/{work_item_id}/complete",
    dependencies=[Depends(require_token)],
)
def work_item_complete(
    work_item_id: str,
    request: CompleteWorkItemRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            complete_work_item(
                session,
                work_item_id,
                actor=request.actor,
                evidence=request.evidence,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/work-items/{work_item_id}/claim/renew",
    dependencies=[Depends(require_token)],
)
def work_item_claim_renew(
    work_item_id: str,
    request: RenewWorkClaimRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            renew_claim(
                session,
                work_item_id,
                actor=request.actor,
                idempotency_key=request.idempotency_key,
                lease_seconds=settings.work_claim_lease_seconds,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/work-items/{work_item_id}/claim/release",
    dependencies=[Depends(require_token)],
)
def work_item_claim_release(
    work_item_id: str,
    request: ReleaseWorkClaimRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            release_claim(
                session,
                work_item_id,
                actor=request.actor,
                reason=request.reason,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/internal/work-items/{work_item_id}/release",
    dependencies=[Depends(require_token)],
)
def work_item_release(
    work_item_id: str,
    request: IdempotencyRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            release_work_item(
                session,
                work_item_id,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/internal/work-items/{work_item_id}/suspend",
    dependencies=[Depends(require_token)],
)
def work_item_suspend(
    work_item_id: str,
    request: SuspendWorkItemRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            suspend_work_item(
                session,
                work_item_id,
                actor=request.actor,
                reason=request.reason,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc


@app.post(
    "/api/v1/internal/work-items/{work_item_id}/resume",
    dependencies=[Depends(require_token)],
)
def work_item_resume(
    work_item_id: str,
    request: ResumeWorkItemRequest,
    session: Session = Depends(get_session),
):
    try:
        return _work_item_payload(
            resume_work_item(
                session,
                work_item_id,
                actor=request.actor,
                idempotency_key=request.idempotency_key,
            )
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work item not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
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
        view = publisher.publish(session, publication_id)
        _sync_publication_watch(session, publication_id)
        return _payload(view)
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
        view = broker.request(session, publication_id)
        _sync_publication_watch(session, publication_id)
        return _payload(view)
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
        sync_review_watch(
            session,
            publication_id,
            expected_actors=(
                *_configured_actors(settings.codex_review_actors),
                *_configured_actors(settings.human_review_actors),
            ),
            codex_review_mode=settings.codex_review_mode,
        )
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


@app.post("/api/v1/github/webhooks")
async def github_webhook_receive(
    request: Request,
    x_hub_signature_256: str | None = Header(
        default=None,
        alias="X-Hub-Signature-256",
    ),
    x_github_delivery: str | None = Header(
        default=None,
        alias="X-GitHub-Delivery",
    ),
    x_github_event: str | None = Header(
        default=None,
        alias="X-GitHub-Event",
    ),
    session: Session = Depends(get_session),
    gateway: GitHubWebhookGateway = Depends(get_github_webhook_gateway),
):
    body = await _read_limited_webhook_body(
        request,
        gateway.maximum_payload_bytes,
    )
    try:
        receipt = gateway.ingest(
            session,
            delivery_id=(x_github_delivery or ""),
            event_name=(x_github_event or ""),
            signature=x_hub_signature_256,
            body=body,
        )
    except GitHubWebhookAuthError as exc:
        raise HTTPException(status_code=401, detail="invalid GitHub webhook signature") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except GitHubWebhookError as exc:
        raise HTTPException(status_code=400, detail="invalid GitHub webhook delivery") from exc

    try:
        processing = await run_in_threadpool(
            gateway.process_delivery,
            session,
            receipt.delivery_id,
        )
        delivery = get_webhook_delivery(session, receipt.delivery_id)
        return {
            "delivery": asdict(delivery),
            "processing": asdict(processing),
        }
    except DomainError as exc:
        raise _conflict(exc) from exc
    except (
        GitHubAuthError,
        GitHubApiError,
        CodexReviewError,
        GitHubWebhookError,
    ) as exc:
        raise HTTPException(status_code=502, detail="GitHub webhook processing failed closed") from exc


@app.post(
    "/api/v1/internal/github/webhooks/reconcile",
    dependencies=[Depends(require_token)],
)
def github_webhook_reconcile(
    publication_id: str | None = None,
    session: Session = Depends(get_session),
    gateway: GitHubWebhookGateway = Depends(get_github_authoritative_gateway),
):
    try:
        if publication_id is not None:
            return asdict(
                gateway.reconcile_publication(
                    session,
                    publication_id,
                )
            )
        return [
            asdict(item)
            for item in gateway.reconcile_pending(session)
        ]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="webhook/publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except (
        GitHubAuthError,
        GitHubApiError,
        CodexReviewError,
        GitHubWebhookError,
    ) as exc:
        raise HTTPException(status_code=502, detail="GitHub reconciliation failed closed") from exc


@app.get(
    "/api/v1/internal/github/review-watches/{publication_id}",
    dependencies=[Depends(require_token)],
)
def github_review_watch_get(
    publication_id: str,
    session: Session = Depends(get_session),
):
    try:
        return asdict(get_review_watch(session, publication_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="review watch not found") from exc


@app.post(
    "/api/v1/internal/publications/{publication_id}/plane-reviews",
    dependencies=[Depends(require_token)],
)
def plane_review_submit(
    publication_id: str,
    request: PlaneReviewRequest,
    session: Session = Depends(get_session),
    publisher: PlaneReviewPublisher = Depends(get_plane_review_publisher),
):
    try:
        record_plane_review(
            session,
            publication_id,
            run_id=request.review_run_id,
            reviewer_kind=request.reviewer_kind,
            reviewer=request.reviewer,
            reviewed_head_sha=request.reviewed_head_sha,
            body=request.body,
            comments=request.comments,
            idempotency_key=request.idempotency_key,
        )
        result = publisher.materialize(
            session,
            publication_id,
            request.review_run_id,
        )
        _sync_publication_watch(session, publication_id)
        return result
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except PlaneReviewError as exc:
        raise HTTPException(
            status_code=502,
            detail="Plane review publication failed closed",
        ) from exc


@app.post("/api/v1/publications/{publication_id}/reviews", dependencies=[Depends(require_token)])
def review_record(
    publication_id: str,
    request: ReviewRequest,
    session: Session = Depends(get_session),
    gateway: GitHubWebhookGateway = Depends(get_github_authoritative_gateway),
):
    try:
        gateway.assert_review_write_current(session, publication_id)
        view = record_review(
            session,
            publication_id,
            reviewed_head_sha=request.reviewed_head_sha,
            decision=request.decision,
            require_codex_review=(
                settings.codex_review_mode.strip().lower() == "required"
            ),
        )
        _sync_publication_watch(session, publication_id)
        return _payload(view)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except GitHubWebhookError as exc:
        raise HTTPException(
            status_code=502,
            detail="GitHub review write readback failed closed",
        ) from exc

@app.post("/api/v1/internal/publications/{publication_id}/mergeability", dependencies=[Depends(require_token)])
def mergeability_record(
    publication_id: str,
    request: MergeabilityRequest,
    session: Session = Depends(get_session),
    gateway: GitHubWebhookGateway = Depends(get_github_authoritative_gateway),
):
    try:
        pull = gateway.assert_mergeability_write_current(
            session,
            publication_id,
            head_sha=request.head_sha,
        )
        if pull.mergeable is None:
            raise DomainError("GitHub mergeability is still pending")
        if request.mergeable is not pull.mergeable:
            raise DomainError(
                "reported mergeability does not match current GitHub state"
            )
        view = record_mergeability(
            session,
            publication_id,
            head_sha=pull.head_sha,
            mergeable=pull.mergeable,
        )
        _sync_publication_watch(session, publication_id)
        return _payload(view)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except GitHubWebhookError as exc:
        raise HTTPException(
            status_code=502,
            detail="GitHub mergeability readback failed closed",
        ) from exc


@app.post(
    "/api/v1/internal/publications/{publication_id}/merge",
    dependencies=[Depends(require_token)],
)
def merge_execute(
    publication_id: str,
    session: Session = Depends(get_session),
    coordinator: MergeCoordinator = Depends(get_merge_coordinator),
    gateway: GitHubWebhookGateway = Depends(get_github_authoritative_gateway),
):
    try:
        gateway.authorize_merge(session, publication_id)
        view = coordinator.merge(session, publication_id)
        _sync_publication_watch(session, publication_id)
        return _payload(view)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except (
        GitHubAuthError,
        GitHubApiError,
        CodexReviewError,
        GitHubWebhookError,
    ) as exc:
        raise HTTPException(
            status_code=502,
            detail="governed merge failed closed",
        ) from exc
    except MergeError as exc:
        raise HTTPException(
            status_code=502,
            detail="governed merge failed closed",
        ) from exc


@app.post(
    "/api/v1/internal/publications/{publication_id}/merge/reconcile",
    dependencies=[Depends(require_token)],
)
def merge_reconcile(
    publication_id: str,
    session: Session = Depends(get_session),
    coordinator: MergeCoordinator = Depends(get_merge_coordinator),
):
    try:
        view = coordinator.reconcile(session, publication_id)
        _sync_publication_watch(session, publication_id)
        return _payload(view)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="publication not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except MergePolicyViolationRecorded as exc:
        _sync_publication_watch(session, publication_id)
        raise HTTPException(
            status_code=502,
            detail="merge reconciliation failed closed",
        ) from exc
    except MergeError as exc:
        raise HTTPException(
            status_code=502,
            detail="merge reconciliation failed closed",
        ) from exc


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
        view = materializer.materialize(session, work_package_id)
        _sync_publication_watch(session, view.publication_id)
        return _work_package_payload(view)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="work package not found") from exc
    except DomainError as exc:
        raise _conflict(exc) from exc
    except RemediationMaterializationError as exc:
        raise HTTPException(
            status_code=502,
            detail="remediation materialization failed closed",
        ) from exc
