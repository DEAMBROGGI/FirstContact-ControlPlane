import asyncio
import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import SecretStr

import control_plane.main as main_module
from control_plane.config import settings
from control_plane.codex_review import CodexReviewError
from control_plane.db import get_session
from control_plane.domain import AutomatedReviewStatus, EventType, ValidationStatus
from control_plane.github_api import GitHubApiError, PullRequestSnapshot
from control_plane.github_app import GitHubAuthError
from control_plane.github_webhook import (
    GitHubWebhookGateway,
    WebhookProcessResult,
    mark_delivery_retry,
    sync_review_watch,
)
from control_plane.main import (
    app,
    get_github_authoritative_gateway,
    get_github_webhook_gateway,
)
from control_plane.models import GitHubWebhookDeliveryRow, ReviewWatchRow
from control_plane.profile_registry import profile_for_repository
from control_plane.publisher import PublicationError
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.repository import load_events
from control_plane.service import (
    complete_codex_review,
    create_publication,
    mark_remote_published,
    request_codex_review,
    record_validation,
    submit_verified_candidate,
)


REPOSITORY = "DEAMBROGGI/FirstContact-ControlPlane"
SECRET = "api-webhook-secret"
BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


class NoRemoteTokenProvider:
    def installation_access(self, *_args, **_kwargs):
        raise AssertionError("unsupported webhook event must not request GitHub access")


class NoRemoteGitHub:
    pass


def client_for(session, gateway=None):
    if gateway is None:
        gateway = GitHubWebhookGateway(
            token_provider=NoRemoteTokenProvider(),
            github=NoRemoteGitHub(),
            codex_review_mode="required",
            codex_actors=("chatgpt-codex-connector[bot]",),
            human_review_actors=("DEAMBROGGI",),
            webhook_secret=SECRET,
            maximum_payload_bytes=1024 * 1024,
        )

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_github_webhook_gateway] = lambda: gateway
    app.dependency_overrides[get_github_authoritative_gateway] = lambda: gateway
    return TestClient(app)


def client_for_session(session):
    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    return TestClient(app)


def configure_github_app_without_webhook_secret(monkeypatch):
    monkeypatch.setattr(settings, "publisher_mode", "github-app")
    monkeypatch.setattr(settings, "github_webhook_secret", SecretStr(""))
    monkeypatch.setattr(settings, "codex_review_mode", "disabled")
    monkeypatch.setattr(settings, "codex_review_actors", "")
    monkeypatch.setattr(settings, "human_review_actors", "DEAMBROGGI")
    monkeypatch.setattr(
        main_module,
        "GitHubAppTokenProvider",
        FakeApiTokenProvider,
    )
    monkeypatch.setattr(
        main_module,
        "GitHubRepositoryGateway",
        lambda **_kwargs: FakeApiGitHub(),
    )


def published_publication(session):
    view = create_publication(session, REPOSITORY, 2602)
    view = submit_verified_candidate(
        session,
        view.publication_id,
        VerifiedCandidateSource(
            bundle_sha256="a" * 64,
            byte_length=1234,
            quarantine_id="a" * 64,
            base_sha=BASE,
            head_sha=HEAD,
            tree_sha=TREE,
        ),
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )
    return mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch="control-plane/issue-2602-api",
        base_branch="master",
        pull_request_number=44,
    )


class FakeApiTokenProvider:
    def __init__(self, **_kwargs):
        pass

    def installation_access(self, *_args, **_kwargs):
        return SimpleNamespace(token="installation-token")

    def close(self):
        pass


class FakeApiGitHub:
    def pull_request(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == 44
        assert token == "installation-token"
        return PullRequestSnapshot(
            number=44,
            state="open",
            base_ref="master",
            head_ref="control-plane/issue-2602-api",
            head_sha=HEAD,
            mergeable=True,
        )

    def ref_sha(self, repository, branch, token):
        assert repository == REPOSITORY
        assert branch == "master"
        assert token == "installation-token"
        return BASE

    def list_pull_reviews(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == 44
        assert token == "installation-token"
        return []

    def close(self):
        pass


def signed_body():
    body = json.dumps(
        {
            "zen": "wake up only",
            "repository": {"full_name": REPOSITORY},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return body, signature


def signed_push_body():
    body = json.dumps(
        {
            "ref": "refs/heads/master",
            "after": BASE,
            "repository": {"full_name": REPOSITORY},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return body, signature


def test_public_webhook_endpoint_requires_signature_not_internal_token(session):
    client = client_for(session)
    body, signature = signed_body()
    headers = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": signature,
        "X-GitHub-Delivery": "api-delivery-1",
        "X-GitHub-Event": "ping",
    }
    try:
        accepted = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers=headers,
        )
        assert accepted.status_code == 200, accepted.text
        delivery = accepted.json()["delivery"]
        assert delivery["state"] == "IGNORED"
        assert delivery["attempt_count"] == 0
        assert delivery["processed_at"] is None
        assert accepted.json()["processing"]["outcome"] == "IGNORED"

        row = session.get(GitHubWebhookDeliveryRow, "api-delivery-1")
        assert row is not None
        assert row.state == "IGNORED"

        replay = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers=headers,
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["delivery"] == delivery
        assert replay.json()["processing"]["outcome"] == "IGNORED"

        unauthorized_reconcile = client.post(
            "/api/v1/internal/github/webhooks/reconcile",
        )
        assert unauthorized_reconcile.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_public_webhook_returns_post_processing_state_and_idempotent_replay(session):
    gateway = GitHubWebhookGateway(
        token_provider=FakeApiTokenProvider(),
        github=FakeApiGitHub(),
        codex_review_mode="required",
        codex_actors=("chatgpt-codex-connector[bot]",),
        human_review_actors=("DEAMBROGGI",),
        webhook_secret=SECRET,
        maximum_payload_bytes=1024 * 1024,
    )
    client = client_for(session, gateway)
    body, signature = signed_push_body()
    headers = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": signature,
        "X-GitHub-Delivery": "api-processed-push-1",
        "X-GitHub-Event": "push",
    }
    try:
        accepted = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers=headers,
        )
        assert accepted.status_code == 200, accepted.text
        delivery = accepted.json()["delivery"]
        assert delivery["state"] == "PROCESSED"
        assert delivery["attempt_count"] == 1
        assert delivery["processed_at"] is not None
        assert accepted.json()["processing"]["outcome"] == (
            "BASE_PUSH_STALE:0:RECOVERED:0"
        )

        replay = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers=headers,
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["delivery"] == delivery
        assert replay.json()["processing"]["outcome"] == "PROCESSED"

        row = session.get(GitHubWebhookDeliveryRow, "api-processed-push-1")
        assert row is not None
        assert row.state == "PROCESSED"
        assert row.attempt_count == 1
        assert row.processed_at is not None
    finally:
        app.dependency_overrides.clear()


def test_public_webhook_endpoint_rejects_bad_signature_without_persistence(session):
    client = client_for(session)
    body, _signature = signed_body()
    try:
        rejected = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=" + ("0" * 64),
                "X-GitHub-Delivery": "api-delivery-invalid",
                "X-GitHub-Event": "ping",
            },
        )
        assert rejected.status_code == 401
        assert session.get(
            GitHubWebhookDeliveryRow,
            "api-delivery-invalid",
        ) is None
    finally:
        app.dependency_overrides.clear()


def test_webhook_stream_body_enforces_limit_with_and_without_content_length():
    class OversizedDeclaredRequest:
        headers = {"content-length": "6"}

        async def stream(self):
            raise AssertionError("oversized declared body must not be consumed")
            yield b""

    with pytest.raises(HTTPException) as declared_error:
        asyncio.run(
            main_module._read_limited_webhook_body(
                OversizedDeclaredRequest(),
                maximum_bytes=5,
            )
        )
    assert declared_error.value.status_code == 413

    class ChunkedRequest:
        headers = {}

        async def stream(self):
            yield b"1234"
            yield b"56"

    with pytest.raises(HTTPException) as streamed_error:
        asyncio.run(
            main_module._read_limited_webhook_body(
                ChunkedRequest(),
                maximum_bytes=5,
            )
        )
    assert streamed_error.value.status_code == 413


def test_public_webhook_runs_sync_delivery_processing_in_threadpool(
    session,
    monkeypatch,
):
    thread_ids = {}
    original_run_in_threadpool = main_module.run_in_threadpool

    def process_delivery(_gateway, _session, delivery_id):
        thread_ids["worker"] = threading.get_ident()
        return WebhookProcessResult(
            delivery_id=delivery_id,
            publication_id=None,
            outcome="IGNORED",
            next_role="NONE",
            next_action="DONE",
            watch_state=None,
        )

    async def observed_run_in_threadpool(function, *args):
        thread_ids["event_loop"] = threading.get_ident()
        return await original_run_in_threadpool(function, *args)

    monkeypatch.setattr(
        GitHubWebhookGateway,
        "process_delivery",
        process_delivery,
    )
    monkeypatch.setattr(
        main_module,
        "run_in_threadpool",
        observed_run_in_threadpool,
    )
    client = client_for(session)
    body, signature = signed_body()
    try:
        response = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Delivery": "api-threadpool-delivery",
                "X-GitHub-Event": "ping",
            },
        )
        assert response.status_code == 200, response.text
        assert thread_ids["worker"] != thread_ids["event_loop"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "error_type",
    [GitHubAuthError, GitHubApiError, CodexReviewError],
)
def test_public_webhook_sanitizes_retryable_processing_errors(
    session,
    monkeypatch,
    error_type,
):
    internal_detail = "provider response includes private diagnostic detail"

    def fail_processing(_gateway, current_session, delivery_id):
        mark_delivery_retry(current_session, delivery_id, internal_detail)
        raise error_type(internal_detail)

    monkeypatch.setattr(GitHubWebhookGateway, "process_delivery", fail_processing)
    client = client_for(session)
    body, signature = signed_body()
    delivery_id = f"api-retry-{error_type.__name__}"
    try:
        response = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Delivery": delivery_id,
                "X-GitHub-Event": "ping",
            },
        )

        assert response.status_code == 502
        assert response.json() == {
            "detail": "GitHub webhook processing failed closed"
        }
        assert internal_detail not in response.text
        row = session.get(GitHubWebhookDeliveryRow, delivery_id)
        assert row is not None
        assert row.state == "PENDING"
        assert row.attempt_count == 1
        assert row.processed_at is None
    finally:
        app.dependency_overrides.clear()


def test_public_webhook_endpoint_requires_configured_secret(session, monkeypatch):
    configure_github_app_without_webhook_secret(monkeypatch)
    client = client_for_session(session)
    try:
        rejected = client.post(
            "/api/v1/github/webhooks",
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=" + ("0" * 64),
                "X-GitHub-Delivery": "api-delivery-no-secret",
                "X-GitHub-Event": "ping",
            },
        )
        assert rejected.status_code == 503
        assert rejected.json()["detail"] == "GitHub webhook secret is not configured"
        assert session.get(
            GitHubWebhookDeliveryRow,
            "api-delivery-no-secret",
        ) is None
    finally:
        app.dependency_overrides.clear()


def test_internal_publication_reconcile_does_not_require_webhook_secret(
    session,
    monkeypatch,
):
    configure_github_app_without_webhook_secret(monkeypatch)
    view = published_publication(session)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=("DEAMBROGGI",),
    )
    client = client_for_session(session)
    try:
        reconciled = client.post(
            "/api/v1/internal/github/webhooks/reconcile",
            params={"publication_id": view.publication_id},
            headers={"X-Control-Plane-Token": settings.internal_token},
        )
        assert reconciled.status_code == 200, reconciled.text
        assert reconciled.json()["outcome"] == "RECONCILED"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("error_type", [GitHubApiError, CodexReviewError])
def test_internal_webhook_reconcile_sanitizes_provider_errors(
    session,
    error_type,
):
    internal_detail = "provider response includes private diagnostic detail"

    class FailingGateway:
        def reconcile_publication(self, *_args, **_kwargs):
            raise error_type(internal_detail)

    client = client_for_session(session)
    app.dependency_overrides[get_github_authoritative_gateway] = (
        lambda: FailingGateway()
    )
    try:
        response = client.post(
            "/api/v1/internal/github/webhooks/reconcile",
            params={"publication_id": "provider-error-publication"},
            headers={"X-Control-Plane-Token": settings.internal_token},
        )

        assert response.status_code == 502
        assert response.json() == {
            "detail": "GitHub reconciliation failed closed"
        }
        assert internal_detail not in response.text
    finally:
        app.dependency_overrides.clear()


def test_direct_human_review_readback_does_not_require_webhook_secret(
    session,
    monkeypatch,
):
    configure_github_app_without_webhook_secret(monkeypatch)
    view = published_publication(session)
    client = client_for_session(session)
    try:
        reviewed = client.post(
            f"/api/v1/publications/{view.publication_id}/reviews",
            headers={"X-Control-Plane-Token": settings.internal_token},
            json={
                "reviewed_head_sha": HEAD,
                "decision": "CHANGES_REQUIRED",
            },
        )
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["review_decision"] == "CHANGES_REQUIRED"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("decision", ["APPROVED", "CHANGES_REQUIRED"])
def test_direct_human_review_rejects_merged_pull_without_recording_event(
    session,
    monkeypatch,
    decision,
):
    configure_github_app_without_webhook_secret(monkeypatch)

    class MergedApiGitHub(FakeApiGitHub):
        def pull_request(self, repository, number, token):
            pull = super().pull_request(repository, number, token)
            return PullRequestSnapshot(
                number=pull.number,
                state="closed",
                base_ref=pull.base_ref,
                head_ref=pull.head_ref,
                head_sha=pull.head_sha,
                merged=True,
                merge_commit_sha="4" * 40,
            )

    monkeypatch.setattr(
        main_module,
        "GitHubRepositoryGateway",
        lambda **_kwargs: MergedApiGitHub(),
    )
    view = published_publication(session)
    client = client_for_session(session)
    try:
        response = client.post(
            f"/api/v1/publications/{view.publication_id}/reviews",
            headers={"X-Control-Plane-Token": settings.internal_token},
            json={"reviewed_head_sha": HEAD, "decision": decision},
        )

        assert response.status_code == 409
        assert "already merged" in response.json()["detail"]
        assert not any(
            event["event_type"] == EventType.REVIEW_RECORDED.value
            for event in load_events(session, view.publication_id)
        )
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    ("mode", "expected_role", "expected_action"),
    [
        ("advisory", "HUMAN_REVIEWER", "WAIT_HUMAN_REVIEW"),
        ("required", "IMPLEMENTER", "REMEDIATE_FINDINGS"),
    ],
)
def test_codex_review_reconcile_syncs_watch_using_configured_mode(
    session,
    monkeypatch,
    mode,
    expected_role,
    expected_action,
):
    @dataclass(frozen=True)
    class Observation:
        outcome: str = "RECONCILED"

    class Broker:
        def reconcile(self, _session, _publication_id):
            return Observation()

    monkeypatch.setattr(settings, "codex_review_mode", mode)
    monkeypatch.setattr(settings, "codex_review_actors", "CODEX")
    monkeypatch.setattr(settings, "human_review_actors", "DEAMBROGGI")
    view = published_publication(session)
    requested = request_codex_review(
        session,
        view.publication_id,
        mode=mode,
        expected_head_sha=HEAD,
    )
    complete_codex_review(
        session,
        view.publication_id,
        run_id=requested.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.CHANGES_REQUIRED,
        findings=[{"path": "src/example.py", "line": 1, "body": "finding"}],
        provider_review_ids=[1],
        provider_comment_ids=[2],
    )
    client = client_for_session(session)
    app.dependency_overrides[main_module.get_codex_review_broker] = lambda: Broker()
    try:
        response = client.post(
            f"/api/v1/internal/publications/{view.publication_id}/codex-review/reconcile",
            headers={"X-Control-Plane-Token": settings.internal_token},
        )

        assert response.status_code == 200, response.text
        expected_state = "IN_REVIEW" if mode == "advisory" else "CHANGES_REQUIRED"
        assert response.json()["publication"]["state"] == expected_state
        watch = session.get(ReviewWatchRow, view.publication_id)
        assert watch is not None
        assert watch.next_role == expected_role
        assert watch.next_action == expected_action
    finally:
        app.dependency_overrides.clear()


def test_internal_reconcile_reconstructs_missing_legacy_review_watch(
    session,
    monkeypatch,
):
    configure_github_app_without_webhook_secret(monkeypatch)
    view = published_publication(session)
    assert session.get(ReviewWatchRow, view.publication_id) is None
    client = client_for_session(session)
    headers = {"X-Control-Plane-Token": settings.internal_token}
    watch_url = f"/api/v1/internal/github/review-watches/{view.publication_id}"
    try:
        missing = client.get(watch_url, headers=headers)
        assert missing.status_code == 404

        reconciled = client.post(
            "/api/v1/internal/github/webhooks/reconcile",
            params={"publication_id": view.publication_id},
            headers=headers,
        )
        assert reconciled.status_code == 200, reconciled.text
        assert reconciled.json()["outcome"] == "RECONCILED"
        assert session.get(ReviewWatchRow, view.publication_id) is not None

        reconstructed = client.get(watch_url, headers=headers)
        assert reconstructed.status_code == 200, reconstructed.text
        assert reconstructed.json()["publication_id"] == view.publication_id
        assert reconstructed.json()["watched_head_sha"] == HEAD
    finally:
        app.dependency_overrides.clear()


def test_successful_publication_materializes_watch_without_codex_request(
    session,
    monkeypatch,
):
    configure_github_app_without_webhook_secret(monkeypatch)
    view = published_publication(session)
    assert session.get(ReviewWatchRow, view.publication_id) is None

    class FailedPublisher:
        def publish(self, _session, _publication_id):
            raise PublicationError("simulated publication failure")

    with pytest.raises(HTTPException) as failed:
        main_module.publication_publish(
            view.publication_id,
            session=session,
            publisher=FailedPublisher(),
        )
    assert failed.value.status_code == 502
    assert session.get(ReviewWatchRow, view.publication_id) is None

    class SuccessfulPublisher:
        def publish(self, _session, publication_id):
            assert publication_id == view.publication_id
            return view

    response = main_module.publication_publish(
        view.publication_id,
        session=session,
        publisher=SuccessfulPublisher(),
    )

    assert response["publication_id"] == view.publication_id
    watch = session.get(ReviewWatchRow, view.publication_id)
    assert watch is not None
    assert watch.watched_head_sha == HEAD
    assert watch.state == "ACTIVE"
    assert watch.next_role == "HUMAN_REVIEWER"
    assert watch.next_action == "WAIT_HUMAN_REVIEW"



def test_lifespan_runs_pending_recovery_after_init(monkeypatch):
    calls = []

    monkeypatch.setattr(
        main_module,
        "init_db",
        lambda: calls.append("init"),
    )
    monkeypatch.setattr(
        main_module,
        "_startup_reconcile_pending_webhooks",
        lambda: calls.append("recover") or 0,
    )

    async def run():
        async with main_module.lifespan(main_module.app):
            calls.append("yield")

    asyncio.run(run())

    assert calls == ["init", "recover", "yield"]
