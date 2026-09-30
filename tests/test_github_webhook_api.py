import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from control_plane.config import settings
from control_plane.db import get_session
from control_plane.github_webhook import GitHubWebhookGateway
from control_plane.main import app, get_github_webhook_gateway
from control_plane.models import GitHubWebhookDeliveryRow


REPOSITORY = "DEAMBROGGI/FirstContact-ControlPlane"
SECRET = "api-webhook-secret"


class NoRemoteTokenProvider:
    def installation_access(self, *_args, **_kwargs):
        raise AssertionError("unsupported webhook event must not request GitHub access")


class NoRemoteGitHub:
    pass


def client_for(session):
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
    return TestClient(app)


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


def test_public_webhook_endpoint_requires_signature_not_internal_token(session):
    client = client_for(session)
    body, signature = signed_body()
    try:
        accepted = client.post(
            "/api/v1/github/webhooks",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Delivery": "api-delivery-1",
                "X-GitHub-Event": "ping",
            },
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["delivery"]["state"] == "IGNORED"
        assert accepted.json()["processing"]["outcome"] == "IGNORED"

        row = session.get(GitHubWebhookDeliveryRow, "api-delivery-1")
        assert row is not None
        assert row.state == "IGNORED"

        unauthorized_reconcile = client.post(
            "/api/v1/internal/github/webhooks/reconcile",
        )
        assert unauthorized_reconcile.status_code == 401
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
