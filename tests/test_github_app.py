from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from control_plane.github_app import GitHubAppTokenProvider, GitHubAuthError


def test_github_app_jwt_and_repository_scoped_installation_token(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = (tmp_path / "app.pem").resolve()
    key_path.write_bytes(pem)
    public_key = private_key.public_key()
    now = datetime(2026, 9, 27, 19, 0, tzinfo=timezone.utc)
    observed = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        authorization = request.headers["Authorization"]
        assert authorization.startswith("Bearer ")
        app_jwt = authorization.removeprefix("Bearer ")
        claims = jwt.decode(
            app_jwt,
            public_key,
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_iat": False},
        )
        assert claims["iss"] == "123456"
        assert claims["exp"] - claims["iat"] == 600

        if request.url.path == "/repos/DEAMBROGGI/FirstContact/installation":
            return httpx.Response(200, json={"id": 987654})
        if request.url.path == "/app/installations/987654/access_tokens":
            body = json.loads(request.content.decode("utf-8"))
            assert body == {
                "repositories": ["FirstContact"],
                "permissions": {
                    "contents": "write",
                    "pull_requests": "write",
                },
            }
            return httpx.Response(
                201,
                json={
                    "token": "ghs_123456_stateless_token_shape_is_opaque",
                    "expires_at": "2026-09-27T20:00:00Z",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://api.github.test",
    )
    provider = GitHubAppTokenProvider(
        app_id="123456",
        private_key_path=key_path,
        api_url="https://api.github.test",
        client=client,
        now=lambda: now,
    )

    access = provider.installation_access("DEAMBROGGI/FirstContact")

    assert access.installation_id == 987654
    assert access.token == "ghs_123456_stateless_token_shape_is_opaque"
    assert access.expires_at == datetime(
        2026, 9, 27, 20, 0, tzinfo=timezone.utc
    )
    assert len(observed) == 2


def test_installation_token_allows_issue_permission_and_rejects_project_scope(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = (tmp_path / "app.pem").resolve()
    key_path.write_bytes(pem)
    now = datetime(2026, 9, 27, 19, 0, tzinfo=timezone.utc)
    access_token_request = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/DEAMBROGGI/FirstContact/installation":
            return httpx.Response(200, json={"id": 987654})
        if request.url.path == "/app/installations/987654/access_tokens":
            access_token_request.update(json.loads(request.content.decode("utf-8")))
            return httpx.Response(
                201,
                json={
                    "token": "opaque-token-never-logged",
                    "expires_at": "2026-09-27T20:00:00Z",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    provider = GitHubAppTokenProvider(
        app_id="123456",
        private_key_path=key_path,
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: now,
    )

    access = provider.installation_access(
        "DEAMBROGGI/FirstContact",
        permissions={"issues": "write"},
    )

    assert access.installation_id == 987654
    assert access_token_request == {
        "repositories": ["FirstContact"],
        "permissions": {"issues": "write"},
    }
    with pytest.raises(GitHubAuthError, match="unsupported installation permission"):
        provider.installation_access(
            "DEAMBROGGI/FirstContact",
            permissions={"organization_projects": "write"},
        )
