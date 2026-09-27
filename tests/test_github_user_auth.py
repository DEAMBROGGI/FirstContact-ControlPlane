from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from control_plane.github_user_auth import (
    GitHubDeviceFlow,
    GitHubUserAccessProvider,
    GitHubUserAuthError,
    GitHubUserTokenStore,
    StoredUserCredential,
)


NOW = datetime(2026, 9, 27, 22, 0, tzinfo=timezone.utc)


def test_device_flow_authorizes_expected_user_and_stores_refreshable_credential(
    tmp_path,
):
    token_path = (tmp_path / "review-user.json").resolve()
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, str(request.url)))
        if request.url.path == "/login/device/code":
            return httpx.Response(
                200,
                json={
                    "device_code": "device-secret",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://github.com/login/device",
                    "expires_in": 900,
                    "interval": 5,
                },
            )
        if request.url.path == "/login/oauth/access_token":
            body = request.content.decode("utf-8")
            assert "client_id=Iv-review-client" in body
            assert "device_code=device-secret" in body
            return httpx.Response(
                200,
                json={
                    "access_token": "ghu_access_secret",
                    "expires_in": 28800,
                    "refresh_token": "ghr_refresh_secret",
                    "refresh_token_expires_in": 15897600,
                    "token_type": "bearer",
                    "scope": "",
                },
            )
        if request.url.path == "/user":
            assert request.headers["Authorization"] == "Bearer ghu_access_secret"
            return httpx.Response(200, json={"login": "DEAMBROGGI"})
        raise AssertionError(str(request.url))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    store = GitHubUserTokenStore(token_path)
    flow = GitHubDeviceFlow(
        client_id="Iv-review-client",
        store=store,
        client=client,
        now=lambda: NOW,
        sleep=lambda _seconds: None,
    )

    authorization = flow.start()
    credential = flow.wait_and_store(
        authorization,
        expected_login="DEAMBROGGI",
    )

    assert authorization.user_code == "ABCD-EFGH"
    assert credential.login == "DEAMBROGGI"
    assert credential.access_expires_at == NOW + timedelta(hours=8)
    assert store.load() == credential
    assert token_path.is_file()
    assert len(requests) == 3


def test_user_access_provider_refreshes_expiring_device_flow_token(tmp_path):
    token_path = (tmp_path / "review-user.json").resolve()
    store = GitHubUserTokenStore(token_path)
    store.save(
        StoredUserCredential(
            access_token="old-access",
            access_expires_at=NOW + timedelta(seconds=30),
            refresh_token="old-refresh",
            refresh_expires_at=NOW + timedelta(days=30),
            login="DEAMBROGGI",
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            body = request.content.decode("utf-8")
            assert "grant_type=refresh_token" in body
            assert "refresh_token=old-refresh" in body
            return httpx.Response(
                200,
                json={
                    "access_token": "new-access",
                    "expires_in": 28800,
                    "refresh_token": "new-refresh",
                    "refresh_token_expires_in": 15897600,
                },
            )
        if request.url.path == "/user":
            assert request.headers["Authorization"] == "Bearer new-access"
            return httpx.Response(200, json={"login": "DEAMBROGGI"})
        raise AssertionError(str(request.url))

    provider = GitHubUserAccessProvider(
        client_id="Iv-review-client",
        token_path=token_path,
        expected_login="DEAMBROGGI",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: NOW,
    )

    access = provider.access()

    assert access.token == "new-access"
    assert access.login == "DEAMBROGGI"
    assert store.load().refresh_token == "new-refresh"


def test_user_access_provider_rejects_wrong_stored_identity(tmp_path):
    token_path = (tmp_path / "review-user.json").resolve()
    GitHubUserTokenStore(token_path).save(
        StoredUserCredential(
            access_token="access",
            access_expires_at=NOW + timedelta(hours=1),
            refresh_token="refresh",
            refresh_expires_at=NOW + timedelta(days=30),
            login="OTHER",
        )
    )
    provider = GitHubUserAccessProvider(
        client_id="Iv-review-client",
        token_path=token_path,
        expected_login="DEAMBROGGI",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: None)),
        now=lambda: NOW,
    )

    with pytest.raises(GitHubUserAuthError, match="does not match"):
        provider.access()


def test_device_flow_disabled_fails_closed(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/device/code":
            return httpx.Response(
                200,
                json={
                    "device_code": "device-secret",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://github.com/login/device",
                    "expires_in": 900,
                    "interval": 5,
                },
            )
        return httpx.Response(
            200,
            json={"error": "device_flow_disabled"},
        )

    flow = GitHubDeviceFlow(
        client_id="Iv-review-client",
        store=GitHubUserTokenStore(
            (tmp_path / "review-user.json").resolve()
        ),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: NOW,
        sleep=lambda _seconds: None,
    )

    authorization = flow.start()
    with pytest.raises(GitHubUserAuthError, match="device flow is disabled"):
        flow.wait_and_store(
            authorization,
            expected_login="DEAMBROGGI",
        )
