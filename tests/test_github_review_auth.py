from __future__ import annotations

import subprocess
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from control_plane.config import Settings
from control_plane.github_api import GitHubRepositoryGateway
from control_plane.github_review_auth import (
    GitHubReviewAuthError,
    GitHubReviewTokenProvider,
)

TOKEN = "github_pat_test-secret-value"


def provider(handler, *, token=TOKEN, expected_login="DEAMBROGGI"):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    github = GitHubRepositoryGateway(client=client)
    return GitHubReviewTokenProvider(
        token=SecretStr(token),
        expected_login=expected_login,
        github=github,
    ), client


def test_missing_token_fails_before_calling_github():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"login": "DEAMBROGGI"})

    value, client = provider(handler, token="")
    try:
        with pytest.raises(GitHubReviewAuthError, match="not configured"):
            value.access()
        assert requests == []
    finally:
        client.close()


@pytest.mark.parametrize("token", ["ghp_classic-token", "not-a-token"])
def test_non_fine_grained_token_fails_before_calling_github(token):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"login": "DEAMBROGGI"})

    value, client = provider(handler, token=token)
    try:
        with pytest.raises(GitHubReviewAuthError, match="fine-grained"):
            value.access()
        assert requests == []
    finally:
        client.close()


def test_correct_identity_returns_runtime_only_access_without_repr_leak():
    def handler(request):
        assert request.method == "GET"
        assert request.url.path == "/user"
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        return httpx.Response(200, json={"login": "DEAMBROGGI"})

    value, client = provider(handler)
    try:
        access = value.access()
        assert access.token == TOKEN
        assert access.login == "DEAMBROGGI"
        assert TOKEN not in repr(access)
        assert TOKEN not in repr(value)
    finally:
        client.close()


def test_wrong_identity_fails_closed_without_echoing_token():
    def handler(_request):
        return httpx.Response(200, json={"login": "OTHER"})

    value, client = provider(handler)
    try:
        with pytest.raises(GitHubReviewAuthError) as error:
            value.access()
        assert TOKEN not in str(error.value)
    finally:
        client.close()


def test_github_transport_errors_do_not_echo_token():
    def handler(request):
        raise httpx.ConnectError(
            f"transport failed for {TOKEN}",
            request=request,
        )

    value, client = provider(handler)
    try:
        with pytest.raises(GitHubReviewAuthError) as error:
            value.access()
        assert TOKEN not in str(error.value)
        assert error.value.__cause__ is None
    finally:
        client.close()


def test_settings_representation_masks_runtime_token():
    configured = Settings(codex_review_user_token=SecretStr(TOKEN))

    assert TOKEN not in repr(configured)
    assert str(configured.codex_review_user_token) == "**********"


def test_expected_trigger_login_default_is_fail_closed():
    assert Settings.model_fields["codex_review_trigger_login"].default == ""


def test_removed_trigger_auth_artifacts_stay_absent_from_active_sources():
    root = Path(__file__).resolve().parents[1]
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    paths = [root / item.decode("utf-8") for item in listed.split(b"\0") if item]
    # This archived definition is pinned by the immutable control-plane v3
    # profile. Current source, active config, tests, and documentation must be clean.
    historical_job = Path("control_plane/job_definitions/codex-review-broker.v1.json")
    excluded = {
        "".join(("Device", " Flow")),
        "_".join(("device", "flow")),
        "_".join(("refresh", "token")),
        "CONTROL_PLANE_CODEX_REVIEW_" + "GITHUB_CLIENT_ID",
        "CONTROL_PLANE_CODEX_REVIEW_" + "USER_TOKEN_PATH",
        "codex-review-" + "credentials",
        "GitHub" + "UserAccessProvider",
        "github_user" + "_auth",
    }
    violations = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if relative == historical_job.as_posix() or path.suffix.lower() not in {
            ".env",
            ".json",
            ".md",
            ".py",
            ".toml",
            ".yaml",
            ".yml",
        }:
            continue
        try:
            contents = path.read_text(encoding="utf-8").casefold()
        except (OSError, UnicodeError):
            continue
        if any(item.casefold() in contents for item in excluded):
            violations.append(relative)

    assert violations == []
