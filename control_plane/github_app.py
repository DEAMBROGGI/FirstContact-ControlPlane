from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import httpx
import jwt


class GitHubAuthError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class InstallationAccess:
    installation_id: int
    token: str
    expires_at: datetime


class GitHubAppTokenProvider:
    def __init__(
        self,
        *,
        app_id: str,
        private_key_path: str | Path,
        api_url: str = "https://api.github.com",
        client: httpx.Client | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.app_id = str(app_id).strip()
        self.private_key_path = Path(private_key_path).expanduser()
        self.api_url = api_url.rstrip("/")
        self.client = client or httpx.Client(timeout=15.0)
        self._owns_client = client is None
        self.now = now or (lambda: datetime.now(timezone.utc))

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> "GitHubAppTokenProvider":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
    def _jwt(self) -> str:
        if not self.app_id:
            raise GitHubAuthError("GitHub App id is not configured")
        if not self.private_key_path.is_absolute():
            raise GitHubAuthError("GitHub App private-key path must be absolute")
        if not self.private_key_path.is_file():
            raise GitHubAuthError("GitHub App private key is unavailable")
        try:
            private_key = self.private_key_path.read_bytes()
        except OSError as exc:
            raise GitHubAuthError("GitHub App private key cannot be read") from exc

        now = self.now().astimezone(timezone.utc)
        issued_at = now - timedelta(seconds=60)
        expires_at = now + timedelta(minutes=9)
        try:
            return jwt.encode(
                {
                    "iat": int(issued_at.timestamp()),
                    "exp": int(expires_at.timestamp()),
                    "iss": self.app_id,
                },
                private_key,
                algorithm="RS256",
            )
        except Exception as exc:
            raise GitHubAuthError("GitHub App JWT signing failed") from exc

    @staticmethod
    def _repository_parts(repository: str) -> tuple[str, str]:
        parts = repository.split("/")
        if len(parts) != 2 or not all(parts):
            raise GitHubAuthError("repository must be owner/name")
        owner, name = parts
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        if any(char not in allowed for char in owner + name):
            raise GitHubAuthError("repository contains unsupported characters")
        return owner, name
    def _headers(self, app_jwt: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "FirstContact-ControlPlane/0.1",
        }

    def _request(
        self,
        method: str,
        url: str,
        *,
        app_jwt: str,
        json: dict | None = None,
    ) -> httpx.Response:
        try:
            response = self.client.request(
                method,
                url,
                headers=self._headers(app_jwt),
                json=json,
            )
        except httpx.HTTPError as exc:
            raise GitHubAuthError("GitHub App authentication request failed") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise GitHubAuthError(
                f"GitHub App authentication failed with HTTP {response.status_code}"
            )
        return response

    def installation_access(
        self,
        repository: str,
        *,
        permissions: dict[str, str] | None = None,
    ) -> InstallationAccess:
        owner, name = self._repository_parts(repository)
        requested_permissions = permissions or {
            "contents": "write",
            "pull_requests": "write",
        }
        allowed_permissions = {
            "contents": {"read", "write"},
            "pull_requests": {"read", "write"},
            "issues": {"read", "write"},
        }
        if not requested_permissions:
            raise GitHubAuthError("installation permissions cannot be empty")
        for key, value in requested_permissions.items():
            if key not in allowed_permissions or value not in allowed_permissions[key]:
                raise GitHubAuthError("unsupported installation permission request")
        app_jwt = self._jwt()

        installation_response = self._request(
            "GET",
            f"{self.api_url}/repos/{owner}/{name}/installation",
            app_jwt=app_jwt,
        )
        try:
            installation_id = int(installation_response.json()["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubAuthError("GitHub installation response is invalid") from exc

        token_response = self._request(
            "POST",
            f"{self.api_url}/app/installations/{installation_id}/access_tokens",
            app_jwt=app_jwt,
            json={
                "repositories": [name],
                "permissions": requested_permissions,
            },
        )
        try:
            payload = token_response.json()
            token = str(payload["token"])
            expires_at = datetime.fromisoformat(
                str(payload["expires_at"]).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubAuthError("GitHub installation token response is invalid") from exc

        if not token:
            raise GitHubAuthError("GitHub installation token is empty")
        if expires_at <= self.now().astimezone(timezone.utc):
            raise GitHubAuthError("GitHub installation token is already expired")
        return InstallationAccess(
            installation_id=installation_id,
            token=token,
            expires_at=expires_at,
        )
