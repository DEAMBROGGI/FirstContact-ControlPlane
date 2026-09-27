from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import httpx


class GitHubUserAuthError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DeviceAuthorization:
    device_code: str
    user_code: str
    verification_uri: str
    expires_at: datetime
    interval_seconds: int


@dataclass(frozen=True, slots=True)
class StoredUserCredential:
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    login: str


@dataclass(frozen=True, slots=True)
class UserAccess:
    token: str
    login: str
    expires_at: datetime


class GitHubUserTokenStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        if not self.path.is_absolute():
            raise GitHubUserAuthError(
                "GitHub user-token path must be absolute"
            )

    def load(self) -> StoredUserCredential:
        if not self.path.is_file():
            raise GitHubUserAuthError(
                "GitHub review user credential is unavailable"
            )
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return StoredUserCredential(
                access_token=str(payload["access_token"]),
                access_expires_at=datetime.fromisoformat(
                    str(payload["access_expires_at"])
                ).astimezone(timezone.utc),
                refresh_token=str(payload["refresh_token"]),
                refresh_expires_at=datetime.fromisoformat(
                    str(payload["refresh_expires_at"])
                ).astimezone(timezone.utc),
                login=str(payload["login"]),
            )
        except (
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise GitHubUserAuthError(
                "GitHub review user credential is invalid"
            ) from exc

    def save(self, credential: StoredUserCredential) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.tmp"
        )
        payload = {
            "access_token": credential.access_token,
            "access_expires_at": credential.access_expires_at.isoformat(),
            "refresh_token": credential.refresh_token,
            "refresh_expires_at": credential.refresh_expires_at.isoformat(),
            "login": credential.login,
        }
        try:
            temp.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            if os.name != "nt":
                os.chmod(temp, 0o600)
            os.replace(temp, self.path)
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise GitHubUserAuthError(
                "failed to persist GitHub review user credential"
            ) from exc


class GitHubDeviceFlow:
    def __init__(
        self,
        *,
        client_id: str,
        store: GitHubUserTokenStore,
        github_url: str = "https://github.com",
        api_url: str = "https://api.github.com",
        client: httpx.Client | None = None,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.client_id = client_id.strip()
        self.store = store
        self.github_url = github_url.rstrip("/")
        self.api_url = api_url.rstrip("/")
        self.client = client or httpx.Client(timeout=15.0)
        self._owns_client = client is None
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep or time.sleep

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    @staticmethod
    def _json_headers() -> dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": "FirstContact-ControlPlane/0.1",
        }

    def start(self) -> DeviceAuthorization:
        if not self.client_id:
            raise GitHubUserAuthError(
                "Codex review GitHub client id is not configured"
            )
        try:
            response = self.client.post(
                f"{self.github_url}/login/device/code",
                headers=self._json_headers(),
                data={"client_id": self.client_id},
            )
        except httpx.HTTPError as exc:
            raise GitHubUserAuthError(
                "GitHub device authorization request failed"
            ) from exc
        if response.status_code != 200:
            raise GitHubUserAuthError(
                f"GitHub device authorization failed with HTTP "
                f"{response.status_code}"
            )
        try:
            payload = response.json()
            expires_in = int(payload["expires_in"])
            interval = max(1, int(payload.get("interval", 5)))
            return DeviceAuthorization(
                device_code=str(payload["device_code"]),
                user_code=str(payload["user_code"]),
                verification_uri=str(payload["verification_uri"]),
                expires_at=self.now().astimezone(timezone.utc)
                + timedelta(seconds=expires_in),
                interval_seconds=interval,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubUserAuthError(
                "GitHub device authorization response is invalid"
            ) from exc

    def _exchange_once(
        self,
        authorization: DeviceAuthorization,
    ) -> tuple[dict | None, int]:
        try:
            response = self.client.post(
                f"{self.github_url}/login/oauth/access_token",
                headers=self._json_headers(),
                data={
                    "client_id": self.client_id,
                    "device_code": authorization.device_code,
                    "grant_type": (
                        "urn:ietf:params:oauth:grant-type:device_code"
                    ),
                },
            )
        except httpx.HTTPError as exc:
            raise GitHubUserAuthError(
                "GitHub device token exchange failed"
            ) from exc
        if response.status_code != 200:
            raise GitHubUserAuthError(
                f"GitHub device token exchange failed with HTTP "
                f"{response.status_code}"
            )
        payload = response.json()
        error = payload.get("error")
        if error is None:
            return payload, authorization.interval_seconds
        if error == "authorization_pending":
            return None, authorization.interval_seconds
        if error == "slow_down":
            return None, authorization.interval_seconds + 5
        if error == "device_flow_disabled":
            raise GitHubUserAuthError(
                "GitHub App device flow is disabled"
            )
        if error == "access_denied":
            raise GitHubUserAuthError(
                "GitHub device authorization was denied"
            )
        if error in {"expired_token", "token_expired"}:
            raise GitHubUserAuthError(
                "GitHub device authorization expired"
            )
        raise GitHubUserAuthError(
            f"GitHub device authorization failed: {error}"
        )

    def _identify_user(self, access_token: str) -> str:
        try:
            response = self.client.get(
                f"{self.api_url}/user",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {access_token}",
                    "X-GitHub-Api-Version": "2026-03-10",
                    "User-Agent": "FirstContact-ControlPlane/0.1",
                },
            )
        except httpx.HTTPError as exc:
            raise GitHubUserAuthError(
                "GitHub user identity request failed"
            ) from exc
        if response.status_code != 200:
            raise GitHubUserAuthError(
                f"GitHub user identity failed with HTTP "
                f"{response.status_code}"
            )
        try:
            login = str(response.json()["login"])
        except (KeyError, TypeError) as exc:
            raise GitHubUserAuthError(
                "GitHub user identity response is invalid"
            ) from exc
        if not login:
            raise GitHubUserAuthError("GitHub user login is empty")
        return login

    def wait_and_store(
        self,
        authorization: DeviceAuthorization,
        *,
        expected_login: str,
    ) -> StoredUserCredential:
        delay = authorization.interval_seconds
        while self.now().astimezone(timezone.utc) < authorization.expires_at:
            payload, delay = self._exchange_once(authorization)
            if payload is None:
                self.sleep(delay)
                continue
            credential = self._credential_from_token_payload(
                payload,
                expected_login=expected_login,
            )
            self.store.save(credential)
            return credential
        raise GitHubUserAuthError(
            "GitHub device authorization expired"
        )

    def _credential_from_token_payload(
        self,
        payload: dict,
        *,
        expected_login: str,
    ) -> StoredUserCredential:
        try:
            access_token = str(payload["access_token"])
            refresh_token = str(payload["refresh_token"])
            expires_in = int(payload["expires_in"])
            refresh_expires_in = int(payload["refresh_token_expires_in"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubUserAuthError(
                "GitHub user-token response is invalid"
            ) from exc
        now = self.now().astimezone(timezone.utc)
        login = self._identify_user(access_token)
        if expected_login and login.lower() != expected_login.lower():
            raise GitHubUserAuthError(
                "authorized GitHub user does not match configured reviewer"
            )
        return StoredUserCredential(
            access_token=access_token,
            access_expires_at=now + timedelta(seconds=expires_in),
            refresh_token=refresh_token,
            refresh_expires_at=now
            + timedelta(seconds=refresh_expires_in),
            login=login,
        )

    def refresh(
        self,
        credential: StoredUserCredential,
        *,
        expected_login: str,
    ) -> StoredUserCredential:
        now = self.now().astimezone(timezone.utc)
        if credential.refresh_expires_at <= now:
            raise GitHubUserAuthError(
                "GitHub review refresh token has expired"
            )
        try:
            response = self.client.post(
                f"{self.github_url}/login/oauth/access_token",
                headers=self._json_headers(),
                data={
                    "client_id": self.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": credential.refresh_token,
                },
            )
        except httpx.HTTPError as exc:
            raise GitHubUserAuthError(
                "GitHub review user-token refresh failed"
            ) from exc
        if response.status_code != 200:
            raise GitHubUserAuthError(
                f"GitHub review user-token refresh failed with HTTP "
                f"{response.status_code}"
            )
        payload = response.json()
        if payload.get("error"):
            raise GitHubUserAuthError(
                "GitHub review user-token refresh was rejected"
            )
        refreshed = self._credential_from_token_payload(
            payload,
            expected_login=expected_login,
        )
        self.store.save(refreshed)
        return refreshed


class GitHubUserAccessProvider:
    def __init__(
        self,
        *,
        client_id: str,
        token_path: str | Path,
        expected_login: str,
        github_url: str = "https://github.com",
        api_url: str = "https://api.github.com",
        client: httpx.Client | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.expected_login = expected_login.strip()
        self.store = GitHubUserTokenStore(token_path)
        self.flow = GitHubDeviceFlow(
            client_id=client_id,
            store=self.store,
            github_url=github_url,
            api_url=api_url,
            client=client,
            now=now,
        )
        self.now = now or (lambda: datetime.now(timezone.utc))

    def close(self) -> None:
        self.flow.close()

    def access(self) -> UserAccess:
        credential = self.store.load()
        now = self.now().astimezone(timezone.utc)
        if credential.login.lower() != self.expected_login.lower():
            raise GitHubUserAuthError(
                "stored GitHub review user does not match configured reviewer"
            )
        if credential.access_expires_at <= now + timedelta(minutes=2):
            credential = self.flow.refresh(
                credential,
                expected_login=self.expected_login,
            )
        return UserAccess(
            token=credential.access_token,
            login=credential.login,
            expires_at=credential.access_expires_at,
        )


def _authorize_cli() -> int:
    parser = argparse.ArgumentParser(
        description="Authorize the Codex Review Broker GitHub user."
    )
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--token-path", required=True)
    parser.add_argument("--expected-login", required=True)
    args = parser.parse_args()

    store = GitHubUserTokenStore(args.token_path)
    flow = GitHubDeviceFlow(
        client_id=args.client_id,
        store=store,
    )
    try:
        authorization = flow.start()
        print(f"DEVICE_USER_CODE={authorization.user_code}", flush=True)
        print(
            f"DEVICE_VERIFICATION_URI={authorization.verification_uri}",
            flush=True,
        )
        print("WAITING_FOR_AUTHORIZATION=True", flush=True)
        credential = flow.wait_and_store(
            authorization,
            expected_login=args.expected_login,
        )
        print(f"AUTHORIZED_LOGIN={credential.login}", flush=True)
        print("USER_CREDENTIAL_STORED=True", flush=True)
        return 0
    finally:
        flow.close()


if __name__ == "__main__":
    raise SystemExit(_authorize_cli())
