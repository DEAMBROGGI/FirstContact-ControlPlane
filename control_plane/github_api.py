from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

import httpx


class GitHubApiError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    default_branch: str


@dataclass(frozen=True, slots=True)
class PullRequestSnapshot:
    number: int
    state: str
    base_ref: str
    head_ref: str
    head_sha: str


class GitHubRepositoryGateway:
    def __init__(
        self,
        *,
        api_url: str = "https://api.github.com",
        client: httpx.Client | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.client = client or httpx.Client(timeout=15.0)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> "GitHubRepositoryGateway":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
    @staticmethod
    def _parts(repository: str) -> tuple[str, str]:
        parts = repository.split("/")
        if len(parts) != 2 or not all(parts):
            raise GitHubApiError("repository must be owner/name")
        return parts[0], parts[1]

    @staticmethod
    def _headers(token: str) -> dict[str, str]:
        if not token:
            raise GitHubApiError("installation token is unavailable")
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "FirstContact-ControlPlane/0.1",
        }

    def _request(
        self,
        method: str,
        url: str,
        *,
        token: str,
        params: dict[str, str] | None = None,
        json: dict | None = None,
        allow_404: bool = False,
    ) -> httpx.Response | None:
        try:
            response = self.client.request(
                method,
                url,
                headers=self._headers(token),
                params=params,
                json=json,
            )
        except httpx.HTTPError as exc:
            raise GitHubApiError("GitHub repository request failed") from exc
        if allow_404 and response.status_code == 404:
            return None
        if response.status_code < 200 or response.status_code >= 300:
            raise GitHubApiError(
                f"GitHub repository request failed with HTTP {response.status_code}"
            )
        return response
    def repository(self, repository: str, token: str) -> RepositorySnapshot:
        owner, name = self._parts(repository)
        response = self._request(
            "GET",
            f"{self.api_url}/repos/{owner}/{name}",
            token=token,
        )
        assert response is not None
        try:
            default_branch = str(response.json()["default_branch"])
        except (KeyError, TypeError) as exc:
            raise GitHubApiError("GitHub repository metadata is invalid") from exc
        if not default_branch:
            raise GitHubApiError("GitHub repository has no default branch")
        return RepositorySnapshot(default_branch=default_branch)

    def ref_sha(self, repository: str, branch: str, token: str) -> str | None:
        owner, name = self._parts(repository)
        encoded = quote(f"heads/{branch}", safe="")
        response = self._request(
            "GET",
            f"{self.api_url}/repos/{owner}/{name}/git/ref/{encoded}",
            token=token,
            allow_404=True,
        )
        if response is None:
            return None
        try:
            value = str(response.json()["object"]["sha"]).lower()
        except (KeyError, TypeError) as exc:
            raise GitHubApiError("GitHub ref response is invalid") from exc
        if len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            raise GitHubApiError("GitHub ref SHA is invalid")
        return value
    def _pull_snapshot(self, payload: dict) -> PullRequestSnapshot:
        try:
            snapshot = PullRequestSnapshot(
                number=int(payload["number"]),
                state=str(payload["state"]),
                base_ref=str(payload["base"]["ref"]),
                head_ref=str(payload["head"]["ref"]),
                head_sha=str(payload["head"]["sha"]).lower(),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub pull request response is invalid") from exc
        if len(snapshot.head_sha) != 40 or any(
            c not in "0123456789abcdef" for c in snapshot.head_sha
        ):
            raise GitHubApiError("GitHub pull request head SHA is invalid")
        return snapshot

    def pull_request(
        self,
        repository: str,
        number: int,
        token: str,
    ) -> PullRequestSnapshot:
        owner, name = self._parts(repository)
        response = self._request(
            "GET",
            f"{self.api_url}/repos/{owner}/{name}/pulls/{number}",
            token=token,
        )
        assert response is not None
        return self._pull_snapshot(response.json())
    def ensure_pull_request(
        self,
        repository: str,
        *,
        base_branch: str,
        head_branch: str,
        expected_head_sha: str,
        issue_number: int,
        token: str,
    ) -> PullRequestSnapshot:
        owner, name = self._parts(repository)
        response = self._request(
            "GET",
            f"{self.api_url}/repos/{owner}/{name}/pulls",
            token=token,
            params={
                "state": "all",
                "head": f"{owner}:{head_branch}",
                "base": base_branch,
            },
        )
        assert response is not None
        payload = response.json()
        if not isinstance(payload, list):
            raise GitHubApiError("GitHub pull request search response is invalid")
        if len(payload) > 1:
            raise GitHubApiError("multiple pull requests exist for publication branch")

        if payload:
            candidate = self._pull_snapshot(payload[0])
            if candidate.state != "open":
                raise GitHubApiError("publication pull request is not open")
            number = candidate.number
        else:
            created = self._request(
                "POST",
                f"{self.api_url}/repos/{owner}/{name}/pulls",
                token=token,
                json={
                    "title": f"Control Plane candidate for issue #{issue_number}",
                    "head": head_branch,
                    "base": base_branch,
                    "body": (
                        "Published by FirstContact Control Plane after deterministic "
                        "candidate admission."
                    ),
                },
            )
            assert created is not None
            try:
                number = int(created.json()["number"])
            except (KeyError, TypeError, ValueError) as exc:
                raise GitHubApiError("created pull request response is invalid") from exc

        snapshot = self.pull_request(repository, number, token)
        if snapshot.state != "open":
            raise GitHubApiError("publication pull request is not open")
        if snapshot.base_ref != base_branch:
            raise GitHubApiError("publication pull request base does not match")
        if snapshot.head_ref != head_branch:
            raise GitHubApiError("publication pull request head ref does not match")
        if snapshot.head_sha != expected_head_sha.lower():
            raise GitHubApiError("publication pull request head SHA does not match")
        return snapshot
