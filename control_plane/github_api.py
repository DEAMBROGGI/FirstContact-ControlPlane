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


@dataclass(frozen=True, slots=True)
class IssueCommentSnapshot:
    comment_id: int
    actor: str
    body: str
    created_at: str


@dataclass(frozen=True, slots=True)
class PullReviewSnapshot:
    review_id: int
    actor: str
    body: str
    state: str
    commit_id: str
    submitted_at: str | None


@dataclass(frozen=True, slots=True)
class PullReviewCommentSnapshot:
    comment_id: int
    review_id: int | None
    actor: str
    body: str
    commit_id: str
    path: str
    line: int | None
    created_at: str


@dataclass(frozen=True, slots=True)
class IssueReactionSnapshot:
    reaction_id: int
    actor: str
    content: str
    created_at: str


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
            raise GitHubApiError("GitHub bearer token is unavailable")
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
        request_failed = False
        try:
            response = self.client.request(
                method,
                url,
                headers=self._headers(token),
                params=params,
                json=json,
            )
        except httpx.HTTPError:
            request_failed = True
        if request_failed:
            raise GitHubApiError("GitHub repository request failed")
        if allow_404 and response.status_code == 404:
            return None
        if response.status_code < 200 or response.status_code >= 300:
            raise GitHubApiError(
                f"GitHub repository request failed with HTTP {response.status_code}"
            )
        return response

    def authenticated_user_login(self, token: str) -> str:
        response = self._request("GET", f"{self.api_url}/user", token=token)
        assert response is not None
        invalid_response = False
        try:
            payload = response.json()
        except ValueError:
            payload = None
            invalid_response = True
        if invalid_response or not isinstance(payload, dict):
            raise GitHubApiError("GitHub authenticated user response is invalid")
        login = payload.get("login")
        if not isinstance(login, str) or not login or login != login.strip():
            raise GitHubApiError("GitHub authenticated user response is invalid")
        return login

    @staticmethod
    def _next_link(response: httpx.Response) -> str | None:
        raw = response.headers.get("Link") or response.headers.get("link")
        if not raw:
            return None
        for part in raw.split(","):
            segments = [item.strip() for item in part.split(";")]
            if not segments:
                continue
            target = segments[0]
            relations = {
                item.split("=", 1)[1].strip().strip('"')
                for item in segments[1:]
                if item.startswith("rel=") and "=" in item
            }
            if "next" not in relations:
                continue
            if not (target.startswith("<") and target.endswith(">")):
                raise GitHubApiError("GitHub pagination Link target is invalid")
            return target[1:-1]
        return None

    def _paginate(
        self,
        url: str,
        *,
        token: str,
        params: dict[str, str] | None = None,
        max_pages: int = 100,
    ) -> list[dict]:
        items: list[dict] = []
        next_url: str | None = url
        next_params = params
        pages = 0
        while next_url is not None:
            pages += 1
            if pages > max_pages:
                raise GitHubApiError("GitHub pagination exceeded safety limit")
            response = self._request(
                "GET",
                next_url,
                token=token,
                params=next_params,
            )
            assert response is not None
            payload = response.json()
            if not isinstance(payload, list):
                raise GitHubApiError("GitHub paginated response is invalid")
            items.extend(payload)
            candidate = self._next_link(response)
            if candidate is None:
                next_url = None
                continue
            if not candidate.startswith(f"{self.api_url}/"):
                raise GitHubApiError("GitHub pagination escaped configured API")
            next_url = candidate
            next_params = None
        return items

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


    def add_issue_comment(
        self,
        repository: str,
        issue_number: int,
        body: str,
        token: str,
    ) -> IssueCommentSnapshot:
        owner, name = self._parts(repository)
        response = self._request(
            "POST",
            f"{self.api_url}/repos/{owner}/{name}/issues/{issue_number}/comments",
            token=token,
            json={"body": body},
        )
        assert response is not None
        return self._issue_comment_snapshot(response.json())

    @staticmethod
    def _issue_comment_snapshot(payload: dict) -> IssueCommentSnapshot:
        try:
            return IssueCommentSnapshot(
                comment_id=int(payload["id"]),
                actor=str(payload["user"]["login"]),
                body=str(payload.get("body") or ""),
                created_at=str(payload["created_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub issue comment response is invalid") from exc

    def list_issue_comments(
        self,
        repository: str,
        issue_number: int,
        token: str,
    ) -> list[IssueCommentSnapshot]:
        owner, name = self._parts(repository)
        payload = self._paginate(
            f"{self.api_url}/repos/{owner}/{name}/issues/{issue_number}/comments",
            token=token,
            params={"per_page": "100"},
        )
        return [self._issue_comment_snapshot(item) for item in payload]
    @staticmethod
    def _pull_review_snapshot(payload: dict) -> PullReviewSnapshot:
        try:
            commit_id = str(payload.get("commit_id") or "").lower()
            if commit_id and (
                len(commit_id) != 40
                or any(c not in "0123456789abcdef" for c in commit_id)
            ):
                raise ValueError("invalid commit id")
            return PullReviewSnapshot(
                review_id=int(payload["id"]),
                actor=str(payload["user"]["login"]),
                body=str(payload.get("body") or ""),
                state=str(payload.get("state") or ""),
                commit_id=commit_id,
                submitted_at=(
                    str(payload["submitted_at"])
                    if payload.get("submitted_at") is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub pull review response is invalid") from exc

    def list_pull_reviews(
        self,
        repository: str,
        pull_number: int,
        token: str,
    ) -> list[PullReviewSnapshot]:
        owner, name = self._parts(repository)
        payload = self._paginate(
            f"{self.api_url}/repos/{owner}/{name}/pulls/{pull_number}/reviews",
            token=token,
            params={"per_page": "100"},
        )
        return [self._pull_review_snapshot(item) for item in payload]
    @staticmethod
    def _pull_review_comment_snapshot(payload: dict) -> PullReviewCommentSnapshot:
        try:
            commit_id = str(payload.get("commit_id") or "").lower()
            if commit_id and (
                len(commit_id) != 40
                or any(c not in "0123456789abcdef" for c in commit_id)
            ):
                raise ValueError("invalid commit id")
            return PullReviewCommentSnapshot(
                comment_id=int(payload["id"]),
                review_id=(
                    int(payload["pull_request_review_id"])
                    if payload.get("pull_request_review_id") is not None
                    else None
                ),
                actor=str(payload["user"]["login"]),
                body=str(payload.get("body") or ""),
                commit_id=commit_id,
                path=str(payload.get("path") or ""),
                line=(
                    int(payload["line"])
                    if payload.get("line") is not None
                    else None
                ),
                created_at=str(payload["created_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError(
                "GitHub pull review comment response is invalid"
            ) from exc

    def list_pull_review_comments(
        self,
        repository: str,
        pull_number: int,
        token: str,
    ) -> list[PullReviewCommentSnapshot]:
        owner, name = self._parts(repository)
        payload = self._paginate(
            f"{self.api_url}/repos/{owner}/{name}/pulls/{pull_number}/comments",
            token=token,
            params={"per_page": "100"},
        )
        return [self._pull_review_comment_snapshot(item) for item in payload]

    @staticmethod
    def _issue_reaction_snapshot(payload: dict) -> IssueReactionSnapshot:
        try:
            return IssueReactionSnapshot(
                reaction_id=int(payload["id"]),
                actor=str(payload["user"]["login"]),
                content=str(payload["content"]),
                created_at=str(payload["created_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub issue reaction response is invalid") from exc

    def list_issue_comment_reactions(
        self,
        repository: str,
        comment_id: int,
        token: str,
    ) -> list[IssueReactionSnapshot]:
        owner, name = self._parts(repository)
        payload = self._paginate(
            f"{self.api_url}/repos/{owner}/{name}/issues/comments/{comment_id}/reactions",
            token=token,
            params={"per_page": "100"},
        )
        return [self._issue_reaction_snapshot(item) for item in payload]
