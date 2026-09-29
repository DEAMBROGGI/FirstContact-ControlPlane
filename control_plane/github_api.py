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
    merged: bool = False
    merge_commit_sha: str | None = None


@dataclass(frozen=True, slots=True)
class IssueSnapshot:
    number: int
    state: str
    body: str
    database_id: int | None = None
    issue_node_id: str | None = None
    actor: str | None = None
    labels: tuple[str, ...] = ()
    html_url: str | None = None


@dataclass(frozen=True, slots=True)
class IssueCommentSnapshot:
    comment_id: int
    actor: str
    body: str
    created_at: str


@dataclass(frozen=True, slots=True)
class PullMergeEventSnapshot:
    commit_id: str
    actor: str | None
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
    in_reply_to_id: int | None = None


@dataclass(frozen=True, slots=True)
class IssueReactionSnapshot:
    reaction_id: int
    actor: str
    content: str
    created_at: str


@dataclass(frozen=True, slots=True)
class PullReviewCommentReactionSnapshot:
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
            merge_commit_sha = (
                str(payload["merge_commit_sha"]).lower()
                if payload.get("merge_commit_sha") is not None
                else None
            )
            snapshot = PullRequestSnapshot(
                number=int(payload["number"]),
                state=str(payload["state"]),
                base_ref=str(payload["base"]["ref"]),
                head_ref=str(payload["head"]["ref"]),
                head_sha=str(payload["head"]["sha"]).lower(),
                merged=bool(payload.get("merged", False)),
                merge_commit_sha=merge_commit_sha,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub pull request response is invalid") from exc
        if len(snapshot.head_sha) != 40 or any(
            c not in "0123456789abcdef" for c in snapshot.head_sha
        ):
            raise GitHubApiError("GitHub pull request head SHA is invalid")
        if snapshot.merge_commit_sha is not None and (
            len(snapshot.merge_commit_sha) != 40
            or any(
                c not in "0123456789abcdef"
                for c in snapshot.merge_commit_sha
            )
        ):
            raise GitHubApiError("GitHub pull request merge commit SHA is invalid")
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

    def pull_request_merge_event(
        self,
        repository: str,
        number: int,
        token: str,
    ) -> PullMergeEventSnapshot | None:
        if number <= 0:
            raise GitHubApiError("pull request number is invalid")
        owner, name = self._parts(repository)
        payload = self._paginate(
            f"{self.api_url}/repos/{owner}/{name}/issues/{number}/events",
            token=token,
            params={"per_page": "100"},
        )
        merged_events = [
            item
            for item in payload
            if isinstance(item, dict) and item.get("event") == "merged"
        ]
        if not merged_events:
            return None
        if len(merged_events) != 1:
            raise GitHubApiError("GitHub merged event is ambiguous")
        item = merged_events[0]
        try:
            commit_id = str(item["commit_id"]).lower()
            created_at = str(item["created_at"])
            actor = (
                str(item["actor"]["login"])
                if item.get("actor") is not None
                else None
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub merged event is invalid") from exc
        if len(commit_id) != 40 or any(
            char not in "0123456789abcdef" for char in commit_id
        ):
            raise GitHubApiError("GitHub merged event commit SHA is invalid")
        if not created_at.strip():
            raise GitHubApiError("GitHub merged event timestamp is invalid")
        return PullMergeEventSnapshot(
            commit_id=commit_id,
            actor=actor,
            created_at=created_at,
        )

    def pull_request_merged(
        self,
        repository: str,
        number: int,
        token: str,
    ) -> bool:
        if number <= 0:
            raise GitHubApiError("pull request number is invalid")
        owner, name = self._parts(repository)
        response = self._request(
            "GET",
            f"{self.api_url}/repos/{owner}/{name}/pulls/{number}/merge",
            token=token,
            allow_404=True,
        )
        if response is None:
            return False
        if response.status_code != 204:
            raise GitHubApiError(
                "GitHub merged-status response is invalid"
            )
        return True

    def merge_pull_request(
        self,
        repository: str,
        number: int,
        *,
        expected_head_sha: str,
        token: str,
        merge_method: str = "merge",
    ) -> str:
        if number <= 0:
            raise GitHubApiError("pull request number is invalid")
        head = expected_head_sha.lower()
        if len(head) != 40 or any(
            char not in "0123456789abcdef" for char in head
        ):
            raise GitHubApiError("expected pull request head SHA is invalid")
        if merge_method not in {"merge", "squash", "rebase"}:
            raise GitHubApiError("merge method is invalid")
        owner, name = self._parts(repository)
        response = self._request(
            "PUT",
            f"{self.api_url}/repos/{owner}/{name}/pulls/{number}/merge",
            token=token,
            json={"sha": head, "merge_method": merge_method},
        )
        assert response is not None
        try:
            payload = response.json()
            merged = bool(payload["merged"])
            merge_sha = str(payload["sha"]).lower()
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub merge response is invalid") from exc
        if not merged:
            raise GitHubApiError("GitHub did not merge the pull request")
        if len(merge_sha) != 40 or any(
            char not in "0123456789abcdef" for char in merge_sha
        ):
            raise GitHubApiError("GitHub merge response SHA is invalid")
        return merge_sha

    def issue(
        self,
        repository: str,
        number: int,
        token: str,
    ) -> IssueSnapshot:
        owner, name = self._parts(repository)
        response = self._request(
            "GET",
            f"{self.api_url}/repos/{owner}/{name}/issues/{number}",
            token=token,
        )
        assert response is not None
        try:
            return self._issue_snapshot(response.json())
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub issue response is invalid") from exc

    @staticmethod
    def _issue_snapshot(payload: dict) -> IssueSnapshot:
        try:
            return IssueSnapshot(
                number=int(payload["number"]),
                state=str(payload["state"]),
                body=str(payload.get("body") or ""),
                database_id=(
                    int(payload["id"])
                    if payload.get("id") is not None
                    else None
                ),
                issue_node_id=(
                    str(payload["node_id"])
                    if payload.get("node_id") is not None
                    else None
                ),
                actor=(
                    str(payload["user"]["login"])
                    if payload.get("user") is not None
                    else None
                ),
                labels=tuple(
                    str(item["name"])
                    for item in payload.get("labels", [])
                    if isinstance(item, dict) and item.get("name") is not None
                ),
                html_url=(
                    str(payload["html_url"])
                    if payload.get("html_url") is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub issue response is invalid") from exc

    def list_issues(
        self,
        repository: str,
        token: str,
    ) -> list[IssueSnapshot]:
        owner, name = self._parts(repository)
        payload = self._paginate(
            f"{self.api_url}/repos/{owner}/{name}/issues",
            token=token,
            params={"state": "all", "per_page": "100"},
        )
        return [
            self._issue_snapshot(item)
            for item in payload
            if "pull_request" not in item
        ]

    def create_issue(
        self,
        repository: str,
        *,
        title: str,
        body: str,
        labels: tuple[str, ...],
        token: str,
    ) -> IssueSnapshot:
        if not title.strip() or not body.strip() or not labels:
            raise GitHubApiError("implementation issue title, body, and labels are required")
        owner, name = self._parts(repository)
        response = self._request(
            "POST",
            f"{self.api_url}/repos/{owner}/{name}/issues",
            token=token,
            json={"title": title, "body": body, "labels": list(labels)},
        )
        assert response is not None
        return self._issue_snapshot(response.json())

    def add_issue_labels(
        self,
        repository: str,
        issue_number: int,
        labels: tuple[str, ...],
        token: str,
    ) -> None:
        if issue_number <= 0 or not labels or any(not item.strip() for item in labels):
            raise GitHubApiError("issue label projection is invalid")
        owner, name = self._parts(repository)
        self._request(
            "POST",
            f"{self.api_url}/repos/{owner}/{name}/issues/{issue_number}/labels",
            token=token,
            json={"labels": list(labels)},
        )

    def remove_issue_label(
        self,
        repository: str,
        issue_number: int,
        label: str,
        token: str,
    ) -> None:
        if issue_number <= 0 or not label.strip():
            raise GitHubApiError("issue label identity is invalid")
        owner, name = self._parts(repository)
        self._request(
            "DELETE",
            f"{self.api_url}/repos/{owner}/{name}/issues/{issue_number}/labels/"
            f"{quote(label, safe='')}",
            token=token,
        )

    def ensure_issue_labels(
        self,
        repository: str,
        issue_number: int,
        desired_labels: tuple[str, ...],
        token: str,
    ) -> IssueSnapshot:
        current = self.issue(repository, issue_number, token)
        desired = set(desired_labels)
        managed_prefixes = ("status:", "type:", "priority:")
        for label in current.labels:
            if label.startswith(managed_prefixes) and label not in desired:
                self.remove_issue_label(repository, issue_number, label, token)
        missing = tuple(sorted(desired - set(current.labels)))
        if missing:
            self.add_issue_labels(repository, issue_number, missing, token)
        result = self.issue(repository, issue_number, token)
        if not desired.issubset(set(result.labels)):
            raise GitHubApiError("issue label projection did not verify")
        if any(
            label.startswith(managed_prefixes) and label not in desired
            for label in result.labels
        ):
            raise GitHubApiError("stale managed issue labels remain")
        return result

    def ensure_sub_issue(
        self,
        repository: str,
        parent_issue_number: int,
        sub_issue_database_id: int,
        token: str,
    ) -> None:
        if parent_issue_number <= 0 or sub_issue_database_id <= 0:
            raise GitHubApiError("parent/sub-issue identity is invalid")
        owner, name = self._parts(repository)
        endpoint = (
            f"{self.api_url}/repos/{owner}/{name}/issues/"
            f"{parent_issue_number}/sub_issues"
        )
        children = self._paginate(
            endpoint,
            token=token,
            params={"per_page": "100"},
        )
        child_ids: list[int] = []
        for item in children:
            if not isinstance(item, dict):
                raise GitHubApiError("GitHub sub-issue listing is invalid")
            try:
                child_id = int(item["id"])
            except (KeyError, TypeError, ValueError) as exc:
                raise GitHubApiError("GitHub sub-issue listing is invalid") from exc
            if child_id <= 0:
                raise GitHubApiError("GitHub sub-issue listing is invalid")
            child_ids.append(child_id)
        if child_ids.count(sub_issue_database_id) > 1:
            raise GitHubApiError("GitHub sub-issue link is ambiguous")
        if sub_issue_database_id in child_ids:
            return
        write_error: GitHubApiError | None = None
        try:
            self._request(
                "POST",
                endpoint,
                token=token,
                json={"sub_issue_id": sub_issue_database_id},
            )
        except GitHubApiError as exc:
            # The link may have committed even if the write response was
            # malformed or lost. The authoritative proof is the bounded
            # sub-issue listing readback, not the POST response body.
            write_error = exc

        readback = self._paginate(
            endpoint,
            token=token,
            params={"per_page": "100"},
        )
        readback_ids: list[int] = []
        for item in readback:
            if not isinstance(item, dict):
                raise GitHubApiError("GitHub sub-issue listing is invalid")
            try:
                child_id = int(item["id"])
            except (KeyError, TypeError, ValueError) as exc:
                raise GitHubApiError("GitHub sub-issue listing is invalid") from exc
            if child_id <= 0:
                raise GitHubApiError("GitHub sub-issue listing is invalid")
            readback_ids.append(child_id)

        if readback_ids.count(sub_issue_database_id) > 1:
            raise GitHubApiError("GitHub sub-issue link is ambiguous")
        if sub_issue_database_id in readback_ids:
            return
        if write_error is not None:
            raise GitHubApiError("GitHub sub-issue link failed closed") from write_error
        raise GitHubApiError("GitHub sub-issue link did not verify")

    def ensure_project_v2_status(
        self,
        repository: str,
        issue_node_id: str,
        *,
        project_number: int,
        field_name: str,
        status: str,
        project_token: str,
    ) -> str:
        allowed_statuses = {
            "Backlog",
            "Ready",
            "In Progress",
            "Blocked",
            "Review",
            "Done",
            "Suspended",
        }
        if (
            not issue_node_id.strip()
            or project_number <= 0
            or not field_name.strip()
            or status not in allowed_statuses
        ):
            raise GitHubApiError("Project V2 projection identity or status is invalid")
        owner, _name = self._parts(repository)
        graphql_url = self.api_url
        if graphql_url.endswith("/api/v3"):
            graphql_url = graphql_url[:-7] + "/api/graphql"
        else:
            graphql_url += "/graphql"

        def graphql(query: str, variables: dict) -> dict:
            try:
                response = self.client.request(
                    "POST",
                    graphql_url,
                    headers=self._headers(project_token),
                    json={"query": query, "variables": variables},
                )
            except httpx.HTTPError as exc:
                raise GitHubApiError("GitHub Project V2 projection failed") from exc
            if response.status_code < 200 or response.status_code >= 300:
                raise GitHubApiError(
                    f"GitHub Project V2 projection failed with HTTP {response.status_code}"
                )
            try:
                payload = response.json()
                if payload.get("errors") or not isinstance(payload.get("data"), dict):
                    raise ValueError("GraphQL response has errors")
                return payload["data"]
            except (TypeError, ValueError) as exc:
                raise GitHubApiError("GitHub Project V2 response is invalid") from exc

        project_query = """
        query($owner: String!, $number: Int!) {
          repositoryOwner(login: $owner) {
            __typename
            ... on Organization {
              projectV2(number: $number) {
                id
                fields(first: 100) {
                  nodes {
                    __typename
                    ... on ProjectV2SingleSelectField {
                      id
                      name
                      options { id name }
                    }
                  }
                }
              }
            }
            ... on User {
              projectV2(number: $number) {
                id
                fields(first: 100) {
                  nodes {
                    __typename
                    ... on ProjectV2SingleSelectField {
                      id
                      name
                      options { id name }
                    }
                  }
                }
              }
            }
          }
        }
        """
        data = graphql(project_query, {"owner": owner, "number": project_number})
        owner_data = data.get("repositoryOwner") or {}
        if owner_data.get("__typename") not in {"User", "Organization"}:
            raise GitHubApiError("configured GitHub Project V2 owner was not found")
        project = owner_data.get("projectV2") or {}
        project_id = str(project.get("id") or "")
        if not project_id:
            raise GitHubApiError("configured GitHub Project V2 was not found")
        fields = project.get("fields", {}).get("nodes", [])
        matching = [
            field
            for field in fields
            if field.get("__typename") == "ProjectV2SingleSelectField"
            and field.get("name") == field_name
        ]
        if len(matching) != 1:
            raise GitHubApiError("configured Project V2 lifecycle field is ambiguous")
        field = matching[0]
        options = [
            option
            for option in field.get("options", [])
            if option.get("name") == status
        ]
        if len(options) != 1:
            raise GitHubApiError("Project V2 lifecycle option is missing or ambiguous")
        option_id = str(options[0].get("id") or "")
        field_id = str(field.get("id") or "")
        if not field_id or not option_id:
            raise GitHubApiError("Project V2 lifecycle field identity is invalid")

        item_query = """
        query($projectId: ID!, $after: String) {
          node(id: $projectId) {
            ... on ProjectV2 {
              items(first: 100, after: $after) {
                nodes {
                  id
                  content { ... on Issue { id } ... on PullRequest { id } }
                }
                pageInfo { endCursor hasNextPage }
              }
            }
          }
        }
        """
        item_id = None
        cursor = None
        pagination_exhausted = False
        for _page in range(100):
            item_data = graphql(item_query, {"projectId": project_id, "after": cursor})
            connection = item_data.get("node", {}).get("items") or {}
            nodes = connection.get("nodes", [])
            matches = [
                str(item.get("id") or "")
                for item in nodes
                if str((item.get("content") or {}).get("id") or "") == issue_node_id
            ]
            if len(matches) > 1:
                raise GitHubApiError("issue appears more than once in the Project V2")
            if matches:
                item_id = matches[0]
                break
            page_info = connection.get("pageInfo", {})
            if page_info.get("hasNextPage") is not True:
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                raise GitHubApiError("Project V2 item cursor is missing")
            if _page == 99:
                pagination_exhausted = True
        if pagination_exhausted and not item_id:
            raise GitHubApiError(
                "Project V2 item pagination safety cap was exhausted"
            )
        if not item_id:
            add_query = """
            mutation($projectId: ID!, $contentId: ID!) {
              addProjectV2ItemById(input: {projectId: $projectId, contentId: $contentId}) {
                item { id }
              }
            }
            """
            add_data = graphql(
                add_query,
                {"projectId": project_id, "contentId": issue_node_id},
            )
            item_id = str(
                add_data.get("addProjectV2ItemById", {}).get("item", {}).get("id") or ""
            )
            if not item_id:
                raise GitHubApiError("GitHub Project V2 item creation did not verify")

        update_query = """
        mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
          updateProjectV2ItemFieldValue(input: {
            projectId: $projectId,
            itemId: $itemId,
            fieldId: $fieldId,
            value: {singleSelectOptionId: $optionId}
          }) {
            projectV2Item { id }
          }
        }
        """
        update_data = graphql(
            update_query,
            {
                "projectId": project_id,
                "itemId": item_id,
                "fieldId": field_id,
                "optionId": option_id,
            },
        )
        updated_id = str(
            update_data.get("updateProjectV2ItemFieldValue", {})
            .get("projectV2Item", {})
            .get("id")
            or ""
        )
        if updated_id != item_id:
            raise GitHubApiError("Project V2 lifecycle status did not verify")
        return item_id

    def close_issue(
        self,
        repository: str,
        number: int,
        token: str,
    ) -> IssueSnapshot:
        owner, name = self._parts(repository)
        current = self.issue(repository, number, token)
        if current.state == "closed":
            return current
        if current.state != "open":
            raise GitHubApiError("implementation issue state is unknown")
        response = self._request(
            "PATCH",
            f"{self.api_url}/repos/{owner}/{name}/issues/{number}",
            token=token,
            json={"state": "closed", "state_reason": "completed"},
        )
        assert response is not None
        try:
            payload = response.json()
            closed = IssueSnapshot(
                number=int(payload["number"]),
                state=str(payload["state"]),
                body=str(payload.get("body") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("closed GitHub issue response is invalid") from exc
        if closed.number != number or closed.state != "closed":
            raise GitHubApiError("GitHub issue close did not verify")
        return closed
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
    def _issue_reaction_snapshot(payload: dict) -> IssueReactionSnapshot:
        try:
            reaction_id = int(payload["id"])
            actor = str(payload["user"]["login"])
            content = str(payload["content"])
            created_at = str(payload["created_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub issue reaction response is invalid") from exc
        if reaction_id <= 0 or not actor or not created_at or content not in {
            "+1",
            "-1",
            "laugh",
            "confused",
            "heart",
            "hooray",
            "rocket",
            "eyes",
        }:
            raise GitHubApiError("GitHub issue reaction response is invalid")
        return IssueReactionSnapshot(
            reaction_id=reaction_id,
            actor=actor,
            content=content,
            created_at=created_at,
        )

    def list_issue_comment_reactions(
        self,
        repository: str,
        comment_id: int,
        token: str,
    ) -> list[IssueReactionSnapshot]:
        if comment_id <= 0:
            raise GitHubApiError("issue comment id must be positive")
        owner, name = self._parts(repository)
        payload = self._paginate(
            f"{self.api_url}/repos/{owner}/{name}/issues/comments/{comment_id}/reactions",
            token=token,
            params={"per_page": "100"},
        )
        return [self._issue_reaction_snapshot(item) for item in payload]

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

    def create_pull_review(
        self,
        repository: str,
        pull_number: int,
        *,
        commit_id: str,
        body: str,
        comments: list[dict],
        token: str,
    ) -> PullReviewSnapshot:
        normalized_head = commit_id.lower()
        if (
            pull_number <= 0
            or len(normalized_head) != 40
            or any(c not in "0123456789abcdef" for c in normalized_head)
            or not body.strip()
            or len(comments) > 200
        ):
            raise GitHubApiError("pull review payload is invalid")

        wire_comments = []
        for item in comments:
            path = str(item.get("path") or "").strip()
            line = item.get("line")
            side = str(item.get("side") or "").upper()
            comment_body = str(item.get("body") or "").strip()
            if (
                not path
                or not isinstance(line, int)
                or line <= 0
                or side not in {"LEFT", "RIGHT"}
                or not comment_body
            ):
                raise GitHubApiError("pull review comment payload is invalid")
            wire_comments.append(
                {
                    "path": path,
                    "line": line,
                    "side": side,
                    "body": comment_body,
                }
            )

        owner, name = self._parts(repository)
        response = self._request(
            "POST",
            f"{self.api_url}/repos/{owner}/{name}/pulls/{pull_number}/reviews",
            token=token,
            json={
                "commit_id": normalized_head,
                "body": body,
                "event": "COMMENT",
                "comments": wire_comments,
            },
        )
        assert response is not None
        review = self._pull_review_snapshot(response.json())
        if review.review_id <= 0 or review.commit_id != normalized_head:
            raise GitHubApiError("GitHub pull review identity does not match request")
        return review

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
                in_reply_to_id=(
                    int(payload["in_reply_to_id"])
                    if payload.get("in_reply_to_id") is not None
                    else None
                ),
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

    def reply_to_pull_review_comment(
        self,
        repository: str,
        pull_number: int,
        comment_id: int,
        body: str,
        token: str,
    ) -> PullReviewCommentSnapshot:
        if pull_number <= 0 or comment_id <= 0 or not body.strip():
            raise GitHubApiError("pull review reply identity or body is invalid")
        owner, name = self._parts(repository)
        response = self._request(
            "POST",
            f"{self.api_url}/repos/{owner}/{name}/pulls/{pull_number}/comments/{comment_id}/replies",
            token=token,
            json={"body": body},
        )
        assert response is not None
        reply = self._pull_review_comment_snapshot(response.json())
        if reply.in_reply_to_id != comment_id:
            raise GitHubApiError("GitHub review reply parent does not match")
        return reply

    @staticmethod
    def _pull_review_comment_reaction_snapshot(
        payload: dict,
    ) -> PullReviewCommentReactionSnapshot:
        try:
            return PullReviewCommentReactionSnapshot(
                reaction_id=int(payload["id"]),
                actor=str(payload["user"]["login"]),
                content=str(payload["content"]),
                created_at=str(payload["created_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError("GitHub issue reaction response is invalid") from exc

    def add_pull_review_comment_reaction(
        self,
        repository: str,
        comment_id: int,
        content: str,
        token: str,
    ) -> PullReviewCommentReactionSnapshot:
        if comment_id <= 0 or content not in {"+1", "-1"}:
            raise GitHubApiError("remediation reaction identity or content is invalid")
        owner, name = self._parts(repository)
        response = self._request(
            "POST",
            f"{self.api_url}/repos/{owner}/{name}/pulls/comments/{comment_id}/reactions",
            token=token,
            json={"content": content},
        )
        assert response is not None
        reaction = self._pull_review_comment_reaction_snapshot(response.json())
        if reaction.content != content:
            raise GitHubApiError("GitHub reaction readback does not match request")
        return reaction

    def resolve_pull_review_thread(
        self,
        repository: str,
        pull_number: int,
        comment_id: int,
        token: str,
    ) -> str:
        """Resolve the one review thread containing this exact comment id."""
        owner, name = self._parts(repository)
        if pull_number <= 0 or comment_id <= 0:
            raise GitHubApiError("review thread identity is invalid")
        graphql_url = self.api_url
        if graphql_url.endswith("/api/v3"):
            graphql_url = graphql_url[:-7] + "/api/graphql"
        else:
            graphql_url += "/graphql"
        query = """
        query($owner: String!, $name: String!, $number: Int!, $after: String) {
          repository(owner: $owner, name: $name) {
            pullRequest(number: $number) {
              reviewThreads(first: 100, after: $after) {
                nodes {
                  id
                  isResolved
                  comments(first: 100) { nodes { databaseId } }
                }
                pageInfo { endCursor hasNextPage }
              }
            }
          }
        }
        """
        cursor = None
        thread_id = None
        resolved = False
        for _page in range(100):
            try:
                response = self.client.request(
                    "POST",
                    graphql_url,
                    headers=self._headers(token),
                    json={
                        "query": query,
                        "variables": {
                            "owner": owner,
                            "name": name,
                            "number": pull_number,
                            "after": cursor,
                        },
                    },
                )
            except httpx.HTTPError as exc:
                raise GitHubApiError("GitHub review thread lookup failed") from exc
            if response.status_code < 200 or response.status_code >= 300:
                raise GitHubApiError(
                    f"GitHub review thread lookup failed with HTTP {response.status_code}"
                )
            try:
                payload = response.json()
                if payload.get("errors"):
                    raise ValueError("GraphQL error")
                connection = payload["data"]["repository"]["pullRequest"]["reviewThreads"]
                nodes = connection["nodes"]
                page_info = connection["pageInfo"]
            except (KeyError, TypeError, ValueError) as exc:
                raise GitHubApiError("GitHub review thread response is invalid") from exc
            for node in nodes:
                comment_nodes = node.get("comments", {}).get("nodes", [])
                try:
                    contains_comment = any(
                        int(item.get("databaseId", -1)) == comment_id
                        for item in comment_nodes
                    )
                except (TypeError, ValueError) as exc:
                    raise GitHubApiError(
                        "GitHub review thread comments are invalid"
                    ) from exc
                if contains_comment:
                    thread_id = str(node.get("id") or "")
                    resolved = node.get("isResolved") is True
                    break
            if thread_id:
                break
            if page_info.get("hasNextPage") is not True:
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                raise GitHubApiError("GitHub review thread cursor is missing")
        if not thread_id:
            raise GitHubApiError("provider review thread was not found")
        if resolved:
            return thread_id

        mutation = """
        mutation($threadId: ID!) {
          resolveReviewThread(input: {threadId: $threadId}) {
            thread { id isResolved }
          }
        }
        """
        try:
            response = self.client.request(
                "POST",
                graphql_url,
                headers=self._headers(token),
                json={"query": mutation, "variables": {"threadId": thread_id}},
            )
        except httpx.HTTPError as exc:
            raise GitHubApiError("GitHub review thread resolution failed") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise GitHubApiError(
                f"GitHub review thread resolution failed with HTTP {response.status_code}"
            )
        try:
            payload = response.json()
            if payload.get("errors"):
                raise ValueError("GraphQL error")
            resolved_thread = payload["data"]["resolveReviewThread"]["thread"]
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubApiError(
                "GitHub review thread resolution response is invalid"
            ) from exc
        if (
            resolved_thread.get("id") != thread_id
            or resolved_thread.get("isResolved") is not True
        ):
            raise GitHubApiError("GitHub review thread did not resolve")
        return thread_id
