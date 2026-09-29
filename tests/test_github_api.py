from __future__ import annotations

import json

import httpx
import pytest

from control_plane.github_api import GitHubApiError, GitHubRepositoryGateway

HEAD = "2" * 40


def test_repository_gateway_creates_and_reads_back_exact_pull_request():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.url.query))
        assert request.headers["Authorization"] == "Bearer installation-token"

        if request.method == "GET" and request.url.path.endswith("/repos/DEAMBROGGI/FirstContact"):
            return httpx.Response(200, json={"default_branch": "master"})
        if request.method == "GET" and "/git/ref/" in request.url.path:
            if request.url.path.endswith("heads/master"):
                return httpx.Response(200, json={"object": {"sha": "1" * 40}})
            return httpx.Response(404, json={"message": "Not Found"})
        if request.method == "GET" and request.url.path.endswith("/pulls"):
            return httpx.Response(200, json=[])
        if request.method == "POST" and request.url.path.endswith("/pulls"):
            body = json.loads(request.content.decode("utf-8"))
            assert body["head"] == "control-plane/issue-6-abcd1234"
            assert body["base"] == "master"
            return httpx.Response(201, json={"number": 17})
        if request.method == "GET" and request.url.path.endswith("/pulls/17"):
            return httpx.Response(
                200,
                json={
                    "number": 17,
                    "state": "open",
                    "base": {"ref": "master"},
                    "head": {
                        "ref": "control-plane/issue-6-abcd1234",
                        "sha": HEAD,
                    },
                },
            )
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=client,
    )

    repo = github.repository("DEAMBROGGI/FirstContact", "installation-token")
    assert repo.default_branch == "master"
    assert github.ref_sha(
        "DEAMBROGGI/FirstContact",
        "missing",
        "installation-token",
    ) is None
    pull = github.ensure_pull_request(
        "DEAMBROGGI/FirstContact",
        base_branch="master",
        head_branch="control-plane/issue-6-abcd1234",
        expected_head_sha=HEAD,
        issue_number=6,
        token="installation-token",
    )
    assert pull.number == 17
    assert pull.head_sha == HEAD


def test_pull_request_readback_mismatch_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/pulls"):
            return httpx.Response(
                200,
                json=[
                    {
                        "number": 17,
                        "state": "open",
                        "base": {"ref": "master"},
                        "head": {"ref": "wrong-branch", "sha": HEAD},
                    }
                ],
            )
        if request.method == "GET" and request.url.path.endswith("/pulls/17"):
            return httpx.Response(
                200,
                json={
                    "number": 17,
                    "state": "open",
                    "base": {"ref": "master"},
                    "head": {"ref": "wrong-branch", "sha": HEAD},
                },
            )
        raise AssertionError(str(request.url))

    gateway = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(GitHubApiError, match="head ref"):
        gateway.ensure_pull_request(
            "DEAMBROGGI/FirstContact",
            base_branch="master",
            head_branch="control-plane/issue-6-abcd1234",
            expected_head_sha=HEAD,
            issue_number=6,
            token="installation-token",
        )


def test_review_comment_listing_exhausts_github_pagination():
    def payload(comment_id):
        return {
            "id": comment_id,
            "pull_request_review_id": 77,
            "user": {"login": "chatgpt-codex-connector[bot]"},
            "body": f"finding-{comment_id}",
            "commit_id": HEAD,
            "path": "control_plane/example.py",
            "line": comment_id,
            "created_at": "2026-09-27T21:00:00Z",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        page = request.url.params.get("page")
        if page == "2":
            return httpx.Response(200, json=[payload(2)])
        return httpx.Response(
            200,
            json=[payload(1)],
            headers={
                "Link": (
                    '<https://api.github.test/repos/DEAMBROGGI/'
                    'FirstContact/pulls/12/comments?per_page=100&page=2>; '
                    'rel="next"'
                )
            },
        )

    gateway = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    comments = gateway.list_pull_review_comments(
        "DEAMBROGGI/FirstContact",
        12,
        "installation-token",
    )

    assert [item.comment_id for item in comments] == [1, 2]


def test_issue_comment_reactions_are_paginated_and_validated():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert request.method == "GET"
        assert request.url.path == "/repos/DEAMBROGGI/FirstContact/issues/comments/7001/reactions"
        if "page=2" in str(request.url):
            return httpx.Response(
                200,
                json=[{
                    "id": 702,
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "content": "+1",
                    "created_at": "2026-09-28T12:02:00Z",
                }],
            )
        return httpx.Response(
            200,
            json=[{
                "id": 701,
                "user": {"login": "someone"},
                "content": "eyes",
                "created_at": "2026-09-28T12:01:00Z",
            }],
            headers={
                "Link": '<https://api.github.test/repos/DEAMBROGGI/FirstContact/issues/comments/7001/reactions?per_page=100&page=2>; rel="next"'
            },
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    reactions = github.list_issue_comment_reactions(
        "DEAMBROGGI/FirstContact", 7001, "installation-token"
    )

    assert [(item.reaction_id, item.content) for item in reactions] == [
        (701, "eyes"),
        (702, "+1"),
    ]
    assert len(seen) == 2


def test_pull_review_comment_reaction_uses_pull_request_endpoint_and_readback():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (
            "/repos/DEAMBROGGI/FirstContact/pulls/comments/4101/reactions"
        )
        assert json.loads(request.content.decode("utf-8")) == {"content": "+1"}
        return httpx.Response(
            201,
            json={
                "id": 901,
                "user": {"login": "firstcontact-control-plane[bot]"},
                "content": "+1",
                "created_at": "2026-09-28T12:00:00Z",
            },
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    reaction = github.add_pull_review_comment_reaction(
        "DEAMBROGGI/FirstContact",
        4101,
        "+1",
        "installation-token",
    )

    assert reaction.reaction_id == 901
    assert reaction.actor == "firstcontact-control-plane[bot]"


def test_review_thread_resolution_targets_exact_comment_and_verifies_mutation():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == "https://api.github.test/graphql"
        body = json.loads(request.content.decode("utf-8"))
        calls.append(body)
        if "reviewThreads(first: 100" in body["query"]:
            assert body["variables"] == {
                "owner": "DEAMBROGGI",
                "name": "FirstContact",
                "number": 13,
                "after": None,
            }
            return httpx.Response(
                200,
                json={
                    "data": {
                        "repository": {
                            "pullRequest": {
                                "reviewThreads": {
                                    "nodes": [
                                        {
                                            "id": "PRRT_kwDO_exact",
                                            "isResolved": False,
                                            "comments": {"nodes": [{"databaseId": 4101}]},
                                        }
                                    ],
                                    "pageInfo": {
                                        "endCursor": None,
                                        "hasNextPage": False,
                                    },
                                }
                            }
                        }
                    }
                },
            )

        assert "resolveReviewThread" in body["query"]
        assert body["variables"] == {"threadId": "PRRT_kwDO_exact"}
        return httpx.Response(
            200,
            json={
                "data": {
                    "resolveReviewThread": {
                        "thread": {
                            "id": "PRRT_kwDO_exact",
                            "isResolved": True,
                        }
                    }
                }
            },
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    resolved_id = github.resolve_pull_review_thread(
        "DEAMBROGGI/FirstContact",
        13,
        4101,
        "installation-token",
    )

    assert resolved_id == "PRRT_kwDO_exact"
    assert len(calls) == 2


def test_project_v2_projection_adds_issue_and_sets_lifecycle_field():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.github.test/graphql"
        assert request.headers["Authorization"] == "Bearer dedicated-project-token"
        body = json.loads(request.content.decode("utf-8"))
        query = body["query"]
        variables = body["variables"]
        calls.append((query, variables))
        if "projectV2(number: $number)" in query:
            assert "repositoryOwner(login: $owner)" in query
            assert "organization(login: $owner)" not in query
            assert "user(login: $owner)" not in query
            return httpx.Response(
                200,
                json={
                    "data": {
                        "repositoryOwner": {
                            "__typename": "User",
                            "projectV2": {
                                "id": "PVT_project4",
                                "fields": {
                                    "nodes": [
                                        {
                                            "__typename": "ProjectV2SingleSelectField",
                                            "id": "PVTSSF_lifecycle",
                                            "name": "Lifecycle",
                                            "options": [
                                                {"id": "opt_backlog", "name": "Backlog"},
                                                {"id": "opt_ready", "name": "Ready"},
                                                {"id": "opt_progress", "name": "In Progress"},
                                                {"id": "opt_blocked", "name": "Blocked"},
                                                {"id": "opt_review", "name": "Review"},
                                                {"id": "opt_done", "name": "Done"},
                                                {"id": "opt_suspended", "name": "Suspended"},
                                            ],
                                        }
                                    ]
                                },
                            }
                        },
                    }
                },
            )
        if "items(first: 100" in query:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "node": {
                            "items": {
                                "nodes": [],
                                "pageInfo": {"endCursor": None, "hasNextPage": False},
                            }
                        }
                    }
                },
            )
        if "addProjectV2ItemById" in query:
            assert variables == {"projectId": "PVT_project4", "contentId": "I_issue14"}
            return httpx.Response(
                200,
                json={"data": {"addProjectV2ItemById": {"item": {"id": "PVTI_item14"}}}},
            )
        assert "updateProjectV2ItemFieldValue" in query
        assert variables == {
            "projectId": "PVT_project4",
            "itemId": "PVTI_item14",
            "fieldId": "PVTSSF_lifecycle",
            "optionId": "opt_review",
        }
        return httpx.Response(
            200,
            json={
                "data": {
                    "updateProjectV2ItemFieldValue": {
                        "projectV2Item": {"id": "PVTI_item14"}
                    }
                }
            },
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    item_id = github.ensure_project_v2_status(
        "DEAMBROGGI/FirstContact-ControlPlane",
        "I_issue14",
        project_number=4,
        field_name="Lifecycle",
        status="Review",
        project_token="dedicated-project-token",
    )

    assert item_id == "PVTI_item14"
    assert len(calls) == 4


def test_project_v2_pagination_cap_fails_closed_without_add_mutation():
    item_pages = 0
    add_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal item_pages, add_calls
        body = json.loads(request.content.decode("utf-8"))
        query = body["query"]
        if "projectV2(number: $number)" in query:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "repositoryOwner": {
                            "__typename": "User",
                            "projectV2": {
                                "id": "PVT_project4",
                                "fields": {
                                    "nodes": [{
                                        "__typename": "ProjectV2SingleSelectField",
                                        "id": "PVTSSF_lifecycle",
                                        "name": "Lifecycle",
                                        "options": [{"id": "opt_review", "name": "Review"}],
                                    }]
                                },
                            },
                        }
                    }
                },
            )
        if "items(first: 100" in query:
            item_pages += 1
            return httpx.Response(
                200,
                json={
                    "data": {
                        "node": {
                            "items": {
                                "nodes": [],
                                "pageInfo": {
                                    "endCursor": f"cursor-{item_pages}",
                                    "hasNextPage": True,
                                },
                            }
                        }
                    }
                },
            )
        if "addProjectV2ItemById" in query:
            add_calls += 1
            return httpx.Response(500, json={"message": "must not mutate"})
        raise AssertionError(query)

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(GitHubApiError, match="pagination safety cap"):
        github.ensure_project_v2_status(
            "DEAMBROGGI/FirstContact-ControlPlane",
            "I_issue14",
            project_number=4,
            field_name="Lifecycle",
            status="Review",
            project_token="dedicated-project-token",
        )

    assert item_pages == 100
    assert add_calls == 0


def test_project_v2_retry_recovers_lost_add_response_without_duplicate_item():
    calls = []
    items = []
    add_calls = 0
    update_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal add_calls, update_calls
        assert request.headers["Authorization"] == "Bearer dedicated-project-token"
        body = json.loads(request.content.decode("utf-8"))
        query = body["query"]
        calls.append(query)
        if "projectV2(number: $number)" in query:
            assert "repositoryOwner(login: $owner)" in query
            assert "organization(login: $owner)" not in query
            assert "user(login: $owner)" not in query
            return httpx.Response(
                200,
                json={
                    "data": {
                        "repositoryOwner": {
                            "__typename": "User",
                            "projectV2": {
                                "id": "PVT_project4",
                                "fields": {
                                    "nodes": [
                                        {
                                            "__typename": "ProjectV2SingleSelectField",
                                            "id": "PVTSSF_lifecycle",
                                            "name": "Lifecycle",
                                            "options": [{"id": "opt_review", "name": "Review"}],
                                        }
                                    ]
                                },
                            }
                        },
                    }
                },
            )
        if "items(first: 100" in query:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "node": {
                            "items": {
                                "nodes": list(items),
                                "pageInfo": {"endCursor": None, "hasNextPage": False},
                            }
                        }
                    }
                },
            )
        if "addProjectV2ItemById" in query:
            add_calls += 1
            items.append({"id": "PVTI_item14", "content": {"id": "I_issue14"}})
            return httpx.Response(502, json={"message": "response lost after mutation"})
        assert "updateProjectV2ItemFieldValue" in query
        update_calls += 1
        return httpx.Response(
            200,
            json={
                "data": {
                    "updateProjectV2ItemFieldValue": {
                        "projectV2Item": {"id": "PVTI_item14"}
                    }
                }
            },
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    parameters = {
        "project_number": 4,
        "field_name": "Lifecycle",
        "status": "Review",
        "project_token": "dedicated-project-token",
    }
    with pytest.raises(GitHubApiError, match="HTTP 502"):
        github.ensure_project_v2_status(
            "DEAMBROGGI/FirstContact-ControlPlane",
            "I_issue14",
            **parameters,
        )

    recovered = github.ensure_project_v2_status(
        "DEAMBROGGI/FirstContact-ControlPlane",
        "I_issue14",
        **parameters,
    )

    assert recovered == "PVTI_item14"
    assert add_calls == 1
    assert update_calls == 1
    assert len(items) == 1
    assert len(calls) == 6


def test_sub_issue_link_is_idempotent_and_uses_issue_database_id():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "GET":
            if len([call for call in calls if call[0] == "GET"]) == 1:
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=[{"id": 10100, "number": 101}])
        assert request.method == "POST"
        assert request.url.path.endswith("/issues/10/sub_issues")
        assert json.loads(request.content.decode("utf-8")) == {"sub_issue_id": 10100}
        return httpx.Response(
            201,
            json={"id": 10100, "number": 101, "state": "open", "body": ""},
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    github.ensure_sub_issue("DEAMBROGGI/FirstContact-ControlPlane", 10, 10100, "token")
    github.ensure_sub_issue("DEAMBROGGI/FirstContact-ControlPlane", 10, 10100, "token")

    assert [method for method, _path in calls] == ["GET", "POST", "GET"]


def test_sub_issue_link_fails_closed_on_malformed_listing():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, json=[{"id": "not-a-database-id"}])

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(GitHubApiError, match="listing is invalid"):
        github.ensure_sub_issue(
            "DEAMBROGGI/FirstContact-ControlPlane",
            10,
            10100,
            "token",
        )


def test_issue_creation_and_managed_label_projection_use_bounded_routes():
    calls = []
    labels = ["type:fix", "priority:P1", "status:ready"]
    body = "<!-- firstcontact-control-plane:remediation-issue batch=abc -->"

    def issue_payload():
        return {
            "id": 1400,
            "node_id": "I_issue14",
            "number": 14,
            "state": "open",
            "body": body,
            "user": {"login": "firstcontact-control-plane[bot]"},
            "labels": [{"name": item} for item in labels],
            "html_url": "https://github.com/DEAMBROGGI/FirstContact-ControlPlane/issues/14",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append((request.method, path))
        if request.method == "POST" and path.endswith("/issues"):
            payload = json.loads(request.content.decode("utf-8"))
            assert payload["title"].startswith("[P1][IMPLEMENTATION FIX]")
            assert payload["body"] == body
            assert set(payload["labels"]) == set(labels)
            return httpx.Response(201, json=issue_payload())
        if request.method == "GET" and path.endswith("/issues/14"):
            return httpx.Response(200, json=issue_payload())
        if request.method == "DELETE":
            assert "/issues/14/labels/" in path
            labels.remove("status:ready")
            return httpx.Response(204)
        if request.method == "POST" and path.endswith("/issues/14/labels"):
            added = json.loads(request.content.decode("utf-8"))["labels"]
            labels.extend(added)
            return httpx.Response(200, json=[{"name": item} for item in labels])
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    issue = github.create_issue(
        "DEAMBROGGI/FirstContact-ControlPlane",
        title="[P1][IMPLEMENTATION FIX] batch",
        body=body,
        labels=("status:ready", "type:fix", "priority:P1"),
        token="installation-token",
    )
    projected = github.ensure_issue_labels(
        "DEAMBROGGI/FirstContact-ControlPlane",
        issue.number,
        ("status:in-progress", "type:fix", "priority:P1"),
        "installation-token",
    )

    assert issue.database_id == 1400
    assert issue.issue_node_id == "I_issue14"
    assert set(projected.labels) == {"status:in-progress", "type:fix", "priority:P1"}
    assert [method for method, _path in calls] == ["POST", "GET", "DELETE", "POST", "GET"]


def test_merge_pull_request_binds_expected_head_and_returns_merge_commit():
    merge_sha = "4" * 40

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert request.url.path == (
            "/repos/DEAMBROGGI/FirstContact/pulls/13/merge"
        )
        assert request.headers["Authorization"] == "Bearer installation-token"
        assert json.loads(request.content.decode("utf-8")) == {
            "sha": HEAD,
            "merge_method": "merge",
        }
        return httpx.Response(
            200,
            json={
                "sha": merge_sha,
                "merged": True,
                "message": "Pull Request successfully merged",
            },
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    result = github.merge_pull_request(
        "DEAMBROGGI/FirstContact",
        13,
        expected_head_sha=HEAD,
        token="installation-token",
    )

    assert result == merge_sha


def test_pull_request_snapshot_exposes_merged_receipt():
    merge_sha = "5" * 40

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == (
            "/repos/DEAMBROGGI/FirstContact/pulls/13"
        )
        return httpx.Response(
            200,
            json={
                "number": 13,
                "state": "closed",
                "merged": True,
                "merge_commit_sha": merge_sha,
                "base": {"ref": "master"},
                "head": {
                    "ref": "control-plane/issue-22-canonical",
                    "sha": HEAD,
                },
            },
        )

    github = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    pull = github.pull_request(
        "DEAMBROGGI/FirstContact",
        13,
        "installation-token",
    )

    assert pull.merged is True
    assert pull.merge_commit_sha == merge_sha
    assert pull.head_sha == HEAD
