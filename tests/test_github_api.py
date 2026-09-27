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
