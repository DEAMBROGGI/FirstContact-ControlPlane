from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from control_plane.domain import (
    AutomatedReviewStatus,
    DomainError,
    PublicationState,
    ValidationStatus,
)
from control_plane.github_api import (
    GitHubApiError,
    GitHubRepositoryGateway,
    PullRequestSnapshot,
    PullReviewCommentSnapshot,
    PullReviewSnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.plane_review import (
    PlaneReviewPublisher,
    record_plane_review,
)
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.remediation import create_work_package
from control_plane.repository import load_events
from control_plane.service import (
    create_publication,
    mark_codex_review_unavailable,
    mark_remote_published,
    record_validation,
    request_codex_review,
    submit_verified_candidate,
)

REPOSITORY = "DEAMBROGGI/FirstContact"
BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


def candidate() -> VerifiedCandidateSource:
    return VerifiedCandidateSource(
        bundle_sha256="a" * 64,
        byte_length=2048,
        quarantine_id="a" * 64,
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
    )


def publish(session):
    view = create_publication(session, REPOSITORY, 10)
    view = submit_verified_candidate(session, view.publication_id, candidate())
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )
    assert view.state is PublicationState.ADMITTED
    return mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch="control-plane/issue-10-abcdef01",
        base_branch="master",
        pull_request_number=13,
    )


def principal_comments():
    return [
        {
            "finding_id": "principal:reviewer-binding",
            "normalized_identity": "principal:fingerprint:reviewer-binding",
            "priority": "P1",
            "path": "control_plane/remediation.py",
            "line": 947,
            "side": "RIGHT",
            "body": "Bind verification identity to the recorded fallback reviewer.",
        }
    ]


class FakeTokenProvider:
    def installation_access(self, repository, *, permissions):
        assert repository == REPOSITORY
        assert permissions == {"pull_requests": "write"}
        return InstallationAccess(
            installation_id=123,
            token="installation-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    def bot_login(self):
        return "firstcontact-control-plane[bot]"


class FakeGitHub:
    def __init__(self, view):
        self.view = view
        self.reviews = []
        self.comments = []
        self.create_calls = 0
        self.drop_response_once = True

    def pull_request(self, repository, number, token):
        assert repository == REPOSITORY
        assert token == "installation-token"
        return PullRequestSnapshot(
            number=number,
            state="open",
            base_ref=self.view.base_branch,
            head_ref=self.view.remote_branch,
            head_sha=HEAD,
        )

    def list_pull_reviews(self, repository, pull_number, token):
        return list(self.reviews)

    def list_pull_review_comments(self, repository, pull_number, token):
        return list(self.comments)

    def create_pull_review(
        self,
        repository,
        pull_number,
        *,
        commit_id,
        body,
        comments,
        token,
    ):
        self.create_calls += 1
        review = PullReviewSnapshot(
            review_id=9101,
            actor="firstcontact-control-plane[bot]",
            body=body,
            state="COMMENTED",
            commit_id=commit_id,
            submitted_at="2026-09-29T17:00:00Z",
        )
        self.reviews.append(review)
        for index, item in enumerate(comments, 1):
            self.comments.append(
                PullReviewCommentSnapshot(
                    comment_id=9200 + index,
                    review_id=review.review_id,
                    actor="firstcontact-control-plane[bot]",
                    body=item["body"],
                    commit_id=commit_id,
                    path=item["path"],
                    line=item["line"],
                    created_at="2026-09-29T17:00:00Z",
                )
            )
        if self.drop_response_once:
            self.drop_response_once = False
            raise GitHubApiError("simulated lost response after accepted review")
        return review


def test_plane_review_persists_before_write_recovers_and_becomes_work_package_source(session):
    view = publish(session)
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=HEAD,
    )
    mark_codex_review_unavailable(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=HEAD,
        reason="Provider unavailable.",
    )

    recorded = record_plane_review(
        session,
        view.publication_id,
        run_id="principal-review:001",
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Independent exact-head review found one actionable issue.",
        comments=principal_comments(),
        idempotency_key="principal-review-001",
    )
    assert recorded["provider"] == "PLANE_REVIEW"
    assert load_events(session, view.publication_id)[-1]["event_type"] == "PLANE_REVIEW_RECORDED"

    github = FakeGitHub(view)
    publisher = PlaneReviewPublisher(
        token_provider=FakeTokenProvider(),
        github=github,
    )
    materialized = publisher.materialize(
        session,
        view.publication_id,
        "principal-review:001",
    )
    assert materialized["provider"] == "PLANE_REVIEW"
    assert materialized["provider_review_ids"] == [9101]
    assert materialized["provider_comment_ids"] == [9201]
    assert github.create_calls == 1
    assert [
        event["event_type"]
        for event in load_events(session, view.publication_id)[-2:]
    ] == ["PLANE_REVIEW_RECORDED", "PLANE_REVIEW_MATERIALIZED"]

    repeated = publisher.materialize(
        session,
        view.publication_id,
        "principal-review:001",
    )
    assert repeated == materialized
    assert github.create_calls == 1

    source = materialized["findings"][0]
    package = create_work_package(
        session,
        publication_id=view.publication_id,
        implementation_issue_number=19,
        review_run_id=materialized["run_id"],
        review_provider="PLANE_REVIEW",
        provider_review_id=9101,
        reviewed_head_sha=HEAD,
        findings=[
            {
                "finding_id": source["finding_id"],
                "normalized_identity": source["normalized_identity"],
                "priority": source["priority"],
                "source": {
                    "kind": "PROVIDER_THREAD",
                    "provider": "PLANE_REVIEW",
                    "provider_review_id": source["provider_review_id"],
                    "provider_thread_id": source["provider_comment_id"],
                },
                "principal_decision": {
                    "decision": "ACCEPTED",
                    "actor": "principal-reviewer:chatgpt",
                    "reason": None,
                },
                "desired_reaction": "+1",
            }
        ],
        idempotency_key="issue19-plane-review",
    )
    assert package.review_run["provider"] == "PLANE_REVIEW"
    finding = package.findings[0]
    assert finding["finding_id"] == "principal:reviewer-binding"
    assert finding["source"]["provider_thread_id"] == 9201
    assert finding["source"]["path"] == "control_plane/remediation.py"
    assert finding["source"]["line"] == 947


def test_plane_review_source_rejects_invented_receipt(session):
    view = publish(session)
    record_plane_review(
        session,
        view.publication_id,
        run_id="principal-review:002",
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Independent exact-head review.",
        comments=principal_comments(),
        idempotency_key="principal-review-002",
    )
    github = FakeGitHub(view)
    github.drop_response_once = False
    materialized = PlaneReviewPublisher(
        token_provider=FakeTokenProvider(),
        github=github,
    ).materialize(session, view.publication_id, "principal-review:002")

    source = materialized["findings"][0]
    with pytest.raises(DomainError, match="not owned by the source review"):
        create_work_package(
            session,
            publication_id=view.publication_id,
            implementation_issue_number=20,
            review_run_id=materialized["run_id"],
            review_provider="PLANE_REVIEW",
            provider_review_id=9101,
            reviewed_head_sha=HEAD,
            findings=[
                {
                    "finding_id": source["finding_id"],
                    "normalized_identity": source["normalized_identity"],
                    "priority": source["priority"],
                    "source": {
                        "kind": "PROVIDER_THREAD",
                        "provider": "PLANE_REVIEW",
                        "provider_review_id": 9101,
                        "provider_thread_id": 9999,
                    },
                    "principal_decision": {
                        "decision": "ACCEPTED",
                        "actor": "principal-reviewer:chatgpt",
                        "reason": None,
                    },
                    "desired_reaction": "+1",
                }
            ],
            idempotency_key="invented-plane-receipt",
        )


def test_plane_review_rejects_reserved_automation_mention(session):
    view = publish(session)
    unsafe = "do not emit " + "@" + "codex review"
    with pytest.raises(DomainError, match="reserved automation mention"):
        record_plane_review(
            session,
            view.publication_id,
            run_id="principal-review:003",
            reviewer_kind="PRINCIPAL_REVIEWER",
            reviewer="principal-reviewer:chatgpt",
            reviewed_head_sha=HEAD,
            body=unsafe,
            comments=[],
            idempotency_key="principal-review-003",
        )


def test_github_gateway_creates_native_pull_review():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/repos/DEAMBROGGI/FirstContact/pulls/13/reviews"
        payload = __import__("json").loads(request.content)
        assert payload["commit_id"] == HEAD
        assert payload["event"] == "COMMENT"
        assert payload["comments"][0]["side"] == "RIGHT"
        return httpx.Response(
            200,
            json={
                "id": 9101,
                "user": {"login": "firstcontact-control-plane[bot]"},
                "body": payload["body"],
                "state": "COMMENTED",
                "commit_id": HEAD,
                "submitted_at": "2026-09-29T17:00:00Z",
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    gateway = GitHubRepositoryGateway(
        api_url="https://api.github.test",
        client=client,
    )
    review = gateway.create_pull_review(
        REPOSITORY,
        13,
        commit_id=HEAD,
        body="Plane review",
        comments=[
            {
                "path": "control_plane/remediation.py",
                "line": 947,
                "side": "RIGHT",
                "body": "Finding body",
            }
        ],
        token="token",
    )
    assert review.review_id == 9101
    assert review.commit_id == HEAD
