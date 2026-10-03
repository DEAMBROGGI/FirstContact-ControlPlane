from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

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
    PlaneReviewError,
    PlaneReviewPublisher,
    record_plane_review,
)
from control_plane.pr_findings import reconcile_pr_findings
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
    view = mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch="control-plane/issue-10-abcdef01",
        base_branch="master",
        pull_request_number=13,
    )
    github = SimpleNamespace(
        pull_request=lambda repository, number, token: PullRequestSnapshot(
            number=view.pull_request_number,
            state="open",
            base_ref=view.base_branch,
            head_ref=view.remote_branch,
            head_sha=view.remote_head_sha,
            base_sha=BASE,
        ),
        ref_sha=lambda repository, branch, token: BASE,
        list_pull_reviews=lambda repository, number, token: [],
        list_pull_review_comments=lambda repository, number, token: [],
        list_pull_review_threads=lambda repository, number, token: [],
    )
    reconcile_pr_findings(
        session,
        view.publication_id,
        github=github,
        token="test-installation-token",
    )
    return view


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


def _materialized_plane_source(session, *, run_id: str):
    view = publish(session)
    record_plane_review(
        session,
        view.publication_id,
        run_id=run_id,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Independent exact-head review.",
        comments=principal_comments(),
        idempotency_key=f"{run_id}:record",
    )
    github = FakeGitHub(view)
    github.drop_response_once = False
    materialized = PlaneReviewPublisher(
        token_provider=FakeTokenProvider(),
        github=github,
    ).materialize(session, view.publication_id, run_id)
    return view, materialized


def _package_finding(source):
    return {
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


def test_plane_review_work_package_binds_priority_and_reviewer_authority(session):
    view, materialized = _materialized_plane_source(
        session,
        run_id="principal-review:authority",
    )
    source = materialized["findings"][0]

    wrong_priority = _package_finding(source)
    wrong_priority["priority"] = "P0"
    with pytest.raises(DomainError, match="priority differs"):
        create_work_package(
            session,
            publication_id=view.publication_id,
            implementation_issue_number=31,
            review_run_id=materialized["run_id"],
            review_provider="PLANE_REVIEW",
            provider_review_id=source["provider_review_id"],
            reviewed_head_sha=HEAD,
            findings=[wrong_priority],
            idempotency_key="plane-wrong-priority",
        )

    wrong_actor = _package_finding(source)
    wrong_actor["principal_decision"]["actor"] = "different-principal-reviewer"
    with pytest.raises(DomainError, match="decision differs"):
        create_work_package(
            session,
            publication_id=view.publication_id,
            implementation_issue_number=32,
            review_run_id=materialized["run_id"],
            review_provider="PLANE_REVIEW",
            provider_review_id=source["provider_review_id"],
            reviewed_head_sha=HEAD,
            findings=[wrong_actor],
            idempotency_key="plane-wrong-reviewer",
        )

    rejected = _package_finding(source)
    rejected["principal_decision"] = {
        "decision": "REJECTED",
        "actor": "principal-reviewer:chatgpt",
        "reason": "Attempted source reinterpretation.",
    }
    rejected["desired_reaction"] = "-1"
    with pytest.raises(DomainError, match="decision differs"):
        create_work_package(
            session,
            publication_id=view.publication_id,
            implementation_issue_number=33,
            review_run_id=materialized["run_id"],
            review_provider="PLANE_REVIEW",
            provider_review_id=source["provider_review_id"],
            reviewed_head_sha=HEAD,
            findings=[rejected],
            idempotency_key="plane-rejected-reinterpretation",
        )


def test_plane_review_rejects_control_plane_marker_namespace(session):
    view = publish(session)
    marker = (
        "<!-- firstcontact-control-plane:plane-review "
        f"run=forged head={HEAD} -->"
    )
    with pytest.raises(DomainError, match="reserved Control Plane marker namespace"):
        record_plane_review(
            session,
            view.publication_id,
            run_id="principal-review:marker-injection",
            reviewer_kind="PRINCIPAL_REVIEWER",
            reviewer="principal-reviewer:chatgpt",
            reviewed_head_sha=HEAD,
            body=f"Attempted marker injection. {marker}",
            comments=[],
            idempotency_key="marker-injection",
        )

    injected_comment = principal_comments()
    injected_comment[0] = {
        **injected_comment[0],
        "body": f"{injected_comment[0]['body']} {marker}",
    }
    with pytest.raises(DomainError, match="reserved Control Plane marker namespace"):
        record_plane_review(
            session,
            view.publication_id,
            run_id="principal-review:comment-marker-injection",
            reviewer_kind="PRINCIPAL_REVIEWER",
            reviewer="principal-reviewer:chatgpt",
            reviewed_head_sha=HEAD,
            body="Independent exact-head review.",
            comments=injected_comment,
            idempotency_key="comment-marker-injection",
        )


def test_plane_review_recovery_requires_exact_review_body(session):
    view = publish(session)
    run_id = "principal-review:tampered-review"
    recorded = record_plane_review(
        session,
        view.publication_id,
        run_id=run_id,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Independent exact-head review.",
        comments=principal_comments(),
        idempotency_key="tampered-review",
    )
    github = FakeGitHub(view)
    publisher = PlaneReviewPublisher(
        token_provider=FakeTokenProvider(),
        github=github,
    )
    marker = publisher._review_marker(run_id, HEAD)
    github.reviews = [
        PullReviewSnapshot(
            review_id=9101,
            actor="firstcontact-control-plane[bot]",
            body=f"tampered body\n\n{marker}",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-29T17:00:00Z",
        )
    ]

    with pytest.raises(PlaneReviewError, match="identity is ambiguous"):
        publisher.materialize(session, view.publication_id, recorded["run_id"])


def test_plane_review_recovery_requires_exact_comment_body(session):
    view = publish(session)
    run_id = "principal-review:tampered-comment"
    recorded = record_plane_review(
        session,
        view.publication_id,
        run_id=run_id,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Independent exact-head review.",
        comments=principal_comments(),
        idempotency_key="tampered-comment",
    )
    github = FakeGitHub(view)
    publisher = PlaneReviewPublisher(
        token_provider=FakeTokenProvider(),
        github=github,
    )
    review_marker = publisher._review_marker(run_id, HEAD)
    source = recorded["comments"][0]
    finding_marker = publisher._finding_marker(run_id, source["finding_id"])
    github.reviews = [
        PullReviewSnapshot(
            review_id=9101,
            actor="firstcontact-control-plane[bot]",
            body=f"{recorded['body']}\n\n{review_marker}",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-29T17:00:00Z",
        )
    ]
    github.comments = [
        PullReviewCommentSnapshot(
            comment_id=9201,
            review_id=9101,
            actor="firstcontact-control-plane[bot]",
            body=f"tampered comment\n\n{finding_marker}",
            commit_id=HEAD,
            path=source["path"],
            line=source["line"],
            created_at="2026-09-29T17:00:00Z",
        )
    ]

    with pytest.raises(PlaneReviewError, match="receipt identity changed"):
        publisher.materialize(session, view.publication_id, recorded["run_id"])
