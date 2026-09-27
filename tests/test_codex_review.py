from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from control_plane.codex_review import (
    CodexReviewBroker,
    CodexReviewError,
    assert_no_reserved_automation_mentions,
)
from control_plane.domain import (
    AutomatedReviewStatus,
    DomainError,
    PublicationState,
    ReviewDecision,
    ValidationStatus,
)
from control_plane.github_api import (
    IssueCommentSnapshot,
    PullRequestSnapshot,
    PullReviewCommentSnapshot,
    PullReviewSnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.service import (
    create_publication,
    get_view,
    mark_remote_published,
    record_review,
    record_validation,
    submit_verified_candidate,
)

BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


def source():
    return VerifiedCandidateSource(
        bundle_sha256="a" * 64,
        byte_length=1234,
        quarantine_id="a" * 64,
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
    )


def published_publication(session):
    view = create_publication(session, "DEAMBROGGI/FirstContact", 88)
    view = submit_verified_candidate(session, view.publication_id, source())
    profile = profile_for_repository(view.repository)
    for index, job in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )
    return mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch="control-plane/issue-88-abcd1234",
        base_branch="master",
        pull_request_number=44,
    )


class FakeTokenProvider:
    def __init__(self):
        self.requests = []

    def installation_access(self, repository, *, permissions=None):
        self.requests.append((repository, permissions))
        return InstallationAccess(
            installation_id=123,
            token="review-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )


class FakeGitHub:
    def __init__(self):
        self.head_sha = HEAD
        self.issue_comments = []
        self.reviews = []
        self.review_comments = []
        self.posted_bodies = []

    def pull_request(self, repository, number, token):
        assert repository == "DEAMBROGGI/FirstContact"
        assert number == 44
        assert token == "review-token"
        return PullRequestSnapshot(
            number=44,
            state="open",
            base_ref="master",
            head_ref="control-plane/issue-88-abcd1234",
            head_sha=self.head_sha,
        )

    def list_issue_comments(self, repository, number, token):
        return list(self.issue_comments)

    def add_issue_comment(self, repository, number, body, token):
        self.posted_bodies.append(body)
        item = IssueCommentSnapshot(
            comment_id=900 + len(self.issue_comments),
            actor="firstcontact-control-plane[bot]",
            body=body,
            created_at="2026-09-27T20:00:00Z",
        )
        self.issue_comments.append(item)
        return item

    def list_pull_reviews(self, repository, number, token):
        return list(self.reviews)

    def list_pull_review_comments(self, repository, number, token):
        return list(self.review_comments)


def broker(*, github=None, mode="required", actors=("codex[bot]",)):
    token_provider = FakeTokenProvider()
    github = github or FakeGitHub()
    value = CodexReviewBroker(
        token_provider=token_provider,
        github=github,
        mode=mode,
        allowed_actors=actors,
    )
    return value, token_provider, github


def test_reserved_codex_mentions_are_rejected():
    for value in (
        "@codex review",
        "please @Codex review this",
        "@codex security review",
    ):
        with pytest.raises(DomainError, match="reserved"):
            assert_no_reserved_automation_mentions(value)

    assert_no_reserved_automation_mentions("codex review without mention")


def test_broker_acquires_exact_head_lock_and_trigger_is_idempotent(session):
    view = published_publication(session)
    value, tokens, github = broker()

    first = value.request(session, view.publication_id)

    assert first.state is PublicationState.IN_REVIEW
    assert first.automated_reviewer == "CODEX_CODE_REVIEW"
    assert first.automated_review_status is AutomatedReviewStatus.RUNNING
    assert first.automated_review_head_sha == HEAD
    assert first.automated_review_trigger_comment_id == 900
    assert github.posted_bodies[0].startswith("@codex review\n\n<!--")
    assert tokens.requests[0][1] == {
        "issues": "write",
        "pull_requests": "read",
    }

    second = value.request(session, view.publication_id)
    assert second.automated_review_trigger_comment_id == 900
    assert len(github.posted_bodies) == 1


def test_human_review_is_locked_while_codex_runs(session):
    view = published_publication(session)
    value, _tokens, _github = broker()
    value.request(session, view.publication_id)

    with pytest.raises(DomainError, match="locked"):
        record_review(
            session,
            view.publication_id,
            reviewed_head_sha=HEAD,
            decision=ReviewDecision.APPROVED,
        )


def test_required_mode_blocks_human_review_before_codex_pass(session):
    view = published_publication(session)

    with pytest.raises(DomainError, match="required Codex"):
        record_review(
            session,
            view.publication_id,
            reviewed_head_sha=HEAD,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )


def test_clean_native_codex_review_releases_human_review(session):
    view = published_publication(session)
    value, tokens, github = broker()
    running = value.request(session, view.publication_id)
    github.reviews.append(
        PullReviewSnapshot(
            review_id=501,
            actor="codex[bot]",
            body="No blocking findings.",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-27T20:01:00Z",
        )
    )

    observed = value.reconcile(session, view.publication_id)
    after = get_view(session, view.publication_id)

    assert observed.state == "PASS"
    assert after.automated_review_status is AutomatedReviewStatus.PASS
    assert after.automated_reviewer is None
    assert tokens.requests[-1][1] == {
        "issues": "read",
        "pull_requests": "read",
    }

    approved = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    assert approved.state is PublicationState.APPROVED


def test_codex_inline_finding_moves_publication_to_changes_required(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    value.request(session, view.publication_id)
    github.reviews.append(
        PullReviewSnapshot(
            review_id=502,
            actor="codex[bot]",
            body="Found one issue.",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-27T20:01:00Z",
        )
    )
    github.review_comments.append(
        PullReviewCommentSnapshot(
            comment_id=601,
            review_id=502,
            actor="codex[bot]",
            body="This can publish the wrong ref.",
            commit_id=HEAD,
            path="control_plane/publisher.py",
            line=123,
            created_at="2026-09-27T20:01:01Z",
        )
    )

    observed = value.reconcile(session, view.publication_id)
    after = get_view(session, view.publication_id)

    assert observed.state == "CHANGES_REQUIRED"
    assert after.state is PublicationState.CHANGES_REQUIRED
    assert after.automated_review_findings_count == 1


def test_untrusted_review_actor_does_not_complete_codex_run(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    value.request(session, view.publication_id)
    github.reviews.append(
        PullReviewSnapshot(
            review_id=503,
            actor="someone-else",
            body="looks fine",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-27T20:01:00Z",
        )
    )

    observed = value.reconcile(session, view.publication_id)
    assert observed.state == "RUNNING"
    assert "someone-else" in observed.actors
    assert get_view(
        session,
        view.publication_id,
    ).automated_review_status is AutomatedReviewStatus.RUNNING


def test_stale_pr_head_fails_before_review_lock(session):
    view = published_publication(session)
    github = FakeGitHub()
    github.head_sha = "f" * 40
    value, _tokens, _github = broker(github=github)

    with pytest.raises(CodexReviewError, match="failed closed"):
        value.request(session, view.publication_id)

    assert get_view(session, view.publication_id).automated_review_status is None


def test_disabled_mode_never_invokes_github(session):
    view = published_publication(session)
    value, tokens, github = broker(mode="disabled")

    with pytest.raises(DomainError, match="disabled"):
        value.request(session, view.publication_id)

    assert tokens.requests == []
    assert github.posted_bodies == []
