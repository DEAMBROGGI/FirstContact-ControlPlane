from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr

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
    IssueReactionSnapshot,
    PullRequestSnapshot,
    PullReviewCommentSnapshot,
    PullReviewSnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.github_review_auth import (
    GitHubReviewTokenProvider,
)
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.repository import load_events
from control_plane.service import (
    claim_codex_review_trigger_dispatch,
    create_publication,
    get_view,
    mark_remote_published,
    mark_codex_review_unavailable,
    record_review,
    record_validation,
    release_codex_review_trigger_dispatch,
    request_codex_review,
    submit_verified_candidate,
)

BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40
TRIGGER_AT = "2026-09-27T20:00:00Z"
CODEX_ACTOR = "chatgpt-codex-connector[bot]"


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
        self.reactions = []
        self.posted_bodies = []
        self.trigger_actor = "DEAMBROGGI"
        self.authenticated_login = "DEAMBROGGI"
        self.authenticated_user_requests = 0
        self.pull_request_requests = 0
        self.issue_comment_list_requests = 0

    def authenticated_user_login(self, token):
        self.authenticated_user_requests += 1
        assert token == "github_pat_human-review-token"
        return self.authenticated_login

    def pull_request(self, repository, number, token):
        self.pull_request_requests += 1
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
        self.issue_comment_list_requests += 1
        assert token == "review-token"
        return list(self.issue_comments)

    def add_issue_comment(self, repository, number, body, token):
        assert token == "github_pat_human-review-token"
        self.posted_bodies.append(body)
        item = IssueCommentSnapshot(
            comment_id=900 + len(self.issue_comments),
            actor=self.trigger_actor,
            body=body,
            created_at=TRIGGER_AT,
        )
        self.issue_comments.append(item)
        return item

    def list_pull_reviews(self, repository, number, token):
        assert token == "review-token"
        return list(self.reviews)

    def list_pull_review_comments(self, repository, number, token):
        assert token == "review-token"
        return list(self.review_comments)

    def list_issue_comment_reactions(self, repository, comment_id, token):
        assert token == "review-token"
        return list(self.reactions)


def broker(
    *,
    github=None,
    mode="required",
    actors=("chatgpt-codex-connector",),
    trigger_token="github_pat_human-review-token",
):
    token_provider = FakeTokenProvider()
    github = github or FakeGitHub()
    trigger_user = GitHubReviewTokenProvider(
        token=SecretStr(trigger_token),
        expected_login="DEAMBROGGI",
        github=github,
    )
    value = CodexReviewBroker(
        token_provider=token_provider,
        github=github,
        mode=mode,
        allowed_actors=actors,
        trigger_user=trigger_user,
    )
    return value, token_provider, github


def remove_trigger_credential(value):
    value.trigger_user = GitHubReviewTokenProvider(
        token=SecretStr(""),
        expected_login="DEAMBROGGI",
        github=value.github,
    )


def add_codex_review(github, *, review_id=501, submitted_at="2026-09-27T20:01:00Z"):
    github.reviews.append(
        PullReviewSnapshot(
            review_id=review_id,
            actor=CODEX_ACTOR,
            body="Codex review complete.",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at=submitted_at,
        )
    )


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
    assert first.automated_review_trigger_actor == "DEAMBROGGI"
    assert first.automated_review_triggered_at == TRIGGER_AT
    assert github.posted_bodies[0].startswith("@codex review\n\n<!--")
    assert tokens.requests[0][1] == {
        "issues": "read",
        "pull_requests": "read",
    }
    run_id = first.automated_review_run_id
    before_retry_events = load_events(session, view.publication_id)
    user_requests = github.authenticated_user_requests

    second = value.request(session, view.publication_id)
    assert second.automated_review_run_id == run_id
    assert second.automated_review_trigger_comment_id == 900
    assert len(github.posted_bodies) == 1
    assert github.authenticated_user_requests == user_requests
    assert load_events(session, view.publication_id) == before_retry_events
    ledger = json.dumps(load_events(session, view.publication_id))
    assert "github_pat_human-review-token" not in ledger


def test_pass_same_head_reads_back_without_trigger_credential(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    first = value.request(session, view.publication_id)
    add_codex_review(github)
    assert value.reconcile(session, view.publication_id).state == "PASS"
    before = load_events(session, view.publication_id)
    user_requests = github.authenticated_user_requests
    comment_count = len(github.posted_bodies)
    remove_trigger_credential(value)

    result = value.request(session, view.publication_id)

    assert result.automated_review_status is AutomatedReviewStatus.PASS
    assert result.automated_review_head_sha == HEAD
    assert result.automated_review_run_id == first.automated_review_run_id
    assert github.authenticated_user_requests == user_requests
    assert len(github.posted_bodies) == comment_count
    assert load_events(session, view.publication_id) == before


def test_changes_required_same_head_reads_back_without_trigger_credential(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    first = value.request(session, view.publication_id)
    add_codex_review(github, review_id=502)
    github.review_comments.append(
        PullReviewCommentSnapshot(
            comment_id=602,
            review_id=502,
            actor=CODEX_ACTOR,
            body="Requires a change.",
            commit_id=HEAD,
            path="control_plane/domain.py",
            line=10,
            created_at="2026-09-27T20:01:01Z",
        )
    )
    assert value.reconcile(session, view.publication_id).state == "CHANGES_REQUIRED"
    before = load_events(session, view.publication_id)
    user_requests = github.authenticated_user_requests
    comment_count = len(github.posted_bodies)
    remove_trigger_credential(value)

    result = value.request(session, view.publication_id)

    assert result.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
    assert result.automated_review_head_sha == HEAD
    assert result.automated_review_run_id == first.automated_review_run_id
    assert github.authenticated_user_requests == user_requests
    assert len(github.posted_bodies) == comment_count
    assert load_events(session, view.publication_id) == before


def test_running_with_registered_trigger_reads_back_without_credential(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    first = value.request(session, view.publication_id)
    comment_id = first.automated_review_trigger_comment_id
    assert comment_id is not None
    before = load_events(session, view.publication_id)
    user_requests = github.authenticated_user_requests
    comment_count = len(github.posted_bodies)
    remove_trigger_credential(value)

    result = value.request(session, view.publication_id)

    assert result.automated_review_status is AutomatedReviewStatus.RUNNING
    assert result.automated_review_run_id == first.automated_review_run_id
    assert result.automated_review_trigger_comment_id == comment_id
    assert github.authenticated_user_requests == user_requests
    assert len(github.posted_bodies) == comment_count
    assert load_events(session, view.publication_id) == before


def test_running_without_registered_trigger_recovers_dispatch_once(session):
    view = published_publication(session)
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
    )
    run_id = running.automated_review_run_id
    assert run_id is not None
    assert running.automated_review_trigger_comment_id is None
    value, _tokens, github = broker()

    recovered = value.request(session, view.publication_id)

    assert recovered.automated_review_status is AutomatedReviewStatus.RUNNING
    assert recovered.automated_review_run_id == run_id
    assert recovered.automated_review_trigger_comment_id is not None
    assert github.authenticated_user_requests == 1
    assert len(github.posted_bodies) == 1
    before_retry = load_events(session, view.publication_id)
    comment_id = recovered.automated_review_trigger_comment_id
    remove_trigger_credential(value)

    retried = value.request(session, view.publication_id)

    assert retried.automated_review_status is AutomatedReviewStatus.RUNNING
    assert retried.automated_review_run_id == run_id
    assert retried.automated_review_trigger_comment_id == comment_id
    assert github.authenticated_user_requests == 1
    assert len(github.posted_bodies) == 1
    assert load_events(session, view.publication_id) == before_retry


def test_retry_during_active_dispatch_lease_does_not_create_second_run_or_comment(
    session,
):
    view = published_publication(session)
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
    )
    run_id = running.automated_review_run_id
    assert run_id is not None
    lease_id = "dispatch-owner-a"
    assert claim_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=run_id,
        lease_id=lease_id,
    )
    value, _tokens, github = broker()
    before_retry = load_events(session, view.publication_id)

    concurrent_retry = value.request(session, view.publication_id)

    assert concurrent_retry.automated_review_run_id == run_id
    assert concurrent_retry.automated_review_trigger_comment_id is None
    assert github.authenticated_user_requests == 1
    assert github.posted_bodies == []
    assert load_events(session, view.publication_id) == before_retry

    release_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=run_id,
        lease_id=lease_id,
    )
    dispatched = value.request(session, view.publication_id)

    assert dispatched.automated_review_run_id == run_id
    assert dispatched.automated_review_trigger_comment_id is not None
    assert len(github.posted_bodies) == 1
    before_idempotent_retry = load_events(session, view.publication_id)
    remove_trigger_credential(value)

    retried = value.request(session, view.publication_id)

    assert retried.automated_review_run_id == run_id
    assert retried.automated_review_trigger_comment_id == (
        dispatched.automated_review_trigger_comment_id
    )
    assert github.authenticated_user_requests == 2
    assert len(github.posted_bodies) == 1
    assert load_events(session, view.publication_id) == before_idempotent_retry


def test_trigger_identity_mismatch_fails_before_comment_or_run(session):
    view = published_publication(session)
    github = FakeGitHub()
    github.authenticated_login = "OTHER"
    value, _tokens, _github = broker(github=github)

    with pytest.raises(CodexReviewError, match="failed closed"):
        value.request(session, view.publication_id)

    assert github.posted_bodies == []
    assert get_view(session, view.publication_id).automated_review_status is None


def test_missing_trigger_token_fails_before_comment_or_run(session):
    view = published_publication(session)
    github = FakeGitHub()
    value, _tokens, _github = broker(github=github, trigger_token="")

    with pytest.raises(CodexReviewError, match="failed closed"):
        value.request(session, view.publication_id)

    assert github.posted_bodies == []
    assert get_view(session, view.publication_id).automated_review_status is None


def test_returned_trigger_actor_mismatch_fails_closed(session):
    view = published_publication(session)
    github = FakeGitHub()
    github.trigger_actor = "OTHER"
    value, _tokens, _github = broker(github=github)

    with pytest.raises(CodexReviewError, match="failed closed"):
        value.request(session, view.publication_id)

    assert len(github.posted_bodies) == 1
    assert get_view(
        session, view.publication_id
    ).automated_review_status is AutomatedReviewStatus.UNAVAILABLE


def test_dispatch_lease_serializes_trigger_ownership(session):
    view = published_publication(session)
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
    )
    run_id = running.automated_review_run_id
    assert run_id is not None

    assert claim_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=run_id,
        lease_id="lease-a",
    )
    assert not claim_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=run_id,
        lease_id="lease-b",
    )
    release_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=run_id,
        lease_id="lease-a",
    )
    assert claim_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=run_id,
        lease_id="lease-b",
    )


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
    value, _tokens, github = broker()
    value.request(session, view.publication_id)
    add_codex_review(github)

    observed = value.reconcile(session, view.publication_id)
    after = get_view(session, view.publication_id)

    assert observed.state == "PASS"
    assert after.automated_review_status is AutomatedReviewStatus.PASS
    approved = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    assert approved.state is PublicationState.APPROVED


def test_clean_codex_thumbsup_reaction_can_complete_pass(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    running = value.request(session, view.publication_id)
    github.reactions.append(
        IssueReactionSnapshot(
            reaction_id=701,
            actor=CODEX_ACTOR,
            content="+1",
            created_at="2026-09-27T20:01:00Z",
        )
    )

    observed = value.reconcile(session, view.publication_id)
    assert observed.state == "PASS"
    assert observed.matching_reactions == 1
    assert get_view(
        session,
        view.publication_id,
    ).automated_review_status is AutomatedReviewStatus.PASS


def test_required_codex_finding_moves_publication_to_changes_required(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    value.request(session, view.publication_id)
    add_codex_review(github, review_id=502)
    github.review_comments.append(
        PullReviewCommentSnapshot(
            comment_id=601,
            review_id=502,
            actor=CODEX_ACTOR,
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


def test_advisory_codex_finding_does_not_block_human_review(session):
    view = published_publication(session)
    value, _tokens, github = broker(mode="advisory")
    value.request(session, view.publication_id)
    add_codex_review(github, review_id=504)
    github.review_comments.append(
        PullReviewCommentSnapshot(
            comment_id=602,
            review_id=504,
            actor=CODEX_ACTOR,
            body="Advisory issue.",
            commit_id=HEAD,
            path="control_plane/domain.py",
            line=10,
            created_at="2026-09-27T20:01:01Z",
        )
    )

    observed = value.reconcile(session, view.publication_id)
    after = get_view(session, view.publication_id)

    assert observed.state == "CHANGES_REQUIRED"
    assert after.state is PublicationState.IN_REVIEW
    assert after.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
    reviewed = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
    )
    assert reviewed.state is PublicationState.APPROVED


def test_review_from_before_governed_trigger_is_ignored(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    value.request(session, view.publication_id)
    add_codex_review(
        github,
        review_id=505,
        submitted_at="2026-09-27T19:59:59Z",
    )

    observed = value.reconcile(session, view.publication_id)
    assert observed.state == "RUNNING"


def test_additional_codex_invocation_makes_result_ambiguous(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    value.request(session, view.publication_id)
    github.issue_comments.append(
        IssueCommentSnapshot(
            comment_id=999,
            actor="DEAMBROGGI",
            body="@codex review",
            created_at="2026-09-27T20:00:30Z",
        )
    )
    add_codex_review(github)

    with pytest.raises(CodexReviewError, match="additional Codex invocation"):
        value.reconcile(session, view.publication_id)


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


def test_preexisting_unmanaged_codex_invocation_blocks_governed_trigger(session):
    from control_plane.repository import load_events

    view = published_publication(session)
    published = next(
        event
        for event in reversed(load_events(session, view.publication_id))
        if event["event_type"] == "REMOTE_PUBLISHED"
    )
    published_at = datetime.fromisoformat(published["occurred_at"])
    value, _tokens, github = broker()
    github.issue_comments.append(
        IssueCommentSnapshot(
            comment_id=850,
            actor="DEAMBROGGI",
            body="@codex review",
            created_at=(published_at + timedelta(seconds=1)).isoformat(),
        )
    )

    with pytest.raises(CodexReviewError, match="failed closed"):
        value.request(session, view.publication_id)

    assert github.posted_bodies == []
    after = get_view(session, view.publication_id)
    assert after.automated_review_status is AutomatedReviewStatus.UNAVAILABLE


def test_retry_after_unavailable_creates_new_codex_attempt(session):
    view = published_publication(session)
    first = request_codex_review(
        session,
        view.publication_id,
        mode="required",
    )
    first_run = first.automated_review_run_id
    assert first_run is not None
    mark_codex_review_unavailable(
        session,
        view.publication_id,
        run_id=first_run,
        reviewed_head_sha=HEAD,
        reason="TEMPORARY_PROVIDER_FAILURE",
    )

    second = request_codex_review(
        session,
        view.publication_id,
        mode="required",
    )

    assert second.automated_review_status is AutomatedReviewStatus.RUNNING
    assert second.automated_review_run_id is not None
    assert second.automated_review_run_id != first_run


def test_legacy_codex_trigger_event_remains_foldable():
    from control_plane.domain import fold_events

    events = [
        {
            "event_type": "PUBLICATION_CREATED",
            "payload": {"repository": "DEAMBROGGI/FirstContact-ControlPlane", "issue_number": 10},
        },
        {
            "event_type": "REMOTE_PUBLISHED",
            "payload": {"head_sha": HEAD, "pull_request_number": 12},
        },
        {
            "event_type": "CODEX_REVIEW_REQUESTED",
            "payload": {
                "run_id": "legacy-run",
                "head_sha": HEAD,
                "mode": "required",
            },
        },
        {
            "event_type": "CODEX_REVIEW_TRIGGERED",
            "payload": {"run_id": "legacy-run", "comment_id": 5860110112},
        },
    ]
    view = fold_events("legacy-publication", events)

    assert view.automated_review_trigger_comment_id == 5860110112
    assert view.automated_review_trigger_actor is None
    assert view.automated_review_triggered_at is None


def test_unmanaged_codex_invocation_from_older_head_does_not_poison_retry(session):
    view = published_publication(session)
    value, _tokens, github = broker()
    github.issue_comments.append(
        IssueCommentSnapshot(
            comment_id=851,
            actor="DEAMBROGGI",
            body="@codex review",
            created_at="2000-01-01T00:00:00Z",
        )
    )

    requested = value.request(session, view.publication_id)

    assert requested.automated_review_status is AutomatedReviewStatus.RUNNING
    assert requested.automated_review_trigger_comment_id is not None
    assert requested.automated_review_trigger_comment_id != 851
    assert len(github.posted_bodies) == 1
