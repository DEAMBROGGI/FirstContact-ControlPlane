from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from control_plane.domain import (
    AutomatedReviewStatus,
    DomainError,
    EventType,
    PublicationState,
    ReviewDecision,
    ValidationStatus,
)
from control_plane.github_api import (
    IssueCommentSnapshot,
    PullMergeEventSnapshot,
    PullRequestSnapshot,
    PullReviewSnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.github_webhook import (
    GitHubWebhookAuthError,
    GitHubWebhookError,
    GitHubWebhookGateway,
    _lock_delivery_scope,
    get_review_watch,
    get_webhook_delivery,
    mark_delivery_retry,
    persist_webhook_delivery,
    sync_review_watch,
)
from control_plane.models import GitHubWebhookDeliveryRow
from control_plane.main import review_record
from control_plane.schemas import ReviewRequest
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.repository import load_events
from control_plane.service import (
    claim_codex_review_trigger_dispatch,
    complete_codex_review,
    complete_codex_review_trigger_dispatch,
    create_publication,
    get_view,
    mark_remote_published,
    record_validation,
    request_codex_review,
    submit_verified_candidate,
)


REPOSITORY = "DEAMBROGGI/FirstContact-ControlPlane"
BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40
TRIGGER_AT = "2026-09-30T12:00:00Z"
CODEX_ACTOR = "chatgpt-codex-connector[bot]"
HUMAN_ACTOR = "DEAMBROGGI"
SECRET = "webhook-test-secret"
USAGE_LIMIT = (
    "You have reached your Codex usage limits for code reviews. "
    "You can see your limits in the Codex usage dashboard."
)


def candidate() -> VerifiedCandidateSource:
    return VerifiedCandidateSource(
        bundle_sha256="a" * 64,
        byte_length=1234,
        quarantine_id="a" * 64,
        base_sha=BASE,
        head_sha=HEAD,
        tree_sha=TREE,
    )


def published(session, issue_number=2601):
    view = create_publication(session, REPOSITORY, issue_number)
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
    return mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch=f"control-plane/issue-{issue_number}-webhook",
        base_branch="master",
        pull_request_number=44,
    )


def start_codex(session, view):
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=HEAD,
    )
    assert running.automated_review_run_id is not None
    lease_id = "lease-webhook-test"
    assert claim_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        lease_id=lease_id,
    )
    return complete_codex_review_trigger_dispatch(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        lease_id=lease_id,
        comment_id=700,
        actor=HUMAN_ACTOR,
        created_at=TRIGGER_AT,
    )


def complete_codex_pass(session, view):
    assert view.automated_review_run_id is not None
    return complete_codex_review(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[501],
        provider_comment_ids=[],
        provider_reaction_ids=[],
    )


def raw_delivery(
    *,
    event_name: str,
    action: str = "created",
    comment_id: int | None = None,
    review_id: int | None = None,
    review_actor: str | None = None,
):
    payload = {
        "action": action,
        "repository": {"full_name": REPOSITORY},
        "issue": {
            "number": 44,
            "pull_request": {"url": "https://example.invalid/pr/44"},
        },
    }
    if event_name.startswith("pull_request"):
        payload["pull_request"] = {
            "number": 44,
            "head": {"sha": HEAD},
            "base": {"ref": "master"},
        }
    if comment_id is not None:
        payload["comment"] = {
            "id": comment_id,
            "user": {"login": CODEX_ACTOR},
        }
    if review_id is not None:
        payload["review"] = {
            "id": review_id,
            "user": {"login": review_actor or HUMAN_ACTOR},
        }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return body, signature


class FakeTokenProvider:
    def __init__(self):
        self.requests = []

    def installation_access(self, repository, *, permissions=None):
        self.requests.append((repository, permissions))
        return InstallationAccess(
            installation_id=123,
            token="installation-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )


class FakeGitHub:
    def __init__(self):
        self.head_sha = HEAD
        self.mergeable = None
        self.merged = False
        self.issue_comments = []
        self.reviews = []
        self.review_comments = []
        self.reactions = []
        self.ref_shas = {"master": BASE}

    def pull_request(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == 44
        assert token == "installation-token"
        return PullRequestSnapshot(
            number=44,
            state="closed" if self.merged else "open",
            base_ref="master",
            head_ref="control-plane/issue-2601-webhook",
            head_sha=self.head_sha,
            merged=self.merged,
            merge_commit_sha=("9" * 40 if self.merged else None),
            mergeable=self.mergeable,
        )

    def list_issue_comments(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == 44
        assert token == "installation-token"
        return list(self.issue_comments)

    def list_pull_reviews(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == 44
        assert token == "installation-token"
        return list(self.reviews)

    def list_pull_review_comments(self, repository, number, token):
        assert token == "installation-token"
        return list(self.review_comments)

    def list_issue_comment_reactions(self, repository, comment_id, token):
        assert token == "installation-token"
        return list(self.reactions)

    def ref_sha(self, repository, branch, token):
        assert repository == REPOSITORY
        assert token == "installation-token"
        return self.ref_shas.get(branch)

    def pull_request_merged(self, repository, number, token):
        assert token == "installation-token"
        return self.merged

    def pull_request_merge_event(self, repository, number, token):
        if not self.merged:
            return None
        return PullMergeEventSnapshot(
            commit_id="9" * 40,
            actor="firstcontact-control-plane[bot]",
            created_at="2026-09-30T13:00:00Z",
        )


def gateway(github=None):
    return GitHubWebhookGateway(
        token_provider=FakeTokenProvider(),
        github=github or FakeGitHub(),
        codex_review_mode="required",
        codex_actors=(CODEX_ACTOR,),
        human_review_actors=(HUMAN_ACTOR,),
        webhook_secret=SECRET,
        maximum_payload_bytes=1024 * 1024,
    )


def test_signed_delivery_persists_once_and_conflicting_reuse_fails(session):
    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=701,
    )

    first = persist_webhook_delivery(
        session,
        delivery_id="delivery-1",
        event_name="issue_comment",
        signature=signature,
        body=body,
        secret=SECRET,
        maximum_bytes=1024 * 1024,
    )
    replay = persist_webhook_delivery(
        session,
        delivery_id="delivery-1",
        event_name="issue_comment",
        signature=signature,
        body=body,
        secret=SECRET,
        maximum_bytes=1024 * 1024,
    )

    assert first.delivery_id == replay.delivery_id
    assert session.query(GitHubWebhookDeliveryRow).count() == 1

    conflicting_body, conflicting_signature = raw_delivery(
        event_name="issue_comment",
        comment_id=702,
    )
    with pytest.raises(DomainError, match="conflicting evidence"):
        persist_webhook_delivery(
            session,
            delivery_id="delivery-1",
            event_name="issue_comment",
            signature=conflicting_signature,
            body=conflicting_body,
            secret=SECRET,
            maximum_bytes=1024 * 1024,
        )

    assert session.query(GitHubWebhookDeliveryRow).count() == 1


def test_invalid_signature_never_persists_inbox_row(session):
    body, _signature = raw_delivery(
        event_name="issue_comment",
        comment_id=701,
    )

    with pytest.raises(GitHubWebhookAuthError):
        persist_webhook_delivery(
            session,
            delivery_id="delivery-invalid",
            event_name="issue_comment",
            signature="sha256=" + ("0" * 64),
            body=body,
            secret=SECRET,
            maximum_bytes=1024 * 1024,
        )

    assert session.get(GitHubWebhookDeliveryRow, "delivery-invalid") is None


def test_usage_limit_webhook_marks_matching_exact_run_unavailable(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [
        IssueCommentSnapshot(
            comment_id=700,
            actor=HUMAN_ACTOR,
            body=(
                "@codex review\n\n"
                f"<!-- firstcontact-control-plane:codex-review "
                f"run={view.automated_review_run_id} head={HEAD} -->"
            ),
            created_at=TRIGGER_AT,
        ),
        IssueCommentSnapshot(
            comment_id=701,
            actor=CODEX_ACTOR,
            body=USAGE_LIMIT,
            created_at="2026-09-30T12:01:00Z",
        ),
    ]
    value = gateway(github)

    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=701,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-usage-limit",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )
    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert result.outcome == "CODEX_UNAVAILABLE"
    assert result.next_role == "PRINCIPAL_REVIEWER"
    assert result.next_action == "PRINCIPAL_FALLBACK"
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"


def test_stale_human_review_cannot_advance_exact_head(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=801,
            actor=HUMAN_ACTOR,
            body="approve stale",
            state="APPROVED",
            commit_id="4" * 40,
            submitted_at="2026-09-30T12:05:00Z",
        )
    ]
    value = gateway(github)

    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=801,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-stale-human",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )
    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert result.outcome == "STALE_HUMAN_REVIEW"
    assert result.next_action == "WAIT_HUMAN_REVIEW"


def test_exact_human_approval_can_advance_directly_to_ready_to_merge(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.mergeable = True
    github.reviews = [
        PullReviewSnapshot(
            review_id=802,
            actor=HUMAN_ACTOR,
            body="approved exact head",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:06:00Z",
        )
    ]
    value = gateway(github)

    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=802,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-human-approved",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )
    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    assert current.state is PublicationState.READY_TO_MERGE
    assert current.mergeable is True
    assert result.next_role == "CONTROL_PLANE"
    assert result.next_action == "MERGE"


def test_pending_human_delivery_can_resume_after_restart_when_gate_becomes_ready(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=803,
            actor=HUMAN_ACTOR,
            body="approved before provider finished",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:07:00Z",
        )
    ]

    first_gateway = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=803,
        review_actor=HUMAN_ACTOR,
    )
    receipt = first_gateway.ingest(
        session,
        delivery_id="delivery-human-early",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )
    deferred = first_gateway.process_delivery(session, receipt.delivery_id)

    assert deferred.outcome == "DEFERRED"
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"
    assert get_view(session, view.publication_id).state is PublicationState.IN_REVIEW

    complete_codex_pass(
        session,
        get_view(session, view.publication_id),
    )

    restarted_gateway = gateway(github)
    resumed = restarted_gateway.reconcile_pending(session)

    assert len(resumed) == 1
    assert resumed[0].delivery_id == receipt.delivery_id
    assert get_view(session, view.publication_id).state is PublicationState.APPROVED
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"

    watch = get_review_watch(session, view.publication_id)
    assert watch.next_action == "CHECK_MERGEABILITY"


def test_review_watch_reconstructs_provider_next_action_from_publication(session):
    view = start_codex(session, published(session))
    watch = sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )

    assert watch.watched_head_sha == HEAD
    assert watch.review_run_id == view.automated_review_run_id
    assert watch.next_role == "PROVIDER"
    assert watch.next_action == "WAIT_PROVIDER"
    assert set(watch.expected_actors) == {
        CODEX_ACTOR.lower(),
        HUMAN_ACTOR.lower(),
    }


def test_stale_review_watch_is_fail_closed_even_when_publication_is_in_review(session):
    view = start_codex(session, published(session))
    stale = sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
        state="STALE",
    )

    assert stale.state == "STALE"
    assert stale.next_role == "CONTROL_PLANE"
    assert stale.next_action == "BLOCKED"

    replayed = sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )
    assert replayed.state == "STALE"
    assert replayed.next_role == "CONTROL_PLANE"
    assert replayed.next_action == "BLOCKED"


def test_direct_human_review_is_blocked_when_base_ref_drifted(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.ref_shas["master"] = "4" * 40
    value = gateway(github)

    with pytest.raises(DomainError, match="publication base is stale"):
        value.assert_review_write_current(session, view.publication_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]

    assert current.state is PublicationState.IN_REVIEW
    assert review_events == []
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_direct_human_review_endpoint_is_blocked_when_base_ref_drifted(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.ref_shas["master"] = "4" * 40
    value = gateway(github)

    with pytest.raises(HTTPException) as caught:
        review_record(
            view.publication_id,
            ReviewRequest(
                reviewed_head_sha=HEAD,
                decision=ReviewDecision.APPROVED,
            ),
            session,
            value,
        )

    assert caught.value.status_code == 409
    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert current.state is PublicationState.IN_REVIEW
    assert review_events == []
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_direct_human_review_endpoint_allows_current_base(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    value = gateway(FakeGitHub())

    approved = review_record(
        view.publication_id,
        ReviewRequest(
            reviewed_head_sha=HEAD,
            decision=ReviewDecision.APPROVED,
        ),
        session,
        value,
    )

    assert approved["state"] == PublicationState.APPROVED.value
    assert get_review_watch(session, view.publication_id).state == "ACTIVE"



def test_duplicate_human_review_delivery_does_not_duplicate_review_event(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=804,
            actor=HUMAN_ACTOR,
            body="same approval replayed",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:08:00Z",
        )
    ]
    value = gateway(github)

    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=804,
        review_actor=HUMAN_ACTOR,
    )
    first = value.ingest(
        session,
        delivery_id="delivery-human-replay-1",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )
    value.process_delivery(session, first.delivery_id)

    second = value.ingest(
        session,
        delivery_id="delivery-human-replay-2",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )
    replay = value.process_delivery(session, second.delivery_id)

    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert len(review_events) == 1
    assert replay.outcome.startswith("HUMAN_APPROVED_ALREADY_RECORDED")
    assert get_webhook_delivery(session, second.delivery_id).state == "PROCESSED"


def test_pull_request_synchronize_with_unrecorded_head_marks_watch_stale(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.head_sha = "4" * 40
    value = gateway(github)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )

    body, signature = raw_delivery(
        event_name="pull_request",
        action="synchronize",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-sync-stale",
        event_name="pull_request",
        signature=signature,
        body=body,
    )
    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert current.remote_head_sha == HEAD
    assert current.automated_review_status is AutomatedReviewStatus.RUNNING
    assert watch.state == "STALE"
    assert result.outcome == "STALE_HEAD"
    assert result.next_action == "BLOCKED"


def test_lost_usage_limit_webhook_converges_through_reconciliation(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [
        IssueCommentSnapshot(
            comment_id=700,
            actor=HUMAN_ACTOR,
            body=(
                "@codex review\n\n"
                f"<!-- firstcontact-control-plane:codex-review "
                f"run={view.automated_review_run_id} head={HEAD} -->"
            ),
            created_at=TRIGGER_AT,
        ),
        IssueCommentSnapshot(
            comment_id=705,
            actor=CODEX_ACTOR,
            body=USAGE_LIMIT,
            created_at="2026-09-30T12:09:00Z",
        ),
    ]
    value = gateway(github)

    result = value.reconcile_publication(
        session,
        view.publication_id,
    )

    current = get_view(session, view.publication_id)
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert result.outcome == "RECONCILED"
    assert result.next_action == "PRINCIPAL_FALLBACK"


def test_usage_limit_with_mutated_trigger_marker_fails_closed(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [
        IssueCommentSnapshot(
            comment_id=700,
            actor=HUMAN_ACTOR,
            body="@codex review without governed marker",
            created_at=TRIGGER_AT,
        ),
        IssueCommentSnapshot(
            comment_id=706,
            actor=CODEX_ACTOR,
            body=USAGE_LIMIT,
            created_at="2026-09-30T12:10:00Z",
        ),
    ]
    value = gateway(github)

    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=706,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-mutated-trigger",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )

    from control_plane.github_webhook import GitHubWebhookError

    with pytest.raises(GitHubWebhookError, match="trigger marker changed"):
        value.process_delivery(session, receipt.delivery_id)

    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.RUNNING
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"




@pytest.mark.parametrize("wakeup_review_id", [810, 811])
def test_out_of_order_human_review_wakeup_uses_latest_remote_decision(
    session,
    wakeup_review_id,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=810,
            actor=HUMAN_ACTOR,
            body="older approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:10:00Z",
        ),
        PullReviewSnapshot(
            review_id=811,
            actor=HUMAN_ACTOR,
            body="newer changes requested",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:11:00Z",
        ),
    ]
    value = gateway(github)

    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=wakeup_review_id,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-human-order-{wakeup_review_id}",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )
    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert current.review_decision is not None
    assert current.review_decision.value == "CHANGES_REQUIRED"
    assert result.outcome == "HUMAN_CHANGES_REQUIRED"

    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert len(review_events) == 1
    assert review_events[0]["payload"]["decision"] == "CHANGES_REQUIRED"


def test_base_push_stale_blocks_later_human_review_and_mergeability(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.ref_shas["master"] = "8" * 40
    github.mergeable = True
    github.reviews = [
        PullReviewSnapshot(
            review_id=812,
            actor=HUMAN_ACTOR,
            body="approval after base drift",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:12:00Z",
        )
    ]
    value = gateway(github)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )

def test_base_push_back_to_candidate_sha_is_the_only_stale_watch_recovery(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.ref_shas["master"] = "8" * 40
    value = gateway(github)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )

    stale_body = json.dumps(
        {
            "ref": "refs/heads/master",
            "after": "8" * 40,
            "repository": {"full_name": REPOSITORY},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    stale_signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        stale_body,
        hashlib.sha256,
    ).hexdigest()
    stale_receipt = value.ingest(
        session,
        delivery_id="delivery-base-push-stale-recovery-1",
        event_name="push",
        signature=stale_signature,
        body=stale_body,
    )
    stale_result = value.process_delivery(session, stale_receipt.delivery_id)

    assert stale_result.outcome == "BASE_PUSH_STALE:1:RECOVERED:0"
    assert stale_result.next_action == "BLOCKED"
    assert get_review_watch(session, view.publication_id).state == "STALE"

    github.ref_shas["master"] = BASE
    recovery_body = json.dumps(
        {
            "ref": "refs/heads/master",
            "after": BASE,
            "repository": {"full_name": REPOSITORY},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    recovery_signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        recovery_body,
        hashlib.sha256,
    ).hexdigest()
    recovery_receipt = value.ingest(
        session,
        delivery_id="delivery-base-push-recovery-2",
        event_name="push",
        signature=recovery_signature,
        body=recovery_body,
    )
    recovery_result = value.process_delivery(session, recovery_receipt.delivery_id)

    watch = get_review_watch(session, view.publication_id)
    assert recovery_result.outcome == "BASE_PUSH_STALE:0:RECOVERED:1"
    assert recovery_result.next_action == "DONE"
    assert watch.state == "ACTIVE"
    assert watch.next_role == "PROVIDER"
    assert watch.next_action == "WAIT_PROVIDER"


    push_payload = {
        "ref": "refs/heads/master",
        "after": "8" * 40,
        "repository": {"full_name": REPOSITORY},
    }
    push_body = json.dumps(
        push_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    push_signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        push_body,
        hashlib.sha256,
    ).hexdigest()
    push_receipt = value.ingest(
        session,
        delivery_id="delivery-base-push-stale",
        event_name="push",
        signature=push_signature,
        body=push_body,
    )
    push_result = value.process_delivery(session, push_receipt.delivery_id)

    assert push_result.outcome == "BASE_PUSH_STALE:1:RECOVERED:0"
    assert get_review_watch(session, view.publication_id).state == "STALE"

    review_body, review_signature = raw_delivery(
        event_name="pull_request_review",
        review_id=812,
        review_actor=HUMAN_ACTOR,
    )
    review_receipt = value.ingest(
        session,
        delivery_id="delivery-human-after-base-drift",
        event_name="pull_request_review",
        signature=review_signature,
        body=review_body,
    )
    review_result = value.process_delivery(session, review_receipt.delivery_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert current.mergeable is None
    assert review_result.outcome == "STALE_BASE"
    assert review_result.next_role == "CONTROL_PLANE"
    assert review_result.next_action == "BLOCKED"
    assert watch.state == "STALE"

    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert review_events == []


def test_best_effort_pending_recovery_isolates_one_failed_delivery(session):
    published(session)
    value = gateway(FakeGitHub())

    first_body, first_signature = raw_delivery(
        event_name="issue_comment",
        comment_id=720,
    )
    second_body, second_signature = raw_delivery(
        event_name="issue_comment",
        comment_id=721,
    )
    value.ingest(
        session,
        delivery_id="delivery-startup-bad",
        event_name="issue_comment",
        signature=first_signature,
        body=first_body,
    )
    value.ingest(
        session,
        delivery_id="delivery-startup-good",
        event_name="issue_comment",
        signature=second_signature,
        body=second_body,
    )

    original = value.process_delivery
    seen = []

    def flaky_process(supplied_session, delivery_id):
        seen.append(delivery_id)
        if delivery_id == "delivery-startup-bad":
            mark_delivery_retry(
                supplied_session,
                delivery_id,
                "simulated startup recovery failure",
            )
            raise GitHubWebhookError("simulated startup recovery failure")
        return original(supplied_session, delivery_id)

    value.process_delivery = flaky_process
    recovered = value.reconcile_pending_best_effort(session, limit=2)

    assert seen == ["delivery-startup-bad", "delivery-startup-good"]
    assert len(recovered) == 1
    assert recovered[0].delivery_id == "delivery-startup-good"
    assert get_webhook_delivery(session, "delivery-startup-bad").state == "PENDING"
    assert (
        get_webhook_delivery(session, "delivery-startup-bad").last_error
        == "simulated startup recovery failure"
    )
    assert get_webhook_delivery(session, "delivery-startup-good").state == "PROCESSED"


def test_delivery_scope_uses_postgres_advisory_lock():
    class Dialect:
        name = "postgresql"

    class Bind:
        dialect = Dialect()

    class FakeSession:
        def __init__(self):
            self.calls = []

        def get_bind(self):
            return Bind()

        def execute(self, statement, params):
            self.calls.append((str(statement), params))

    session = FakeSession()
    _lock_delivery_scope(session, "delivery-concurrent-1")

    assert len(session.calls) == 1
    sql, params = session.calls[0]
    assert "pg_advisory_xact_lock" in sql
    assert set(params) == {"webhook_delivery_key"}
    assert isinstance(params["webhook_delivery_key"], int)


def test_delivery_scope_is_noop_outside_postgres():
    class Dialect:
        name = "sqlite"

    class Bind:
        dialect = Dialect()

    class FakeSession:
        def get_bind(self):
            return Bind()

        def execute(self, *_args, **_kwargs):
            raise AssertionError("SQLite must not execute PostgreSQL advisory locks")

    _lock_delivery_scope(FakeSession(), "delivery-sqlite")
