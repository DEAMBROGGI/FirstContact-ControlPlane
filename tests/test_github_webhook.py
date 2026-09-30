from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from control_plane.domain import (
    AutomatedReviewStatus,
    DomainError,
    PublicationState,
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
    GitHubWebhookGateway,
    get_review_watch,
    get_webhook_delivery,
    persist_webhook_delivery,
    sync_review_watch,
)
from control_plane.models import GitHubWebhookDeliveryRow
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
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
            body="@codex review",
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
