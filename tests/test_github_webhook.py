from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from control_plane.codex_review import CodexReviewBroker, CodexReviewError
from control_plane.domain import (
    AutomatedReviewStatus,
    DomainError,
    EventType,
    PublicationState,
    ReviewDecision,
    ValidationStatus,
)
from control_plane.github_api import (
    GitHubApiError,
    GitHubCommitSnapshot,
    IssueCommentSnapshot,
    PullMergeEventSnapshot,
    PullRequestSnapshot,
    PullReviewCommentSnapshot,
    PullReviewSnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.plane_review import (
    complete_plane_review_materialization,
    record_plane_review,
)
from control_plane.github_webhook import (
    GitHubWebhookAuthError,
    GitHubWebhookDeliveryClaimLost,
    GitHubWebhookError,
    GitHubWebhookGateway,
    WebhookProcessResult,
    _lock_delivery_scope,
    get_review_watch,
    get_webhook_delivery,
    mark_delivery_processed,
    mark_delivery_retry,
    persist_webhook_delivery,
    sync_review_watch,
)
from control_plane.models import (
    GitHubWebhookDeliveryClaimRow,
    GitHubWebhookDeliveryRow,
    ReviewWatchRow,
)
from control_plane.main import mergeability_record, review_record
from control_plane.schemas import MergeabilityRequest, ReviewRequest
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.repository import load_events
from control_plane.service import (
    claim_codex_review_trigger_dispatch,
    complete_codex_review,
    complete_codex_review_trigger_dispatch,
    clear_human_review_block,
    create_publication,
    get_view,
    mark_codex_review_unavailable,
    mark_remote_published,
    record_mergeability,
    record_merge_policy_violation,
    record_review,
    record_validation,
    request_codex_review,
    submit_verified_candidate,
)


REPOSITORY = "DEAMBROGGI/FirstContact-ControlPlane"
BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40
NEXT_HEAD = "5" * 40
NEXT_TREE = "6" * 40
TRIGGER_AT = "2026-09-30T12:00:00Z"
CODEX_ACTOR = "chatgpt-codex-connector[bot]"
HUMAN_ACTOR = "DEAMBROGGI"
SECOND_HUMAN_ACTOR = "second-reviewer"
UNLISTED_ACTOR = "outside-reviewer"
SECRET = "webhook-test-secret"
USAGE_LIMIT = (
    "You have reached your Codex usage limits for code reviews. "
    "You can see your limits in the Codex usage dashboard."
)
CODEX_RESULT_AT = "2026-09-30T12:04:00Z"


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


def publish_next_head(session, view):
    source = VerifiedCandidateSource(
        bundle_sha256="b" * 64,
        byte_length=2345,
        quarantine_id="b" * 64,
        base_sha=BASE,
        head_sha=NEXT_HEAD,
        tree_sha=NEXT_TREE,
    )
    submit_verified_candidate(session, view.publication_id, source)
    profile = profile_for_repository(view.repository)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 20:064x}",
        )
    return mark_remote_published(
        session,
        view.publication_id,
        NEXT_HEAD,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )


def start_codex(session, view, *, expected_head_sha=HEAD, mode="required"):
    running = request_codex_review(
        session,
        view.publication_id,
        mode=mode,
        expected_head_sha=expected_head_sha,
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
    provider_review = codex_provider_review()
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
        provider_completed_at=CODEX_RESULT_AT,
        provider_evidence_sha256=CodexReviewBroker._provider_evidence_digest(
            [provider_review],
            [],
            [],
        ),
    )


def codex_provider_review():
    return PullReviewSnapshot(
        review_id=501,
        actor=CODEX_ACTOR,
        body="Codex review passed",
        state="COMMENTED",
        commit_id=HEAD,
        submitted_at=CODEX_RESULT_AT,
    )


def codex_gate_time(session, view):
    event = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.CODEX_REVIEW_COMPLETED.value
        and event["payload"].get("run_id") == view.automated_review_run_id
        and event["payload"].get("result") == AutomatedReviewStatus.PASS.value
    )
    timestamp = datetime.fromisoformat(event["payload"]["provider_completed_at"])
    return (
        timestamp.replace(tzinfo=timezone.utc)
        if timestamp.tzinfo is None
        else timestamp.astimezone(timezone.utc)
    )


def test_terminal_codex_reconciliation_uses_full_provider_readback(
    session,
    monkeypatch,
):
    view = published(session)
    running = start_codex(session, view)
    complete_codex_pass(session, running)

    class Observation:
        state = "PASS"

    class BrokerSpy:
        calls = 0

        def reconcile(self, *_args, **_kwargs):
            self.calls += 1
            return Observation()

        def audit_terminal_deletion_evidence(self, *_args, **_kwargs):
            raise AssertionError("merge gate must reread provider evidence")

    broker_spy = BrokerSpy()
    gateway = object.__new__(GitHubWebhookGateway)
    monkeypatch.setattr(gateway, "_codex_broker", lambda: broker_spy)

    outcome = gateway._reconcile_codex(
        session,
        view.publication_id,
        token="unused-test-token",
        include_provider_evidence=True,
    )

    assert outcome == "CODEX_PASS"
    assert broker_spy.calls == 1


def test_authorize_merge_requests_full_codex_provider_readback(
    session,
    monkeypatch,
):
    class StopAfterProbe(Exception):
        pass

    captured = {}
    gateway = object.__new__(GitHubWebhookGateway)

    def reconcile_publication(_session, _publication_id, **kwargs):
        captured.update(kwargs)
        raise StopAfterProbe

    monkeypatch.setattr(gateway, "reconcile_publication", reconcile_publication)

    with pytest.raises(StopAfterProbe):
        gateway.authorize_merge(session, "publication-for-test")

    assert captured["require_authoritative_codex_evidence"] is True


def raw_delivery(
    *,
    event_name: str,
    action: str = "created",
    comment_id: int | None = None,
    comment_body: str | None = None,
    comment_created_at: str | None = None,
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
        comment = {
            "id": comment_id,
            "user": {"login": CODEX_ACTOR},
        }
        if comment_body is not None:
            comment["body"] = comment_body
        if comment_created_at is not None:
            comment["created_at"] = comment_created_at
        payload["comment"] = comment
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


def raw_review_comment_delivery(
    *,
    comment_id,
    review_id,
    body_text,
    created_at,
    actor=CODEX_ACTOR,
    commit_id=HEAD,
):
    payload = {
        "action": "deleted",
        "repository": {"full_name": REPOSITORY},
        "pull_request": {
            "number": 44,
            "head": {"sha": HEAD},
            "base": {"ref": "master"},
        },
        "comment": {
            "id": comment_id,
            "pull_request_review_id": review_id,
            "user": {"login": actor},
            "body": body_text,
            "commit_id": commit_id,
            "path": "control_plane/domain.py",
            "line": 40,
            "created_at": created_at,
        },
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return body, signature


def raw_push_delivery(after):
    payload = {
        "ref": "refs/heads/master",
        "after": after,
        "repository": {"full_name": REPOSITORY},
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return body, signature


def process_human_review_delivery(
    session,
    value,
    *,
    delivery_id,
    review_id,
    action="submitted",
    review_actor=HUMAN_ACTOR,
):
    body, signature = raw_delivery(
        event_name="pull_request_review",
        action=action,
        review_id=review_id,
        review_actor=review_actor,
    )
    receipt = value.ingest(
        session,
        delivery_id=delivery_id,
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )
    return value.process_delivery(session, receipt.delivery_id)


def process_closed_unmerged_pr_delivery(session, value, *, delivery_id):
    body, signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    receipt = value.ingest(
        session,
        delivery_id=delivery_id,
        event_name="pull_request",
        signature=signature,
        body=body,
    )
    return value.process_delivery(session, receipt.delivery_id)


def process_base_push_delivery(
    session,
    value,
    *,
    delivery_id,
    after,
):
    body, signature = raw_push_delivery(after)
    receipt = value.ingest(
        session,
        delivery_id=delivery_id,
        event_name="push",
        signature=signature,
        body=body,
    )
    return value.process_delivery(session, receipt.delivery_id)


def raw_wakeup_delivery(
    event_name,
    *,
    repository=REPOSITORY,
    head_sha=HEAD,
    pull_numbers=(44,),
):
    payload = {"repository": {"full_name": repository}}
    if event_name == "check_run":
        payload.update(
            {
                "action": "completed",
                "check_run": {
                    "head_sha": head_sha,
                    "pull_requests": [
                        {"number": number}
                        for number in pull_numbers
                    ],
                },
            }
        )
    else:
        payload.update({"state": "success", "sha": head_sha})
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
        self.closed = False
        self.issue_comments = []
        self.reviews = []
        self.pull_review_list_calls = 0
        self.review_comments = []
        self.reactions = []
        self.ref_shas = {"master": BASE}

    def pull_request(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == 44
        assert token == "installation-token"
        return PullRequestSnapshot(
            number=44,
            state="closed" if self.merged or self.closed else "open",
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
        self.pull_review_list_calls += 1
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

    def commit(self, repository, sha, token):
        assert repository == REPOSITORY
        assert token == "installation-token"
        assert self.merged and sha == "9" * 40
        return GitHubCommitSnapshot(
            sha=sha,
            tree_sha=TREE,
            parents=(BASE, HEAD),
        )


def gateway(
    github=None,
    *,
    mode="required",
    human_actors=(HUMAN_ACTOR,),
):
    return GitHubWebhookGateway(
        token_provider=FakeTokenProvider(),
        github=github or FakeGitHub(),
        codex_review_mode=mode,
        codex_actors=(CODEX_ACTOR,),
        human_review_actors=human_actors,
        webhook_secret=SECRET,
        maximum_payload_bytes=1024 * 1024,
    )


def governed_codex_trigger(view):
    return IssueCommentSnapshot(
        comment_id=view.automated_review_trigger_comment_id,
        actor=view.automated_review_trigger_actor,
        body=(
            "@codex review\n\n"
            f"<!-- firstcontact-control-plane:codex-review "
            f"run={view.automated_review_run_id} "
            f"head={view.automated_review_head_sha} -->"
        ),
        created_at=view.automated_review_triggered_at,
    )


def usage_limit_response(comment_id, created_at, body=USAGE_LIMIT):
    return IssueCommentSnapshot(
        comment_id=comment_id,
        actor=CODEX_ACTOR,
        body=body,
        created_at=created_at,
    )


def assert_stale_review_blocked(session, view, result, expected_outcome):
    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert result.outcome == expected_outcome
    assert result.next_role == "CONTROL_PLANE"
    assert result.next_action == "BLOCKED"
    assert result.watch_state == "STALE"
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert current.mergeable is None
    assert watch.watched_head_sha == HEAD
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"

    event_types = {
        event["event_type"]
        for event in load_events(session, view.publication_id)
    }
    assert EventType.REVIEW_RECORDED.value not in event_types
    assert EventType.MERGEABILITY_RECORDED.value not in event_types
    assert EventType.MERGED.value not in event_types
    assert EventType.CODEX_REVIEW_COMPLETED.value not in event_types


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


def test_usage_limit_with_concurrent_reserved_invocation_fails_closed(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [
        governed_codex_trigger(view),
        usage_limit_response(701, "2026-09-30T12:01:00Z"),
        IssueCommentSnapshot(
            comment_id=702,
            actor=HUMAN_ACTOR,
            body="@codex review",
            created_at="2026-09-30T12:02:00Z",
        ),
    ]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=701,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-usage-limit-ambiguous",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )

    with pytest.raises(CodexReviewError, match="additional Codex invocation"):
        value.process_delivery(session, receipt.delivery_id)

    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.RUNNING
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"


@pytest.mark.parametrize(
    ("mode", "expected_role", "expected_action"),
    [
        ("disabled", "HUMAN_REVIEWER", "WAIT_HUMAN_REVIEW"),
        ("advisory", "PROVIDER", "WAIT_PROVIDER"),
        ("required", "PROVIDER", "WAIT_PROVIDER"),
    ],
)
def test_review_watch_next_role_respects_codex_mode_without_a_run(
    session,
    mode,
    expected_role,
    expected_action,
):
    view = published(session)

    result = gateway(FakeGitHub(), mode=mode).reconcile_publication(
        session,
        view.publication_id,
    )

    assert result.next_role == expected_role
    assert result.next_action == expected_action
    watch = get_review_watch(session, view.publication_id)
    assert watch.next_role == expected_role
    assert watch.next_action == expected_action


@pytest.mark.parametrize(
    ("mode", "expected_state", "expected_role", "expected_action"),
    [
        (
            "advisory",
            PublicationState.IN_REVIEW,
            "HUMAN_REVIEWER",
            "WAIT_HUMAN_REVIEW",
        ),
        (
            "required",
            PublicationState.CHANGES_REQUIRED,
            "IMPLEMENTER",
            "REMEDIATE_FINDINGS",
        ),
    ],
)
def test_codex_findings_watch_projection_respects_review_mode(
    session,
    mode,
    expected_state,
    expected_role,
    expected_action,
):
    view = start_codex(session, published(session), mode=mode)
    complete_codex_review(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.CHANGES_REQUIRED,
        findings=[
            {
                "provider_comment_id": 601,
                "provider_review_id": 501,
                "path": "control_plane/domain.py",
                "line": 10,
                "body": "Finding requires review.",
            }
        ],
        provider_review_ids=[501],
        provider_comment_ids=[601],
    )
    value = gateway(FakeGitHub(), mode=mode)

    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert current.state is expected_state
    assert current.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
    assert result.next_role == expected_role
    assert result.next_action == expected_action
    assert watch.next_role == expected_role
    assert watch.next_action == expected_action


@pytest.mark.parametrize(
    ("deleted_body", "delivery_suffix"),
    [
        ("an unrelated deleted comment", "unrelated"),
        (USAGE_LIMIT, "usage-limit"),
    ],
)
def test_deleted_issue_comment_uses_current_evidence_not_deleted_receipt(
    session,
    deleted_body,
    delivery_suffix,
):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="issue_comment",
        action="deleted",
        comment_id=701,
        comment_body=deleted_body,
    )
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-deleted-comment-{delivery_suffix}",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    assert result.outcome == "CODEX_RUNNING"
    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.RUNNING
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"


def test_deleted_post_trigger_invocation_blocks_codex_terminalization(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [
        governed_codex_trigger(view),
        usage_limit_response(702, "2026-09-30T12:03:00Z"),
    ]
    value = gateway(github)
    deleted_body, deleted_signature = raw_delivery(
        event_name="issue_comment",
        action="deleted",
        comment_id=701,
        comment_body="@codex review from an unmanaged actor",
        comment_created_at="2026-09-30T12:02:00Z",
    )
    deleted_receipt = value.ingest(
        session,
        delivery_id="delivery-deleted-concurrent-codex-invocation",
        event_name="issue_comment",
        signature=deleted_signature,
        body=deleted_body,
    )
    usage_body, usage_signature = raw_delivery(
        event_name="issue_comment",
        comment_id=702,
        comment_body=USAGE_LIMIT,
        comment_created_at="2026-09-30T12:03:00Z",
    )
    usage_receipt = value.ingest(
        session,
        delivery_id="delivery-usage-limit-after-deleted-invocation",
        event_name="issue_comment",
        signature=usage_signature,
        body=usage_body,
    )

    with pytest.raises(CodexReviewError, match="additional Codex invocation"):
        value.process_delivery(session, usage_receipt.delivery_id)
    with pytest.raises(CodexReviewError, match="additional Codex invocation"):
        value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    event_types = {
        event["event_type"]
        for event in load_events(session, view.publication_id)
    }
    assert current.automated_review_status is AutomatedReviewStatus.RUNNING
    assert EventType.CODEX_REVIEW_COMPLETED.value not in event_types
    assert EventType.CODEX_REVIEW_UNAVAILABLE.value not in event_types
    assert get_webhook_delivery(session, deleted_receipt.delivery_id).state == "PENDING"
    assert get_webhook_delivery(session, usage_receipt.delivery_id).state == "PENDING"


def test_deleted_codex_finding_comment_blocks_active_run_from_passing(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    github.reviews = [
        codex_provider_review(),
        PullReviewSnapshot(
            review_id=520,
            actor=CODEX_ACTOR,
            body="Codex findings",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:01:00Z",
        )
    ]
    value = gateway(github)
    body, signature = raw_review_comment_delivery(
        comment_id=620,
        review_id=520,
        body_text="A finding that was deleted before reconciliation.",
        created_at="2026-09-30T12:02:00Z",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-deleted-codex-finding-active",
        event_name="pull_request_review_comment",
        signature=signature,
        body=body,
    )

    with pytest.raises(CodexReviewError, match="deleted Codex finding"):
        value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    event_types = {
        event["event_type"]
        for event in load_events(session, view.publication_id)
    }
    assert current.automated_review_status is AutomatedReviewStatus.RUNNING
    assert EventType.CODEX_REVIEW_COMPLETED.value not in event_types
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"


def test_delayed_signed_invocation_deletion_invalidates_completed_codex_run(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="issue_comment",
        action="deleted",
        comment_id=710,
        comment_body="@codex review from an unmanaged invocation",
        comment_created_at="2026-09-30T12:02:00Z",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-late-deleted-invocation-after-pass",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    invalidation = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.CODEX_REVIEW_INVALIDATED.value
    )
    assert result.outcome == "CODEX_INVALIDATED"
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert invalidation["payload"]["run_id"] == view.automated_review_run_id
    assert invalidation["payload"]["head_sha"] == HEAD
    assert invalidation["payload"]["evidence_ids"] == [710]
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"


def test_delayed_signed_finding_deletion_invalidates_terminal_codex_result(session):
    view = start_codex(session, published(session))
    complete_codex_review(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.CHANGES_REQUIRED,
        findings=[
            {
                "provider_comment_id": 641,
                "provider_review_id": 541,
                "path": "control_plane/domain.py",
                "line": 40,
                "body": "Finding removed after terminal evidence was recorded.",
            }
        ],
        provider_review_ids=[541],
        provider_comment_ids=[641],
        provider_completed_at=CODEX_RESULT_AT,
    )
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    value = gateway(github)
    body, signature = raw_review_comment_delivery(
        comment_id=641,
        review_id=541,
        body_text="Finding removed after terminal evidence was recorded.",
        created_at="2026-09-30T12:02:00Z",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-late-deleted-terminal-codex-finding",
        event_name="pull_request_review_comment",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    invalidation = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.CODEX_REVIEW_INVALIDATED.value
    )
    assert result.outcome == "CODEX_INVALIDATED"
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert invalidation["payload"]["evidence_ids"] == [641]
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"


def test_explicit_reconciliation_invalidates_deleted_finding_by_recorded_review_id(
    session,
):
    view = start_codex(session, published(session))
    complete_codex_review(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[542],
        provider_comment_ids=[],
        provider_reaction_ids=[],
        provider_completed_at=CODEX_RESULT_AT,
    )
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    value = gateway(github)
    body, signature = raw_review_comment_delivery(
        comment_id=642,
        review_id=542,
        body_text="A finding deleted before terminal provider readback.",
        created_at="2026-09-30T12:02:00Z",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-deleted-finding-omitted-from-terminal-result",
        event_name="pull_request_review_comment",
        signature=signature,
        body=body,
    )

    value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    invalidation = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.CODEX_REVIEW_INVALIDATED.value
    )
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert invalidation["payload"]["evidence_ids"] == [642]
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"


def test_native_findings_only_complete_with_provider_timestamp(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    github.reviews = [
        PullReviewSnapshot(
            review_id=530,
            actor=CODEX_ACTOR,
            body="Codex findings",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:01:00Z",
        )
    ]
    github.review_comments = [
        PullReviewCommentSnapshot(
            comment_id=630,
            review_id=530,
            actor=CODEX_ACTOR,
            body="A native Codex finding.",
            commit_id=HEAD,
            path="control_plane/domain.py",
            line=40,
            created_at="2026-09-30T12:02:00Z",
        )
    ]

    result = gateway(github).reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    completion = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.CODEX_REVIEW_COMPLETED.value
    )
    assert current.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
    assert current.automated_review_findings_count == 1
    assert completion["payload"]["provider_completed_at"] == "2026-09-30T12:02:00+00:00"
    assert result.next_action == "REMEDIATE_FINDINGS"


def test_ambiguous_usage_limit_and_native_findings_block_codex_gate(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [
        governed_codex_trigger(view),
        usage_limit_response(731, "2026-09-30T12:03:00Z"),
    ]
    github.reviews = [
        PullReviewSnapshot(
            review_id=531,
            actor=CODEX_ACTOR,
            body="Codex findings",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:01:00Z",
        )
    ]
    github.review_comments = [
        PullReviewCommentSnapshot(
            comment_id=631,
            review_id=531,
            actor=CODEX_ACTOR,
            body="A finding coincides with the usage-limit response.",
            commit_id=HEAD,
            path="control_plane/domain.py",
            line=40,
            created_at="2026-09-30T12:03:00Z",
        )
    ]

    result = gateway(github).reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    event_types = [
        event["event_type"]
        for event in load_events(session, view.publication_id)
    ]
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert result.next_role == "IMPLEMENTER"
    assert result.next_action == "REMEDIATE_FINDINGS"
    assert EventType.CODEX_REVIEW_INVALIDATED.value in event_types
    assert EventType.CODEX_REVIEW_UNAVAILABLE.value not in event_types
    assert EventType.CODEX_REVIEW_COMPLETED.value not in event_types


def test_later_native_findings_supersede_timestamped_usage_limit(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [
        governed_codex_trigger(view),
        usage_limit_response(732, "2026-09-30T12:02:00Z"),
    ]
    value = gateway(github)
    first = value.reconcile_publication(session, view.publication_id)
    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert first.next_action == "PRINCIPAL_FALLBACK"

    github.reviews = [
        PullReviewSnapshot(
            review_id=532,
            actor=CODEX_ACTOR,
            body="Codex findings arrived after usage-limit artifact",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:05:00Z",
        )
    ]
    github.review_comments = [
        PullReviewCommentSnapshot(
            comment_id=632,
            review_id=532,
            actor=CODEX_ACTOR,
            body="A native finding that must not be hidden by UNAVAILABLE.",
            commit_id=HEAD,
            path="control_plane/domain.py",
            line=40,
            created_at="2026-09-30T12:06:00Z",
        )
    ]
    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=532,
        review_actor=CODEX_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-native-findings-after-usage-limit",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    completion = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.CODEX_REVIEW_COMPLETED.value
    ]
    assert current.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert len(completion) == 1
    assert completion[0]["payload"]["supersedes_unavailability"] is True
    assert result.outcome == "CODEX_CHANGES_REQUIRED"


def test_pre_trigger_deleted_codex_invocation_does_not_block_reconciliation(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="issue_comment",
        action="deleted",
        comment_id=703,
        comment_body="@codex review before the governed trigger",
        comment_created_at="2026-09-30T11:59:00Z",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-deleted-pre-trigger-invocation",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )

    result = value.reconcile_publication(session, view.publication_id)

    assert result.outcome == "RECONCILED"
    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.RUNNING
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"


def test_out_of_policy_merged_pull_settles_delivery_and_blocks_watch(session):
    view = published(session)
    github = FakeGitHub()
    github.merged = True
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-out-of-policy-merge",
        event_name="pull_request",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    policy_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.MERGE_POLICY_VIOLATION.value
    ]
    assert current.merge_policy_violation is True
    assert len(policy_events) == 1
    assert result.outcome == "MERGE_POLICY_VIOLATION"
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_merged_pull_with_head_drift_stales_before_merge_reconciliation(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )

    class TrackingMergedGitHub(FakeGitHub):
        def __init__(self):
            super().__init__()
            self.merge_reconciliation_attempts = 0

        def pull_request_merged(self, repository, number, token):
            self.merge_reconciliation_attempts += 1
            return super().pull_request_merged(repository, number, token)

        def pull_request_merge_event(self, repository, number, token):
            self.merge_reconciliation_attempts += 1
            return super().pull_request_merge_event(repository, number, token)

    github = TrackingMergedGitHub()
    github.merged = True
    github.head_sha = "4" * 40
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-merged-stale-head",
        event_name="pull_request",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    watch = get_review_watch(session, view.publication_id)
    event_types = {
        event["event_type"]
        for event in load_events(session, view.publication_id)
    }
    assert result.outcome == "STALE_HEAD"
    assert result.next_role == "CONTROL_PLANE"
    assert result.next_action == "BLOCKED"
    assert result.watch_state == "STALE"
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"
    assert github.merge_reconciliation_attempts == 0
    assert EventType.MERGED.value not in event_types
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"


def test_full_reconcile_stale_merged_head_precedes_codex_terminalization(session):
    view = start_codex(session, published(session))

    class TrackingMergedGitHub(FakeGitHub):
        def __init__(self):
            super().__init__()
            self.merge_reconciliation_attempts = 0

        def pull_request_merged(self, repository, number, token):
            self.merge_reconciliation_attempts += 1
            return super().pull_request_merged(repository, number, token)

        def pull_request_merge_event(self, repository, number, token):
            self.merge_reconciliation_attempts += 1
            return super().pull_request_merge_event(repository, number, token)

    github = TrackingMergedGitHub()
    github.merged = True
    github.head_sha = "4" * 40
    github.issue_comments = [
        governed_codex_trigger(view),
        usage_limit_response(704, "2026-09-30T12:03:00Z"),
    ]
    result = gateway(github).reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    event_types = {
        event["event_type"]
        for event in load_events(session, view.publication_id)
    }
    assert result.outcome == "STALE_HEAD"
    assert result.next_role == "CONTROL_PLANE"
    assert result.next_action == "BLOCKED"
    assert result.watch_state == "STALE"
    assert watch.state == "STALE"
    assert current.automated_review_status is AutomatedReviewStatus.RUNNING
    assert EventType.CODEX_REVIEW_UNAVAILABLE.value not in event_types
    assert EventType.MERGED.value not in event_types
    assert github.merge_reconciliation_attempts == 0


def test_full_reconcile_exact_merged_head_preserves_merge_policy_path(session):
    view = start_codex(session, published(session))

    class TrackingMergedGitHub(FakeGitHub):
        def __init__(self):
            super().__init__()
            self.merge_reconciliation_attempts = 0

        def pull_request_merged(self, repository, number, token):
            self.merge_reconciliation_attempts += 1
            return super().pull_request_merged(repository, number, token)

        def pull_request_merge_event(self, repository, number, token):
            self.merge_reconciliation_attempts += 1
            return super().pull_request_merge_event(repository, number, token)

    github = TrackingMergedGitHub()
    github.merged = True
    github.issue_comments = [governed_codex_trigger(view)]
    result = gateway(github).reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    event_types = [
        event["event_type"]
        for event in load_events(session, view.publication_id)
    ]
    assert result.outcome == "MERGE_POLICY_VIOLATION"
    assert current.merge_policy_violation is True
    assert current.automated_review_status is AutomatedReviewStatus.RUNNING
    assert event_types.count(EventType.MERGE_POLICY_VIOLATION.value) == 1
    assert EventType.CODEX_REVIEW_UNAVAILABLE.value not in event_types
    assert github.merge_reconciliation_attempts > 0


@pytest.mark.parametrize("delivery_path", [False, True])
@pytest.mark.parametrize("latest_review_state", ["DISMISSED", "CHANGES_REQUESTED"])
def test_external_merge_refreshes_human_review_before_classification(
    session,
    delivery_path,
    latest_review_state,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    github.reviews = [
        PullReviewSnapshot(
            review_id=990,
            actor=HUMAN_ACTOR,
            body="exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)
    process_human_review_delivery(
        session,
        value,
        delivery_id=f"delivery-external-merge-approval-{delivery_path}-{latest_review_state}",
        review_id=990,
    )
    record_mergeability(
        session,
        view.publication_id,
        head_sha=HEAD,
        mergeable=True,
    )
    github.reviews = [
        PullReviewSnapshot(
            review_id=990,
            actor=HUMAN_ACTOR,
            body="approval changed before external merge",
            state=latest_review_state,
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    github.merged = True

    if delivery_path:
        body, signature = raw_delivery(
            event_name="pull_request",
            action="closed",
        )
        receipt = value.ingest(
            session,
            delivery_id=f"delivery-external-merge-{latest_review_state}",
            event_name="pull_request",
            signature=signature,
            body=body,
        )
        result = value.process_delivery(session, receipt.delivery_id)
    else:
        result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    event_types = {
        event["event_type"]
        for event in load_events(session, view.publication_id)
    }
    assert result.outcome == "MERGE_POLICY_VIOLATION"
    assert current.merge_policy_violation is True
    assert current.state is not PublicationState.MERGED
    assert EventType.MERGED.value not in event_types


@pytest.mark.parametrize("delivery_path", [False, True])
def test_external_merge_checks_validated_base_before_classification(
    session,
    delivery_path,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    github.reviews = [
        PullReviewSnapshot(
            review_id=991,
            actor=HUMAN_ACTOR,
            body="exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)
    process_human_review_delivery(
        session,
        value,
        delivery_id=f"delivery-external-base-approval-{delivery_path}",
        review_id=991,
    )
    record_mergeability(
        session,
        view.publication_id,
        head_sha=HEAD,
        mergeable=True,
    )
    github.ref_shas["master"] = "8" * 40
    github.merged = True

    if delivery_path:
        body, signature = raw_delivery(
            event_name="pull_request",
            action="closed",
        )
        receipt = value.ingest(
            session,
            delivery_id="delivery-external-base-merged",
            event_name="pull_request",
            signature=signature,
            body=body,
        )
        result = value.process_delivery(session, receipt.delivery_id)
    else:
        result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    event_types = {
        event["event_type"]
        for event in load_events(session, view.publication_id)
    }
    assert result.outcome == "MERGE_POLICY_VIOLATION"
    assert current.merge_policy_violation is True
    assert current.state is not PublicationState.MERGED
    assert EventType.MERGED.value not in event_types


def test_merged_approved_pull_cannot_record_mergeability(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    github.reviews = [codex_provider_review()]
    github.merged = True
    github.mergeable = True
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request",
        action="synchronize",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-merged-approved-synchronize",
        event_name="pull_request",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    mergeability_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.MERGEABILITY_RECORDED.value
    ]
    assert current.state is PublicationState.APPROVED
    assert current.mergeable is None
    assert current.merge_policy_violation is True
    assert mergeability_events == []
    assert result.outcome == "MERGE_POLICY_VIOLATION"
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"
    watch = get_review_watch(session, view.publication_id)
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_merge_readback_error_keeps_delivery_retryable(session):
    view = published(session)

    class MergeReadbackFailureGitHub(FakeGitHub):
        def pull_request_merge_event(self, repository, number, token):
            raise GitHubApiError("simulated merge readback failure")

    github = MergeReadbackFailureGitHub()
    github.merged = True
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-merge-readback-failure",
        event_name="pull_request",
        signature=signature,
        body=body,
    )

    with pytest.raises(GitHubWebhookError, match="closed PR reconciliation failed"):
        value.process_delivery(session, receipt.delivery_id)

    assert get_view(session, view.publication_id).merge_policy_violation is False
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"


def test_stale_human_review_cannot_advance_exact_head(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.reviews = [
        codex_provider_review(),
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


def test_closed_unmerged_pr_blocks_watch_and_later_human_approval(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.closed = True
    github.reviews = [
        codex_provider_review(),
        PullReviewSnapshot(
            review_id=806,
            actor=HUMAN_ACTOR,
            body="approval after close",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(codex_gate_time(session, view) + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)

    closed_body, closed_signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    closed_receipt = value.ingest(
        session,
        delivery_id="delivery-pr-closed-unmerged",
        event_name="pull_request",
        signature=closed_signature,
        body=closed_body,
    )
    closed_result = value.process_delivery(session, closed_receipt.delivery_id)

    assert closed_result.outcome == "PULL_CLOSED_UNMERGED"
    watch = get_review_watch(session, view.publication_id)
    assert watch.state == "CLOSED_UNMERGED"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"
    with pytest.raises(DomainError, match="closed unmerged"):
        value.assert_review_write_current(session, view.publication_id)

    review_body, review_signature = raw_delivery(
        event_name="pull_request_review",
        review_id=806,
        review_actor=HUMAN_ACTOR,
    )
    review_receipt = value.ingest(
        session,
        delivery_id="delivery-review-after-pr-close",
        event_name="pull_request_review",
        signature=review_signature,
        body=review_body,
    )
    review_result = value.process_delivery(session, review_receipt.delivery_id)

    assert review_result.outcome == "PULL_CLOSED_UNMERGED"
    assert get_view(session, view.publication_id).state is PublicationState.IN_REVIEW
    assert get_view(session, view.publication_id).review_decision is None
    assert get_review_watch(session, view.publication_id).state == "CLOSED_UNMERGED"
    assert not [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]


def test_closed_unmerged_pr_reopens_same_governed_watch(session):
    view = published(session)
    github = FakeGitHub()
    github.closed = True
    value = gateway(github)
    closed_body, closed_signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    closed = value.ingest(
        session,
        delivery_id="delivery-reopen-close",
        event_name="pull_request",
        signature=closed_signature,
        body=closed_body,
    )
    closed_result = value.process_delivery(session, closed.delivery_id)
    assert closed_result.outcome == "PULL_CLOSED_UNMERGED"
    assert get_review_watch(session, view.publication_id).state == "CLOSED_UNMERGED"

    github.closed = False
    reopened_body, reopened_signature = raw_delivery(
        event_name="pull_request",
        action="reopened",
    )
    reopened = value.ingest(
        session,
        delivery_id="delivery-reopen-open",
        event_name="pull_request",
        signature=reopened_signature,
        body=reopened_body,
    )

    result = value.process_delivery(session, reopened.delivery_id)

    watch = get_review_watch(session, view.publication_id)
    assert result.outcome == "PULL_OBSERVED"
    assert watch.state == "ACTIVE"
    assert watch.next_role == "PROVIDER"
    assert watch.next_action == "WAIT_PROVIDER"


@pytest.mark.parametrize(
    ("drift", "expected_outcome"),
    [("head", "STALE_HEAD"), ("base", "STALE_BASE")],
)
def test_reopened_pr_with_stale_head_or_base_remains_blocked(
    session,
    drift,
    expected_outcome,
):
    view = published(session)
    github = FakeGitHub()
    github.closed = True
    value = gateway(github)
    closed_body, closed_signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    closed = value.ingest(
        session,
        delivery_id=f"delivery-reopen-stale-close-{drift}",
        event_name="pull_request",
        signature=closed_signature,
        body=closed_body,
    )
    value.process_delivery(session, closed.delivery_id)

    github.closed = False
    if drift == "head":
        github.head_sha = "4" * 40
    else:
        github.ref_shas["master"] = "8" * 40
    reopened_body, reopened_signature = raw_delivery(
        event_name="pull_request",
        action="reopened",
    )
    reopened = value.ingest(
        session,
        delivery_id=f"delivery-reopen-stale-open-{drift}",
        event_name="pull_request",
        signature=reopened_signature,
        body=reopened_body,
    )

    result = value.process_delivery(session, reopened.delivery_id)

    watch = get_review_watch(session, view.publication_id)
    assert result.outcome == expected_outcome
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_reconciliation_recovers_missed_reopen_for_same_governed_watch(session):
    view = published(session)
    github = FakeGitHub()
    value = gateway(github)
    github.closed = True

    closed_result = process_closed_unmerged_pr_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-reopen-close",
    )
    assert closed_result.watch_state == "CLOSED_UNMERGED"
    assert get_review_watch(session, view.publication_id).state == "CLOSED_UNMERGED"

    github.closed = False
    result = value.reconcile_publication(session, view.publication_id)

    watch = get_review_watch(session, view.publication_id)
    assert result.outcome == "RECONCILED"
    assert result.watch_state == "ACTIVE"
    assert watch.state == "ACTIVE"
    assert watch.next_role == "PROVIDER"
    assert watch.next_action == "WAIT_PROVIDER"


@pytest.mark.parametrize(
    ("drift", "expected_outcome"),
    [("head", "STALE_HEAD"), ("base", "STALE_BASE")],
)
def test_reconciliation_does_not_reopen_closed_watch_with_head_or_base_drift(
    session,
    drift,
    expected_outcome,
):
    view = published(session)
    github = FakeGitHub()
    value = gateway(github)
    github.closed = True
    process_closed_unmerged_pr_delivery(
        session,
        value,
        delivery_id=f"delivery-reconcile-reopen-close-{drift}",
    )

    github.closed = False
    if drift == "head":
        github.head_sha = "4" * 40
    else:
        github.ref_shas["master"] = "8" * 40
    result = value.reconcile_publication(session, view.publication_id)

    watch = get_review_watch(session, view.publication_id)
    assert result.outcome == expected_outcome
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_reconciliation_does_not_reopen_closed_watch_with_merge_policy_violation(
    session,
):
    view = published(session)
    github = FakeGitHub()
    value = gateway(github)
    github.closed = True
    process_closed_unmerged_pr_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-reopen-violation-close",
    )
    record_merge_policy_violation(
        session,
        view.publication_id,
        head_sha=HEAD,
        pull_request_number=44,
        merge_commit_sha="9" * 40,
    )

    github.closed = False
    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert result.watch_state == "CLOSED_UNMERGED"
    assert current.merge_policy_violation is True
    assert watch.state == "CLOSED_UNMERGED"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_reopened_pr_does_not_clear_merge_policy_violation(session):
    view = published(session)
    github = FakeGitHub()
    github.closed = True
    value = gateway(github)
    closed_body, closed_signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    closed = value.ingest(
        session,
        delivery_id="delivery-reopen-violation-close",
        event_name="pull_request",
        signature=closed_signature,
        body=closed_body,
    )
    value.process_delivery(session, closed.delivery_id)
    record_merge_policy_violation(
        session,
        view.publication_id,
        head_sha=HEAD,
        pull_request_number=44,
        merge_commit_sha="9" * 40,
    )

    github.closed = False
    reopened_body, reopened_signature = raw_delivery(
        event_name="pull_request",
        action="reopened",
    )
    reopened = value.ingest(
        session,
        delivery_id="delivery-reopen-violation-open",
        event_name="pull_request",
        signature=reopened_signature,
        body=reopened_body,
    )

    value.process_delivery(session, reopened.delivery_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert current.merge_policy_violation is True
    assert watch.state == "CLOSED_UNMERGED"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_verified_merge_completes_watch_after_unmerged_close(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    record_mergeability(
        session,
        view.publication_id,
        head_sha=HEAD,
        mergeable=True,
    )
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    github.reviews = [
        codex_provider_review(),
        PullReviewSnapshot(
            review_id=804,
            actor=HUMAN_ACTOR,
            body="current exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    github.closed = True
    value = gateway(github)
    sync_review_watch(session, view.publication_id)

    unmerged_body, unmerged_signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    unmerged_receipt = value.ingest(
        session,
        delivery_id="delivery-pr-close-before-merge",
        event_name="pull_request",
        signature=unmerged_signature,
        body=unmerged_body,
    )
    value.process_delivery(session, unmerged_receipt.delivery_id)
    assert get_review_watch(session, view.publication_id).state == "CLOSED_UNMERGED"

    github.merged = True
    merged_body, merged_signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    merged_receipt = value.ingest(
        session,
        delivery_id="delivery-pr-merged-after-close",
        event_name="pull_request",
        signature=merged_signature,
        body=merged_body,
    )
    result = value.process_delivery(session, merged_receipt.delivery_id)

    assert result.outcome == "PULL_CLOSED_RECONCILED"
    assert get_view(session, view.publication_id).state is PublicationState.MERGED
    watch = get_review_watch(session, view.publication_id)
    assert watch.state == "DONE"
    assert watch.next_role == "NONE"
    assert watch.next_action == "DONE"


def test_full_reconciliation_does_not_reopen_a_merged_closed_watch(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.issue_comments = [governed_codex_trigger(view)]
    github.reviews = [
        codex_provider_review(),
        PullReviewSnapshot(
            review_id=995,
            actor=HUMAN_ACTOR,
            body="exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-merged-watch-approval",
        review_id=995,
    )
    record_mergeability(
        session,
        view.publication_id,
        head_sha=HEAD,
        mergeable=True,
    )
    github.closed = True
    process_closed_unmerged_pr_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-merged-watch-close",
    )

    github.merged = True
    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.MERGED
    assert watch.state == "DONE"
    assert watch.next_action == "DONE"


def test_closed_unmerged_pr_cannot_become_merge_ready_from_old_approval(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    github = FakeGitHub()
    github.closed = True
    github.mergeable = True
    value = gateway(github)
    sync_review_watch(session, view.publication_id)
    body, signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-approved-pr-closed-unmerged",
        event_name="pull_request",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    assert result.outcome == "PULL_CLOSED_UNMERGED"
    assert current.state is PublicationState.APPROVED
    assert current.mergeable is None
    watch = get_review_watch(session, view.publication_id)
    assert watch.state == "CLOSED_UNMERGED"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


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
            submitted_at=(codex_gate_time(session, view) + timedelta(seconds=1)).isoformat(),
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


def test_pending_pre_gate_human_approval_stays_stale_after_codex_completes(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=803,
            actor=HUMAN_ACTOR,
            body="approved before provider finished",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:03:00Z",
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
    assert resumed[0].outcome == "STALE_HUMAN_REVIEW"
    current = get_view(session, view.publication_id)
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"

    watch = get_review_watch(session, view.publication_id)
    assert watch.next_action == "WAIT_HUMAN_REVIEW"


@pytest.mark.parametrize(
    ("mode", "review_state", "expected_state"),
    [
        ("disabled", "APPROVED", PublicationState.APPROVED),
        ("advisory", "APPROVED", PublicationState.APPROVED),
        ("required", "CHANGES_REQUESTED", PublicationState.CHANGES_REQUIRED),
    ],
)
def test_webhook_human_review_gate_applies_only_to_required_approvals(
    session,
    mode,
    review_state,
    expected_state,
):
    view = published(session)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=804,
            actor=HUMAN_ACTOR,
            body="human decision",
            state=review_state,
            commit_id=HEAD,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
    ]
    value = gateway(github, mode=mode)
    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=804,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-human-mode-{mode}-{review_state}",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    assert current.state is expected_state
    assert current.review_decision is not None
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"
    assert result.outcome.startswith("HUMAN_")


@pytest.mark.parametrize(
    ("offset_seconds", "expected_state"),
    [
        (-1, PublicationState.IN_REVIEW),
        (0, PublicationState.IN_REVIEW),
        (1, PublicationState.APPROVED),
    ],
)
def test_required_approval_must_follow_exact_head_codex_adjudication(
    session,
    offset_seconds,
    expected_state,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=805,
            actor=HUMAN_ACTOR,
            body="approval timestamp boundary",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(
                gate_time + timedelta(seconds=offset_seconds)
            ).isoformat(),
        )
    ]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=805,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-human-gate-{offset_seconds}",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    assert get_view(session, view.publication_id).state is expected_state
    if expected_state is PublicationState.IN_REVIEW:
        assert result.outcome == "STALE_HUMAN_REVIEW"
        assert get_view(session, view.publication_id).review_decision is None
    else:
        assert result.outcome.startswith("HUMAN_APPROVED")


def test_delayed_codex_reconciliation_uses_provider_evidence_time(session):
    view = start_codex(session, published(session))
    now = datetime.now(timezone.utc)
    provider_time = now - timedelta(minutes=3)
    approval_time = now - timedelta(minutes=2)
    completed = complete_codex_review(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[501],
        provider_comment_ids=[],
        provider_completed_at=provider_time.isoformat(),
    )
    completion_event = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.CODEX_REVIEW_COMPLETED.value
    )
    reconciliation_time = datetime.fromisoformat(completion_event["occurred_at"])
    if reconciliation_time.tzinfo is None:
        reconciliation_time = reconciliation_time.replace(tzinfo=timezone.utc)
    assert reconciliation_time > approval_time

    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=808,
            actor=HUMAN_ACTOR,
            body="approved after provider completion",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=approval_time.isoformat(),
        )
    ]
    value = gateway(github)
    result = process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-human-after-provider-before-reconcile",
        review_id=808,
    )

    assert completed.automated_review_status is AutomatedReviewStatus.PASS
    assert get_view(session, view.publication_id).state is PublicationState.APPROVED
    assert result.outcome.startswith("HUMAN_APPROVED")


def test_missing_codex_provider_timestamp_blocks_human_approval(session):
    view = start_codex(session, published(session))
    complete_codex_review(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[501],
        provider_comment_ids=[],
    )
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=809,
            actor=HUMAN_ACTOR,
            body="approval with missing provider time",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:05:00Z",
        )
    ]
    value = gateway(github)

    with pytest.raises(GitHubWebhookError, match="provider completion timestamp is missing"):
        process_human_review_delivery(
            session,
            value,
            delivery_id="delivery-human-missing-provider-time",
            review_id=809,
        )

    assert get_view(session, view.publication_id).state is PublicationState.IN_REVIEW
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert review_events == []


@pytest.mark.parametrize(
    ("offset_seconds", "expected_state"),
    [
        (-1, PublicationState.IN_REVIEW),
        (0, PublicationState.IN_REVIEW),
        (1, PublicationState.APPROVED),
    ],
)
def test_required_approval_timestamp_uses_exact_plane_fallback_gate(
    session,
    offset_seconds,
    expected_state,
):
    view = start_codex(session, published(session))
    unavailable = mark_codex_review_unavailable(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        reason="provider unavailable for timestamp test",
    )
    plane_run_id = "principal-review:test-fallback-timestamp"
    record_plane_review(
        session,
        view.publication_id,
        run_id=plane_run_id,
        reviewer_kind="FALLBACK_REVIEWER",
        reviewer="principal-reviewer:test",
        reviewed_head_sha=HEAD,
        body="Exact-head fallback review.",
        comments=[],
        idempotency_key="fallback-timestamp-record",
    )
    complete_plane_review_materialization(
        session,
        view.publication_id,
        run_id=plane_run_id,
        provider_review_id=9010,
        receipts=[],
    )
    fallback_event = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.PLANE_REVIEW_MATERIALIZED.value
        and event["payload"].get("run_id") == plane_run_id
    )
    gate_time = datetime.fromisoformat(fallback_event["occurred_at"])
    if gate_time.tzinfo is None:
        gate_time = gate_time.replace(tzinfo=timezone.utc)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=807,
            actor=HUMAN_ACTOR,
            body="approval timestamp boundary",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(
                gate_time + timedelta(seconds=offset_seconds)
            ).isoformat(),
        )
    ]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=807,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-fallback-gate-{offset_seconds}",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    assert unavailable.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert get_view(session, view.publication_id).state is expected_state
    if expected_state is PublicationState.IN_REVIEW:
        assert result.outcome == "STALE_HUMAN_REVIEW"
    else:
        assert result.outcome.startswith("HUMAN_APPROVED")


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


def test_review_watch_clears_actors_removed_from_configuration(session):
    view = published(session)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )

    updated = sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(),
    )

    row = session.get(ReviewWatchRow, view.publication_id)
    assert row is not None
    assert updated.expected_actors == ()
    assert row.expected_actors == []


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


def test_same_generation_stale_watch_remains_blocked_after_base_returns(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.ref_shas["master"] = "8" * 40
    value = gateway(github)

    with pytest.raises(DomainError, match="publication base is stale"):
        value.assert_review_write_current(session, view.publication_id)
    assert get_review_watch(session, view.publication_id).state == "STALE"

    github.ref_shas["master"] = BASE
    with pytest.raises(DomainError, match="publication base is stale"):
        value.assert_review_write_current(session, view.publication_id)

    watch = get_review_watch(session, view.publication_id)
    assert watch.watched_head_sha == HEAD
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_governed_remote_publication_starts_active_review_watch_generation(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    stale = sync_review_watch(session, view.publication_id, state="STALE")
    assert stale.watched_head_sha == HEAD
    assert stale.state == "STALE"

    published_next = publish_next_head(session, view)
    watch = sync_review_watch(session, published_next.publication_id)

    assert published_next.remote_head_sha == NEXT_HEAD
    assert watch.watched_head_sha == NEXT_HEAD
    assert watch.state == "ACTIVE"
    assert watch.next_role == "PROVIDER"
    assert watch.next_action == "WAIT_PROVIDER"


def test_new_codex_run_on_governed_head_keeps_watch_active_waiting_for_provider(
    session,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    sync_review_watch(session, view.publication_id, state="STALE")
    published_next = publish_next_head(session, view)
    running = start_codex(
        session,
        published_next,
        expected_head_sha=NEXT_HEAD,
    )

    watch = sync_review_watch(session, running.publication_id)

    assert watch.watched_head_sha == NEXT_HEAD
    assert watch.review_run_id == running.automated_review_run_id
    assert watch.state == "ACTIVE"
    assert watch.next_role == "PROVIDER"
    assert watch.next_action == "WAIT_PROVIDER"


def test_external_pull_head_drift_does_not_clear_stale_watch(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    sync_review_watch(session, view.publication_id)
    github = FakeGitHub()
    github.head_sha = "4" * 40
    value = gateway(github)

    drifted = value.reconcile_publication(session, view.publication_id)
    assert drifted.outcome == "STALE_HEAD"
    assert get_review_watch(session, view.publication_id).state == "STALE"

    github.head_sha = HEAD
    recovered_externally = value.reconcile_publication(session, view.publication_id)

    assert recovered_externally.outcome == "STALE_BASE"
    watch = get_review_watch(session, view.publication_id)
    assert watch.watched_head_sha == HEAD
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_h2_reconcile_is_not_blocked_by_h1_stale_watch(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    sync_review_watch(session, view.publication_id, state="STALE")
    published_next = publish_next_head(session, view)
    running = start_codex(
        session,
        published_next,
        expected_head_sha=NEXT_HEAD,
    )
    github = FakeGitHub()
    github.head_sha = NEXT_HEAD
    github.issue_comments = [governed_codex_trigger(running)]

    result = gateway(github).reconcile_publication(session, running.publication_id)

    watch = get_review_watch(session, running.publication_id)
    assert result.outcome == "RECONCILED"
    assert result.watch_state == "ACTIVE"
    assert result.next_role == "PROVIDER"
    assert result.next_action == "WAIT_PROVIDER"
    assert watch.watched_head_sha == NEXT_HEAD
    assert watch.review_run_id == running.automated_review_run_id
    assert watch.state == "ACTIVE"


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


def test_stale_watch_cannot_rearm_when_watched_head_changes(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    stale = sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
        state="STALE",
    )
    assert stale.state == "STALE"

    row = session.get(ReviewWatchRow, view.publication_id)
    assert row is not None
    row.watched_head_sha = "9" * 40
    session.commit()

    current = sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )

    assert current.state == "STALE"
    assert current.watched_head_sha == HEAD
    assert current.next_role == "CONTROL_PLANE"
    assert current.next_action == "BLOCKED"


def test_direct_human_review_stays_blocked_after_base_returns_without_push(
    session,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.ref_shas["master"] = "4" * 40
    value = gateway(github)

    with pytest.raises(DomainError, match="publication base is stale"):
        value.assert_review_write_current(session, view.publication_id)

    github.ref_shas["master"] = BASE
    row = session.get(ReviewWatchRow, view.publication_id)
    assert row is not None
    row.watched_head_sha = "9" * 40
    session.commit()

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


def test_direct_mergeability_endpoint_blocks_stale_base(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.mergeable = True
    value = gateway(github)
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

    github.ref_shas["master"] = "4" * 40
    with pytest.raises(HTTPException) as caught:
        mergeability_record(
            view.publication_id,
            MergeabilityRequest(head_sha=HEAD, mergeable=True),
            session,
            value,
        )

    assert caught.value.status_code == 409
    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    mergeability_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.MERGEABILITY_RECORDED.value
    ]
    assert current.state is PublicationState.APPROVED
    assert current.mergeable is None
    assert mergeability_events == []
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_direct_mergeability_endpoint_rejects_client_value_mismatch(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.mergeable = False
    value = gateway(github)
    review_record(
        view.publication_id,
        ReviewRequest(
            reviewed_head_sha=HEAD,
            decision=ReviewDecision.APPROVED,
        ),
        session,
        value,
    )

    with pytest.raises(HTTPException) as caught:
        mergeability_record(
            view.publication_id,
            MergeabilityRequest(head_sha=HEAD, mergeable=True),
            session,
            value,
        )

    assert caught.value.status_code == 409
    current = get_view(session, view.publication_id)
    mergeability_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.MERGEABILITY_RECORDED.value
    ]
    assert current.state is PublicationState.APPROVED
    assert current.mergeable is None
    assert mergeability_events == []



@pytest.mark.parametrize("github_mergeable", [False, True])
def test_direct_mergeability_endpoint_rejects_already_merged_pr(
    session,
    github_mergeable,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    value = gateway(github)
    review_record(
        view.publication_id,
        ReviewRequest(
            reviewed_head_sha=HEAD,
            decision=ReviewDecision.APPROVED,
        ),
        session,
        value,
    )
    github.merged = True
    github.mergeable = github_mergeable

    with pytest.raises(HTTPException) as caught:
        mergeability_record(
            view.publication_id,
            MergeabilityRequest(
                head_sha=HEAD,
                mergeable=github_mergeable,
            ),
            session,
            value,
        )

    current = get_view(session, view.publication_id)
    mergeability_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.MERGEABILITY_RECORDED.value
    ]
    assert caught.value.status_code == 409
    assert "already merged" in caught.value.detail
    assert current.state is PublicationState.APPROVED
    assert current.mergeable is None
    assert mergeability_events == []

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
            submitted_at=(codex_gate_time(session, view) + timedelta(seconds=1)).isoformat(),
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


def test_delivery_claim_blocks_reentrant_processing_and_releases_retry(session, monkeypatch):
    published(session)
    first_gateway = gateway(FakeGitHub())
    second_gateway = gateway(FakeGitHub())
    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=794,
    )
    receipt = first_gateway.ingest(
        session,
        delivery_id="delivery-reentrant-claim",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )
    second_entries = []

    def unexpected_second_entry(*_args, **_kwargs):
        second_entries.append(True)
        return "SECOND_ENTRY"

    monkeypatch.setattr(
        second_gateway,
        "_process_pull_delivery",
        unexpected_second_entry,
    )

    def fail_after_reentry(current_session, *_args, **_kwargs):
        with Session(bind=current_session.get_bind()) as competing_session:
            reentrant = second_gateway.process_delivery(
                competing_session,
                receipt.delivery_id,
            )
        assert reentrant.outcome == "PROCESSING"
        raise GitHubWebhookError("simulated processing failure")

    monkeypatch.setattr(first_gateway, "_process_pull_delivery", fail_after_reentry)

    with pytest.raises(GitHubWebhookError, match="simulated processing failure"):
        first_gateway.process_delivery(session, receipt.delivery_id)

    claim = session.get(GitHubWebhookDeliveryClaimRow, receipt.delivery_id)
    assert second_entries == []
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"
    assert claim is not None
    assert claim.owner_id is None
    assert claim.lease_expires_at is None


def test_expired_delivery_claim_is_recovered_by_new_owner(session, monkeypatch):
    published(session)
    first_gateway = gateway(FakeGitHub())
    recovery_gateway = gateway(FakeGitHub())
    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=795,
    )
    receipt = first_gateway.ingest(
        session,
        delivery_id="delivery-abandoned-claim",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )

    def crash_worker(*_args, **_kwargs):
        raise RuntimeError("simulated worker termination")

    monkeypatch.setattr(first_gateway, "_process_pull_delivery", crash_worker)
    with pytest.raises(RuntimeError, match="simulated worker termination"):
        first_gateway.process_delivery(session, receipt.delivery_id)

    claim = session.get(GitHubWebhookDeliveryClaimRow, receipt.delivery_id)
    assert claim is not None
    first_owner = claim.owner_id
    assert first_owner is not None
    assert claim.generation == 1
    claim.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    session.commit()

    monkeypatch.setattr(
        recovery_gateway,
        "_process_pull_delivery",
        lambda *_args, **_kwargs: "RECOVERED",
    )
    recovered = recovery_gateway.process_delivery(session, receipt.delivery_id)

    claim = session.get(GitHubWebhookDeliveryClaimRow, receipt.delivery_id)
    assert recovered.outcome == "RECOVERED"
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"
    assert claim is not None
    assert claim.owner_id != first_owner
    assert claim.generation == 2


def test_ownerless_worker_cannot_finalize_or_release_active_claim(session):
    value = gateway(FakeGitHub())
    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=796,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-ownerless-claim-update",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )
    claim = session.get(GitHubWebhookDeliveryClaimRow, receipt.delivery_id)
    assert claim is not None
    claim.owner_id = "active-webhook-owner"
    claim.generation = 7
    claim.lease_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    session.commit()

    with pytest.raises(GitHubWebhookDeliveryClaimLost, match="active webhook delivery owner"):
        mark_delivery_processed(session, receipt.delivery_id)
    with pytest.raises(GitHubWebhookDeliveryClaimLost, match="another worker"):
        mark_delivery_retry(session, receipt.delivery_id, "ownerless retry")

    session.expire_all()
    claim = session.get(GitHubWebhookDeliveryClaimRow, receipt.delivery_id)
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"
    assert claim is not None
    assert claim.owner_id == "active-webhook-owner"
    assert claim.generation == 7


def test_corrupt_delivery_claim_is_not_recovered_or_released(session):
    value = gateway(FakeGitHub())
    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=797,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-corrupt-claim",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )
    claim = session.get(GitHubWebhookDeliveryClaimRow, receipt.delivery_id)
    assert claim is not None
    claim.owner_id = "inconsistent-webhook-owner"
    claim.generation = 9
    claim.lease_expires_at = None
    session.commit()

    result = value.process_delivery(session, receipt.delivery_id)

    with pytest.raises(GitHubWebhookDeliveryClaimLost, match="another worker"):
        mark_delivery_retry(session, receipt.delivery_id, "corrupt claim")
    session.expire_all()
    claim = session.get(GitHubWebhookDeliveryClaimRow, receipt.delivery_id)
    assert result.outcome == "PROCESSING"
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PENDING"
    assert claim is not None
    assert claim.owner_id == "inconsistent-webhook-owner"
    assert claim.generation == 9
    assert claim.lease_expires_at is None


@pytest.mark.parametrize("was_ready", [False, True])
def test_later_exact_head_changes_request_revokes_approval_idempotently(
    session,
    was_ready,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    if was_ready:
        record_mergeability(
            session,
            view.publication_id,
            head_sha=HEAD,
            mergeable=True,
        )
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.mergeable = True
    github.reviews = [
        PullReviewSnapshot(
            review_id=901,
            actor=HUMAN_ACTOR,
            body="approved exact head",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=902,
            actor=HUMAN_ACTOR,
            body="changes requested on exact head",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]
    value = gateway(github)

    def process_review(delivery_id):
        body, signature = raw_delivery(
            event_name="pull_request_review",
            review_id=902,
            review_actor=HUMAN_ACTOR,
        )
        receipt = value.ingest(
            session,
            delivery_id=delivery_id,
            event_name="pull_request_review",
            signature=signature,
            body=body,
        )
        return value.process_delivery(session, receipt.delivery_id)

    result = process_review(
        f"delivery-changes-after-approval-{was_ready}-first"
    )
    replay = process_review(
        f"delivery-changes-after-approval-{was_ready}-replay"
    )

    current = get_view(session, view.publication_id)
    events = load_events(session, view.publication_id)
    review_events = [
        event
        for event in events
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert current.review_decision is ReviewDecision.CHANGES_REQUIRED
    assert result.outcome == "HUMAN_CHANGES_REQUIRED"
    assert replay.outcome == "HUMAN_CHANGES_REQUIRED_ALREADY_RECORDED"
    assert [event["payload"]["decision"] for event in review_events] == [
        ReviewDecision.APPROVED.value,
        ReviewDecision.CHANGES_REQUIRED.value,
    ]
    assert sum(
        event["event_type"] == EventType.MERGEABILITY_RECORDED.value
        for event in events
    ) == int(was_ready)
    assert current.mergeable is (True if was_ready else None)
    assert get_webhook_delivery(
        session,
        f"delivery-changes-after-approval-{was_ready}-first",
    ).state == "PROCESSED"
    assert get_webhook_delivery(
        session,
        f"delivery-changes-after-approval-{was_ready}-replay",
    ).state == "PROCESSED"


@pytest.mark.parametrize("was_ready", [False, True])
def test_dismissed_human_review_revokes_exact_head_approval_idempotently(
    session,
    was_ready,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.mergeable = False
    github.reviews = [
        PullReviewSnapshot(
            review_id=910,
            actor=HUMAN_ACTOR,
            body="exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)

    process_human_review_delivery(
        session,
        value,
        delivery_id=f"delivery-dismissal-approval-{was_ready}",
        review_id=910,
    )
    current = get_view(session, view.publication_id)
    assert current.state is PublicationState.APPROVED
    if was_ready:
        record_mergeability(
            session,
            view.publication_id,
            head_sha=HEAD,
            mergeable=True,
        )
    mergeability_event_count = sum(
        event["event_type"] == EventType.MERGEABILITY_RECORDED.value
        for event in load_events(session, view.publication_id)
    )

    github.reviews = [
        PullReviewSnapshot(
            review_id=910,
            actor=HUMAN_ACTOR,
            body="dismissed exact-head approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    delivery_id = f"delivery-dismissal-{was_ready}-first"
    result = process_human_review_delivery(
        session,
        value,
        delivery_id=delivery_id,
        review_id=910,
        action="dismissed",
    )
    replay = process_human_review_delivery(
        session,
        value,
        delivery_id=f"delivery-dismissal-{was_ready}-replay",
        review_id=910,
        action="dismissed",
    )
    same_delivery_replay = process_human_review_delivery(
        session,
        value,
        delivery_id=delivery_id,
        review_id=910,
        action="dismissed",
    )

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert result.outcome == "HUMAN_REVIEW_CLEARED"
    assert replay.outcome == "HUMAN_REVIEW_NOT_FOUND"
    assert same_delivery_replay.outcome == "PROCESSED"
    assert [event["payload"]["decision"] for event in review_events] == [
        ReviewDecision.APPROVED.value,
        ReviewDecision.CHANGES_REQUIRED.value,
    ]
    assert [event["payload"]["github_review_id"] for event in review_events] == [
        910,
        910,
    ]
    clearance_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.HUMAN_REVIEW_CLEARED.value
    ]
    assert len(clearance_events) == 1
    assert clearance_events[0]["payload"]["blocking_review_id"] == 910
    assert clearance_events[0]["payload"]["clearing_review_id"] == 910
    assert sum(
        event["event_type"] == EventType.MERGEABILITY_RECORDED.value
        for event in load_events(session, view.publication_id)
    ) == mergeability_event_count
    watch = get_review_watch(session, view.publication_id)
    assert watch.next_role == "HUMAN_REVIEWER"
    assert watch.next_action == "WAIT_HUMAN_REVIEW"


@pytest.mark.parametrize(
    ("review_id", "review_actor", "reviewed_head", "expected_outcome"),
    [
        (920, HUMAN_ACTOR, "4" * 40, "STALE_HUMAN_REVIEW"),
        (920, UNLISTED_ACTOR, HEAD, "NON_HUMAN_REVIEW_ACTOR"),
        (921, SECOND_HUMAN_ACTOR, HEAD, "HUMAN_APPROVAL_REMAINS"),
    ],
)
def test_stale_unlisted_or_unrelated_dismissal_does_not_revoke_approval(
    session,
    review_id,
    review_actor,
    reviewed_head,
    expected_outcome,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=920,
            actor=HUMAN_ACTOR,
            body="exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(
        github,
        human_actors=(HUMAN_ACTOR, SECOND_HUMAN_ACTOR),
    )
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-dismissal-prior-approval",
        review_id=920,
    )

    dismissal_reviews = [
        PullReviewSnapshot(
            review_id=review_id,
            actor=review_actor,
            body="dismissal evidence",
            state="DISMISSED",
            commit_id=reviewed_head,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        )
    ]
    if review_id == 921:
        dismissal_reviews.append(
            PullReviewSnapshot(
                review_id=920,
                actor=HUMAN_ACTOR,
                body="separate active exact-head approval",
                state="APPROVED",
                commit_id=HEAD,
                submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
            )
        )
    github.reviews = dismissal_reviews
    result = process_human_review_delivery(
        session,
        value,
        delivery_id=f"delivery-dismissal-invalid-{review_id}-{review_actor}",
        review_id=review_id,
        action="dismissed",
        review_actor=review_actor,
    )

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert result.outcome.startswith(expected_outcome)
    assert current.state is PublicationState.APPROVED
    assert current.review_decision is ReviewDecision.APPROVED
    assert len(review_events) == 1
    assert review_events[0]["payload"]["github_review_id"] == 920


def test_same_reviewer_tied_decision_timestamps_fail_closed(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    submitted_at = (codex_gate_time(session, view) + timedelta(seconds=1)).isoformat()
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=925,
            actor=HUMAN_ACTOR,
            body="exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=submitted_at,
        ),
        PullReviewSnapshot(
            review_id=926,
            actor=HUMAN_ACTOR,
            body="exact-head changes request",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at=submitted_at,
        ),
    ]
    value = gateway(github)

    with pytest.raises(GitHubWebhookError, match="timestamp is ambiguous"):
        process_human_review_delivery(
            session,
            value,
            delivery_id="delivery-human-review-tied-timestamps",
            review_id=926,
        )

    current = get_view(session, view.publication_id)
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert not [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert get_webhook_delivery(
        session,
        "delivery-human-review-tied-timestamps",
    ).state == "PENDING"


@pytest.mark.parametrize("was_ready", [False, True])
def test_dismissals_follow_effective_approval_per_reviewer(session, was_ready):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=930,
            actor=HUMAN_ACTOR,
            body="recorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(
        github,
        human_actors=(HUMAN_ACTOR, SECOND_HUMAN_ACTOR),
    )
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-dismissal-replacement-approval",
        review_id=930,
    )
    if was_ready:
        record_mergeability(
            session,
            view.publication_id,
            head_sha=HEAD,
            mergeable=True,
        )

    github.reviews = [
        PullReviewSnapshot(
            review_id=930,
            actor=HUMAN_ACTOR,
            body="recorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=931,
            actor=SECOND_HUMAN_ACTOR,
            body="unrecorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]
    active_approvals = value._effective_active_human_approvals(
        github.reviews,
        head_sha=HEAD,
        submitted_after=gate_time,
    )
    assert {item.review_id for item in active_approvals} == {930, 931}

    github.reviews = [
        PullReviewSnapshot(
            review_id=930,
            actor=HUMAN_ACTOR,
            body="dismissed recorded approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=931,
            actor=SECOND_HUMAN_ACTOR,
            body="unrecorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]
    result = process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-dismissal-replayed-after-reapproval",
        review_id=930,
        action="dismissed",
    )
    after_first_dismissal = get_view(session, view.publication_id)
    assert after_first_dismissal.state is (
        PublicationState.READY_TO_MERGE
        if was_ready
        else PublicationState.APPROVED
    )

    github.reviews = [
        PullReviewSnapshot(
            review_id=930,
            actor=HUMAN_ACTOR,
            body="dismissed recorded approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=931,
            actor=SECOND_HUMAN_ACTOR,
            body="dismissed unrecorded approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]
    final_dismissal_id = f"delivery-dismissal-final-{was_ready}"
    final_dismissal = process_human_review_delivery(
        session,
        value,
        delivery_id=final_dismissal_id,
        review_id=931,
        action="dismissed",
        review_actor=SECOND_HUMAN_ACTOR,
    )
    final_dismissal_replay = process_human_review_delivery(
        session,
        value,
        delivery_id=f"{final_dismissal_id}-replay",
        review_id=931,
        action="dismissed",
        review_actor=SECOND_HUMAN_ACTOR,
    )

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert result.outcome.startswith("HUMAN_APPROVAL_REMAINS")
    assert final_dismissal.outcome == "HUMAN_REVIEW_CLEARED"
    assert final_dismissal_replay.outcome == "HUMAN_REVIEW_NOT_FOUND"
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert [event["payload"]["decision"] for event in review_events] == [
        ReviewDecision.APPROVED.value,
        ReviewDecision.CHANGES_REQUIRED.value,
    ]
    assert [event["payload"]["github_review_id"] for event in review_events] == [
        930,
        930,
    ]


@pytest.mark.parametrize("later_review_state", [
    "CHANGES_REQUESTED",
    "REQUEST_CHANGES",
    "DISMISSED",
])
def test_later_nonapproval_supersedes_historical_exact_head_approval(
    session,
    later_review_state,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=940,
            actor=HUMAN_ACTOR,
            body="recorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(
        github,
        human_actors=(HUMAN_ACTOR, SECOND_HUMAN_ACTOR),
    )
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-dismissal-historical-a-approval",
        review_id=940,
    )

    github.reviews = [
        PullReviewSnapshot(
            review_id=942,
            actor=SECOND_HUMAN_ACTOR,
            body="later nonapproval state",
            state=later_review_state,
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=3)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=940,
            actor=HUMAN_ACTOR,
            body="dismissed recorded approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=941,
            actor=SECOND_HUMAN_ACTOR,
            body="historical exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]
    result = process_human_review_delivery(
        session,
        value,
        delivery_id=f"delivery-dismissal-superseded-{later_review_state}",
        review_id=940,
        action="dismissed",
    )

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    expected_state = (
        PublicationState.IN_REVIEW
        if later_review_state == "DISMISSED"
        else PublicationState.CHANGES_REQUIRED
    )
    expected_outcome = (
        "HUMAN_REVIEW_CLEARED"
        if later_review_state == "DISMISSED"
        else "HUMAN_CHANGES_REQUIRED"
    )
    assert result.outcome == expected_outcome
    assert current.state is expected_state
    assert current.review_decision is (
        None
        if later_review_state == "DISMISSED"
        else ReviewDecision.CHANGES_REQUIRED
    )
    assert [event["payload"]["decision"] for event in review_events] == [
        ReviewDecision.APPROVED.value,
        ReviewDecision.CHANGES_REQUIRED.value,
    ]


def test_full_reconcile_clears_human_block_after_lost_dismissal(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=950,
            actor=HUMAN_ACTOR,
            body="exact-head changes request",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)
    blocking = process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-human-blocker-recorded",
        review_id=950,
    )
    assert blocking.outcome == "HUMAN_CHANGES_REQUIRED"
    assert get_view(session, view.publication_id).state is PublicationState.CHANGES_REQUIRED

    github.reviews = [
        PullReviewSnapshot(
            review_id=950,
            actor=HUMAN_ACTOR,
            body="dismissed exact-head changes request",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    events = load_events(session, view.publication_id)
    blocker_event = next(
        event
        for event in events
        if event["event_type"] == EventType.REVIEW_RECORDED.value
        and event["payload"]["decision"] == ReviewDecision.CHANGES_REQUIRED.value
    )
    clearance_events = [
        event
        for event in events
        if event["event_type"] == EventType.HUMAN_REVIEW_CLEARED.value
    ]
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert len(clearance_events) == 1
    assert clearance_events[0]["payload"] == {
        "reviewed_head_sha": HEAD,
        "cleared_review_event_sequence": blocker_event["sequence"],
        "blocking_review_id": 950,
        "clearing_review_id": 950,
        "clearing_review_state": "DISMISSED",
    }

    clear_human_review_block(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        cleared_review_event_sequence=blocker_event["sequence"],
        blocking_review_id=950,
        clearing_review_id=950,
        clearing_review_state="DISMISSED",
    )
    assert len(
        [
            event
            for event in load_events(session, view.publication_id)
            if event["event_type"] == EventType.HUMAN_REVIEW_CLEARED.value
        ]
    ) == 1
    with pytest.raises(DomainError, match="provenance is invalid"):
        clear_human_review_block(
            session,
            view.publication_id,
            reviewed_head_sha=HEAD,
            cleared_review_event_sequence=True,
            blocking_review_id=950,
            clearing_review_id=950,
            clearing_review_state="DISMISSED",
        )
    with pytest.raises(DomainError, match="decision is invalid"):
        clear_human_review_block(
            session,
            view.publication_id,
            reviewed_head_sha=HEAD,
            cleared_review_event_sequence=blocker_event["sequence"],
            blocking_review_id=950,
            clearing_review_id=950,
            clearing_review_state="COMMENTED",
        )
    with pytest.raises(DomainError, match="evidence conflicts"):
        clear_human_review_block(
            session,
            view.publication_id,
            reviewed_head_sha=HEAD,
            cleared_review_event_sequence=blocker_event["sequence"],
            blocking_review_id=951,
            clearing_review_id=950,
            clearing_review_state="DISMISSED",
        )


def test_active_other_reviewer_request_prevents_human_block_clearance(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=952,
            actor=HUMAN_ACTOR,
            body="blocking changes request",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(
        github,
        human_actors=(HUMAN_ACTOR, SECOND_HUMAN_ACTOR),
    )
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-human-blocker-with-other-reviewer",
        review_id=952,
    )
    github.reviews = [
        PullReviewSnapshot(
            review_id=952,
            actor=HUMAN_ACTOR,
            body="dismissed blocking changes request",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=953,
            actor=SECOND_HUMAN_ACTOR,
            body="active other-reviewer changes request",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]

    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    events = load_events(session, view.publication_id)
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert current.review_decision is ReviewDecision.CHANGES_REQUIRED
    assert not [
        event
        for event in events
        if event["event_type"] == EventType.HUMAN_REVIEW_CLEARED.value
    ]
    assert [
        event["payload"]["github_review_id"]
        for event in events
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ] == [952]


def test_human_block_is_cleared_before_later_approval_is_recorded(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=954,
            actor=HUMAN_ACTOR,
            body="blocking changes request",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-human-blocker-before-approval",
        review_id=954,
    )
    github.reviews.append(
        PullReviewSnapshot(
            review_id=955,
            actor=HUMAN_ACTOR,
            body="later exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        )
    )

    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    events = load_events(session, view.publication_id)
    review_events = [
        event
        for event in events
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    clearance_event = next(
        event
        for event in events
        if event["event_type"] == EventType.HUMAN_REVIEW_CLEARED.value
    )
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.APPROVED
    assert [event["payload"]["decision"] for event in review_events] == [
        ReviewDecision.CHANGES_REQUIRED.value,
        ReviewDecision.APPROVED.value,
    ]
    assert review_events[0]["sequence"] < clearance_event["sequence"]
    assert clearance_event["sequence"] < review_events[1]["sequence"]
    assert clearance_event["payload"]["clearing_review_id"] == 955
    assert clearance_event["payload"]["clearing_review_state"] == "APPROVED"


def test_required_codex_findings_cannot_be_cleared_as_human_review(session):
    view = start_codex(session, published(session))
    complete_codex_review(
        session,
        view.publication_id,
        run_id=view.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.CHANGES_REQUIRED,
        findings=[
            {
                "provider_comment_id": 602,
                "provider_review_id": 502,
                "path": "control_plane/domain.py",
                "line": 11,
                "body": "Required Codex finding.",
            }
        ],
        provider_review_ids=[502],
        provider_comment_ids=[602],
    )
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=956,
            actor=HUMAN_ACTOR,
            body="dismissed human review",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:02:00Z",
        )
    ]
    value = gateway(github)

    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    events = load_events(session, view.publication_id)
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert current.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
    assert not [
        event
        for event in events
        if event["event_type"] == EventType.HUMAN_REVIEW_CLEARED.value
    ]


@pytest.mark.parametrize("was_ready", [False, True])
def test_full_reconcile_revokes_approval_after_lost_dismissal(session, was_ready):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=960,
            actor=HUMAN_ACTOR,
            body="recorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(github)
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-lost-dismissal-approval",
        review_id=960,
    )
    if was_ready:
        record_mergeability(
            session,
            view.publication_id,
            head_sha=HEAD,
            mergeable=True,
        )

    github.reviews = [
        PullReviewSnapshot(
            review_id=960,
            actor=HUMAN_ACTOR,
            body="dismissed exact-head approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.IN_REVIEW
    assert current.review_decision is None
    assert [event["payload"]["decision"] for event in review_events] == [
        ReviewDecision.APPROVED.value,
        ReviewDecision.CHANGES_REQUIRED.value,
    ]
    assert [event["payload"]["github_review_id"] for event in review_events] == [
        960,
        960,
    ]


@pytest.mark.parametrize(
    ("dismissed_review_present", "expected_review_id"),
    [(True, 1001), (False, None)],
)
def test_full_reconcile_revocation_provenance_requires_attributable_dismissal(
    session,
    dismissed_review_present,
    expected_review_id,
):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=1000,
            actor=HUMAN_ACTOR,
            body="pre-adjudication approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time - timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=1001,
            actor=SECOND_HUMAN_ACTOR,
            body="post-adjudication approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
    ]
    value = gateway(
        github,
        human_actors=(HUMAN_ACTOR, SECOND_HUMAN_ACTOR),
    )
    approval_result = process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-provenance-approval",
        review_id=1001,
        review_actor=SECOND_HUMAN_ACTOR,
    )
    assert approval_result.outcome.startswith("HUMAN_APPROVED")
    assert get_view(session, view.publication_id).state is PublicationState.APPROVED

    github.reviews = [
        PullReviewSnapshot(
            review_id=1000,
            actor=HUMAN_ACTOR,
            body="pre-adjudication approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time - timedelta(seconds=1)).isoformat(),
        ),
    ]
    if dismissed_review_present:
        github.reviews.append(
            PullReviewSnapshot(
                review_id=1001,
                actor=SECOND_HUMAN_ACTOR,
                body="dismissed post-adjudication approval",
                state="DISMISSED",
                commit_id=HEAD,
                submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
            )
        )
    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    revocation_events = [
        event
        for event in review_events
        if event["payload"]["decision"] == ReviewDecision.CHANGES_REQUIRED.value
    ]
    assert result.outcome == "RECONCILED"
    assert current.state is (
        PublicationState.IN_REVIEW
        if dismissed_review_present
        else PublicationState.CHANGES_REQUIRED
    )
    assert current.review_decision is (
        None
        if dismissed_review_present
        else ReviewDecision.CHANGES_REQUIRED
    )
    assert len(revocation_events) == 1
    if expected_review_id is None:
        assert "github_review_id" not in revocation_events[0]["payload"]
    else:
        assert revocation_events[0]["payload"]["github_review_id"] == expected_review_id
        assert revocation_events[0]["payload"]["github_review_id"] != 1000


def test_full_reconcile_keeps_approval_when_another_reviewer_remains_active(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=970,
            actor=HUMAN_ACTOR,
            body="recorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(
        github,
        human_actors=(HUMAN_ACTOR, SECOND_HUMAN_ACTOR),
    )
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-other-approval-recorded",
        review_id=970,
    )

    github.reviews = [
        PullReviewSnapshot(
            review_id=970,
            actor=HUMAN_ACTOR,
            body="dismissed exact-head approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=971,
            actor=SECOND_HUMAN_ACTOR,
            body="active exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]
    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.APPROVED
    assert current.review_decision is ReviewDecision.APPROVED
    assert len(review_events) == 1
    assert review_events[0]["payload"]["github_review_id"] == 970


def test_comment_and_other_reviewer_dismissal_do_not_erase_active_approval(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=980,
            actor=HUMAN_ACTOR,
            body="recorded exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        )
    ]
    value = gateway(
        github,
        human_actors=(HUMAN_ACTOR, SECOND_HUMAN_ACTOR),
    )
    process_human_review_delivery(
        session,
        value,
        delivery_id="delivery-reconcile-comment-approval-recorded",
        review_id=980,
    )

    github.reviews = [
        PullReviewSnapshot(
            review_id=980,
            actor=HUMAN_ACTOR,
            body="original exact-head approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=981,
            actor=SECOND_HUMAN_ACTOR,
            body="dismissed approval",
            state="DISMISSED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=982,
            actor=HUMAN_ACTOR,
            body="non-decision comment review",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=3)).isoformat(),
        ),
    ]
    active_approvals = value._effective_active_human_approvals(
        github.reviews,
        head_sha=HEAD,
        submitted_after=gate_time,
    )
    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert {item.review_id for item in active_approvals} == {980}
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.APPROVED
    assert current.review_decision is ReviewDecision.APPROVED
    assert len(review_events) == 1


def test_comment_does_not_supersede_changes_requested_review(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    gate_time = codex_gate_time(session, view)
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=990,
            actor=HUMAN_ACTOR,
            body="request changes",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=1)).isoformat(),
        ),
        PullReviewSnapshot(
            review_id=991,
            actor=HUMAN_ACTOR,
            body="later non-decision comment",
            state="COMMENTED",
            commit_id=HEAD,
            submitted_at=(gate_time + timedelta(seconds=2)).isoformat(),
        ),
    ]

    result = gateway(github).reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert result.outcome == "RECONCILED"
    assert current.state is PublicationState.CHANGES_REQUIRED
    assert current.review_decision is ReviewDecision.CHANGES_REQUIRED
    assert len(review_events) == 1
    assert review_events[0]["payload"]["github_review_id"] == 990


def test_stale_head_changes_request_does_not_revoke_approval(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    github = FakeGitHub()
    github.reviews = [
        PullReviewSnapshot(
            review_id=903,
            actor=HUMAN_ACTOR,
            body="stale changes request",
            state="CHANGES_REQUESTED",
            commit_id="4" * 40,
            submitted_at="2026-09-30T12:10:00Z",
        )
    ]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=903,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-stale-changes-request",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    assert result.outcome.startswith("STALE_HUMAN_REVIEW")
    assert current.state is PublicationState.APPROVED
    assert current.review_decision is ReviewDecision.APPROVED
    assert len(review_events) == 1


def test_stale_base_changes_request_does_not_revoke_approval(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    github = FakeGitHub()
    github.ref_shas["master"] = "8" * 40
    github.reviews = [
        PullReviewSnapshot(
            review_id=904,
            actor=HUMAN_ACTOR,
            body="changes requested while base is stale",
            state="CHANGES_REQUESTED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:10:00Z",
        )
    ]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="pull_request_review",
        review_id=904,
        review_actor=HUMAN_ACTOR,
    )
    receipt = value.ingest(
        session,
        delivery_id="delivery-stale-base-changes-request",
        event_name="pull_request_review",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    review_events = [
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == EventType.REVIEW_RECORDED.value
    ]
    watch = get_review_watch(session, view.publication_id)
    assert result.outcome.startswith("STALE_BASE")
    assert current.state is PublicationState.APPROVED
    assert current.review_decision is ReviewDecision.APPROVED
    assert len(review_events) == 1
    assert watch.state == "STALE"
    assert watch.next_action == "BLOCKED"


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


@pytest.mark.parametrize("codex_state", ["APPROVED", "CHANGES_REQUESTED"])
def test_stale_head_reconciliation_marks_first_correlated_usage_limit_only(
    session,
    codex_state,
):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.head_sha = "4" * 40
    github.mergeable = True
    github.issue_comments = [
        usage_limit_response(712, "2026-09-30T12:30:00Z"),
        usage_limit_response(710, "2026-09-30T12:09:00Z"),
        governed_codex_trigger(view),
        usage_limit_response(
            711,
            "2026-09-30T12:10:00Z",
            body="A later unrelated Codex comment.",
        ),
    ]
    github.reviews = [
        PullReviewSnapshot(
            review_id=813,
            actor=CODEX_ACTOR,
            body="stale automated review",
            state=codex_state,
            commit_id=HEAD,
            submitted_at="2026-09-30T12:11:00Z",
        ),
        PullReviewSnapshot(
            review_id=814,
            actor=HUMAN_ACTOR,
            body="stale human approval",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:12:00Z",
        ),
    ]
    value = gateway(github)

    result = value.reconcile_publication(session, view.publication_id)

    current = get_view(session, view.publication_id)
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert github.pull_review_list_calls == 1
    assert_stale_review_blocked(session, view, result, "STALE_HEAD")


def test_stale_base_reconciliation_marks_correlated_usage_limit_and_blocks_watch(
    session,
):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.ref_shas["master"] = "8" * 40
    github.issue_comments = [
        governed_codex_trigger(view),
        usage_limit_response(715, "2026-09-30T12:09:00Z"),
    ]
    github.reviews = [
        PullReviewSnapshot(
            review_id=815,
            actor=HUMAN_ACTOR,
            body="approval after base drift",
            state="APPROVED",
            commit_id=HEAD,
            submitted_at="2026-09-30T12:12:00Z",
        )
    ]
    value = gateway(github)

    result = value.reconcile_publication(session, view.publication_id)

    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert github.pull_review_list_calls == 1
    assert_stale_review_blocked(session, view, result, "STALE_BASE")


@pytest.mark.parametrize(
    ("drift", "expected_outcome"),
    [("head", "STALE_HEAD"), ("base", "STALE_BASE")],
)
def test_usage_limit_issue_comment_delivery_closes_run_before_stale_fence(
    session,
    drift,
    expected_outcome,
):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    if drift == "head":
        github.head_sha = "4" * 40
    else:
        github.ref_shas["master"] = "8" * 40
    github.issue_comments = [
        usage_limit_response(701, "2026-09-30T12:09:00Z"),
        governed_codex_trigger(view),
    ]
    value = gateway(github)
    body, signature = raw_delivery(
        event_name="issue_comment",
        comment_id=701,
    )
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-stale-usage-{drift}",
        event_name="issue_comment",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    current = get_view(session, view.publication_id)
    assert current.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert get_webhook_delivery(session, receipt.delivery_id).state == "PROCESSED"
    assert_stale_review_blocked(session, view, result, expected_outcome)


def test_later_usage_limit_is_ignored_when_first_provider_response_is_unrelated(
    session,
):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.head_sha = "4" * 40
    github.issue_comments = [
        usage_limit_response(722, "2026-09-30T12:30:00Z"),
        governed_codex_trigger(view),
        usage_limit_response(
            720,
            "2026-09-30T12:09:00Z",
            body="A regular Codex review comment without a provider limit.",
        ),
    ]
    value = gateway(github)

    result = value.reconcile_publication(session, view.publication_id)

    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.RUNNING
    assert github.pull_review_list_calls == 1
    assert_stale_review_blocked(session, view, result, "STALE_HEAD")


def test_unavailable_stale_run_allows_successor_candidate_submission(session):
    view = start_codex(session, published(session))
    github = FakeGitHub()
    github.head_sha = "4" * 40
    github.issue_comments = [
        governed_codex_trigger(view),
        usage_limit_response(723, "2026-09-30T12:09:00Z"),
    ]

    result = gateway(github).reconcile_publication(session, view.publication_id)

    assert_stale_review_blocked(session, view, result, "STALE_HEAD")
    successor = submit_verified_candidate(
        session,
        view.publication_id,
        VerifiedCandidateSource(
            bundle_sha256="b" * 64,
            byte_length=2345,
            quarantine_id="b" * 64,
            base_sha=BASE,
            head_sha="5" * 40,
            tree_sha="6" * 40,
        ),
    )

    assert successor.state is PublicationState.VALIDATING
    assert successor.current_candidate.head_sha == "5" * 40
    assert successor.automated_review_status is None


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

    with pytest.raises(CodexReviewError, match="trigger marker is missing"):
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


@pytest.mark.parametrize(
    ("branch", "expected_stale"),
    [("master", 1), ("unrelated", 0)],
)
def test_deleted_base_ref_stales_only_publications_watching_that_base(
    session,
    branch,
    expected_stale,
):
    view = published(session)
    github = FakeGitHub()
    github.ref_shas.pop(branch, None)
    value = gateway(github)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )

    body = json.dumps(
        {
            "ref": f"refs/heads/{branch}",
            "before": BASE,
            "after": "0" * 40,
            "repository": {"full_name": REPOSITORY},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = "sha256=" + hmac.new(
        SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-deleted-base-{branch}",
        event_name="push",
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    assert result.outcome == f"BASE_PUSH_STALE:{expected_stale}:RECOVERED:0"
    watch = get_review_watch(session, view.publication_id)
    assert watch.state == ("STALE" if expected_stale else "ACTIVE")
    if expected_stale:
        assert watch.next_role == "CONTROL_PLANE"
        assert watch.next_action == "BLOCKED"


@pytest.mark.parametrize("event_name", ["check_run", "status"])
def test_check_and_status_wake_exact_governed_publication(session, event_name):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )
    github = FakeGitHub()
    github.mergeable = True
    value = gateway(github)
    body, signature = raw_wakeup_delivery(event_name)
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-{event_name}-governed-target",
        event_name=event_name,
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    assert result.publication_id == view.publication_id
    assert result.outcome == "EVENT_OBSERVED+MERGEABILITY_RECORDED"
    assert get_view(session, view.publication_id).state is PublicationState.READY_TO_MERGE
    assert get_view(session, view.publication_id).mergeable is True


@pytest.mark.parametrize(
    ("event_name", "repository", "head_sha", "pull_numbers"),
    [
        ("check_run", REPOSITORY, HEAD, (999,)),
        ("check_run", REPOSITORY, "4" * 40, (44,)),
        ("status", REPOSITORY, "4" * 40, (44,)),
        ("status", "DEAMBROGGI/FirstContact", HEAD, (44,)),
    ],
)
def test_check_and_status_ignore_foreign_or_unmatched_targets(
    session,
    event_name,
    repository,
    head_sha,
    pull_numbers,
):
    view = published(session)
    sync_review_watch(session, view.publication_id)
    value = gateway(FakeGitHub())
    body, signature = raw_wakeup_delivery(
        event_name,
        repository=repository,
        head_sha=head_sha,
        pull_numbers=pull_numbers,
    )
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-{event_name}-unmatched-{pull_numbers[0]}",
        event_name=event_name,
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    assert result.publication_id is None
    assert result.outcome == "NO_GOVERNED_TARGET"
    assert get_view(session, view.publication_id).state is PublicationState.IN_REVIEW

    replay = value.process_delivery(session, receipt.delivery_id)
    assert replay.publication_id is None
    assert replay.next_role == "NONE"
    assert replay.next_action == "DONE"


@pytest.mark.parametrize("event_name", ["check_run", "status"])
def test_check_and_status_fail_closed_for_ambiguous_governed_targets(
    session,
    event_name,
):
    first = published(session, issue_number=2601)
    second = published(session, issue_number=2602)
    sync_review_watch(session, first.publication_id)
    sync_review_watch(session, second.publication_id)
    value = gateway(FakeGitHub())
    body, signature = raw_wakeup_delivery(event_name)
    receipt = value.ingest(
        session,
        delivery_id=f"delivery-{event_name}-ambiguous-target",
        event_name=event_name,
        signature=signature,
        body=body,
    )

    result = value.process_delivery(session, receipt.delivery_id)

    assert result.publication_id is None
    assert result.outcome == "AMBIGUOUS_GOVERNED_TARGET"
    assert result.next_role == "CONTROL_PLANE"
    assert result.next_action == "BLOCKED"
    assert get_view(session, first.publication_id).state is PublicationState.IN_REVIEW
    assert get_view(session, second.publication_id).state is PublicationState.IN_REVIEW


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

    stale_result = process_base_push_delivery(
        session,
        value,
        delivery_id="delivery-base-push-stale-recovery-1",
        after="8" * 40,
    )

    assert stale_result.outcome == "BASE_PUSH_STALE:1:RECOVERED:0"
    assert stale_result.next_action == "BLOCKED"
    assert get_review_watch(session, view.publication_id).state == "STALE"

    github.ref_shas["master"] = BASE
    with pytest.raises(DomainError, match="publication base is stale"):
        value.assert_review_write_current(session, view.publication_id)
    assert get_review_watch(session, view.publication_id).state == "STALE"

    github.head_sha = "4" * 40
    drifted_recovery = process_base_push_delivery(
        session,
        value,
        delivery_id="delivery-base-push-recovery-drifted",
        after=BASE,
    )
    assert drifted_recovery.outcome == "BASE_PUSH_STALE:1:RECOVERED:0"
    assert drifted_recovery.next_action == "BLOCKED"
    watch = get_review_watch(session, view.publication_id)
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"

    github.head_sha = HEAD
    recovery_result = process_base_push_delivery(
        session,
        value,
        delivery_id="delivery-base-push-recovery-2",
        after=BASE,
    )

    watch = get_review_watch(session, view.publication_id)
    assert recovery_result.outcome == "BASE_PUSH_STALE:0:RECOVERED:1"
    assert recovery_result.next_action == "DONE"
    assert watch.state == "ACTIVE"
    assert watch.next_role == "HUMAN_REVIEWER"
    assert watch.next_action == "WAIT_HUMAN_REVIEW"


@pytest.mark.parametrize("readback_fault", ["api", "number", "head_branch", "base_branch"])
def test_base_push_readback_failure_keeps_watch_blocked_and_delivery_retryable(
    session,
    readback_fault,
):
    class ReadbackFaultGitHub(FakeGitHub):
        def pull_request(self, repository, number, token):
            if readback_fault == "api":
                raise GitHubApiError("simulated canonical PR readback failure")
            pull = super().pull_request(repository, number, token)
            return PullRequestSnapshot(
                number=45 if readback_fault == "number" else pull.number,
                state=pull.state,
                base_ref=(
                    "release"
                    if readback_fault == "base_branch"
                    else pull.base_ref
                ),
                head_ref=(
                    "uncontrolled"
                    if readback_fault == "head_branch"
                    else pull.head_ref
                ),
                head_sha=pull.head_sha,
                merged=pull.merged,
                merge_commit_sha=pull.merge_commit_sha,
                mergeable=pull.mergeable,
            )

    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = ReadbackFaultGitHub()
    github.ref_shas["master"] = "8" * 40
    value = gateway(github)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )
    process_base_push_delivery(
        session,
        value,
        delivery_id=f"delivery-base-push-readback-stale-{readback_fault}",
        after="8" * 40,
    )

    github.ref_shas["master"] = BASE
    expected_error = GitHubApiError if readback_fault == "api" else GitHubWebhookError
    with pytest.raises(expected_error):
        process_base_push_delivery(
            session,
            value,
            delivery_id=f"delivery-base-push-readback-failure-{readback_fault}",
            after=BASE,
        )

    delivery = get_webhook_delivery(
        session,
        f"delivery-base-push-readback-failure-{readback_fault}",
    )
    watch = get_review_watch(session, view.publication_id)
    assert delivery.state == "PENDING"
    assert delivery.attempt_count == 1
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_base_push_cannot_recover_stale_prior_watch_generation(session):
    view = complete_codex_pass(session, start_codex(session, published(session)))
    github = FakeGitHub()
    github.ref_shas["master"] = "8" * 40
    value = gateway(github)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=(CODEX_ACTOR, HUMAN_ACTOR),
    )
    process_base_push_delivery(
        session,
        value,
        delivery_id="delivery-base-push-old-generation-stale",
        after="8" * 40,
    )

    published_next = publish_next_head(session, view)
    assert published_next.remote_head_sha == NEXT_HEAD
    assert get_review_watch(session, view.publication_id).watched_head_sha == HEAD

    github.ref_shas["master"] = BASE
    github.head_sha = NEXT_HEAD
    result = process_base_push_delivery(
        session,
        value,
        delivery_id="delivery-base-push-old-generation-recovery",
        after=BASE,
    )

    watch = get_review_watch(session, view.publication_id)
    assert result.outcome == "BASE_PUSH_STALE:1:RECOVERED:0"
    assert result.next_action == "BLOCKED"
    assert watch.watched_head_sha == HEAD
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


def test_base_push_does_not_clear_stale_watch_with_merge_policy_violation(session):
    view = published(session)
    github = FakeGitHub()
    github.closed = True
    value = gateway(github)
    closed_body, closed_signature = raw_delivery(
        event_name="pull_request",
        action="closed",
    )
    closed = value.ingest(
        session,
        delivery_id="delivery-base-push-policy-close",
        event_name="pull_request",
        signature=closed_signature,
        body=closed_body,
    )
    value.process_delivery(session, closed.delivery_id)
    record_merge_policy_violation(
        session,
        view.publication_id,
        head_sha=HEAD,
        pull_request_number=44,
        merge_commit_sha="9" * 40,
    )
    sync_review_watch(session, view.publication_id, state="STALE")

    github.closed = False
    result = process_base_push_delivery(
        session,
        value,
        delivery_id="delivery-base-push-policy-recovery",
        after=BASE,
    )

    current = get_view(session, view.publication_id)
    watch = get_review_watch(session, view.publication_id)
    assert current.merge_policy_violation is True
    assert result.outcome == "BASE_PUSH_STALE:1:RECOVERED:0"
    assert result.next_action == "BLOCKED"
    assert watch.state == "STALE"
    assert watch.next_role == "CONTROL_PLANE"
    assert watch.next_action == "BLOCKED"


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


def test_startup_pending_recovery_rotates_past_persistent_failures(session):
    published(session)
    value = gateway(FakeGitHub())
    delivery_ids = (
        "delivery-startup-starve-0",
        "delivery-startup-starve-1",
        "delivery-startup-starve-2",
    )
    first_received_at = datetime(2026, 10, 1, tzinfo=timezone.utc)
    for index, delivery_id in enumerate(delivery_ids):
        body, signature = raw_delivery(
            event_name="issue_comment",
            comment_id=730 + index,
        )
        value.ingest(
            session,
            delivery_id=delivery_id,
            event_name="issue_comment",
            signature=signature,
            body=body,
        )
        row = session.get(GitHubWebhookDeliveryRow, delivery_id)
        assert row is not None
        row.received_at = first_received_at + timedelta(seconds=index)
    session.commit()

    attempted = []

    def flaky_process(supplied_session, delivery_id):
        attempted.append(delivery_id)
        if delivery_id in delivery_ids[:2]:
            mark_delivery_retry(
                supplied_session,
                delivery_id,
                "persistent startup recovery failure",
            )
            raise GitHubWebhookError("persistent startup recovery failure")
        return WebhookProcessResult(
            delivery_id=delivery_id,
            publication_id=None,
            outcome="RECOVERED",
            next_role="NONE",
            next_action="DONE",
            watch_state=None,
        )

    value.process_delivery = flaky_process
    value.reconcile_pending_best_effort(session, limit=2)
    assert attempted == list(delivery_ids[:2])

    attempted.clear()
    recovered = value.reconcile_pending_best_effort(session, limit=2)

    assert attempted[0] == delivery_ids[2]
    assert recovered[0].delivery_id == delivery_ids[2]
    assert get_webhook_delivery(session, delivery_ids[0]).attempt_count == 2
    assert get_webhook_delivery(session, delivery_ids[0]).state == "PENDING"
    assert (
        get_webhook_delivery(session, delivery_ids[0]).last_error
        == "persistent startup recovery failure"
    )


def test_pending_reconciliation_reports_failure_and_continues(session):
    published(session)
    value = gateway(FakeGitHub())
    first_body, first_signature = raw_delivery(
        event_name="issue_comment",
        comment_id=722,
    )
    second_body, second_signature = raw_delivery(
        event_name="issue_comment",
        comment_id=723,
    )
    value.ingest(
        session,
        delivery_id="delivery-manual-bad",
        event_name="issue_comment",
        signature=first_signature,
        body=first_body,
    )
    value.ingest(
        session,
        delivery_id="delivery-manual-good",
        event_name="issue_comment",
        signature=second_signature,
        body=second_body,
    )

    original = value.process_delivery
    seen = []

    def flaky_process(supplied_session, delivery_id):
        seen.append(delivery_id)
        if delivery_id == "delivery-manual-bad":
            mark_delivery_retry(
                supplied_session,
                delivery_id,
                "simulated manual recovery failure",
            )
            raise GitHubWebhookError("simulated manual recovery failure")
        return original(supplied_session, delivery_id)

    value.process_delivery = flaky_process
    results = value.reconcile_pending(session)

    assert seen == ["delivery-manual-bad", "delivery-manual-good"]
    assert [result.outcome for result in results] == [
        "FAILED_PENDING",
        "CODEX_NOT_RUNNING",
    ]
    assert results[0].error == "simulated manual recovery failure"
    assert results[0].next_action == "RETRY"
    assert get_webhook_delivery(session, "delivery-manual-bad").state == "PENDING"
    assert get_webhook_delivery(session, "delivery-manual-good").state == "PROCESSED"


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
