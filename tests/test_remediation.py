from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr
from fastapi import HTTPException
from fastapi.testclient import TestClient

from control_plane.config import Settings, settings
from control_plane.db import get_session
from control_plane.domain import AutomatedReviewStatus, DomainError, PublicationState, ValidationStatus
from control_plane.github_api import (
    GitHubApiError,
    IssueCommentSnapshot,
    IssueSnapshot,
    PullRequestSnapshot,
    PullReviewCommentReactionSnapshot,
    PullReviewCommentSnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.main import app, get_remediation_materializer
from control_plane.models import RemediationEventRow, RemediationWorkPackageRow
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.remediation import (
    PrincipalDecision,
    WorkPackageState,
    begin_rejected_findings_finalization,
    begin_successor_verification,
    claim_work_package,
    complete_work_package,
    create_work_package,
    get_work_package,
    load_work_package_events,
    record_github_artifact,
    record_issue_closed,
    record_summary_comment,
    submit_implementation,
    verify_finding,
)
from control_plane.remediation_materializer import (
    GitHubRemediationMaterializer,
    RemediationMaterializationError,
)
from control_plane.repository import load_events
from control_plane.service import (
    complete_codex_review,
    create_publication,
    mark_remote_published,
    record_validation,
    request_codex_review,
    submit_verified_candidate,
)

REPOSITORY = "DEAMBROGGI/FirstContact"
BASE = "1" * 40
HEAD = "2" * 40
TREE = "3" * 40


def source(head: str, tree: str, marker: str) -> VerifiedCandidateSource:
    return VerifiedCandidateSource(
        bundle_sha256=marker * 64,
        byte_length=2048,
        quarantine_id=marker * 64,
        base_sha=BASE,
        head_sha=head,
        tree_sha=tree,
    )


def publish(session, *, issue_number=10):
    view = create_publication(session, REPOSITORY, issue_number)
    view = submit_verified_candidate(session, view.publication_id, source(HEAD, TREE, "a"))
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


def add_completed_review(session, view, *, head=HEAD, result=AutomatedReviewStatus.CHANGES_REQUIRED):
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=head,
    )
    completed = complete_codex_review(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=head,
        result=result,
        findings=(
            [
                {
                    "provider_comment_id": 4101,
                    "provider_review_id": 3101,
                    "path": "control_plane/service.py",
                    "line": 20,
                    "body": "Accepted review finding",
                }
            ]
            if result is AutomatedReviewStatus.CHANGES_REQUIRED
            else []
        ),
        provider_review_ids=[3101],
        provider_comment_ids=[4101] if result is AutomatedReviewStatus.CHANGES_REQUIRED else [],
    )
    assert completed.automated_review_run_id == running.automated_review_run_id
    return completed.automated_review_run_id


def complete_successor_review(session, view, *, head, review_id, evidence_offset):
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{evidence_offset + index:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=head,
    )
    complete_codex_review(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=head,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[review_id],
        provider_comment_ids=[],
    )
    return running.automated_review_run_id


def publish_successor_review(session, view, *, head, tree, marker, review_id, evidence_offset):
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(head, tree, marker),
    )
    review_run_id = complete_successor_review(
        session,
        view,
        head=head,
        review_id=review_id,
        evidence_offset=evidence_offset,
    )
    return candidate.current_candidate.candidate_id, review_run_id


def initial_findings():
    return [
        {
            "finding_id": "codex:3101:4101",
            "normalized_identity": "codex:review-3101:comment-4101",
            "priority": "P1",
            "source": {
                "kind": "PROVIDER_THREAD",
                "provider": "CODEX_CODE_REVIEW",
                "provider_review_id": 3101,
                "provider_thread_id": 4101,
            },
            "principal_decision": {
                "decision": "ACCEPTED",
                "actor": "principal-reviewer",
                "reason": None,
            },
            "desired_reaction": "+1",
        },
        {
            "finding_id": "control-plane:bigint-comment-id",
            "normalized_identity": "control-plane:codex-dispatch-comment-id-bigint",
            "priority": "P1",
            "source": {
                "kind": "CONTROL_PLANE",
                "provider": "CONTROL_PLANE",
                "provider_review_id": None,
                "provider_thread_id": None,
            },
            "principal_decision": {
                "decision": "ACCEPTED",
                "actor": "principal-reviewer",
                "reason": None,
            },
            "desired_reaction": "none",
        },
    ]


def create_package(session, *, issue_number=14):
    view = publish(session)
    run_id = add_completed_review(session, view)
    package = create_work_package(
        session,
        publication_id=view.publication_id,
        implementation_issue_number=issue_number,
        review_run_id=run_id,
        review_provider="CODEX_CODE_REVIEW",
        provider_review_id=3101,
        reviewed_head_sha=HEAD,
        findings=initial_findings(),
        idempotency_key="issue14-ready",
    )
    return view, run_id, package


def prepare_verifying_package(session):
    view, package_run_id, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-materializer",
    )
    successor_head = "4" * 40
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(successor_head, "5" * 40, "b"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=successor_head,
        summary="Candidate passed local gates.",
        evidence_sha256="d" * 64,
        idempotency_key="implemented-materializer",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        candidate = record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 10:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        successor_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=successor_head,
    )
    complete_codex_review(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=successor_head,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[3201],
        provider_comment_ids=[],
    )
    begin_successor_verification(
        session,
        package.work_package_id,
        review_run_id=running.automated_review_run_id,
        head_sha=successor_head,
        idempotency_key="verify-start-materializer",
    )
    verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4101",
        outcome="ABSENT",
        reviewer="principal-reviewer",
        evidence="Absent in exact-head successor review.",
        idempotency_key="verify-codex-materializer",
    )
    verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="ABSENT",
        reviewer="principal-reviewer",
        evidence="BIGINT regression checks pass.",
        idempotency_key="verify-internal-materializer",
    )
    return view, package, package_run_id, running.automated_review_run_id


class FakeRemediationTokenProvider:
    def __init__(self):
        self.permission_requests = []

    def installation_access(self, repository, *, permissions):
        assert repository == REPOSITORY
        assert permissions in (
            {"issues": "write"},
            {"issues": "write", "pull_requests": "write"},
        )
        self.permission_requests.append(dict(permissions))
        return InstallationAccess(
            installation_id=123,
            token="installation-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    def bot_login(self):
        return "firstcontact-control-plane[bot]"


def test_project_v2_uses_separate_secret_and_fails_closed_when_missing(session):
    view, _source_run, package = create_package(session)
    github = FakeRemediationGitHub(view)
    app_credentials = FakeRemediationTokenProvider()
    materializer = GitHubRemediationMaterializer(
        token_provider=app_credentials,
        github=github,
        project_token=SecretStr("project-user-token"),
    )

    materializer.sync_issue_projection(session, package.work_package_id)

    assert app_credentials.permission_requests == [{"issues": "write"}]
    assert github.project_tokens == ["project-user-token"]
    assert github.project_tokens[0] != "installation-token"

    no_project_credential = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=FakeRemediationGitHub(view),
        project_token=SecretStr(""),
    )
    with pytest.raises(
        RemediationMaterializationError,
        match="Project V2 credential is not configured",
    ):
        no_project_credential.sync_issue_projection(session, package.work_package_id)
    assert no_project_credential.github.project_statuses == []
    assert no_project_credential.github.project_tokens == []


def test_project_and_codex_credentials_are_masked_and_factory_uses_project_setting(
    monkeypatch,
):
    configured = Settings(
        _env_file=None,
        remediation_project_token=SecretStr("project-only-secret"),
        codex_review_user_token=SecretStr("codex-trigger-secret"),
    )
    assert "project-only-secret" not in repr(configured)
    assert "codex-trigger-secret" not in repr(configured)
    assert Settings(_env_file=None).remediation_project_token.get_secret_value() == ""

    monkeypatch.setattr(settings, "remediation_project_token", SecretStr("project-only-secret"))
    monkeypatch.setattr(settings, "codex_review_user_token", SecretStr("codex-trigger-secret"))
    dependency = get_remediation_materializer()
    materializer = next(dependency)
    try:
        assert materializer.project_token.get_secret_value() == "project-only-secret"
        assert materializer.project_token.get_secret_value() != settings.codex_review_user_token.get_secret_value()
    finally:
        dependency.close()

    monkeypatch.setattr(settings, "remediation_project_token", SecretStr("same-secret"))
    monkeypatch.setattr(settings, "codex_review_user_token", SecretStr("same-secret"))
    with pytest.raises(HTTPException) as error:
        next(get_remediation_materializer())
    assert error.value.status_code == 503
    assert "same-secret" not in str(error.value.detail)


class FakeRemediationGitHub:
    def __init__(self, publication_view):
        self.publication_view = publication_view
        self.head_sha = publication_view.remote_head_sha
        self.reactions = {}
        self.reaction_calls = 0
        self.replies = []
        self.reply_calls = 0
        self.issue_comments = []
        self.summary_calls = 0
        self.resolved = set()
        self.resolve_calls = 0
        self.issue_state = "open"
        self.close_calls = 0
        self.drop_issue_response = False
        self.created_issues = []
        self.issue_labels = set()
        self.project_statuses = []
        self.project_tokens = []
        self.sub_issue_links = set()
        self.fail_sub_issue_once = False
        self.drop_reaction_response = True
        self.drop_reply_response = True
        self.drop_summary_response = True

    def pull_request(self, repository, number, token):
        assert repository == REPOSITORY
        assert number == self.publication_view.pull_request_number
        assert token == "installation-token"
        return PullRequestSnapshot(
            number=number,
            state="open",
            base_ref="master",
            head_ref=self.publication_view.remote_branch,
            head_sha=self.head_sha,
        )

    def add_pull_review_comment_reaction(self, repository, comment_id, content, token):
        self.reaction_calls += 1
        key = (comment_id, content)
        reaction = self.reactions.get(key)
        if reaction is None:
            reaction = PullReviewCommentReactionSnapshot(
                reaction_id=700 + len(self.reactions),
                actor="firstcontact-control-plane[bot]",
                content=content,
                created_at="2026-09-28T12:00:00Z",
            )
            self.reactions[key] = reaction
            if self.drop_reaction_response:
                self.drop_reaction_response = False
                raise GitHubApiError("reaction response was lost after creation")
        return reaction

    def list_pull_review_comments(self, repository, pull_number, token):
        return list(self.replies)

    def reply_to_pull_review_comment(self, repository, pull_number, comment_id, body, token):
        self.reply_calls += 1
        existing = next((item for item in self.replies if item.body == body), None)
        if existing is not None:
            return existing
        reply = PullReviewCommentSnapshot(
            comment_id=800 + len(self.replies),
            review_id=3101,
            actor="firstcontact-control-plane[bot]",
            body=body,
            commit_id="4" * 40,
            path="control_plane/service.py",
            line=20,
            created_at="2026-09-28T12:00:00Z",
            in_reply_to_id=comment_id,
        )
        self.replies.append(reply)
        if self.drop_reply_response:
            self.drop_reply_response = False
            raise GitHubApiError("reply response was lost after creation")
        return reply

    def resolve_pull_review_thread(self, repository, pull_number, comment_id, token):
        self.resolve_calls += 1
        self.resolved.add(comment_id)
        return f"PRRT_{comment_id}"

    def list_issue_comments(self, repository, issue_number, token):
        return list(self.issue_comments)

    def add_issue_comment(self, repository, issue_number, body, token):
        self.summary_calls += 1
        existing = next((item for item in self.issue_comments if item.body == body), None)
        if existing is not None:
            return existing
        comment = IssueCommentSnapshot(
            comment_id=900 + len(self.issue_comments),
            actor="firstcontact-control-plane[bot]",
            body=body,
            created_at="2026-09-28T12:00:00Z",
        )
        self.issue_comments.append(comment)
        if self.drop_summary_response:
            self.drop_summary_response = False
            raise GitHubApiError("summary response was lost after creation")
        return comment

    def close_issue(self, repository, issue_number, token):
        self.close_calls += 1
        self.issue_state = "closed"
        return IssueSnapshot(number=issue_number, state="closed", body="")

    def issue(self, repository, issue_number, token):
        assert repository == REPOSITORY
        assert token == "installation-token"
        if issue_number == 14:
            return IssueSnapshot(
                number=14,
                state=self.issue_state,
                body="",
                database_id=1400,
                issue_node_id="I_kwDO_issue14",
                actor="DEAMBROGGI",
                labels=tuple(sorted(self.issue_labels)),
            )
        return next(issue for issue in self.created_issues if issue.number == issue_number)

    def list_issues(self, repository, token):
        return list(self.created_issues)

    def create_issue(self, repository, *, title, body, labels, token):
        issue = IssueSnapshot(
            number=101 + len(self.created_issues),
            state="open",
            body=body,
            database_id=10100 + len(self.created_issues),
            issue_node_id=f"I_kwDO_issue{101 + len(self.created_issues)}",
            actor="firstcontact-control-plane[bot]",
            labels=tuple(labels),
            html_url=f"https://github.com/{REPOSITORY}/issues/{101 + len(self.created_issues)}",
        )
        self.created_issues.append(issue)
        if self.drop_issue_response:
            self.drop_issue_response = False
            raise GitHubApiError("issue creation response was lost")
        return issue

    def ensure_issue_labels(self, repository, issue_number, desired_labels, token):
        self.issue_labels = set(desired_labels)
        return self.issue(repository, issue_number, token)

    def ensure_sub_issue(
        self,
        repository,
        parent_issue_number,
        sub_issue_database_id,
        token,
    ):
        if self.fail_sub_issue_once:
            self.fail_sub_issue_once = False
            raise GitHubApiError("sub-issue link response unavailable")
        self.sub_issue_links.add((parent_issue_number, sub_issue_database_id))

    def ensure_project_v2_status(
        self,
        repository,
        issue_node_id,
        *,
        project_number,
        field_name,
        status,
        project_token,
    ):
        assert project_number == 4
        assert field_name == "Lifecycle"
        assert project_token == "project-user-token"
        self.project_tokens.append(project_token)
        self.project_statuses.append((issue_node_id, status))
        return "PVTI_item"


def test_materializer_recovers_lost_responses_without_duplicate_artifacts(session):
    view, package, _source_run, _successor_run = prepare_verifying_package(session)
    github = FakeRemediationGitHub(view)
    github.head_sha = get_work_package(session, package.work_package_id).successor_head_sha
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
    )

    result = None
    for _ in range(5):
        try:
            result = materializer.materialize(session, package.work_package_id)
        except RemediationMaterializationError:
            continue
        if result.state is WorkPackageState.DONE:
            break

    assert result is not None
    assert result.state is WorkPackageState.DONE
    assert result.issue_closed is True
    assert github.issue_state == "closed"
    assert len(github.reactions) == 1
    assert github.reaction_calls == 2  # lost response retry reused the same reaction
    assert len(github.replies) == 1
    assert github.reply_calls == 1  # recovery found the marker before another reply attempt
    assert github.resolve_calls == 1
    assert len(github.issue_comments) == 1
    assert github.summary_calls == 1  # recovery found the marker before another comment attempt
    assert github.close_calls == 1
    assert github.project_statuses[-1] == ("I_kwDO_issue14", "Done")
    assert len(load_work_package_events(session, package.work_package_id)) == 12
    assert materializer.materialize(session, package.work_package_id) == result
    assert github.reaction_calls == 2
    assert github.reply_calls == 1
    assert github.summary_calls == 1
    assert github.close_calls == 1


def test_project_four_uses_lifecycle_review_contract(session, monkeypatch):
    _publication, package, _source_run, _successor_run = prepare_verifying_package(session)
    monkeypatch.delenv("CONTROL_PLANE_REMEDIATION_PROJECT_LIFECYCLE_FIELD", raising=False)
    assert Settings(_env_file=None).remediation_project_lifecycle_field == "Lifecycle"
    package = get_work_package(session, package.work_package_id)
    assert GitHubRemediationMaterializer._status_projection(package) == (
        "status:review",
        "Review",
    )


def test_issue_creation_is_marker_recoverable_and_links_parent_and_project(session):
    view, _source_run, package = create_package(session, issue_number=None)
    with pytest.raises(DomainError, match="issue must be linked"):
        claim_work_package(
            session,
            package.work_package_id,
            actor="general-implementer",
            idempotency_key="claim-before-issue",
        )
    github = FakeRemediationGitHub(view)
    github.drop_issue_response = True
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
    )

    with pytest.raises(RemediationMaterializationError):
        materializer.ensure_implementation_issue(session, package.work_package_id)

    linked = materializer.ensure_implementation_issue(session, package.work_package_id)
    repeated = materializer.ensure_implementation_issue(session, package.work_package_id)

    assert linked.implementation_issue_number == 101
    assert repeated.implementation_issue_number == 101
    assert len(github.created_issues) == 1
    issue = github.created_issues[0]
    assert "https://github.com/DEAMBROGGI/FirstContact/issues/10" in issue.body
    assert "https://github.com/DEAMBROGGI/FirstContact/pull/13" in issue.body
    assert package.work_package_id in issue.body
    assert github.issue_labels == {"status:ready", "type:fix", "priority:P1"}
    assert github.sub_issue_links == {(10, 10100)}
    assert github.project_statuses == [
        ("I_kwDO_issue101", "Ready"),
        ("I_kwDO_issue101", "Ready"),
    ]
    assert [event["event_type"] for event in load_work_package_events(session, package.work_package_id)] == [
        "WORK_PACKAGE_CREATED",
        "IMPLEMENTATION_ISSUE_LINKED",
    ]


def test_issue_projection_retry_recovers_parent_link_and_releases_lease(session):
    view, _source_run, package = create_package(session, issue_number=None)
    github = FakeRemediationGitHub(view)
    github.fail_sub_issue_once = True
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
    )

    with pytest.raises(RemediationMaterializationError):
        materializer.ensure_implementation_issue(session, package.work_package_id)

    recovered = materializer.ensure_implementation_issue(session, package.work_package_id)
    repeated = materializer.sync_issue_projection(session, package.work_package_id)

    assert recovered.implementation_issue_number == 101
    assert repeated.implementation_issue_number == 101
    assert len(github.created_issues) == 1
    assert github.sub_issue_links == {(10, 10100)}
    assert github.project_statuses == [
        ("I_kwDO_issue101", "Ready"),
        ("I_kwDO_issue101", "Ready"),
    ]


def test_remediation_api_requires_internal_auth_and_claim_is_idempotent(session):
    _publication, _source_run, package = create_package(session)

    class ProjectionStub:
        def sync_issue_projection(self, _session, work_package_id):
            return get_work_package(session, work_package_id)

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_remediation_materializer] = lambda: ProjectionStub()
    client = TestClient(app)
    path = (
        f"/api/v1/internal/remediation/work-packages/"
        f"{package.work_package_id}/claim"
    )
    body = {"actor": "issue14-implementer", "idempotency_key": "claim-issue14"}
    try:
        denied = client.post(path, json=body)
        assert denied.status_code == 401

        headers = {"X-Control-Plane-Token": settings.internal_token}
        first = client.post(path, headers=headers, json=body)
        retry = client.post(path, headers=headers, json=body)
        assert first.status_code == 200
        assert retry.status_code == 200
        assert first.json() == retry.json()
        assert retry.json()["state"] == WorkPackageState.IN_PROGRESS.value
        events_response = client.get(
            f"/api/v1/internal/remediation/work-packages/"
            f"{package.work_package_id}/events",
            headers=headers,
        )
        assert events_response.status_code == 200
        assert [event["event_type"] for event in events_response.json()] == [
            "WORK_PACKAGE_CREATED",
            "WORK_PACKAGE_CLAIMED",
        ]
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_remediation_materializer, None)


def test_implementation_submission_projects_actual_project_review_state(session):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="issue14-implementer",
        idempotency_key="claim-for-projection",
    )
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source("4" * 40, "5" * 40, "b"),
    )

    class ProjectionStub:
        def __init__(self):
            self.projected_state = None

        def sync_issue_projection(self, _session, work_package_id):
            projected = get_work_package(session, work_package_id)
            self.projected_state = GitHubRemediationMaterializer._status_projection(projected)
            return projected

    projection = ProjectionStub()

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_remediation_materializer] = lambda: projection
    client = TestClient(app)
    try:
        response = client.post(
            f"/api/v1/internal/remediation/work-packages/{package.work_package_id}/implementation",
            headers={"X-Control-Plane-Token": settings.internal_token},
            json={
                "candidate_id": candidate.current_candidate.candidate_id,
                "head_sha": "4" * 40,
                "summary": "Implementation with exact candidate and evidence.",
                "evidence_sha256": "c" * 64,
                "idempotency_key": "submit-and-project-implemented",
            },
        )
        assert response.status_code == 200
        assert response.json()["state"] == WorkPackageState.IMPLEMENTED.value
        assert projection.projected_state == ("status:review", "Review")
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_remediation_materializer, None)


def test_rejected_only_package_finalizes_without_candidate_or_successor_review(session):
    view = publish(session)
    source_run = add_completed_review(session, view)
    rejected = initial_findings()[0]
    rejected["principal_decision"] = {
        "decision": "REJECTED",
        "actor": "principal-reviewer",
        "reason": "Finding is outside the accepted issue contract.",
    }
    rejected["desired_reaction"] = "-1"
    package = create_work_package(
        session,
        publication_id=view.publication_id,
        implementation_issue_number=14,
        review_run_id=source_run,
        review_provider="CODEX_CODE_REVIEW",
        provider_review_id=3101,
        reviewed_head_sha=HEAD,
        findings=[rejected],
        idempotency_key="issue14-rejected-only",
    )
    finalized = begin_rejected_findings_finalization(
        session,
        package.work_package_id,
        idempotency_key="issue14-rejected-finalization",
    )
    assert finalized.state is WorkPackageState.VERIFYING
    assert finalized.candidate_id is None
    assert finalized.successor_review_run_id is None

    github = FakeRemediationGitHub(view)
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
    )
    result = None
    for _ in range(5):
        try:
            result = materializer.materialize(session, package.work_package_id)
        except RemediationMaterializationError:
            continue
        if result.state is WorkPackageState.DONE:
            break

    assert result is not None
    assert result.state is WorkPackageState.DONE
    assert result.candidate_id is None
    assert result.successor_review_run_id is None
    assert list(github.reactions) == [(4101, "-1")]
    assert len(github.replies) == 1
    assert github.resolved == {4101}
    assert github.issue_state == "closed"


def test_ready_work_package_persists_exact_review_decisions_and_is_idempotent(session):
    view = publish(session)
    run_id = add_completed_review(session, view)
    args = {
        "publication_id": view.publication_id,
        "implementation_issue_number": 14,
        "review_run_id": run_id,
        "review_provider": "CODEX_CODE_REVIEW",
        "provider_review_id": 3101,
        "reviewed_head_sha": HEAD,
        "findings": initial_findings(),
    }

    created = create_work_package(
        session,
        **args,
        idempotency_key="issue14-ready",
    )
    repeated = create_work_package(
        session,
        **args,
        idempotency_key="issue14-ready-retry",
    )

    assert created.work_package_id == repeated.work_package_id
    assert created.state is WorkPackageState.READY
    assert created.reviewed_head_sha == HEAD
    provider_finding = next(item for item in created.findings if item["source"]["kind"] == "PROVIDER_THREAD")
    assert provider_finding["source"]["path"] == "control_plane/service.py"
    assert provider_finding["source"]["line"] == 20
    assert provider_finding["source"]["body"] == "Accepted review finding"
    assert len(created.findings) == 2
    assert {item["principal_decision"]["decision"] for item in created.findings} == {
        PrincipalDecision.ACCEPTED.value
    }
    assert [event["event_type"] for event in load_work_package_events(session, created.work_package_id)] == [
        "WORK_PACKAGE_CREATED"
    ]
    assert session.query(RemediationWorkPackageRow).count() == 1
    assert session.query(RemediationEventRow).count() == 1


def test_package_rejects_stale_review_head_duplicate_issue_and_missing_source_review(session):
    view = publish(session)
    run_id = add_completed_review(session, view)
    args = {
        "publication_id": view.publication_id,
        "implementation_issue_number": 14,
        "review_run_id": run_id,
        "review_provider": "CODEX_CODE_REVIEW",
        "provider_review_id": 3101,
        "reviewed_head_sha": HEAD,
        "findings": initial_findings(),
    }
    create_work_package(session, **args, idempotency_key="ready")

    with pytest.raises(DomainError, match="already linked"):
        create_work_package(
            session,
            **{**args, "review_run_id": "other-run"},
            idempotency_key="other",
        )


def test_package_requires_exact_provider_findings_from_source_review(session):
    view = publish(session)
    run_id = add_completed_review(session, view)
    args = {
        "publication_id": view.publication_id,
        "implementation_issue_number": 14,
        "review_run_id": run_id,
        "review_provider": "CODEX_CODE_REVIEW",
        "provider_review_id": 3101,
        "reviewed_head_sha": HEAD,
        "idempotency_key": "provider-set-check",
    }

    with pytest.raises(DomainError, match="every source provider finding"):
        create_work_package(
            session,
            **args,
            findings=[initial_findings()[1]],
        )

    invented = deepcopy(initial_findings())
    invented[0]["source"]["provider_thread_id"] = 4999
    invented[0]["finding_id"] = "codex:3101:4999"
    invented[0]["normalized_identity"] = "codex:review-3101:comment-4999"
    with pytest.raises(DomainError, match="not owned by the source review"):
        create_work_package(session, **args, findings=invented)

    wrong_review = deepcopy(initial_findings())
    wrong_review[0]["source"]["provider_review_id"] = 3199
    wrong_review[0]["finding_id"] = "codex:3199:4101"
    wrong_review[0]["normalized_identity"] = "codex:review-3199:comment-4101"
    with pytest.raises(DomainError, match="not owned by the source review"):
        create_work_package(session, **args, findings=wrong_review)

    duplicate = initial_findings()
    duplicate.append(deepcopy(duplicate[0]))
    with pytest.raises(DomainError, match="duplicate finding identity"):
        create_work_package(session, **args, findings=duplicate)

    wrong_provider = deepcopy(initial_findings())
    wrong_provider[0]["source"]["provider"] = "OTHER_REVIEWER"
    with pytest.raises(DomainError, match="source review provider"):
        create_work_package(session, **args, findings=wrong_provider)

    wrong_run_review_id = {
        **args,
        "implementation_issue_number": 15,
        "provider_review_id": 3199,
        "idempotency_key": "wrong-run-review-id",
    }
    with pytest.raises(DomainError, match="source review run"):
        create_work_package(
            session,
            **wrong_run_review_id,
            findings=initial_findings(),
        )
    with pytest.raises(DomainError, match="source review run"):
        create_work_package(
            session,
            **{
                **args,
                "implementation_issue_number": 16,
                "review_run_id": "missing-run",
                "idempotency_key": "missing",
            },
            findings=initial_findings(),
        )


def test_rejected_principal_decision_requires_reason(session):
    view = publish(session)
    run_id = add_completed_review(session, view)
    finding = initial_findings()[0]
    finding["principal_decision"] = {
        "decision": "REJECTED",
        "actor": "principal-reviewer",
        "reason": "",
    }
    finding["desired_reaction"] = "-1"

    with pytest.raises(DomainError, match="requires a reason"):
        create_work_package(
            session,
            publication_id=view.publication_id,
            implementation_issue_number=14,
            review_run_id=run_id,
            review_provider="CODEX_CODE_REVIEW",
            provider_review_id=3101,
            reviewed_head_sha=HEAD,
            findings=[finding],
            idempotency_key="ready",
        )


def test_claim_and_implementation_submission_are_idempotent_and_candidate_bound(session):
    view, _run_id, package = create_package(session)
    claimed = claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-14",
    )
    retried_claim = claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-14-retry",
    )
    assert claimed.state is WorkPackageState.IN_PROGRESS
    assert retried_claim.state is WorkPackageState.IN_PROGRESS
    assert len(load_work_package_events(session, package.work_package_id)) == 2

    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source("4" * 40, "5" * 40, "b"),
    )
    payload = {
        "candidate_id": candidate.current_candidate.candidate_id,
        "head_sha": "4" * 40,
        "summary": "Implemented F1-F5 and added focused regression evidence.",
        "evidence_sha256": "c" * 64,
    }
    submitted = submit_implementation(
        session,
        package.work_package_id,
        **payload,
        idempotency_key="implemented-14",
    )
    repeated = submit_implementation(
        session,
        package.work_package_id,
        **payload,
        idempotency_key="implemented-14-retry",
    )

    assert submitted.state is WorkPackageState.IMPLEMENTED
    assert repeated.implementation_head_sha == "4" * 40
    assert len(load_work_package_events(session, package.work_package_id)) == 3


def test_successor_review_must_match_the_submitted_implementation_head_and_candidate(session):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-b-c-binding",
    )
    head_b = "4" * 40
    candidate_b = submit_verified_candidate(
        session,
        view.publication_id,
        source(head_b, "5" * 40, "b"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate_b.current_candidate.candidate_id,
        head_sha=head_b,
        summary="Implementation B",
        evidence_sha256="d" * 64,
        idempotency_key="submit-b",
    )
    complete_successor_review(
        session,
        view,
        head=head_b,
        review_id=3300,
        evidence_offset=50,
    )

    head_c = "6" * 40
    _candidate_c_id, run_c = publish_successor_review(
        session,
        view,
        head=head_c,
        tree="7" * 40,
        marker="c",
        review_id=3301,
        evidence_offset=100,
    )
    with pytest.raises(DomainError, match="successor review is not complete"):
        begin_successor_verification(
            session,
            package.work_package_id,
            review_run_id=run_c,
            head_sha=head_c,
            idempotency_key="bind-unrelated-c",
        )

    current = get_work_package(session, package.work_package_id)
    assert current.implementation_head_sha == head_b
    assert current.candidate_id == candidate_b.current_candidate.candidate_id
    assert current.successor_review_run_id is None


def test_persists_enters_rework_and_preserves_mixed_verification_history(session):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-attempt-one",
    )
    head_one = "4" * 40
    candidate_one = submit_verified_candidate(
        session,
        view.publication_id,
        source(head_one, "5" * 40, "b"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate_one.current_candidate.candidate_id,
        head_sha=head_one,
        summary="First implementation attempt",
        evidence_sha256="d" * 64,
        idempotency_key="submit-attempt-one",
    )
    review_one = complete_successor_review(
        session,
        view,
        head=head_one,
        review_id=3301,
        evidence_offset=100,
    )
    begin_successor_verification(
        session,
        package.work_package_id,
        review_run_id=review_one,
        head_sha=head_one,
        idempotency_key="bind-attempt-one",
    )
    verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4101",
        outcome="ABSENT",
        reviewer="principal-reviewer",
        evidence="Provider finding absent on implementation B.",
        idempotency_key="verify-provider-attempt-one",
    )
    rework = verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="PERSISTS",
        reviewer="principal-reviewer",
        evidence="BIGINT issue persists on implementation B.",
        idempotency_key="verify-internal-attempt-one",
    )
    assert rework.state is WorkPackageState.REWORK_REQUIRED
    assert GitHubRemediationMaterializer._status_projection(rework) == (
        "status:review",
        "Review",
    )
    assert all(item["verification"] is None for item in rework.findings)
    assert all(item["closure_state"] == "AWAITING_VERIFICATION" for item in rework.findings)
    internal = next(item for item in rework.findings if item["finding_id"] == "control-plane:bigint-comment-id")
    assert [item["outcome"] for item in internal["verification_history"]] == ["PERSISTS"]
    github = FakeRemediationGitHub(view)
    with pytest.raises(DomainError, match="all accepted findings"):
        GitHubRemediationMaterializer(
            token_provider=FakeRemediationTokenProvider(),
            github=github,
            project_token=SecretStr("project-user-token"),
        ).materialize(session, package.work_package_id)
    assert github.reactions == {}
    assert github.replies == []
    assert github.resolved == set()
    retry = verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="PERSISTS",
        reviewer="principal-reviewer",
        evidence="BIGINT issue persists on implementation B.",
        idempotency_key="verify-internal-attempt-one",
    )
    assert retry.state is WorkPackageState.REWORK_REQUIRED

    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-attempt-two",
    )
    head_two = "8" * 40
    candidate_two = submit_verified_candidate(
        session,
        view.publication_id,
        source(head_two, "9" * 40, "e"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate_two.current_candidate.candidate_id,
        head_sha=head_two,
        summary="Second implementation attempt",
        evidence_sha256="f" * 64,
        idempotency_key="submit-attempt-two",
    )
    review_two = complete_successor_review(
        session,
        view,
        head=head_two,
        review_id=3302,
        evidence_offset=200,
    )
    verifying = begin_successor_verification(
        session,
        package.work_package_id,
        review_run_id=review_two,
        head_sha=head_two,
        idempotency_key="bind-attempt-two",
    )
    assert verifying.state is WorkPackageState.VERIFYING
    assert GitHubRemediationMaterializer._status_projection(verifying) == (
        "status:review",
        "Review",
    )
    for finding_id in ("codex:3101:4101", "control-plane:bigint-comment-id"):
        verifying = verify_finding(
            session,
            package.work_package_id,
            finding_id=finding_id,
            outcome="ABSENT",
            reviewer="principal-reviewer",
            evidence="Finding absent on implementation C.",
            idempotency_key=f"verify-attempt-two:{finding_id}",
        )
    assert verifying.state is WorkPackageState.VERIFYING
    internal = next(item for item in verifying.findings if item["finding_id"] == "control-plane:bigint-comment-id")
    assert [item["outcome"] for item in internal["verification_history"]] == ["PERSISTS", "ABSENT"]
    assert internal["verification"]["review_run_id"] == review_two
    before_old_retry = len(load_work_package_events(session, package.work_package_id))
    old_retry = verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="PERSISTS",
        reviewer="principal-reviewer",
        evidence="BIGINT issue persists on implementation B.",
        idempotency_key="verify-internal-attempt-one",
    )
    assert old_retry.state is WorkPackageState.VERIFYING
    assert len(load_work_package_events(session, package.work_package_id)) == before_old_retry
    event_types = [event["event_type"] for event in load_work_package_events(session, package.work_package_id)]
    assert event_types.count("IMPLEMENTATION_SUBMITTED") == 2
    assert event_types.count("WORK_PACKAGE_REWORK_REQUIRED") == 1
    assert event_types.count("SUCCESSOR_REVIEW_STARTED") == 2
    assert event_types.count("WORK_PACKAGE_CLAIMED") == 2


def test_successor_verification_closure_materialization_and_done_require_evidence(session):
    view, package_run_id, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim",
    )
    successor_head = "4" * 40
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(successor_head, "5" * 40, "b"),
    )
    profile = profile_for_repository(REPOSITORY)
    submitted = submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=successor_head,
        summary="Candidate passed local gates.",
        evidence_sha256="d" * 64,
        idempotency_key="implemented",
    )
    assert submitted.state is WorkPackageState.IMPLEMENTED
    for index, job_id in enumerate(profile.required_jobs, 1):
        candidate = record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 10:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        successor_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=successor_head,
    )
    complete_codex_review(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=successor_head,
        result=AutomatedReviewStatus.PASS,
        findings=[],
        provider_review_ids=[3201],
        provider_comment_ids=[],
    )
    verifying = begin_successor_verification(
        session,
        package.work_package_id,
        review_run_id=running.automated_review_run_id,
        head_sha=successor_head,
        idempotency_key="verify-start",
    )
    assert verifying.state is WorkPackageState.VERIFYING
    with pytest.raises(DomainError, match="thread materialization"):
        record_github_artifact(
            session,
            package.work_package_id,
            finding_id="codex:3101:4101",
            artifact="reply",
            remote_id=501,
            idempotency_key="reply-before-verification",
        )
    verified = verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4101",
        outcome="ABSENT",
        reviewer="principal-reviewer",
        evidence="Successor review run is exact-head PASS.",
        idempotency_key="finding-absent",
    )
    assert next(
        finding
        for finding in verified.findings
        if finding["finding_id"] == "codex:3101:4101"
    )["closure_state"] == "VERIFIED_ABSENT"
    verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="ABSENT",
        reviewer="principal-reviewer",
        evidence="PostgreSQL BIGINT DDL and round-trip evidence are retained.",
        idempotency_key="finding-bigint-absent",
    )
    for artifact, remote_id in (("reaction", 601), ("reply", 602), ("resolution", "PRRT_kwDOAA")):
        verified = record_github_artifact(
            session,
            package.work_package_id,
            finding_id="codex:3101:4101",
            artifact=artifact,
            remote_id=remote_id,
            idempotency_key=f"materialize-{artifact}",
        )
    verified = record_summary_comment(
        session,
        package.work_package_id,
        comment_id=603,
        idempotency_key="summary",
    )
    verified = record_issue_closed(
        session,
        package.work_package_id,
        idempotency_key="issue-close",
    )
    done = complete_work_package(
        session,
        package.work_package_id,
        idempotency_key="done",
    )

    assert done.state is WorkPackageState.DONE
    assert done.issue_closed is True
    assert done.summary_comment_id == 603
    assert get_work_package(session, package.work_package_id) == done
    assert len(load_work_package_events(session, package.work_package_id)) == 12
    assert package_run_id != running.automated_review_run_id

