import subprocess
from types import SimpleNamespace

from fastapi.testclient import TestClient

from control_plane.config import settings
from control_plane.db import get_session
from control_plane.domain import (
    EventType,
    PublicationState,
    ReviewDecision,
    ValidationStatus,
)
from control_plane.github_api import PullRequestSnapshot, PullReviewSnapshot
from control_plane.github_webhook import (
    GitHubWebhookGateway,
    get_review_watch,
    sync_review_watch,
)
from control_plane.main import (
    app,
    get_github_authoritative_gateway,
    get_merge_coordinator,
    get_quarantine,
)
from control_plane.merge import MergeCoordinator
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import (
    BASE_REF,
    HEAD_REF,
    GitCandidateQuarantine,
    VerifiedCandidateSource,
)
from control_plane.repository import load_events
from control_plane.service import (
    create_publication,
    get_view,
    mark_remote_published,
    record_mergeability,
    record_review,
    record_validation,
    submit_verified_candidate,
)


MERGE_REPOSITORY = "DEAMBROGGI/FirstContact"
MERGE_BASE = "1" * 40
MERGE_HEAD = "2" * 40
MERGE_TREE = "3" * 40
MERGE_COMMIT = "4" * 40
MERGE_BRANCH = "control-plane/issue-22-canonical"
MERGE_PR_NUMBER = 13


def git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def candidate_bundle(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    git(repo, "config", "user.email", "api-test@example.invalid")
    git(repo, "config", "user.name", "API Test")
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "file.txt")
    git(repo, "commit", "--quiet", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "update-ref", BASE_REF, base)
    (repo / "file.txt").write_text("base\nhead\n", encoding="utf-8")
    git(repo, "add", "file.txt")
    git(repo, "commit", "--quiet", "-m", "head")
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "update-ref", HEAD_REF, head)
    bundle = tmp_path / "candidate.bundle"
    git(repo, "bundle", "create", str(bundle), BASE_REF, HEAD_REF)
    return bundle.read_bytes(), head


def merge_publication(session, issue_number, *, ready=True):
    source = VerifiedCandidateSource(
        bundle_sha256="a" * 64,
        byte_length=100,
        quarantine_id="a" * 64,
        base_sha=MERGE_BASE,
        head_sha=MERGE_HEAD,
        tree_sha=MERGE_TREE,
    )
    view = create_publication(session, MERGE_REPOSITORY, issue_number)
    view = submit_verified_candidate(session, view.publication_id, source)
    profile = profile_for_repository(MERGE_REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )
    view = mark_remote_published(
        session,
        view.publication_id,
        MERGE_HEAD,
        branch=MERGE_BRANCH,
        base_branch="master",
        pull_request_number=MERGE_PR_NUMBER,
    )
    view = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=MERGE_HEAD,
        decision=ReviewDecision.APPROVED,
        github_review_id=701,
    )
    if ready:
        view = record_mergeability(
            session,
            view.publication_id,
            head_sha=MERGE_HEAD,
            mergeable=True,
        )
    return view


class MergeApiTokenProvider:
    def installation_access(self, repository, *, permissions=None):
        assert repository == MERGE_REPOSITORY
        return SimpleNamespace(token="installation-token")


class MergeApiGitHub:
    def __init__(self, reviews=(), *, merged=False):
        self.reviews = tuple(reviews)
        self.merged = merged
        self.merge_calls = []

    def pull_request(self, repository, number, token):
        assert repository == MERGE_REPOSITORY
        assert number == MERGE_PR_NUMBER
        assert token == "installation-token"
        return PullRequestSnapshot(
            number=MERGE_PR_NUMBER,
            state="closed" if self.merged else "open",
            base_ref="master",
            head_ref=MERGE_BRANCH,
            head_sha=MERGE_HEAD,
            merged=self.merged,
            merge_commit_sha=MERGE_COMMIT if self.merged else None,
            mergeable=True,
        )

    def pull_request_merged(self, repository, number, token):
        assert repository == MERGE_REPOSITORY
        assert number == MERGE_PR_NUMBER
        assert token == "installation-token"
        return self.merged

    def pull_request_merge_event(self, repository, number, token):
        assert repository == MERGE_REPOSITORY
        assert number == MERGE_PR_NUMBER
        assert token == "installation-token"
        return SimpleNamespace(commit_id=MERGE_COMMIT) if self.merged else None

    def ref_sha(self, repository, branch, token):
        assert repository == MERGE_REPOSITORY
        assert branch == "master"
        assert token == "installation-token"
        return MERGE_BASE

    def list_pull_reviews(self, repository, number, token):
        assert repository == MERGE_REPOSITORY
        assert number == MERGE_PR_NUMBER
        assert token == "installation-token"
        return self.reviews

    def merge_pull_request(
        self,
        repository,
        number,
        *,
        expected_head_sha,
        token,
        merge_method,
    ):
        assert repository == MERGE_REPOSITORY
        assert number == MERGE_PR_NUMBER
        assert expected_head_sha == MERGE_HEAD
        assert token == "installation-token"
        self.merge_calls.append(merge_method)
        self.merged = True
        return MERGE_COMMIT


def merge_endpoint_client(session, github, *, human_review_actors=("DEAMBROGGI",)):
    token_provider = MergeApiTokenProvider()
    coordinator = MergeCoordinator(
        token_provider=token_provider,
        github=github,
    )
    gateway = GitHubWebhookGateway(
        token_provider=token_provider,
        github=github,
        codex_review_mode="disabled",
        codex_actors=(),
        human_review_actors=human_review_actors,
        webhook_secret=None,
        maximum_payload_bytes=1024 * 1024,
    )

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_merge_coordinator] = lambda: coordinator
    app.dependency_overrides[get_github_authoritative_gateway] = lambda: gateway
    return TestClient(app)


def test_api_creates_verified_candidate_and_keeps_publisher_disabled(
    session,
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(settings, "publisher_mode", "disabled")
    def override_session():
        yield session

    quarantine = GitCandidateQuarantine(
        tmp_path / "quarantine",
        max_bundle_bytes=5_000_000,
    )

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_quarantine] = lambda: quarantine
    client = TestClient(app)
    headers = {"X-Control-Plane-Token": settings.internal_token}
    bundle_bytes, head = candidate_bundle(tmp_path)
    try:
        created = client.post(
            "/api/v1/publications",
            headers=headers,
            json={"repository": "DEAMBROGGI/FirstContact", "issue_number": 51},
        )
        assert created.status_code == 200
        publication_id = created.json()["publication_id"]

        candidate = client.post(
            f"/api/v1/publications/{publication_id}/candidate-bundle",
            headers=headers,
            files={
                "bundle": (
                    "candidate.bundle",
                    bundle_bytes,
                    "application/x-git-bundle",
                )
            },
        )
        assert candidate.status_code == 200
        assert candidate.json()["state"] == "VALIDATING"
        assert candidate.json()["current_candidate"]["head_sha"] == head

        old_endpoint = client.post(
            f"/api/v1/publications/{publication_id}/candidates",
            headers=headers,
            json={"base_sha": "1" * 40, "head_sha": "2" * 40, "tree_sha": "3" * 40},
        )
        assert old_endpoint.status_code == 404
        published = client.post(
            f"/api/v1/internal/publications/{publication_id}/publish",
            headers=headers,
        )
        assert published.status_code == 503
        assert published.json()["detail"] == "publisher is disabled"
    finally:
        app.dependency_overrides.clear()


def test_merge_endpoints_are_plane_coordinator_commands(session):
    publication = create_publication(
        session,
        "DEAMBROGGI/FirstContact",
        522,
    )

    class FakeMergeCoordinator:
        def __init__(self):
            self.calls = []

        def merge(self, supplied_session, publication_id):
            assert supplied_session is session
            self.calls.append(("merge", publication_id))
            return get_view(session, publication_id)

        def reconcile(self, supplied_session, publication_id):
            assert supplied_session is session
            self.calls.append(("reconcile", publication_id))
            return get_view(session, publication_id)

    class FakeAuthoritativeGateway:
        def authorize_merge(self, supplied_session, publication_id):
            assert supplied_session is session
            coordinator.calls.append(("authorize", publication_id))

        def reconcile_publication(self, supplied_session, publication_id):
            assert supplied_session is session
            coordinator.calls.append(("gateway_reconcile", publication_id))
            return SimpleNamespace(outcome="RECONCILED")

    coordinator = FakeMergeCoordinator()

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_merge_coordinator] = lambda: coordinator
    app.dependency_overrides[get_github_authoritative_gateway] = (
        lambda: FakeAuthoritativeGateway()
    )
    client = TestClient(app)
    headers = {"X-Control-Plane-Token": settings.internal_token}

    try:
        merged = client.post(
            f"/api/v1/internal/publications/{publication.publication_id}/merge",
            headers=headers,
        )
        assert merged.status_code == 200

        reconciled = client.post(
            (
                f"/api/v1/internal/publications/{publication.publication_id}"
                "/merge/reconcile"
            ),
            headers=headers,
        )
        assert reconciled.status_code == 200

        assert coordinator.calls == [
            ("authorize", publication.publication_id),
            ("merge", publication.publication_id),
            ("gateway_reconcile", publication.publication_id),
        ]
    finally:
        app.dependency_overrides.clear()


def test_merge_endpoint_reconciles_dismissed_approval_before_write(session):
    view = merge_publication(session, 522)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=("DEAMBROGGI",),
        codex_review_mode="disabled",
    )
    github = MergeApiGitHub(
        [
            PullReviewSnapshot(
                review_id=701,
                actor="DEAMBROGGI",
                body="",
                state="DISMISSED",
                commit_id=MERGE_HEAD,
                submitted_at="2026-10-02T12:00:00Z",
            )
        ]
    )
    client = merge_endpoint_client(session, github)
    try:
        response = client.post(
            f"/api/v1/internal/publications/{view.publication_id}/merge",
            headers={"X-Control-Plane-Token": settings.internal_token},
        )

        assert response.status_code == 409
        assert (
            get_view(session, view.publication_id).state
            is not PublicationState.READY_TO_MERGE
        )
        assert github.merge_calls == []
    finally:
        app.dependency_overrides.clear()


def test_merge_endpoint_keeps_same_generation_stale_watch_blocked(session):
    view = merge_publication(session, 523)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=("DEAMBROGGI",),
        state="STALE",
        codex_review_mode="disabled",
    )
    github = MergeApiGitHub(
        [
            PullReviewSnapshot(
                review_id=701,
                actor="DEAMBROGGI",
                body="",
                state="APPROVED",
                commit_id=MERGE_HEAD,
                submitted_at="2026-10-02T12:00:00Z",
            )
        ]
    )
    client = merge_endpoint_client(session, github)
    try:
        response = client.post(
            f"/api/v1/internal/publications/{view.publication_id}/merge",
            headers={"X-Control-Plane-Token": settings.internal_token},
        )

        watch = get_review_watch(session, view.publication_id)
        assert response.status_code == 409
        assert (
            get_view(session, view.publication_id).state
            is PublicationState.READY_TO_MERGE
        )
        assert watch.state == "STALE"
        assert watch.next_role == "CONTROL_PLANE"
        assert watch.next_action == "BLOCKED"
        assert github.merge_calls == []
    finally:
        app.dependency_overrides.clear()


def test_merge_endpoint_accepts_active_approval_and_ignores_comment_review(session):
    view = merge_publication(session, 524)
    sync_review_watch(
        session,
        view.publication_id,
        expected_actors=("DEAMBROGGI",),
        codex_review_mode="disabled",
    )
    github = MergeApiGitHub(
        [
            PullReviewSnapshot(
                review_id=701,
                actor="DEAMBROGGI",
                body="approved",
                state="APPROVED",
                commit_id=MERGE_HEAD,
                submitted_at="2026-10-02T12:00:00Z",
            ),
            PullReviewSnapshot(
                review_id=702,
                actor="DEAMBROGGI",
                body="follow-up comment",
                state="COMMENTED",
                commit_id=MERGE_HEAD,
                submitted_at="2026-10-02T12:01:00Z",
            ),
        ]
    )
    client = merge_endpoint_client(session, github)
    try:
        response = client.post(
            f"/api/v1/internal/publications/{view.publication_id}/merge",
            headers={"X-Control-Plane-Token": settings.internal_token},
        )

        assert response.status_code == 200, response.text
        assert response.json()["state"] == PublicationState.MERGED.value
        assert github.merge_calls == ["merge"]
    finally:
        app.dependency_overrides.clear()


def test_merge_endpoint_blocks_active_changes_requested_by_allowlisted_actor(session):
    view = merge_publication(session, 525)
    github = MergeApiGitHub(
        [
            PullReviewSnapshot(
                review_id=701,
                actor="DEAMBROGGI",
                body="approved",
                state="APPROVED",
                commit_id=MERGE_HEAD,
                submitted_at="2026-10-02T12:00:00Z",
            ),
            PullReviewSnapshot(
                review_id=702,
                actor="second-reviewer",
                body="changes requested",
                state="CHANGES_REQUESTED",
                commit_id=MERGE_HEAD,
                submitted_at="2026-10-02T12:01:00Z",
            ),
        ]
    )
    client = merge_endpoint_client(
        session,
        github,
        human_review_actors=("DEAMBROGGI", "second-reviewer"),
    )
    try:
        response = client.post(
            f"/api/v1/internal/publications/{view.publication_id}/merge",
            headers={"X-Control-Plane-Token": settings.internal_token},
        )

        assert response.status_code == 409
        assert (
            get_view(session, view.publication_id).state
            is PublicationState.CHANGES_REQUIRED
        )
        assert github.merge_calls == []
    finally:
        app.dependency_overrides.clear()


def test_merge_reconcile_syncs_watch_after_recording_policy_violation(session):
    view = merge_publication(session, 526, ready=False)
    github = MergeApiGitHub(merged=True)
    client = merge_endpoint_client(session, github)
    try:
        response = client.post(
            f"/api/v1/internal/publications/{view.publication_id}/merge/reconcile",
            headers={"X-Control-Plane-Token": settings.internal_token},
        )

        watch = get_review_watch(session, view.publication_id)
        violation_events = [
            event
            for event in load_events(session, view.publication_id)
            if event["event_type"] == EventType.MERGE_POLICY_VIOLATION.value
        ]
        assert response.status_code == 502
        assert response.json() == {"detail": "merge reconciliation failed closed"}
        assert len(violation_events) == 1
        assert watch.next_role == "CONTROL_PLANE"
        assert watch.next_action == "BLOCKED"
    finally:
        app.dependency_overrides.clear()
