from __future__ import annotations

import io
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from control_plane.domain import DomainError, PublicationState, ValidationStatus
from control_plane.github_api import PullRequestSnapshot, RepositorySnapshot
from control_plane.github_app import InstallationAccess
from control_plane.models import CandidateSourceRow
from control_plane.profile_registry import profile_for_repository
from control_plane.publisher import GitHubPublisher, GitPushTransport, PublicationError
from control_plane.quarantine import BASE_REF, HEAD_REF, GitCandidateQuarantine
from control_plane.repository import load_events
from control_plane.service import (
    create_publication,
    get_view,
    record_validation,
    submit_verified_candidate,
)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def admitted_publication(session, tmp_path):
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    subprocess.run(["git", "init", "--quiet", str(source_repo)], check=True)
    git(source_repo, "config", "user.email", "publisher@example.invalid")
    git(source_repo, "config", "user.name", "Publisher Test")
    (source_repo / "file.txt").write_text("base\n", encoding="utf-8")
    git(source_repo, "add", "file.txt")
    git(source_repo, "commit", "--quiet", "-m", "base")
    base = git(source_repo, "rev-parse", "HEAD")
    git(source_repo, "update-ref", BASE_REF, base)
    (source_repo / "file.txt").write_text("base\nhead\n", encoding="utf-8")
    git(source_repo, "add", "file.txt")
    git(source_repo, "commit", "--quiet", "-m", "head")
    head = git(source_repo, "rev-parse", "HEAD")
    git(source_repo, "update-ref", HEAD_REF, head)
    bundle = tmp_path / "candidate.bundle"
    git(source_repo, "bundle", "create", str(bundle), BASE_REF, HEAD_REF)

    quarantine = GitCandidateQuarantine(
        tmp_path / "quarantine",
        max_bundle_bytes=5_000_000,
    )
    with bundle.open("rb") as stream:
        source = quarantine.import_stream(stream)
    view = create_publication(session, "DEAMBROGGI/FirstContact", 77)
    view = submit_verified_candidate(session, view.publication_id, source)
    profile = profile_for_repository(view.repository)
    for index, job in enumerate(profile.required_jobs, 1):
        view = record_validation(
            session,
            view.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index:064x}",
        )
    assert view.state is PublicationState.ADMITTED
    return view, quarantine, source
class FakeTokenProvider:
    def installation_access(self, repository):
        assert repository == "DEAMBROGGI/FirstContact"
        return InstallationAccess(
            installation_id=123,
            token="installation-secret",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )


class FakeGateway:
    def __init__(self, *, base_sha, head_sha):
        self.base_sha = base_sha
        self.head_sha = head_sha
        self.target_sha = None
        self.pull_number = 31

    def repository(self, repository, token):
        assert token == "installation-secret"
        return RepositorySnapshot(default_branch="master")

    def ref_sha(self, repository, branch, token):
        assert token == "installation-secret"
        if branch == "master":
            return self.base_sha
        return self.target_sha

    def ensure_pull_request(
        self,
        repository,
        *,
        base_branch,
        head_branch,
        expected_head_sha,
        issue_number,
        token,
    ):
        assert base_branch == "master"
        assert expected_head_sha == self.head_sha
        assert issue_number == 77
        return PullRequestSnapshot(
            number=self.pull_number,
            state="open",
            base_ref=base_branch,
            head_ref=head_branch,
            head_sha=expected_head_sha,
        )


class FakePush:
    def __init__(self, gateway, expected_head):
        self.gateway = gateway
        self.expected_head = expected_head
        self.calls = 0

    def push_exact_head(self, **kwargs):
        assert kwargs["token"] == "installation-secret"
        self.calls += 1
        self.gateway.target_sha = self.expected_head
def publisher_for(view, quarantine, source, gateway=None):
    gateway = gateway or FakeGateway(
        base_sha=view.current_candidate.base_sha,
        head_sha=view.current_candidate.head_sha,
    )
    push = FakePush(gateway, view.current_candidate.head_sha)
    publisher = GitHubPublisher(
        token_provider=FakeTokenProvider(),
        github=gateway,
        quarantine=quarantine,
        git_push=push,
    )
    return publisher, gateway, push


def test_exact_publish_records_readback_metadata_and_retry_is_idempotent(
    session,
    tmp_path,
):
    view, quarantine, source = admitted_publication(session, tmp_path)
    publisher, gateway, push = publisher_for(view, quarantine, source)

    published = publisher.publish(session, view.publication_id)

    assert published.state is PublicationState.IN_REVIEW
    assert published.remote_head_sha == view.current_candidate.head_sha
    assert published.remote_branch.startswith("control-plane/issue-77-")
    assert published.base_branch == "master"
    assert published.pull_request_number == 31
    assert push.calls == 1

    retried = publisher.publish(session, view.publication_id)
    assert retried == published
    assert push.calls == 1

    events = load_events(session, view.publication_id)
    remote_events = [
        event for event in events if event["event_type"] == "REMOTE_PUBLISHED"
    ]
    assert len(remote_events) == 1
    assert "installation-secret" not in str(remote_events[0])


def test_stale_remote_base_fails_before_push(session, tmp_path):
    view, quarantine, source = admitted_publication(session, tmp_path)
    gateway = FakeGateway(
        base_sha="f" * 40,
        head_sha=view.current_candidate.head_sha,
    )
    publisher, _gateway, push = publisher_for(
        view,
        quarantine,
        source,
        gateway=gateway,
    )

    with pytest.raises(PublicationError, match="remote base moved"):
        publisher.publish(session, view.publication_id)

    assert push.calls == 0
    assert get_view(session, view.publication_id).state is PublicationState.ADMITTED
def test_branch_collision_fails_closed(session, tmp_path):
    view, quarantine, source = admitted_publication(session, tmp_path)
    publisher, gateway, push = publisher_for(view, quarantine, source)
    gateway.target_sha = "e" * 40

    with pytest.raises(PublicationError, match="branch collision"):
        publisher.publish(session, view.publication_id)

    assert push.calls == 0


def test_non_admitted_publication_cannot_publish(session, tmp_path):
    admitted, quarantine, source = admitted_publication(session, tmp_path)
    created = create_publication(session, "DEAMBROGGI/FirstContact", 78)
    validating = submit_verified_candidate(session, created.publication_id, source)
    assert validating.state is PublicationState.VALIDATING
    publisher, _gateway, _push = publisher_for(admitted, quarantine, source)

    with pytest.raises(DomainError, match="ADMITTED"):
        publisher.publish(session, created.publication_id)


def test_git_push_keeps_token_out_of_process_arguments(monkeypatch, tmp_path):
    repo = tmp_path / "bare.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(repo)], check=True)
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = list(args)
        captured["env"] = dict(kwargs["env"])
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "super-secret-database-url")
    monkeypatch.setattr("control_plane.publisher.subprocess.run", fake_run)

    GitPushTransport().push_exact_head(
        repo_path=repo,
        repository="DEAMBROGGI/FirstContact",
        branch="control-plane/issue-77-abcdef12",
        token="installation-secret",
    )

    joined = " ".join(captured["args"])
    assert "installation-secret" not in joined
    assert "--force" not in captured["args"]
    assert captured["env"]["CONTROL_PLANE_GIT_TOKEN"] == "installation-secret"
    assert "CONTROL_PLANE_DATABASE_URL" not in captured["env"]
    assert (
        captured["args"][-1]
        == "refs/controlplane/head:refs/heads/control-plane/issue-77-abcdef12"
    )


def test_missing_candidate_source_fails_closed(session, tmp_path):
    view, quarantine, source = admitted_publication(session, tmp_path)
    candidate_id = view.current_candidate.candidate_id
    row = session.get(CandidateSourceRow, candidate_id)
    session.delete(row)
    session.commit()
    publisher, _gateway, push = publisher_for(view, quarantine, source)

    with pytest.raises(PublicationError, match="immutable quarantine source"):
        publisher.publish(session, view.publication_id)

    assert push.calls == 0
    assert get_view(session, view.publication_id).state is PublicationState.ADMITTED


def test_corrupt_quarantine_bundle_fails_closed(session, tmp_path):
    view, quarantine, source = admitted_publication(session, tmp_path)
    bundle_path = (
        quarantine.root
        / "bundles"
        / source.quarantine_id[:2]
        / f"{source.quarantine_id}.bundle"
    )
    bundle_path.write_bytes(b"corrupt")
    publisher, _gateway, push = publisher_for(view, quarantine, source)

    with pytest.raises(PublicationError, match="quarantine verification"):
        publisher.publish(session, view.publication_id)

    assert push.calls == 0
    assert get_view(session, view.publication_id).state is PublicationState.ADMITTED
