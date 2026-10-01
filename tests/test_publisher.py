from __future__ import annotations

import io
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from control_plane.domain import DomainError, PublicationState, ValidationStatus
from control_plane.github_api import (
    GitHubApiError,
    PullRequestSnapshot,
    RepositorySnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.models import CandidateSourceRow
from control_plane.profile_registry import profile_for_repository
from control_plane.publisher import GitHubPublisher, GitPushTransport, PublicationError
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


def admitted_publication(session, tmp_path, issue_number=77):
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
    view = create_publication(session, "DEAMBROGGI/FirstContact", issue_number)
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
        self.base_sha_reads = []
        self.head_sha = head_sha
        self.target_sha = None
        self.pull_number = 31
        self.returned_pull_number = None
        self.pull_state = "open"
        self.pull_missing = False
        self.pull_head_ref = None
        self.pull_base_ref = None
        self.pull_head_sha = None
        self.ensure_calls = 0
        self.pull_request_calls = 0
        self.target_sha_reads = []
        self.pull_responses = []

    def repository(self, repository, token):
        assert token == "installation-secret"
        return RepositorySnapshot(default_branch="master")

    def ref_sha(self, repository, branch, token):
        assert token == "installation-secret"
        if branch == "master":
            if self.base_sha_reads:
                return self.base_sha_reads.pop(0)
            return self.base_sha
        if self.target_sha_reads:
            return self.target_sha_reads.pop(0)
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
        self.ensure_calls += 1
        assert base_branch == "master"
        assert expected_head_sha == self.head_sha
        assert issue_number == 77
        self.pull_head_ref = head_branch
        self.pull_base_ref = base_branch
        self.pull_head_sha = expected_head_sha
        return PullRequestSnapshot(
            number=self.pull_number,
            state="open",
            base_ref=base_branch,
            head_ref=head_branch,
            head_sha=expected_head_sha,
        )

    def pull_request(self, repository, number, token):
        self.pull_request_calls += 1
        assert number == self.pull_number
        if self.pull_responses:
            response = self.pull_responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        if self.pull_missing:
            raise GitHubApiError("pull request not found")
        return PullRequestSnapshot(
            number=self.returned_pull_number or self.pull_number,
            state=self.pull_state,
            base_ref=self.pull_base_ref or "master",
            head_ref=self.pull_head_ref or "control-plane/issue-77-canonical",
            head_sha=self.pull_head_sha or self.head_sha,
        )


class FakePush:
    def __init__(self, gateway, expected_head):
        self.gateway = gateway
        self.expected_head = expected_head
        self.calls = 0
        self.expected_old_shas = []
        self.race_remote_sha = None
        self.race_base_sha = None
        self.restore_calls = []

    def push_governed_head(self, **kwargs):
        assert kwargs["token"] == "installation-secret"
        self.calls += 1
        expected_old_sha = kwargs.get("expected_old_sha")
        self.expected_old_shas.append(expected_old_sha)
        if self.race_remote_sha is not None:
            self.gateway.target_sha = self.race_remote_sha
        if self.gateway.target_sha != expected_old_sha:
            raise PublicationError("remote ref failed exact expected-old lease")
        self.gateway.target_sha = self.expected_head
        self.gateway.pull_head_sha = self.expected_head
        if self.race_base_sha is not None:
            self.gateway.base_sha = self.race_base_sha

    def restore_governed_head(self, **kwargs):
        assert kwargs["token"] == "installation-secret"
        expected_current_sha = kwargs["expected_current_sha"]
        restore_sha = kwargs["restore_sha"]
        self.restore_calls.append((expected_current_sha, restore_sha))
        if self.gateway.target_sha != expected_current_sha:
            raise PublicationError("remote ref failed recovery lease")
        self.gateway.target_sha = restore_sha
        self.gateway.pull_head_sha = restore_sha

def publisher_for(view, quarantine, source, gateway=None, sleep=None):
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
        sleep=sleep or (lambda _delay: None),
    )
    return publisher, gateway, push


def successor_source(
    quarantine,
    first_source,
    tmp_path,
    *,
    descendant=True,
    intermediate_out=None,
):
    source_repo = quarantine.repo_path(first_source.quarantine_id)
    work_repo = tmp_path / ("successor-descendant" if descendant else "successor-sibling")
    subprocess.run(
        ["git", "clone", "--quiet", str(source_repo), str(work_repo)],
        check=True,
        capture_output=True,
    )
    start = first_source.head_sha if descendant else first_source.base_sha
    git(work_repo, "checkout", "--quiet", "--detach", start)
    if intermediate_out is not None:
        (work_repo / "file.txt").write_text(
            "base\nhead\nintermediate\n",
            encoding="utf-8",
        )
        git(work_repo, "add", "file.txt")
        git(
            work_repo,
            "-c",
            "user.email=publisher@example.invalid",
            "-c",
            "user.name=Publisher Test",
            "commit",
            "--quiet",
            "-m",
            "intermediate",
        )
        intermediate_out.append(git(work_repo, "rev-parse", "HEAD"))
    (work_repo / "file.txt").write_text(
        "base\nhead\nintermediate\nsuccessor\n"
        if intermediate_out is not None
        else ("base\nhead\nsuccessor\n" if descendant else "base\nsibling\n"),
        encoding="utf-8",
    )
    git(work_repo, "add", "file.txt")
    git(
        work_repo,
        "-c",
        "user.email=publisher@example.invalid",
        "-c",
        "user.name=Publisher Test",
        "commit",
        "--quiet",
        "-m",
        "successor",
    )
    head = git(work_repo, "rev-parse", "HEAD")
    tree = git(work_repo, "rev-parse", "HEAD^{tree}")
    git(work_repo, "update-ref", BASE_REF, first_source.base_sha)
    git(work_repo, "update-ref", HEAD_REF, head)
    bundle = tmp_path / ("successor-descendant.bundle" if descendant else "successor-sibling.bundle")
    git(work_repo, "bundle", "create", str(bundle), BASE_REF, HEAD_REF)
    with bundle.open("rb") as stream:
        return quarantine.import_stream(stream)


def merge_shaped_successor_source(quarantine, first_source, tmp_path):
    source_repo = quarantine.repo_path(first_source.quarantine_id)
    work_repo = tmp_path / "successor-merge-shaped"
    subprocess.run(
        ["git", "clone", "--quiet", str(source_repo), str(work_repo)],
        check=True,
        capture_output=True,
    )
    git(work_repo, "checkout", "--quiet", "--detach", first_source.base_sha)
    (work_repo / "sibling.txt").write_text("sibling\n", encoding="utf-8")
    git(work_repo, "add", "sibling.txt")
    git(
        work_repo,
        "-c",
        "user.email=publisher@example.invalid",
        "-c",
        "user.name=Publisher Test",
        "commit",
        "--quiet",
        "-m",
        "sibling remote head",
    )
    observed_head = git(work_repo, "rev-parse", "HEAD")
    git(work_repo, "checkout", "--quiet", "--detach", first_source.head_sha)
    subprocess.run(
        [
            "git",
            "-C",
            str(work_repo),
            "-c",
            "user.email=publisher@example.invalid",
            "-c",
            "user.name=Publisher Test",
            "merge",
            "--no-ff",
            "--no-edit",
            observed_head,
        ],
        check=True,
        capture_output=True,
    )
    candidate_head = git(work_repo, "rev-parse", "HEAD")
    git(work_repo, "update-ref", BASE_REF, first_source.base_sha)
    git(work_repo, "update-ref", HEAD_REF, candidate_head)
    bundle = tmp_path / "successor-merge-shaped.bundle"
    git(work_repo, "bundle", "create", str(bundle), BASE_REF, HEAD_REF)
    with bundle.open("rb") as stream:
        source = quarantine.import_stream(stream)
    return source, observed_head


def admit_successor(session, view, new_source):
    updated = submit_verified_candidate(session, view.publication_id, new_source)
    profile = profile_for_repository(updated.repository)
    for index, job in enumerate(profile.required_jobs, 1):
        updated = record_validation(
            session,
            updated.publication_id,
            job_id=job,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 10:064x}",
        )
    return updated


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
    recovered = get_view(session, view.publication_id)
    assert recovered.state is PublicationState.VALIDATION_FAILED
    rejected = [
        event for event in load_events(session, view.publication_id)
        if event["event_type"] == "CANDIDATE_REJECTED"
    ]
    assert rejected[-1]["payload"] == {
        "candidate_id": view.current_candidate.candidate_id,
        "reason": "REMOTE_BASE_MOVED_AFTER_ADMISSION",
    }

def test_remote_base_change_after_preflight_fails_before_governed_push(session, tmp_path):
    view, quarantine, source = admitted_publication(session, tmp_path)
    gateway = FakeGateway(
        base_sha=view.current_candidate.base_sha,
        head_sha=view.current_candidate.head_sha,
    )
    gateway.base_sha_reads = [
        view.current_candidate.base_sha,
        "f" * 40,
    ]
    publisher, _gateway, push = publisher_for(
        view,
        quarantine,
        source,
        gateway=gateway,
    )

    with pytest.raises(PublicationError, match="write boundary"):
        publisher.publish(session, view.publication_id)

    assert push.calls == 0
    assert get_view(session, view.publication_id).state is PublicationState.VALIDATION_FAILED
    assert remote_published_events(session, view.publication_id) == []


def test_post_write_base_drift_restores_governed_branch_before_rejecting_candidate(
    session, tmp_path
):
    first, second, _quarantine, _source, gateway, publisher_b, _push_a, push_b = successor_setup(
        session, tmp_path
    )
    push_b.race_base_sha = "f" * 40

    with pytest.raises(PublicationError, match="before publication authority"):
        publisher_b.publish(session, second.publication_id)

    assert push_b.calls == 1
    assert push_b.restore_calls == [(second.current_candidate.head_sha, first.remote_head_sha)]
    assert gateway.target_sha == first.remote_head_sha
    recovered = get_view(session, second.publication_id)
    assert recovered.state is PublicationState.VALIDATION_FAILED
    remote_events = remote_published_events(session, second.publication_id)
    assert len(remote_events) == 1
    assert remote_events[-1]["payload"]["head_sha"] == first.remote_head_sha


def test_branch_collision_fails_closed(session, tmp_path):
    view, quarantine, source = admitted_publication(session, tmp_path)
    publisher, gateway, push = publisher_for(view, quarantine, source)
    gateway.target_sha = "e" * 40

    with pytest.raises(PublicationError, match="branch collision"):
        publisher.publish(session, view.publication_id)

    assert push.calls == 0


def successor_setup(
    session,
    tmp_path,
    *,
    descendant=True,
    intermediate_out=None,
):
    first, quarantine, first_source = admitted_publication(session, tmp_path)
    publisher_a, gateway, push_a = publisher_for(first, quarantine, first_source)
    published_a = publisher_a.publish(session, first.publication_id)
    new_source = successor_source(
        quarantine,
        first_source,
        tmp_path,
        descendant=descendant,
        intermediate_out=intermediate_out,
    )
    second = admit_successor(session, published_a, new_source)
    gateway.head_sha = second.current_candidate.head_sha
    publisher_b, _gateway, push_b = publisher_for(
        second,
        quarantine,
        new_source,
        gateway=gateway,
    )
    return published_a, second, quarantine, new_source, gateway, publisher_b, push_a, push_b


def test_successor_fast_forward_reuses_same_branch_and_pull_request(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher_b, _push_a, push_b = successor_setup(
        session,
        tmp_path,
    )
    sleeps = []
    publisher_b.sleep = sleeps.append

    published_b = publisher_b.publish(session, second.publication_id)

    assert published_b.state is PublicationState.IN_REVIEW
    assert published_b.remote_head_sha == second.current_candidate.head_sha
    assert published_b.remote_head_sha != first.remote_head_sha
    assert published_b.remote_branch == first.remote_branch
    assert published_b.base_branch == first.base_branch
    assert published_b.pull_request_number == first.pull_request_number
    assert gateway.ensure_calls == 1
    assert gateway.pull_request_calls == 2
    assert sleeps == []
    assert push_b.calls == 1
    assert push_b.expected_old_shas == [first.remote_head_sha]
    events = load_events(session, second.publication_id)
    remote_events = [
        event for event in events if event["event_type"] == "REMOTE_PUBLISHED"
    ]
    assert len(remote_events) == 2
    assert remote_events[-1]["payload"]["head_sha"] == published_b.remote_head_sha
    assert remote_events[-1]["payload"]["previous_head_sha"] == first.remote_head_sha

    retried = publisher_b.publish(session, second.publication_id)
    assert retried == published_b
    assert push_b.calls == 1
    assert gateway.ensure_calls == 1
    assert gateway.pull_request_calls == 4
    assert len(
        [event for event in load_events(session, second.publication_id)
         if event["event_type"] == "REMOTE_PUBLISHED"]
    ) == 2


def test_governed_remote_drift_chain_uses_observed_sha_lease_and_audits_it(
    session,
    tmp_path,
):
    intermediate = []
    (
        first,
        second,
        _quarantine,
        _source,
        gateway,
        publisher,
        _push_a,
        push,
    ) = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate,
    )
    observed_head = intermediate[0]
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head

    published = publisher.publish(session, second.publication_id)

    assert published.state is PublicationState.IN_REVIEW
    assert published.remote_head_sha == second.current_candidate.head_sha
    assert push.calls == 1
    assert push.expected_old_shas == [observed_head]
    remote_events = remote_published_events(session, second.publication_id)
    assert len(remote_events) == 2
    recovered_event = remote_events[-1]["payload"]
    assert recovered_event["previous_head_sha"] == first.remote_head_sha
    assert recovered_event["head_sha"] == second.current_candidate.head_sha
    assert recovered_event["observed_remote_head_sha"] == observed_head

    retried = publisher.publish(session, second.publication_id)

    assert retried == published
    assert push.calls == 1
    assert len(remote_published_events(session, second.publication_id)) == 2


def test_merge_shaped_remote_head_is_rejected_without_strict_h1_to_h2_chain(
    session,
    tmp_path,
):
    first, quarantine, first_source = admitted_publication(session, tmp_path)
    publisher_a, gateway, _push_a = publisher_for(first, quarantine, first_source)
    published_first = publisher_a.publish(session, first.publication_id)
    merge_source, observed_head = merge_shaped_successor_source(
        quarantine,
        first_source,
        tmp_path,
    )
    second = admit_successor(session, published_first, merge_source)
    gateway.head_sha = second.current_candidate.head_sha
    publisher, _gateway, push = publisher_for(
        second,
        quarantine,
        merge_source,
        gateway=gateway,
    )
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head

    assert quarantine.is_ancestor(
        merge_source.quarantine_id,
        published_first.remote_head_sha,
        second.current_candidate.head_sha,
    )
    assert quarantine.is_ancestor(
        merge_source.quarantine_id,
        observed_head,
        second.current_candidate.head_sha,
    )
    assert not quarantine.is_ancestor(
        merge_source.quarantine_id,
        published_first.remote_head_sha,
        observed_head,
    )

    with pytest.raises(PublicationError, match="branch collision"):
        publisher.publish(session, second.publication_id)

    assert gateway.target_sha == observed_head
    assert push.calls == 0
    assert (
        get_view(session, second.publication_id).remote_head_sha
        == published_first.remote_head_sha
    )
    assert len(remote_published_events(session, second.publication_id)) == 1


def test_observed_head_descendant_of_h1_but_outside_candidate_fails_closed(
    session,
    tmp_path,
):
    first, second, quarantine, source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    outside_repo = tmp_path / "observed-outside-candidate"
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            str(quarantine.repo_path(source.quarantine_id)),
            str(outside_repo),
        ],
        check=True,
        capture_output=True,
    )
    git(outside_repo, "checkout", "--quiet", "--detach", first.remote_head_sha)
    (outside_repo / "outside.txt").write_text("outside candidate\n", encoding="utf-8")
    git(outside_repo, "add", "outside.txt")
    git(
        outside_repo,
        "-c",
        "user.email=publisher@example.invalid",
        "-c",
        "user.name=Publisher Test",
        "commit",
        "--quiet",
        "-m",
        "remote head outside candidate",
    )
    observed_head = git(outside_repo, "rev-parse", "HEAD")
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head

    with pytest.raises(PublicationError, match="branch collision"):
        publisher.publish(session, second.publication_id)

    assert gateway.target_sha == observed_head
    assert push.calls == 0
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha
    assert len(remote_published_events(session, second.publication_id)) == 1


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("closed", "not open"),
        ("number", "number changed"),
        ("head_ref", "branch changed"),
        ("base_ref", "base changed"),
        ("head_sha", "observed branch"),
    ],
)
def test_observed_remote_recovery_rejects_changed_canonical_pr_before_push(
    session,
    tmp_path,
    change,
    message,
):
    intermediate = []
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate,
    )
    observed_head = intermediate[0]
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head
    if change == "closed":
        gateway.pull_state = "closed"
    elif change == "number":
        gateway.returned_pull_number = 999
    elif change == "head_ref":
        gateway.pull_head_ref = "unexpected-branch"
    elif change == "base_ref":
        gateway.pull_base_ref = "unexpected-base"
    else:
        gateway.pull_head_sha = "e" * 40

    with pytest.raises(PublicationError, match=message):
        publisher.publish(session, second.publication_id)

    assert gateway.target_sha == observed_head
    assert push.calls == 0
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha
    assert len(remote_published_events(session, second.publication_id)) == 1


def test_observed_branch_pr_head_disagreement_fails_before_push(session, tmp_path):
    intermediate = []
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate,
    )
    observed_head = intermediate[0]
    gateway.target_sha = observed_head
    gateway.pull_head_sha = "e" * 40

    with pytest.raises(PublicationError, match="observed branch"):
        publisher.publish(session, second.publication_id)

    assert gateway.target_sha == observed_head
    assert push.calls == 0
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha
    assert len(remote_published_events(session, second.publication_id)) == 1


def test_observed_remote_recovery_base_drift_before_push_preserves_remote_head(
    session,
    tmp_path,
):
    intermediate = []
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate,
    )
    observed_head = intermediate[0]
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head
    gateway.base_sha = "f" * 40

    with pytest.raises(PublicationError, match="remote base moved after candidate admission"):
        publisher.publish(session, second.publication_id)

    assert gateway.target_sha == observed_head
    assert push.calls == 0
    assert get_view(session, second.publication_id).state is PublicationState.VALIDATION_FAILED
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha
    assert len(remote_published_events(session, second.publication_id)) == 1


def test_observed_remote_recovery_base_drift_after_push_restores_observed_head(
    session,
    tmp_path,
):
    intermediate = []
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate,
    )
    observed_head = intermediate[0]
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head
    push.race_base_sha = "f" * 40

    with pytest.raises(PublicationError, match="before publication authority was recorded"):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert push.expected_old_shas == [observed_head]
    assert push.restore_calls == [(second.current_candidate.head_sha, observed_head)]
    assert gateway.target_sha == observed_head
    assert get_view(session, second.publication_id).state is PublicationState.VALIDATION_FAILED
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha
    assert len(remote_published_events(session, second.publication_id)) == 1


def test_observed_remote_recovery_lease_rejects_branch_race(session, tmp_path):
    intermediate = []
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate,
    )
    observed_head = intermediate[0]
    raced_head = "e" * 40
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head
    push.race_remote_sha = raced_head

    with pytest.raises(PublicationError, match="exact expected-old lease"):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert push.expected_old_shas == [observed_head]
    assert gateway.target_sha == raced_head
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha
    assert len(remote_published_events(session, second.publication_id)) == 1


@pytest.mark.parametrize("unexpected_source", ["branch", "pull_request"])
def test_observed_remote_recovery_rejects_unexpected_post_push_readback(
    session,
    tmp_path,
    unexpected_source,
):
    intermediate = []
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate,
    )
    observed_head = intermediate[0]
    gateway.target_sha = observed_head
    gateway.pull_head_sha = observed_head
    before_events = len(remote_published_events(session, second.publication_id))
    if unexpected_source == "branch":
        gateway.target_sha_reads.extend([observed_head, "e" * 40])
    else:
        gateway.pull_responses.extend(
            [
                pull_snapshot(second, head_sha=observed_head),
                pull_snapshot(second, head_sha="e" * 40),
            ]
        )

    message = (
        "publication branch changed during readback"
        if unexpected_source == "branch"
        else "canonical pull request head changed during readback"
    )
    with pytest.raises(PublicationError, match=message):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert push.expected_old_shas == [observed_head]
    assert get_view(session, second.publication_id).state is PublicationState.ADMITTED
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha
    assert len(remote_published_events(session, second.publication_id)) == before_events


def pull_snapshot(view, *, head_sha=None, state="open", head_ref=None, base_ref=None, number=None):
    return PullRequestSnapshot(
        number=number or view.pull_request_number,
        state=state,
        base_ref=base_ref or view.base_branch,
        head_ref=head_ref or view.remote_branch,
        head_sha=head_sha or view.current_candidate.head_sha,
    )


def remote_published_events(session, publication_id):
    return [
        event
        for event in load_events(session, publication_id)
        if event["event_type"] == "REMOTE_PUBLISHED"
    ]


def test_successor_retries_stale_pr_head_then_converges(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    old_head = first.remote_head_sha
    new_head = second.current_candidate.head_sha
    gateway.pull_responses.extend(
        [
            pull_snapshot(second, head_sha=old_head),  # strict pre-push read
            pull_snapshot(second, head_sha=old_head),  # stale readback
            pull_snapshot(second, head_sha=new_head),
        ]
    )
    sleeps = []
    publisher.sleep = sleeps.append

    published = publisher.publish(session, second.publication_id)

    assert published.remote_head_sha == new_head
    assert push.calls == 1
    assert gateway.pull_request_calls == 3
    assert sleeps == [0.2]
    assert len(remote_published_events(session, second.publication_id)) == 2


def test_successor_retries_stale_branch_and_pr_then_converges(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    old_head = first.remote_head_sha
    new_head = second.current_candidate.head_sha
    gateway.target_sha_reads.extend([old_head, old_head, new_head])
    gateway.pull_responses.extend(
        [
            pull_snapshot(second, head_sha=old_head),
            pull_snapshot(second, head_sha=old_head),
            pull_snapshot(second, head_sha=new_head),
        ]
    )
    sleeps = []
    publisher.sleep = sleeps.append

    published = publisher.publish(session, second.publication_id)

    assert published.remote_head_sha == new_head
    assert push.calls == 1
    assert gateway.pull_request_calls == 3
    assert sleeps == [0.2]
    assert len(remote_published_events(session, second.publication_id)) == 2


def test_persistent_stale_readback_fails_after_bounded_attempts(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    stale_head = first.remote_head_sha
    gateway.pull_responses.extend(
        [pull_snapshot(second, head_sha=stale_head) for _ in range(5)]
    )
    before_events = len(remote_published_events(session, second.publication_id))
    sleeps = []
    publisher.sleep = sleeps.append

    with pytest.raises(PublicationError, match="did not converge after 4 attempts"):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert gateway.pull_request_calls == 5
    assert sleeps == [0.2, 0.2, 0.2]
    assert get_view(session, second.publication_id).state is PublicationState.ADMITTED
    assert len(remote_published_events(session, second.publication_id)) == before_events


def test_unexpected_post_push_branch_sha_fails_without_retry(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    gateway.target_sha_reads.extend([first.remote_head_sha, "e" * 40])
    sleeps = []
    publisher.sleep = sleeps.append
    before_events = len(remote_published_events(session, second.publication_id))

    with pytest.raises(PublicationError, match="branch changed during readback"):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert gateway.pull_request_calls == 1
    assert sleeps == []
    assert len(remote_published_events(session, second.publication_id)) == before_events


def test_unexpected_post_push_pr_sha_fails_without_retry(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    gateway.pull_responses.extend(
        [
            pull_snapshot(second, head_sha=first.remote_head_sha),
            pull_snapshot(second, head_sha="e" * 40),
        ]
    )
    sleeps = []
    publisher.sleep = sleeps.append

    with pytest.raises(PublicationError, match="head changed during readback"):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert gateway.pull_request_calls == 2
    assert sleeps == []
    assert get_view(session, second.publication_id).state is PublicationState.ADMITTED


def test_closed_post_push_pull_request_fails_without_retry(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    gateway.pull_responses.extend(
        [
            pull_snapshot(second, head_sha=first.remote_head_sha),
            pull_snapshot(second, state="closed"),
        ]
    )
    sleeps = []
    publisher.sleep = sleeps.append

    with pytest.raises(PublicationError, match="not open"):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert gateway.pull_request_calls == 2
    assert sleeps == []
    assert get_view(session, second.publication_id).state is PublicationState.ADMITTED


@pytest.mark.parametrize(
    ("snapshot_kwargs", "message"),
    [
        ({"head_ref": "unexpected-branch"}, "branch changed"),
        ({"base_ref": "unexpected-base"}, "base changed"),
        ({"number": 999}, "number changed"),
    ],
)
def test_changed_post_push_pull_identity_fails_without_retry(
    session,
    tmp_path,
    snapshot_kwargs,
    message,
):
    first, second, _quarantine, _source, gateway, publisher, _push_a, push = successor_setup(
        session,
        tmp_path,
    )
    gateway.pull_responses.extend(
        [
            pull_snapshot(second, head_sha=first.remote_head_sha),
            pull_snapshot(second, **snapshot_kwargs),
        ]
    )
    sleeps = []
    publisher.sleep = sleeps.append
    before_events = len(remote_published_events(session, second.publication_id))

    with pytest.raises(PublicationError, match=message):
        publisher.publish(session, second.publication_id)

    assert push.calls == 1
    assert gateway.pull_request_calls == 2
    assert sleeps == []
    assert get_view(session, second.publication_id).state is PublicationState.ADMITTED
    assert len(remote_published_events(session, second.publication_id)) == before_events


def test_successor_rejects_remote_branch_changed_outside_governed_head(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher_b, _push_a, push_b = successor_setup(
        session,
        tmp_path,
    )
    gateway.target_sha = "e" * 40

    with pytest.raises(PublicationError, match="branch collision"):
        publisher_b.publish(session, second.publication_id)

    assert gateway.target_sha == "e" * 40
    assert push_b.calls == 0
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha


@pytest.mark.parametrize("race_target", ["unrelated", "intermediate"])
def test_successor_exact_old_head_lease_rejects_remote_race(
    session,
    tmp_path,
    race_target,
):
    intermediate = []
    (
        first,
        second,
        quarantine,
        source,
        gateway,
        publisher_b,
        _push_a,
        push_b,
    ) = successor_setup(
        session,
        tmp_path,
        intermediate_out=intermediate if race_target == "intermediate" else None,
    )
    raced_sha = "e" * 40 if race_target == "unrelated" else intermediate[0]
    if race_target == "intermediate":
        assert raced_sha != first.remote_head_sha
        assert quarantine.is_ancestor(
            source.quarantine_id,
            first.remote_head_sha,
            second.current_candidate.head_sha,
        )
        assert quarantine.is_ancestor(
            source.quarantine_id,
            raced_sha,
            second.current_candidate.head_sha,
        )
    push_b.race_remote_sha = raced_sha

    with pytest.raises(PublicationError, match="exact expected-old lease"):
        publisher_b.publish(session, second.publication_id)

    assert push_b.calls == 1
    assert push_b.expected_old_shas == [first.remote_head_sha]
    assert gateway.target_sha == raced_sha
    assert (
        get_view(session, second.publication_id).remote_head_sha
        == first.remote_head_sha
    )
    assert len(
        [event for event in load_events(session, second.publication_id)
         if event["event_type"] == "REMOTE_PUBLISHED"]
    ) == 1


def test_successor_recovers_remote_candidate_without_a_second_push(session, tmp_path):
    (
        first,
        second,
        _quarantine,
        _source,
        gateway,
        publisher_b,
        _push_a,
        push_b,
    ) = successor_setup(
        session,
        tmp_path,
    )
    gateway.target_sha = second.current_candidate.head_sha
    gateway.pull_head_sha = second.current_candidate.head_sha
    gateway.pull_responses.extend(
        [
            pull_snapshot(second, head_sha=first.remote_head_sha),
            pull_snapshot(second, head_sha=first.remote_head_sha),
            pull_snapshot(second, head_sha=second.current_candidate.head_sha),
        ]
    )
    sleeps = []
    publisher_b.sleep = sleeps.append

    recovered = publisher_b.publish(session, second.publication_id)

    assert recovered.state is PublicationState.IN_REVIEW
    assert recovered.remote_head_sha == second.current_candidate.head_sha
    assert gateway.target_sha == recovered.remote_head_sha
    assert push_b.calls == 0
    assert gateway.pull_request_calls == 3
    assert sleeps == [0.2]
    remote_events = [
        event for event in load_events(session, second.publication_id)
        if event["event_type"] == "REMOTE_PUBLISHED"
    ]
    assert len(remote_events) == 2
    assert remote_events[-1]["payload"]["previous_head_sha"] == first.remote_head_sha

    retried = publisher_b.publish(session, second.publication_id)
    assert retried == recovered
    assert push_b.calls == 0
    assert len(sleeps) == 1
    assert len(
        [event for event in load_events(session, second.publication_id)
         if event["event_type"] == "REMOTE_PUBLISHED"]
    ) == 2


def test_non_fast_forward_successor_fails_closed(session, tmp_path):
    first, second, _quarantine, _source, gateway, publisher_b, _push_a, push_b = successor_setup(
        session,
        tmp_path,
        descendant=False,
    )
    assert gateway.target_sha == first.remote_head_sha

    with pytest.raises(PublicationError):
        publisher_b.publish(session, second.publication_id)

    assert push_b.calls == 0
    assert get_view(session, second.publication_id).remote_head_sha == first.remote_head_sha


@pytest.mark.parametrize(
    ("pull_state", "pull_missing", "returned_pull_number"),
    [("closed", False, None), ("open", True, None), ("open", False, 32)],
)
def test_successor_never_creates_replacement_for_closed_missing_or_changed_pr(
    session,
    tmp_path,
    pull_state,
    pull_missing,
    returned_pull_number,
):
    _first, second, _quarantine, _source, gateway, publisher_b, _push_a, push_b = successor_setup(
        session,
        tmp_path,
    )
    gateway.pull_state = pull_state
    gateway.pull_missing = pull_missing
    gateway.returned_pull_number = returned_pull_number

    with pytest.raises(PublicationError):
        publisher_b.publish(session, second.publication_id)

    assert gateway.ensure_calls == 1
    assert gateway.pull_request_calls == 1
    assert push_b.calls == 0
    assert get_view(session, second.publication_id).state is PublicationState.ADMITTED


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
        captured["shell"] = kwargs["shell"]
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "super-secret-database-url")
    monkeypatch.setattr("control_plane.publisher.subprocess.run", fake_run)

    GitPushTransport().push_governed_head(
        repo_path=repo,
        repository="DEAMBROGGI/FirstContact",
        branch="control-plane/issue-77-abcdef12",
        token="installation-secret",
    )

    joined = " ".join(captured["args"])
    assert "installation-secret" not in joined
    assert (
        "--force-with-lease=refs/heads/control-plane/issue-77-abcdef12:"
        in captured["args"]
    )
    assert captured["env"]["CONTROL_PLANE_GIT_TOKEN"] == "installation-secret"
    assert "CONTROL_PLANE_DATABASE_URL" not in captured["env"]
    assert captured["shell"] is False
    assert "--no-tags" in captured["args"]
    assert (
        captured["args"][-1]
        == "refs/controlplane/head:refs/heads/control-plane/issue-77-abcdef12"
    )
    assert captured["args"].count(
        "refs/controlplane/head:refs/heads/control-plane/issue-77-abcdef12"
    ) == 1


def test_git_push_uses_exact_expected_old_ref_lease(monkeypatch, tmp_path):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = list(args)
        captured["env"] = dict(kwargs["env"])
        captured["shell"] = kwargs["shell"]
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("control_plane.publisher.subprocess.run", fake_run)
    branch = "control-plane/issue-77-abcdef12"
    old_sha = "a" * 40
    refspec = f"refs/controlplane/head:refs/heads/{branch}"

    GitPushTransport().push_governed_head(
        repo_path=tmp_path,
        repository="DEAMBROGGI/FirstContact",
        branch=branch,
        token="installation-secret",
        expected_old_sha=old_sha,
    )

    assert f"--force-with-lease=refs/heads/{branch}:{old_sha}" in captured["args"]
    assert captured["args"][-1] == refspec
    assert captured["args"].count(refspec) == 1
    assert "--no-tags" in captured["args"]
    assert captured["shell"] is False
    assert "installation-secret" not in " ".join(captured["args"])
    assert captured["env"]["CONTROL_PLANE_GIT_TOKEN"] == "installation-secret"


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
