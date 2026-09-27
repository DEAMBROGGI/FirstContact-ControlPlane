from __future__ import annotations

import io
import subprocess
from pathlib import Path

import pytest

from control_plane.quarantine import (
    BASE_REF,
    HEAD_REF,
    CandidateQuarantineError,
    GitCandidateQuarantine,
)


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def make_bundle(
    tmp_path: Path,
    *,
    include_base: bool = True,
    extra_ref: bool = False,
    disconnected: bool = False,
) -> tuple[bytes, str, str, str]:
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    git(repo, "config", "user.email", "controlplane@example.invalid")
    git(repo, "config", "user.name", "Control Plane Test")
    (repo / "candidate.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "candidate.txt")
    git(repo, "commit", "--quiet", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "update-ref", BASE_REF, base)

    if disconnected:
        git(repo, "checkout", "--quiet", "--orphan", "disconnected")
        git(repo, "rm", "--quiet", "-rf", ".")
        (repo / "candidate.txt").write_text("disconnected\n", encoding="utf-8")
    else:
        (repo / "candidate.txt").write_text("base\nhead\n", encoding="utf-8")
    git(repo, "add", "candidate.txt")
    git(repo, "commit", "--quiet", "-m", "head")
    head = git(repo, "rev-parse", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    git(repo, "update-ref", HEAD_REF, head)

    refs = [HEAD_REF]
    if include_base:
        refs.insert(0, BASE_REF)
    if extra_ref:
        extra = "refs/controlplane/extra"
        git(repo, "update-ref", extra, head)
        refs.append(extra)

    bundle = tmp_path / "candidate.bundle"
    git(repo, "bundle", "create", str(bundle), *refs)
    return bundle.read_bytes(), base, head, tree
def test_valid_bundle_is_verified_and_idempotent(tmp_path):
    payload, base, head, tree = make_bundle(tmp_path)
    root = tmp_path / "quarantine"
    quarantine = GitCandidateQuarantine(root, max_bundle_bytes=5_000_000)

    first = quarantine.import_stream(io.BytesIO(payload))
    second = quarantine.import_stream(io.BytesIO(payload))

    assert first == second
    assert first.base_sha == base
    assert first.head_sha == head
    assert first.tree_sha == tree
    assert first.bundle_sha256 == first.quarantine_id
    assert quarantine.repo_path(first.quarantine_id).is_dir()

    restarted = GitCandidateQuarantine(root, max_bundle_bytes=5_000_000)
    assert restarted.repo_path(first.quarantine_id).is_dir()


def test_bundle_missing_required_ref_is_rejected(tmp_path):
    payload, _base, _head, _tree = make_bundle(tmp_path, include_base=False)
    quarantine = GitCandidateQuarantine(tmp_path / "q", max_bundle_bytes=5_000_000)
    with pytest.raises(CandidateQuarantineError, match="advertise exactly"):
        quarantine.import_stream(io.BytesIO(payload))


def test_bundle_with_extra_ref_is_rejected(tmp_path):
    payload, _base, _head, _tree = make_bundle(tmp_path, extra_ref=True)
    quarantine = GitCandidateQuarantine(tmp_path / "q", max_bundle_bytes=5_000_000)
    with pytest.raises(CandidateQuarantineError, match="advertise exactly"):
        quarantine.import_stream(io.BytesIO(payload))
def test_disconnected_head_is_rejected(tmp_path):
    payload, _base, _head, _tree = make_bundle(tmp_path, disconnected=True)
    quarantine = GitCandidateQuarantine(tmp_path / "q", max_bundle_bytes=5_000_000)
    with pytest.raises(CandidateQuarantineError, match="not descended"):
        quarantine.import_stream(io.BytesIO(payload))


def test_malformed_bundle_is_rejected(tmp_path):
    quarantine = GitCandidateQuarantine(tmp_path / "q", max_bundle_bytes=5_000_000)
    with pytest.raises(CandidateQuarantineError, match="Git operation failed"):
        quarantine.import_stream(io.BytesIO(b"not-a-git-bundle"))


def test_oversize_bundle_is_rejected_before_import(tmp_path):
    quarantine = GitCandidateQuarantine(tmp_path / "q", max_bundle_bytes=3)
    with pytest.raises(CandidateQuarantineError, match="size limit"):
        quarantine.import_stream(io.BytesIO(b"four"))


def test_rejected_bundle_leaves_no_durable_candidate_store(tmp_path):
    payload, _base, _head, _tree = make_bundle(tmp_path, disconnected=True)
    root = tmp_path / "q"
    quarantine = GitCandidateQuarantine(root, max_bundle_bytes=5_000_000)
    with pytest.raises(CandidateQuarantineError):
        quarantine.import_stream(io.BytesIO(payload))
    assert not list((root / "bundles").rglob("*.bundle"))
    assert not list((root / "repos").rglob("*.git"))
