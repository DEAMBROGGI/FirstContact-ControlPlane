from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

BASE_REF = "refs/controlplane/base"
HEAD_REF = "refs/controlplane/head"
EXPECTED_REFS = frozenset({BASE_REF, HEAD_REF})


class CandidateQuarantineError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedCandidateSource:
    bundle_sha256: str
    byte_length: int
    quarantine_id: str
    base_sha: str
    head_sha: str
    tree_sha: str


class GitCandidateQuarantine:
    def __init__(
        self,
        root: str | Path,
        *,
        max_bundle_bytes: int,
        git_executable: str = "git",
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.max_bundle_bytes = max_bundle_bytes
        self.git_executable = git_executable
        if max_bundle_bytes <= 0:
            raise CandidateQuarantineError("max_bundle_bytes must be positive")
    def import_stream(self, stream: BinaryIO) -> VerifiedCandidateSource:
        self._ensure_roots()
        temp_path, digest, byte_length = self._spool_bounded(stream)
        repo_path = self._repo_path(digest)
        repo_existed = repo_path.exists()
        try:
            heads = self._bundle_heads(temp_path)
            if set(heads) != EXPECTED_REFS:
                raise CandidateQuarantineError(
                    "bundle must advertise exactly refs/controlplane/base and refs/controlplane/head"
                )
            if repo_existed:
                source = self._verify_repo(repo_path, digest, byte_length)
            else:
                source = self._import_repo(
                    temp_path,
                    repo_path,
                    digest,
                    byte_length,
                )
            self._commit_bundle(temp_path, digest, byte_length)
            return source
        except Exception:
            if not repo_existed and repo_path.exists():
                self._remove_tree(repo_path)
            raise
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def repo_path(self, quarantine_id: str) -> Path:
        if len(quarantine_id) != 64 or any(c not in "0123456789abcdef" for c in quarantine_id):
            raise CandidateQuarantineError("invalid quarantine identity")
        path = self._repo_path(quarantine_id)
        if not path.is_dir():
            raise CandidateQuarantineError("quarantined repository is unavailable")
        return path

    def verify_existing(
        self,
        quarantine_id: str,
        *,
        byte_length: int,
    ) -> VerifiedCandidateSource:
        repo_path = self.repo_path(quarantine_id)
        bundle_path = self._bundle_path(quarantine_id)
        if not bundle_path.is_file():
            raise CandidateQuarantineError("quarantined bundle is unavailable")
        observed_digest, observed_length = self._hash_file(bundle_path)
        if observed_digest != quarantine_id or observed_length != byte_length:
            raise CandidateQuarantineError("quarantined bundle content identity mismatch")
        return self._verify_repo(repo_path, quarantine_id, byte_length)

    def is_ancestor(
        self,
        quarantine_id: str,
        older_sha: str,
        newer_sha: str,
    ) -> bool:
        repo_path = self.repo_path(quarantine_id)
        for value in (older_sha, newer_sha):
            if len(value) != 40 or any(c not in "0123456789abcdef" for c in value.lower()):
                raise CandidateQuarantineError("invalid Git object identity")
        result = self._run(
            "-C",
            str(repo_path),
            "merge-base",
            "--is-ancestor",
            older_sha.lower(),
            newer_sha.lower(),
            check=False,
        )
        if result.returncode not in {0, 1}:
            raise CandidateQuarantineError("failed to evaluate quarantine ancestry")
        return result.returncode == 0

    def _ensure_roots(self) -> None:
        for path in (
            self.root / "incoming",
            self.root / "bundles",
            self.root / "repos",
        ):
            path.mkdir(parents=True, exist_ok=True)

    def _remove_tree(self, path: Path) -> None:
        if not path.exists():
            return

        def repair_and_retry(function, raw_path, _exc_info):
            os.chmod(raw_path, stat.S_IWRITE)
            function(raw_path)

        last_error: OSError | None = None
        for attempt in range(6):
            try:
                shutil.rmtree(path, onerror=repair_and_retry)
                return
            except FileNotFoundError:
                return
            except OSError as exc:
                last_error = exc
                time.sleep(0.05 * (attempt + 1))
        raise CandidateQuarantineError("failed to clean partial quarantine") from last_error

    def _spool_bounded(self, stream: BinaryIO) -> tuple[Path, str, int]:
        digest = hashlib.sha256()
        total = 0
        fd, raw_path = tempfile.mkstemp(
            prefix="candidate-",
            suffix=".bundle",
            dir=self.root / "incoming",
        )
        path = Path(raw_path)
        try:
            with os.fdopen(fd, "wb") as target:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_bundle_bytes:
                        raise CandidateQuarantineError("candidate bundle exceeds configured size limit")
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        if total == 0:
            path.unlink(missing_ok=True)
            raise CandidateQuarantineError("candidate bundle is empty")
        return path, digest.hexdigest(), total
    def _bundle_path(self, digest: str) -> Path:
        return self.root / "bundles" / digest[:2] / f"{digest}.bundle"

    def _repo_path(self, digest: str) -> Path:
        return self.root / "repos" / digest[:2] / f"{digest}.git"

    def _commit_bundle(self, temp_path: Path, digest: str, byte_length: int) -> Path:
        final = self._bundle_path(digest)
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            observed_digest, observed_length = self._hash_file(final)
            if observed_digest != digest or observed_length != byte_length:
                raise CandidateQuarantineError("content-addressed bundle store is corrupt")
            return final
        os.replace(temp_path, final)
        return final

    def _hash_file(self, path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                digest.update(chunk)
        return digest.hexdigest(), total

    def _git_env(self) -> dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not (
                key.upper().startswith("GIT_")
                or key.upper().startswith("GH_")
                or key.upper().startswith("GITHUB_")
            )
        }
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        return env

    def _run(
        self,
        *args: str,
        check: bool = True,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [self.git_executable, *args],
                check=check,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                env=self._git_env(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CandidateQuarantineError("bounded Git operation failed") from exc
    def _bundle_heads(self, bundle_path: Path) -> dict[str, str]:
        result = self._run("bundle", "list-heads", str(bundle_path))
        heads: dict[str, str] = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) != 2:
                raise CandidateQuarantineError("bundle advertised malformed ref metadata")
            sha, ref = parts
            if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha.lower()):
                raise CandidateQuarantineError("bundle advertised malformed object identity")
            if ref in heads:
                raise CandidateQuarantineError("bundle advertised duplicate ref")
            heads[ref] = sha.lower()
        return heads

    def _import_repo(
        self,
        bundle_path: Path,
        final_repo: Path,
        digest: str,
        byte_length: int,
    ) -> VerifiedCandidateSource:
        final_repo.parent.mkdir(parents=True, exist_ok=True)
        temp_repo = final_repo.parent / f".incoming-{uuid.uuid4().hex}.git"
        try:
            self._run("init", "--bare", "--quiet", str(temp_repo))
            self._run(
                "-C",
                str(temp_repo),
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                str(bundle_path),
                f"{BASE_REF}:{BASE_REF}",
                f"{HEAD_REF}:{HEAD_REF}",
            )
            self._run("-C", str(temp_repo), "fsck", "--full", "--strict", "--no-reflogs")
            source = self._verify_repo(temp_repo, digest, byte_length)
            try:
                os.rename(temp_repo, final_repo)
            except OSError:
                if not final_repo.exists():
                    raise
                self._remove_tree(temp_repo)
                return self._verify_repo(final_repo, digest, byte_length)
            return source
        except Exception:
            self._remove_tree(temp_repo)
            raise
    def _verify_repo(
        self,
        repo_path: Path,
        digest: str,
        byte_length: int,
    ) -> VerifiedCandidateSource:
        refs = self._run(
            "-C",
            str(repo_path),
            "for-each-ref",
            "--format=%(refname)",
        ).stdout.splitlines()
        if set(refs) != EXPECTED_REFS:
            raise CandidateQuarantineError("quarantined repository ref set is invalid")

        for ref in (BASE_REF, HEAD_REF):
            kind = self._run("-C", str(repo_path), "cat-file", "-t", ref).stdout.strip()
            if kind != "commit":
                raise CandidateQuarantineError(f"{ref} must point directly to a commit")

        base = self._run("-C", str(repo_path), "rev-parse", "--verify", BASE_REF).stdout.strip().lower()
        head = self._run("-C", str(repo_path), "rev-parse", "--verify", HEAD_REF).stdout.strip().lower()
        tree = self._run(
            "-C",
            str(repo_path),
            "rev-parse",
            "--verify",
            f"{HEAD_REF}^{{tree}}",
        ).stdout.strip().lower()

        ancestry = self._run(
            "-C",
            str(repo_path),
            "merge-base",
            "--is-ancestor",
            base,
            head,
            check=False,
        )
        if ancestry.returncode != 0:
            raise CandidateQuarantineError("candidate head is not descended from candidate base")

        self._run("-C", str(repo_path), "fsck", "--full", "--strict", "--no-reflogs")
        return VerifiedCandidateSource(
            bundle_sha256=digest,
            byte_length=byte_length,
            quarantine_id=digest,
            base_sha=base,
            head_sha=head,
            tree_sha=tree,
        )
