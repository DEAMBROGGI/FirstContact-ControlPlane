from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sqlalchemy.orm import Session

from .domain import DomainError, PublicationState, PublicationView
from .github_api import GitHubApiError, GitHubRepositoryGateway
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .models import CandidateSourceRow
from .profile_registry import profile_for_repository
from .quarantine import CandidateQuarantineError, GitCandidateQuarantine
from .service import get_view, mark_remote_published

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_READBACK_ATTEMPTS = 4
_READBACK_DELAY_SECONDS = 0.2


class PublicationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    repository: str
    branch: str
    base_branch: str
    head_sha: str
    pull_request_number: int


class GitPushTransport:
    def __init__(self, git_executable: str = "git") -> None:
        self.git_executable = git_executable

    @staticmethod
    def _safe_environment(token: str, askpass: Path) -> dict[str, str]:
        environment: dict[str, str] = {}
        for key in (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "COMSPEC",
            "PATHEXT",
            "LANG",
            "LC_ALL",
        ):
            value = os.environ.get(key)
            if value:
                environment[key] = value
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_ASKPASS": str(askpass),
                "CONTROL_PLANE_GIT_TOKEN": token,
            }
        )
        return environment
    @staticmethod
    def _write_askpass(directory: Path) -> Path:
        if os.name == "nt":
            helper = directory / "askpass.cmd"
            helper.write_text(
                "@echo off\r\n"
                "echo %~1 | findstr /I \"Username\" >nul && "
                "(echo x-access-token& exit /b 0)\r\n"
                "echo %CONTROL_PLANE_GIT_TOKEN%\r\n",
                encoding="utf-8",
            )
        else:
            helper = directory / "askpass.sh"
            helper.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
                "  *) printf '%s\\n' \"$CONTROL_PLANE_GIT_TOKEN\" ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            helper.chmod(0o700)
        return helper

    def push_governed_head(
        self,
        *,
        repo_path: Path,
        repository: str,
        branch: str,
        token: str,
        expected_old_sha: str | None = None,
    ) -> None:
        """Push only if the destination ref still has its governed value.

        Successor callers must prove expected_old_sha is an ancestor of the
        candidate before using the lease. The lease closes the race between
        that proof and GitHub's ref update; it is not authority to rewrite
        history. None means the initial destination ref must still be absent.
        """
        if not _REPOSITORY_RE.fullmatch(repository):
            raise PublicationError("publisher repository identity is invalid")
        if not _BRANCH_RE.fullmatch(branch) or ".." in branch or branch.endswith("/"):
            raise PublicationError("publisher branch identity is invalid")
        if not token:
            raise PublicationError("publisher installation token is unavailable")
        if expected_old_sha is not None and not _SHA_RE.fullmatch(
            expected_old_sha
        ):
            raise PublicationError("expected old publication head is invalid")

        remote_url = f"https://github.com/{repository}.git"
        refspec = f"refs/controlplane/head:refs/heads/{branch}"
        push_args = [
            self.git_executable,
            "-c",
            "credential.helper=",
            "-C",
            str(repo_path),
            "push",
            "--porcelain",
            "--no-verify",
            "--no-tags",
        ]
        expected_ref_value = expected_old_sha or ""
        push_args.append(
            f"--force-with-lease=refs/heads/{branch}:{expected_ref_value}"
        )
        push_args.extend((remote_url, refspec))
        with tempfile.TemporaryDirectory(prefix="fc-controlplane-askpass-") as raw:
            askpass = self._write_askpass(Path(raw))
            environment = self._safe_environment(token, askpass)
            try:
                result = subprocess.run(
                    push_args,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=120,
                    shell=False,
                    env=environment,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise PublicationError("bounded Git publication failed") from exc
        if result.returncode != 0:
            raise PublicationError("GitHub rejected exact-head publication")
class GitHubPublisher:
    def __init__(
        self,
        *,
        token_provider: GitHubAppTokenProvider,
        github: GitHubRepositoryGateway,
        quarantine: GitCandidateQuarantine,
        git_push: GitPushTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.token_provider = token_provider
        self.github = github
        self.quarantine = quarantine
        self.git_push = git_push or GitPushTransport()
        self.sleep = sleep or time.sleep

    @staticmethod
    def publication_branch(view: PublicationView) -> str:
        return f"control-plane/issue-{view.issue_number}-{view.publication_id[:8]}"

    @staticmethod
    def _verify_canonical_pull_request(
        pull,
        *,
        view: PublicationView,
        branch: str,
        base_branch: str,
        expected_head_sha: str,
    ) -> None:
        GitHubPublisher._verify_canonical_pull_request_identity(
            pull,
            view=view,
            branch=branch,
            base_branch=base_branch,
        )
        if pull.head_sha != expected_head_sha:
            raise PublicationError("canonical pull request head does not match")

    @staticmethod
    def _verify_canonical_pull_request_identity(
        pull,
        *,
        view: PublicationView,
        branch: str,
        base_branch: str,
    ) -> None:
        if pull.state != "open":
            raise PublicationError("canonical pull request is not open")
        if pull.number != view.pull_request_number:
            raise PublicationError("canonical pull request number changed")
        if pull.base_ref != base_branch:
            raise PublicationError("canonical pull request base changed")
        if pull.head_ref != branch:
            raise PublicationError("canonical pull request branch changed")

    def _readback_published_head(
        self,
        *,
        repository: str,
        branch: str,
        token: str,
        view: PublicationView,
        base_branch: str,
        expected_head_sha: str,
        previous_head_sha: str | None,
    ):
        """Poll only GitHub readbacks; never repeat a push or ledger write."""
        allowed_heads = {expected_head_sha}
        if previous_head_sha is not None:
            allowed_heads.add(previous_head_sha)
        allowed_branch_values: set[str | None] = set(allowed_heads)
        if previous_head_sha is None:
            allowed_branch_values.add(None)

        for attempt in range(_READBACK_ATTEMPTS):
            target_sha = self.github.ref_sha(repository, branch, token)
            if target_sha not in allowed_branch_values:
                raise PublicationError("publication branch changed during readback")

            pull = None
            if view.remote_head_sha is not None:
                assert view.pull_request_number is not None
                pull = self.github.pull_request(
                    repository,
                    view.pull_request_number,
                    token,
                )
                self._verify_canonical_pull_request_identity(
                    pull,
                    view=view,
                    branch=branch,
                    base_branch=base_branch,
                )
                if pull.head_sha not in allowed_heads:
                    raise PublicationError(
                        "canonical pull request head changed during readback"
                    )

            branch_converged = target_sha == expected_head_sha
            pull_converged = pull is None or pull.head_sha == expected_head_sha
            if branch_converged and pull_converged:
                return pull
            if attempt + 1 < _READBACK_ATTEMPTS:
                self.sleep(_READBACK_DELAY_SECONDS)

        raise PublicationError(
            f"remote publication readback did not converge after {_READBACK_ATTEMPTS} attempts"
        )

    def _verified_source(self, session: Session, view: PublicationView):
        candidate = view.current_candidate
        if candidate is None:
            raise PublicationError("publication has no current candidate")
        source = session.get(CandidateSourceRow, candidate.candidate_id)
        if source is None:
            raise PublicationError("candidate has no immutable quarantine source")
        if (
            source.base_sha != candidate.base_sha
            or source.head_sha != candidate.head_sha
            or source.tree_sha != candidate.tree_sha
            or source.bundle_sha256 != source.quarantine_id
        ):
            raise PublicationError("candidate source metadata does not match admitted identity")
        try:
            verified = self.quarantine.verify_existing(
                source.quarantine_id,
                byte_length=source.byte_length,
            )
        except CandidateQuarantineError as exc:
            raise PublicationError("candidate quarantine verification failed") from exc
        if (
            verified.base_sha != candidate.base_sha
            or verified.head_sha != candidate.head_sha
            or verified.tree_sha != candidate.tree_sha
            or verified.bundle_sha256 != source.bundle_sha256
        ):
            raise PublicationError("quarantine readback does not match admitted candidate")
        return source, verified
    def publish(self, session: Session, publication_id: str) -> PublicationView:
        view = get_view(session, publication_id)
        candidate = view.current_candidate
        if candidate is None:
            raise DomainError("publication has no current candidate")
        if view.state not in {PublicationState.ADMITTED, PublicationState.IN_REVIEW}:
            raise DomainError("publication requires ADMITTED state")

        profile_for_repository(view.repository)
        source, _verified = self._verified_source(session, view)
        branch = self.publication_branch(view)
        if view.remote_head_sha is not None and (
            not view.remote_branch
            or not view.base_branch
            or view.pull_request_number is None
        ):
            raise PublicationError(
                "successor publication is missing governed PR metadata"
            )
        if view.remote_branch is not None and view.remote_branch != branch:
            raise PublicationError("published branch metadata is inconsistent")

        try:
            access = self.token_provider.installation_access(view.repository)
            token = access.token
            repository = self.github.repository(view.repository, token)
            base_branch = view.base_branch or repository.default_branch

            if view.state is PublicationState.ADMITTED:
                remote_base = self.github.ref_sha(view.repository, base_branch, token)
                if remote_base != candidate.base_sha:
                    raise PublicationError("remote base moved after candidate admission")

            target_before = self.github.ref_sha(view.repository, branch, token)
            if view.remote_head_sha is not None:
                if target_before is None:
                    raise PublicationError("published branch disappeared")
                if target_before not in {
                    view.remote_head_sha,
                    candidate.head_sha,
                }:
                    raise PublicationError("publication branch collision")
                assert view.pull_request_number is not None
                existing_pull = self.github.pull_request(
                    view.repository,
                    view.pull_request_number,
                    token,
                )
                if target_before == view.remote_head_sha:
                    self._verify_canonical_pull_request(
                        existing_pull,
                        view=view,
                        branch=branch,
                        base_branch=base_branch,
                        expected_head_sha=target_before,
                    )
                else:
                    self._verify_canonical_pull_request_identity(
                        existing_pull,
                        view=view,
                        branch=branch,
                        base_branch=base_branch,
                    )
                    if existing_pull.head_sha not in {
                        view.remote_head_sha,
                        candidate.head_sha,
                    }:
                        raise PublicationError(
                            "canonical pull request head does not match governed publication"
                        )

            if target_before is None:
                self.git_push.push_governed_head(
                    repo_path=self.quarantine.repo_path(source.quarantine_id),
                    repository=view.repository,
                    branch=branch,
                    token=token,
                )
            elif (
                view.state is PublicationState.ADMITTED
                and view.remote_head_sha is not None
                and view.remote_head_sha != candidate.head_sha
            ):
                if target_before == view.remote_head_sha:
                    if not self.quarantine.is_ancestor(
                        source.quarantine_id,
                        target_before,
                        candidate.head_sha,
                    ):
                        raise PublicationError(
                            "successor candidate is not a fast-forward"
                        )
                    self.git_push.push_governed_head(
                        repo_path=self.quarantine.repo_path(source.quarantine_id),
                        repository=view.repository,
                        branch=branch,
                        token=token,
                        expected_old_sha=view.remote_head_sha,
                    )
                elif target_before == candidate.head_sha:
                    # Recover the exact readback after a push whose ledger
                    # append was interrupted, while still proving its ancestry.
                    if not self.quarantine.is_ancestor(
                        source.quarantine_id,
                        view.remote_head_sha,
                        candidate.head_sha,
                    ):
                        raise PublicationError(
                            "successor candidate is not a fast-forward"
                        )
                else:
                    raise PublicationError("publication branch collision")
            elif target_before != candidate.head_sha:
                raise PublicationError("publication branch collision")

            pull = self._readback_published_head(
                repository=view.repository,
                branch=branch,
                token=token,
                view=view,
                base_branch=base_branch,
                expected_head_sha=candidate.head_sha,
                previous_head_sha=view.remote_head_sha,
            )
            if pull is None:
                pull = self.github.ensure_pull_request(
                    view.repository,
                    base_branch=base_branch,
                    head_branch=branch,
                    expected_head_sha=candidate.head_sha,
                    issue_number=view.issue_number,
                    token=token,
                )
        except (GitHubAuthError, GitHubApiError, CandidateQuarantineError) as exc:
            raise PublicationError("GitHub publication failed closed") from exc

        if view.state is PublicationState.IN_REVIEW:
            if view.remote_head_sha != candidate.head_sha:
                raise PublicationError("published state is stale")
            if view.base_branch is not None and view.base_branch != base_branch:
                raise PublicationError("published base metadata is inconsistent")
            if (
                view.pull_request_number is not None
                and view.pull_request_number != pull.number
            ):
                raise PublicationError("published pull request metadata is inconsistent")
            return view

        return mark_remote_published(
            session,
            publication_id,
            candidate.head_sha,
            branch=branch,
            base_branch=base_branch,
            pull_request_number=pull.number,
        )
