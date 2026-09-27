from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

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

    def push_exact_head(
        self,
        *,
        repo_path: Path,
        repository: str,
        branch: str,
        token: str,
    ) -> None:
        if not _REPOSITORY_RE.fullmatch(repository):
            raise PublicationError("publisher repository identity is invalid")
        if not _BRANCH_RE.fullmatch(branch) or ".." in branch or branch.endswith("/"):
            raise PublicationError("publisher branch identity is invalid")
        if not token:
            raise PublicationError("publisher installation token is unavailable")

        remote_url = f"https://github.com/{repository}.git"
        refspec = f"refs/controlplane/head:refs/heads/{branch}"
        with tempfile.TemporaryDirectory(prefix="fc-controlplane-askpass-") as raw:
            askpass = self._write_askpass(Path(raw))
            environment = self._safe_environment(token, askpass)
            try:
                result = subprocess.run(
                    [
                        self.git_executable,
                        "-c",
                        "credential.helper=",
                        "-C",
                        str(repo_path),
                        "push",
                        "--porcelain",
                        "--no-verify",
                        "--no-tags",
                        remote_url,
                        refspec,
                    ],
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
    ) -> None:
        self.token_provider = token_provider
        self.github = github
        self.quarantine = quarantine
        self.git_push = git_push or GitPushTransport()

    @staticmethod
    def publication_branch(view: PublicationView) -> str:
        return f"control-plane/issue-{view.issue_number}-{view.publication_id[:8]}"

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

        try:
            access = self.token_provider.installation_access(view.repository)
            token = access.token
            repository = self.github.repository(view.repository, token)
            base_branch = repository.default_branch

            if view.state is PublicationState.ADMITTED:
                remote_base = self.github.ref_sha(view.repository, base_branch, token)
                if remote_base != candidate.base_sha:
                    raise PublicationError("remote base moved after candidate admission")

            target_before = self.github.ref_sha(view.repository, branch, token)
            if target_before is None:
                if view.state is PublicationState.IN_REVIEW:
                    raise PublicationError("published branch disappeared")
                self.git_push.push_exact_head(
                    repo_path=self.quarantine.repo_path(source.quarantine_id),
                    repository=view.repository,
                    branch=branch,
                    token=token,
                )
            elif target_before != candidate.head_sha:
                if (
                    view.state is PublicationState.ADMITTED
                    and view.remote_head_sha is not None
                    and target_before == view.remote_head_sha
                    and self.quarantine.is_ancestor(
                        source.quarantine_id,
                        target_before,
                        candidate.head_sha,
                    )
                ):
                    self.git_push.push_exact_head(
                        repo_path=self.quarantine.repo_path(source.quarantine_id),
                        repository=view.repository,
                        branch=branch,
                        token=token,
                    )
                else:
                    raise PublicationError("publication branch collision")

            target_after = self.github.ref_sha(view.repository, branch, token)
            if target_after != candidate.head_sha:
                raise PublicationError("remote head readback does not match admitted candidate")

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
            if view.remote_branch is not None and view.remote_branch != branch:
                raise PublicationError("published branch metadata is inconsistent")
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
