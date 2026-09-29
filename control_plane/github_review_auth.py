from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import SecretStr

from .github_api import GitHubApiError, GitHubRepositoryGateway


class GitHubReviewAuthError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GitHubReviewAccess:
    token: str = field(repr=False, compare=False)
    login: str


class GitHubReviewTokenProvider:
    """Verifies and returns a runtime-only, user-attributed review token."""

    def __init__(
        self,
        *,
        token: SecretStr | str,
        expected_login: str,
        github: GitHubRepositoryGateway,
    ) -> None:
        self._token = token if isinstance(token, SecretStr) else SecretStr(token)
        self.expected_login = expected_login.strip()
        self.github = github

    def access(self) -> GitHubReviewAccess:
        token = self._token.get_secret_value()
        if not token:
            raise GitHubReviewAuthError(
                "Codex review trigger token is not configured"
            )
        if not token.startswith("github_pat_") or any(
            char.isspace() for char in token
        ):
            raise GitHubReviewAuthError(
                "Codex review trigger requires a fine-grained user token"
            )
        if not self.expected_login:
            raise GitHubReviewAuthError(
                "Codex review trigger login is not configured"
            )
        verification_failed = False
        try:
            login = self.github.authenticated_user_login(token)
        except GitHubApiError:
            verification_failed = True
            login = ""
        if verification_failed:
            raise GitHubReviewAuthError(
                "Codex review trigger identity could not be verified"
            )
        if login.casefold() != self.expected_login.casefold():
            raise GitHubReviewAuthError(
                "Codex review trigger identity does not match configured login"
            )
        return GitHubReviewAccess(token=token, login=login)
