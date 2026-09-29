from __future__ import annotations

import hashlib
import uuid

from pydantic import SecretStr
from sqlalchemy.orm import Session

from .domain import AutomatedReviewStatus, DomainError
from .github_api import GitHubApiError, GitHubRepositoryGateway
from .github_app import GitHubAppTokenProvider, GitHubAuthError
from .remediation import (
    RemediationWorkPackageView,
    WorkPackageState,
    claim_github_artifact_dispatch,
    complete_work_package,
    fence_github_artifact_dispatch,
    get_work_package,
    record_implementation_issue_linked,
    record_github_artifact,
    record_issue_closed,
    record_summary_comment,
    release_github_artifact_dispatch,
    successor_review_is_terminal,
)
from .service import get_view


class RemediationMaterializationError(RuntimeError):
    pass


class GitHubRemediationMaterializer:
    def __init__(
        self,
        *,
        token_provider: GitHubAppTokenProvider,
        github: GitHubRepositoryGateway,
        project_token: SecretStr,
        review_thread_token: SecretStr = SecretStr(""),
        project_number: int | None = 4,
        project_lifecycle_field: str = "Lifecycle",
    ) -> None:
        self.token_provider = token_provider
        self.github = github
        self.project_token = project_token
        self.review_thread_token = review_thread_token
        self.project_number = project_number
        self.project_lifecycle_field = project_lifecycle_field

    @staticmethod
    def _marker(work_package_id: str, finding_id: str, artifact: str) -> str:
        finding_key = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:24]
        return (
            "<!-- firstcontact-control-plane:remediation "
            f"batch={work_package_id} finding={finding_key} artifact={artifact} -->"
        )

    @staticmethod
    def _exact_pull_request(
        view: RemediationWorkPackageView,
        publication,
        pull,
        expected_head_sha: str,
    ) -> None:
        if (
            publication.pull_request_number is None
            or pull.number != publication.pull_request_number
            or pull.state != "open"
            or pull.head_sha != expected_head_sha
            or pull.head_ref != publication.remote_branch
            or pull.base_ref != publication.base_branch
        ):
            raise RemediationMaterializationError(
                "canonical pull request changed after successor verification"
            )

    def _verify_current_head(
        self,
        session: Session,
        view: RemediationWorkPackageView,
        token: str,
    ) -> None:
        publication = get_view(session, view.publication_id)
        package = get_work_package(session, view.work_package_id)
        if package.successor_review_run_id and package.successor_head_sha:
            expected_run_id = package.successor_review_run_id
            expected_head_sha = package.successor_head_sha
        elif all(
            finding["principal_decision"]["decision"] == "REJECTED"
            for finding in package.findings
        ):
            expected_run_id = package.review_run["run_id"]
            expected_head_sha = package.reviewed_head_sha
        else:
            expected_run_id = None
            expected_head_sha = None
        terminal_review = successor_review_is_terminal(
            publication.automated_review_status,
            package.successor_fallback
            if package.successor_review_run_id is not None
            else None,
        )
        if (
            package.state is not WorkPackageState.VERIFYING
            or not expected_run_id
            or not expected_head_sha
            or publication.remote_head_sha != expected_head_sha
            or publication.automated_review_head_sha != expected_head_sha
            or publication.automated_review_run_id != expected_run_id
            or not terminal_review
        ):
            raise RemediationMaterializationError(
                "successor review is no longer current for materialization"
            )
        if publication.pull_request_number is None:
            raise RemediationMaterializationError(
                "publication has no canonical pull request"
            )
        pull = self.github.pull_request(
            publication.repository,
            publication.pull_request_number,
            token,
        )
        self._exact_pull_request(view, publication, pull, expected_head_sha)

    @staticmethod
    def _closure_ready(view: RemediationWorkPackageView) -> bool:
        return all(
            finding["closure_state"] in {"VERIFIED_ABSENT", "REJECTED_BY_PRINCIPAL"}
            for finding in view.findings
        )

    @staticmethod
    def _status_projection(
        view: RemediationWorkPackageView,
        *,
        finalizing_done: bool = False,
    ) -> tuple[str, str]:
        if finalizing_done:
            return "status:done", "Done"
        if view.state is WorkPackageState.READY:
            return "status:ready", "Ready"
        if view.state is WorkPackageState.IN_PROGRESS:
            return "status:in-progress", "In Progress"
        if view.state in {
            WorkPackageState.IMPLEMENTED,
            WorkPackageState.VERIFYING,
            WorkPackageState.REWORK_REQUIRED,
        }:
            return "status:review", "Review"
        if view.state is WorkPackageState.DONE:
            return "status:done", "Done"
        raise RemediationMaterializationError("work-package state has no GitHub projection")

    def _desired_labels(
        self,
        view: RemediationWorkPackageView,
        *,
        finalizing_done: bool = False,
    ) -> tuple[str, ...]:
        status_label, _project_status = self._status_projection(
            view,
            finalizing_done=finalizing_done,
        )
        priorities = [finding["priority"] for finding in view.findings]
        priority = min(priorities, key=lambda item: int(item[1:]))
        return (status_label, "type:fix", f"priority:{priority}")

    def _summary_issue_body(
        self,
        session: Session,
        view: RemediationWorkPackageView,
    ) -> str:
        publication = get_view(session, view.publication_id)
        parent_issue_url = (
            f"https://github.com/{view.repository}/issues/{publication.issue_number}"
        )
        pr_url = (
            f"https://github.com/{view.repository}/pull/{publication.pull_request_number}"
            if publication.pull_request_number is not None
            else "Unavailable"
        )
        findings = "\n".join(
            "| {id} | {priority} | {decision} | {feedback} |".format(
                id=item["finding_id"],
                priority=item["priority"],
                decision=item["principal_decision"]["decision"],
                feedback=item["desired_reaction"],
            )
            for item in view.findings
        )
        marker = self._issue_marker(view.work_package_id)
        return (
            f"Parent objective: #{publication.issue_number} ({parent_issue_url})\n\n"
            f"Canonical PR: {pr_url}\n\n"
            f"Source review run: `{view.review_run['run_id']}`\n\n"
            f"Reviewed HEAD: `{view.reviewed_head_sha}`\n\n"
            f"Remediation batch: `{view.work_package_id}`\n\n"
            "Principal Reviewer decisions:\n\n"
            "| Finding | Priority | Decision | Desired feedback |\n"
            "| --- | --- | --- | --- |\n"
            f"{findings}\n\n{marker}"
        )

    @staticmethod
    def _issue_marker(work_package_id: str) -> str:
        return f"<!-- firstcontact-control-plane:remediation-issue batch={work_package_id} -->"

    def _project(
        self,
        view: RemediationWorkPackageView,
        issue_node_id: str,
        *,
        finalizing_done: bool = False,
    ) -> None:
        if self.project_number is None:
            raise RemediationMaterializationError(
                "remediation Project V2 number is not configured"
            )
        project_token = self.project_token.get_secret_value().strip()
        if not project_token:
            raise RemediationMaterializationError(
                "remediation Project V2 credential is not configured"
            )
        _label, project_status = self._status_projection(
            view,
            finalizing_done=finalizing_done,
        )
        self.github.ensure_project_v2_status(
            view.repository,
            issue_node_id,
            project_number=self.project_number,
            field_name=self.project_lifecycle_field,
            status=project_status,
            project_token=project_token,
        )

    def _ensure_issue_projections(
        self,
        session: Session,
        view: RemediationWorkPackageView,
        issue,
        repository_token: str,
    ) -> None:
        publication = get_view(session, view.publication_id)
        if (
            issue.number != view.implementation_issue_number
            or issue.database_id is None
            or issue.issue_node_id is None
            or publication.issue_number <= 0
        ):
            raise RemediationMaterializationError(
                "implementation issue or parent identity is incomplete"
            )
        self.github.ensure_sub_issue(
            view.repository,
            publication.issue_number,
            issue.database_id,
            repository_token,
        )
        self.github.ensure_issue_labels(
            view.repository,
            issue.number,
            self._desired_labels(view),
            repository_token,
        )
        self._project(view, issue.issue_node_id)

    def sync_issue_projection(
        self,
        session: Session,
        work_package_id: str,
    ) -> RemediationWorkPackageView:
        view = get_work_package(session, work_package_id)
        if view.implementation_issue_number is None:
            raise RemediationMaterializationError(
                "work package has no linked implementation issue"
            )
        if self.project_number is None:
            raise RemediationMaterializationError(
                "remediation Project V2 number is not configured"
            )
        lease_id = str(uuid.uuid4())
        artifact_key = "implementation-issue:projection"
        if not claim_github_artifact_dispatch(
            session,
            work_package_id,
            artifact_key=artifact_key,
            lease_id=lease_id,
        ):
            return get_work_package(session, work_package_id)
        try:
            access = self.token_provider.installation_access(
                view.repository,
                permissions={"issues": "write"},
            )
            issue = self.github.issue(
                view.repository,
                view.implementation_issue_number,
                access.token,
            )
            if not fence_github_artifact_dispatch(
                session,
                work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            ):
                return get_work_package(session, work_package_id)
            self._ensure_issue_projections(session, view, issue, access.token)
            return view
        except (GitHubApiError, GitHubAuthError, DomainError) as exc:
            raise RemediationMaterializationError(
                "GitHub remediation projection failed closed"
            ) from exc
        finally:
            release_github_artifact_dispatch(
                session,
                work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            )

    def ensure_implementation_issue(
        self,
        session: Session,
        work_package_id: str,
    ) -> RemediationWorkPackageView:
        view = get_work_package(session, work_package_id)
        if view.implementation_issue_number is not None:
            return self.sync_issue_projection(session, work_package_id)
        if self.project_number is None:
            raise RemediationMaterializationError(
                "remediation Project V2 number is not configured"
            )
        lease_id = str(uuid.uuid4())
        artifact_key = "implementation-issue:create"
        if not claim_github_artifact_dispatch(
            session,
            work_package_id,
            artifact_key=artifact_key,
            lease_id=lease_id,
        ):
            return get_work_package(session, work_package_id)
        try:
            access = self.token_provider.installation_access(
                view.repository,
                permissions={"issues": "write"},
            )
            bot_login = self.token_provider.bot_login()
            marker = self._issue_marker(work_package_id)
            matches = [
                issue
                for issue in self.github.list_issues(view.repository, access.token)
                if marker in issue.body
            ]
            if len(matches) > 1:
                raise RemediationMaterializationError(
                    "duplicate GitHub issues exist for this remediation batch"
                )
            if not fence_github_artifact_dispatch(
                session,
                work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            ):
                return get_work_package(session, work_package_id)
            if matches:
                issue = matches[0]
            else:
                priorities = [finding["priority"] for finding in view.findings]
                priority = min(priorities, key=lambda item: int(item[1:]))
                issue = self.github.create_issue(
                    view.repository,
                    title=f"[P{priority[1:]}][IMPLEMENTATION FIX] Remediation batch {work_package_id[:8]}",
                    body=self._summary_issue_body(session, view),
                    labels=self._desired_labels(view),
                    token=access.token,
                )
            if (
                issue.actor is None
                or issue.actor.strip().lower() != bot_login.strip().lower()
                or marker not in issue.body
                or issue.issue_node_id is None
            ):
                raise RemediationMaterializationError(
                    "implementation issue identity or actor is ambiguous"
                )
            view = record_implementation_issue_linked(
                session,
                work_package_id,
                issue_number=issue.number,
                idempotency_key="github:implementation-issue:linked",
            )
            self._ensure_issue_projections(session, view, issue, access.token)
            return view
        except (GitHubApiError, GitHubAuthError, DomainError) as exc:
            raise RemediationMaterializationError(
                "GitHub implementation issue creation failed closed"
            ) from exc
        finally:
            release_github_artifact_dispatch(
                session,
                work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            )

    def _dispatch(
        self,
        session: Session,
        view: RemediationWorkPackageView,
        *,
        finding_id: str,
        artifact: str,
        token: str,
        operation,
    ) -> bool:
        lease_id = str(uuid.uuid4())
        artifact_key = f"finding:{finding_id}:{artifact}"
        if not claim_github_artifact_dispatch(
            session,
            view.work_package_id,
            artifact_key=artifact_key,
            lease_id=lease_id,
        ):
            return False
        try:
            self._verify_current_head(session, view, token)
            if not fence_github_artifact_dispatch(
                session,
                view.work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            ):
                return False
            remote_id = operation()
            if not fence_github_artifact_dispatch(
                session,
                view.work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            ):
                raise RemediationMaterializationError(
                    "artifact dispatch ownership changed before receipt"
                )
            record_github_artifact(
                session,
                view.work_package_id,
                finding_id=finding_id,
                artifact=artifact,
                remote_id=remote_id,
                idempotency_key=f"github:{finding_id}:{artifact}",
            )
            return True
        finally:
            release_github_artifact_dispatch(
                session,
                view.work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            )

    def _reaction(
        self,
        session: Session,
        view: RemediationWorkPackageView,
        finding: dict,
        *,
        token: str,
        bot_login: str,
    ) -> bool:
        desired = finding["desired_reaction"]
        artifact = finding["materialization"]["reaction"]
        if desired == "none" or artifact == "MATERIALIZED":
            return True
        comment_id = finding["source"]["provider_thread_id"]

        def add_reaction():
            reaction = self.github.add_pull_review_comment_reaction(
                view.repository,
                comment_id,
                desired,
                token,
            )
            if reaction.actor.strip().lower() != bot_login.strip().lower():
                raise RemediationMaterializationError(
                    "GitHub reaction actor does not match the Control Plane App"
                )
            return reaction.reaction_id

        return self._dispatch(
            session,
            view,
            finding_id=finding["finding_id"],
            artifact="reaction",
            token=token,
            operation=add_reaction,
        )

    def _reply(
        self,
        session: Session,
        view: RemediationWorkPackageView,
        finding: dict,
        *,
        token: str,
        bot_login: str,
    ) -> bool:
        if finding["materialization"]["reply"] == "MATERIALIZED":
            return True
        marker = self._marker(view.work_package_id, finding["finding_id"], "reply")
        source = finding["source"]
        parent_comment_id = source["provider_thread_id"]
        publication = get_view(session, view.publication_id)
        if publication.pull_request_number is None:
            raise RemediationMaterializationError("publication has no canonical pull request")

        def add_or_recover_reply():
            replies = [
                comment
                for comment in self.github.list_pull_review_comments(
                    view.repository,
                    publication.pull_request_number,
                    token,
                )
                if marker in comment.body
            ]
            if len(replies) > 1:
                raise RemediationMaterializationError(
                    "multiple materialization replies exist for this finding"
                )
            if replies:
                reply = replies[0]
                if (
                    reply.in_reply_to_id != parent_comment_id
                    or reply.actor.strip().lower() != bot_login.strip().lower()
                ):
                    raise RemediationMaterializationError(
                        "existing materialization reply identity is ambiguous"
                    )
                return reply.comment_id

            decision = finding["principal_decision"]["decision"]
            if decision == "ACCEPTED":
                text = (
                    f"Verified absent in successor review "
                    f"{view.successor_review_run_id} at {view.successor_head_sha}. "
                    f"Implementation candidate {view.candidate_id} "
                    f"({view.implementation_head_sha}) was submitted and validated."
                )
            else:
                text = (
                    "The Principal Reviewer rejected this finding. Reason: "
                    f"{finding['principal_decision']['reason']}"
                )
            response = self.github.reply_to_pull_review_comment(
                view.repository,
                publication.pull_request_number,
                parent_comment_id,
                f"{text}\n\n{marker}",
                token,
            )
            if response.actor.strip().lower() != bot_login.strip().lower():
                raise RemediationMaterializationError(
                    "GitHub reply actor does not match the Control Plane App"
                )
            return response.comment_id

        return self._dispatch(
            session,
            view,
            finding_id=finding["finding_id"],
            artifact="reply",
            token=token,
            operation=add_or_recover_reply,
        )

    def _resolve(
        self,
        session: Session,
        view: RemediationWorkPackageView,
        finding: dict,
        *,
        token: str,
    ) -> bool:
        if finding["materialization"]["resolution"] == "MATERIALIZED":
            return True
        publication = get_view(session, view.publication_id)
        if publication.pull_request_number is None:
            raise RemediationMaterializationError("publication has no canonical pull request")
        review_thread_token = self.review_thread_token.get_secret_value().strip()
        if not review_thread_token:
            raise RemediationMaterializationError(
                "remediation review-thread credential is not configured"
            )
        comment_id = finding["source"]["provider_thread_id"]
        return self._dispatch(
            session,
            view,
            finding_id=finding["finding_id"],
            artifact="resolution",
            token=token,
            operation=lambda: self.github.resolve_pull_review_thread(
                view.repository,
                publication.pull_request_number,
                comment_id,
                review_thread_token,
            ),
        )

    def _ensure_terminal_done_projection(
        self,
        session: Session,
        view: RemediationWorkPackageView,
        *,
        access,
    ) -> RemediationWorkPackageView:
        if view.state is not WorkPackageState.DONE:
            raise DomainError("terminal projection requires authoritative DONE state")
        if view.implementation_issue_number is None:
            raise RemediationMaterializationError(
                "work package has no linked implementation issue"
            )

        if not view.issue_closed:
            lease_id = str(uuid.uuid4())
            artifact_key = "implementation-issue:close"
            if not claim_github_artifact_dispatch(
                session,
                view.work_package_id,
                artifact_key=artifact_key,
                lease_id=lease_id,
            ):
                return get_work_package(session, view.work_package_id)
            try:
                if not fence_github_artifact_dispatch(
                    session,
                    view.work_package_id,
                    artifact_key=artifact_key,
                    lease_id=lease_id,
                ):
                    return get_work_package(session, view.work_package_id)
                closed = self.github.close_issue(
                    view.repository,
                    view.implementation_issue_number,
                    access.token,
                )
                if closed.number != view.implementation_issue_number:
                    raise RemediationMaterializationError(
                        "closed implementation issue identity changed"
                    )
                record_issue_closed(
                    session,
                    view.work_package_id,
                    idempotency_key="github:implementation-issue:close",
                )
            finally:
                release_github_artifact_dispatch(
                    session,
                    view.work_package_id,
                    artifact_key=artifact_key,
                    lease_id=lease_id,
                )
            view = get_work_package(session, view.work_package_id)

        issue = self.github.issue(
            view.repository,
            view.implementation_issue_number,
            access.token,
        )
        if issue.issue_node_id is None:
            raise RemediationMaterializationError(
                "implementation issue has no GitHub node id"
            )
        self.github.ensure_issue_labels(
            view.repository,
            view.implementation_issue_number,
            self._desired_labels(view),
            access.token,
        )
        self._project(view, issue.issue_node_id)
        return get_work_package(session, view.work_package_id)


    def materialize(
        self,
        session: Session,
        work_package_id: str,
    ) -> RemediationWorkPackageView:
        view = get_work_package(session, work_package_id)
        if view.implementation_issue_number is None:
            raise DomainError("implementation issue must be linked before materialization")
        if self.project_number is None:
            raise RemediationMaterializationError(
                "remediation Project V2 number is not configured"
            )
        if view.state is not WorkPackageState.DONE and (
            view.state is not WorkPackageState.VERIFYING or not self._closure_ready(view)
        ):
            raise DomainError(
                "all accepted findings require successor verification before materialization"
            )
        try:
            access = self.token_provider.installation_access(
                view.repository,
                permissions={"issues": "write", "pull_requests": "write"},
            )
            if view.state is WorkPackageState.DONE:
                return self._ensure_terminal_done_projection(
                    session,
                    view,
                    access=access,
                )
            bot_login = self.token_provider.bot_login()
            for initial_finding in view.findings:
                finding = next(
                    item
                    for item in get_work_package(session, work_package_id).findings
                    if item["finding_id"] == initial_finding["finding_id"]
                )
                if finding["source"].get("provider_thread_id") is None:
                    continue
                if not self._reaction(
                    session,
                    view,
                    finding,
                    token=access.token,
                    bot_login=bot_login,
                ):
                    return get_work_package(session, work_package_id)
                finding = next(
                    item
                    for item in get_work_package(session, work_package_id).findings
                    if item["finding_id"] == initial_finding["finding_id"]
                )
                if not self._reply(
                    session,
                    view,
                    finding,
                    token=access.token,
                    bot_login=bot_login,
                ):
                    return get_work_package(session, work_package_id)
                finding = next(
                    item
                    for item in get_work_package(session, work_package_id).findings
                    if item["finding_id"] == initial_finding["finding_id"]
                )
                if not self._resolve(
                    session,
                    view,
                    finding,
                    token=access.token,
                ):
                    return get_work_package(session, work_package_id)

            view = get_work_package(session, work_package_id)
            if view.summary_comment_id is None:
                lease_id = str(uuid.uuid4())
                artifact_key = "implementation-issue:summary"
                if not claim_github_artifact_dispatch(
                    session,
                    work_package_id,
                    artifact_key=artifact_key,
                    lease_id=lease_id,
                ):
                    return get_work_package(session, work_package_id)
                try:
                    self._verify_current_head(session, view, access.token)
                    marker = self._marker(work_package_id, "all", "summary")
                    comments = self.github.list_issue_comments(
                        view.repository,
                        view.implementation_issue_number,
                        access.token,
                    )
                    matches = [item for item in comments if marker in item.body]
                    if len(matches) > 1:
                        raise RemediationMaterializationError(
                            "duplicate work package summary comments exist"
                        )
                    if not fence_github_artifact_dispatch(
                        session,
                        work_package_id,
                        artifact_key=artifact_key,
                        lease_id=lease_id,
                    ):
                        return get_work_package(session, work_package_id)
                    if matches:
                        comment = matches[0]
                        if comment.actor.strip().lower() != bot_login.strip().lower():
                            raise RemediationMaterializationError(
                                "existing summary comment actor is unexpected"
                            )
                    else:
                        findings = ", ".join(
                            item["finding_id"] for item in view.findings
                        )
                        if view.successor_review_run_id and view.successor_head_sha:
                            evidence = (
                                f"Candidate {view.candidate_id} at "
                                f"{view.implementation_head_sha} was reviewed by run "
                                f"{view.successor_review_run_id} at {view.successor_head_sha}."
                            )
                        else:
                            evidence = (
                                "The Principal Reviewer finalized rejected findings "
                                f"from run {view.review_run['run_id']} at "
                                f"{view.reviewed_head_sha}; no code remediation was required."
                            )
                        body = (
                            f"Implementation and verification are ready for authoritative completion for work package "
                            f"{work_package_id}. {evidence} Closed findings: {findings}.\n\n"
                            f"{marker}"
                        )
                        comment = self.github.add_issue_comment(
                            view.repository,
                            view.implementation_issue_number,
                            body,
                            access.token,
                        )
                        if comment.actor.strip().lower() != bot_login.strip().lower():
                            raise RemediationMaterializationError(
                                "summary comment actor does not match the Control Plane App"
                            )
                    if not fence_github_artifact_dispatch(
                        session,
                        work_package_id,
                        artifact_key=artifact_key,
                        lease_id=lease_id,
                    ):
                        raise RemediationMaterializationError(
                            "summary dispatch ownership changed before receipt"
                        )
                    record_summary_comment(
                        session,
                        work_package_id,
                        comment_id=comment.comment_id,
                        idempotency_key="github:implementation-issue:summary",
                    )
                finally:
                    release_github_artifact_dispatch(
                        session,
                        work_package_id,
                        artifact_key=artifact_key,
                        lease_id=lease_id,
                    )

            completed = complete_work_package(
                session,
                work_package_id,
                idempotency_key="github:work-package:done",
            )
            return self._ensure_terminal_done_projection(
                session,
                completed,
                access=access,
            )
        except (GitHubApiError, GitHubAuthError, DomainError) as exc:
            raise RemediationMaterializationError(
                "GitHub remediation materialization failed closed"
            ) from exc
