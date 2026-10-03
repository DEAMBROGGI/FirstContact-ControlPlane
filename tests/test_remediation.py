from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pydantic import SecretStr
from fastapi import HTTPException
from fastapi.testclient import TestClient

from control_plane.config import Settings, settings
from control_plane.codex_findings import codex_review_body_finding_id
from control_plane.db import get_session
from control_plane.domain import (
    AutomatedReviewStatus,
    DomainError,
    EventType,
    PublicationState,
    ReviewDecision,
    ValidationStatus,
)
from control_plane.github_api import (
    GitHubApiError,
    IssueCommentSnapshot,
    IssueSnapshot,
    PullRequestSnapshot,
    PullReviewCommentReactionSnapshot,
    PullReviewCommentSnapshot,
    PullReviewSnapshot,
    PullReviewThreadSnapshot,
)
from control_plane.github_app import InstallationAccess
from control_plane.github_webhook import (
    _derive_next,
    _parse_time,
    _required_adjudication_time,
)
from control_plane.main import app, get_remediation_materializer, get_session
from control_plane.models import RemediationEventRow, RemediationWorkPackageRow
from control_plane.models import (
    PRFindingReconciliationRow,
    RemediationEventRow,
    RemediationWorkPackageRow,
)
from control_plane.plane_review import (
    complete_plane_review_materialization,
    record_plane_review,
)
from control_plane.profile_registry import profile_for_repository
from control_plane.quarantine import VerifiedCandidateSource
from control_plane.remediation import (
    PrincipalDecision,
    WorkPackageState,
    adopt_historical_implementation,
    adopt_historical_pr_finding,
    begin_principal_verification,
    begin_rejected_findings_finalization,
    begin_successor_verification,
    claim_github_artifact_dispatch,
    claim_work_package,
    complete_work_package,
    create_work_package,
    fence_github_artifact_dispatch,
    get_work_package,
    load_work_package_events,
    mark_implementation_rework_required,
    publication_has_unresolved_remediation_findings,
    remediation_watch_action,
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
from control_plane.repository import append_event, load_events
from control_plane.pr_findings import reconcile_pr_findings
from control_plane.pr_findings import latest_reconciliation, reconcile_pr_findings
from control_plane.service import (
    complete_codex_review,
    create_publication,
    get_view,
    mark_codex_review_unavailable,
    mark_remote_published,
    record_review,
    record_validation,
    request_codex_review,
    required_review_adjudication,
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
    published = mark_remote_published(
        session,
        view.publication_id,
        HEAD,
        branch="control-plane/issue-10-abcdef01",
        base_branch="master",
        pull_request_number=13,
    )
    _reconcile_empty_pr_findings(session, published)
    return published


def _reconcile_empty_pr_findings(session, view):
    class EmptyGitHub:
        def pull_request(self, repository, number, token):
            return PullRequestSnapshot(
                number=number,
                state="open",
                base_ref=view.base_branch,
                head_ref=view.remote_branch,
                head_sha=view.remote_head_sha,
                base_sha=BASE,
            )

        def ref_sha(self, repository, branch, token):
            return BASE

        def list_pull_reviews(self, repository, number, token):
            return []

        def list_pull_review_comments(self, repository, number, token):
            return []

        def list_pull_review_threads(self, repository, number, token):
            return []

    return reconcile_pr_findings(
        session,
        view.publication_id,
        github=EmptyGitHub(),
        token="test-installation-token",
    )


def _review_thread_gateway(
    view,
    reviews=(),
    comments=(),
    threads=(),
    base_sha=BASE,
):
    def pull_request(repository, number, token):
        return PullRequestSnapshot(
            number=view.pull_request_number,
            state="open",
            base_ref=view.base_branch,
            head_ref=view.remote_branch,
            head_sha=view.remote_head_sha,
            base_sha=base_sha,
        )

    return SimpleNamespace(
        pull_request=pull_request,
        ref_sha=lambda repository, branch, token: base_sha,
        list_pull_reviews=lambda repository, number, token: list(reviews),
        list_pull_review_comments=lambda repository, number, token: list(comments),
        list_pull_review_threads=lambda repository, number, token: list(threads),
    )


def test_reconciliation_classifies_tracked_orphans_and_excludes_resolved_threads(
    session,
):
    view, _source_run, package = create_package(session)
    comments = [
        PullReviewCommentSnapshot(
            comment_id=4101,
            review_id=3101,
            actor="chatgpt-codex-connector[bot]",
            body="Accepted review finding",
            commit_id=HEAD,
            path="control_plane/service.py",
            line=20,
            created_at="2026-10-01T12:00:00Z",
            side="RIGHT",
        ),
        PullReviewCommentSnapshot(
            comment_id=4201,
            review_id=3201,
            actor="principal-reviewer",
            body="Historical orphan one",
            commit_id=HEAD,
            path="control_plane/remediation.py",
            line=41,
            created_at="2026-10-01T12:01:00Z",
            side="LEFT",
        ),
        PullReviewCommentSnapshot(
            comment_id=4202,
            review_id=3202,
            actor="principal-reviewer",
            body="Historical orphan two",
            commit_id=HEAD,
            path="control_plane/service.py",
            line=52,
            created_at="2026-10-01T12:02:00Z",
            side="RIGHT",
        ),
        PullReviewCommentSnapshot(
            comment_id=4301,
            review_id=3301,
            actor="principal-reviewer",
            body="Already resolved finding",
            commit_id=HEAD,
            path="control_plane/github_api.py",
            line=63,
            created_at="2026-10-01T12:03:00Z",
            side="RIGHT",
        ),
    ]
    reviews = [
        PullReviewSnapshot(3101, "chatgpt-codex-connector[bot]", "", "COMMENTED", HEAD, "2026-10-01T12:00:00Z"),
        PullReviewSnapshot(3201, "principal-reviewer", "", "COMMENTED", HEAD, "2026-10-01T12:01:00Z"),
        PullReviewSnapshot(3202, "principal-reviewer", "", "COMMENTED", HEAD, "2026-10-01T12:02:00Z"),
        PullReviewSnapshot(3301, "principal-reviewer", "", "COMMENTED", HEAD, "2026-10-01T12:03:00Z"),
    ]
    threads = [
        PullReviewThreadSnapshot("PRRT_tracked", False, (4101,), 4101),
        PullReviewThreadSnapshot("PRRT_orphan_1", False, (4201,), 4201),
        PullReviewThreadSnapshot("PRRT_orphan_2", False, (4202,), 4202),
        PullReviewThreadSnapshot("PRRT_resolved", True, (4301,), 4301),
    ]

    receipt = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(view, reviews, comments, threads),
        token="test-installation-token",
    )

    assert receipt["remote_head_sha"] == HEAD
    assert receipt["unresolved_thread_count"] == 3
    assert len(receipt["threads"]) == 3
    by_comment = {item["root_comment_id"]: item for item in receipt["threads"]}
    assert by_comment[4101]["classification"] == "TRACKED"
    assert by_comment[4101]["work_package_id"] == package.work_package_id
    assert by_comment[4101]["finding_id"] == "codex:3101:4101"
    assert by_comment[4201]["classification"] == "ORPHAN"
    assert by_comment[4202]["classification"] == "ORPHAN"
    assert all(item["is_resolved"] is False for item in receipt["threads"])


def test_reconciliation_discovers_real_shape_dismissed_review_orphans(session):
    view = publish(session)
    source_head = "e11e21c6c91d68f6edce8a8b847297ac8a74e20e"
    review = PullReviewSnapshot(
        5372357970,
        "DEAMBROGGI",
        "Historical human review",
        "DISMISSED",
        source_head,
        "2026-09-01T12:00:00Z",
    )
    comments = [
        PullReviewCommentSnapshot(
            4149659655,
            5372357970,
            "DEAMBROGGI",
            "Historical finding one",
            source_head,
            "control_plane/remediation.py",
            120,
            "2026-09-01T12:01:00Z",
            side="RIGHT",
        ),
        PullReviewCommentSnapshot(
            4149659671,
            5372357970,
            "DEAMBROGGI",
            "Historical finding two",
            source_head,
            "control_plane/service.py",
            240,
            "2026-09-01T12:02:00Z",
            side="LEFT",
        ),
    ]
    threads = [
        PullReviewThreadSnapshot("PRRT_historical_1", False, (4149659655,), 4149659655),
        PullReviewThreadSnapshot("PRRT_historical_2", False, (4149659671,), 4149659671),
    ]

    receipt = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(view, [review], comments, threads),
        token="test-installation-token",
    )

    assert [item["root_comment_id"] for item in receipt["threads"]] == [
        4149659655,
        4149659671,
    ]
    assert all(item["classification"] == "ORPHAN" for item in receipt["threads"])
    assert all(item["provider_review_id"] == 5372357970 for item in receipt["threads"])
    assert all(item["source_review_state"] == "DISMISSED" for item in receipt["threads"])
    assert all(
        item["source_reviewed_head_sha"] == source_head
        for item in receipt["threads"]
    )


def test_reconciliation_base_drift_does_not_append_receipt(session):
    view = publish(session)
    previous = latest_reconciliation(session, view.publication_id)
    assert previous is not None

    with pytest.raises(DomainError, match="canonical PR base drifted"):
        reconcile_pr_findings(
            session,
            view.publication_id,
            github=_review_thread_gateway(view, base_sha="4" * 40),
            token="test-installation-token",
        )

    current = latest_reconciliation(session, view.publication_id)
    assert current is not None
    assert current.id == previous.id
    assert current.sequence == previous.sequence


def test_historical_finding_adoption_fails_closed_on_missing_or_corrupt_receipt(
    session,
):
    view, _source_run, package = create_package(session, review_mode="advisory")
    original_findings = get_work_package(session, package.work_package_id).findings
    with pytest.raises(KeyError):
        adopt_historical_pr_finding(
            session,
            package.work_package_id,
            reconciliation_id="missing-reconciliation-receipt",
            root_comment_id=4201,
            principal_review_run_id="principal-adjudication-missing-receipt",
            decision="ACCEPTED",
            reason="Receipt identity must exist in the publication ledger.",
            priority="P1",
            idempotency_key="adopt-missing-receipt",
        )

    comment = PullReviewCommentSnapshot(
        4201,
        3201,
        "DEAMBROGGI",
        "Historical orphan finding",
        HEAD,
        "control_plane/remediation.py",
        41,
        "2026-10-01T12:01:00Z",
        side="RIGHT",
    )
    receipt = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(
            view,
            [PullReviewSnapshot(3201, "DEAMBROGGI", "", "DISMISSED", HEAD, None)],
            [comment],
            [PullReviewThreadSnapshot("PRRT_corrupt", False, (4201,), 4201)],
        ),
        token="test-installation-token",
    )
    row = latest_reconciliation(session, view.publication_id)
    assert row is not None
    row.evidence = {**row.evidence, "remote_head_sha": "4" * 40}

    with pytest.raises(DomainError, match="binding is corrupt"):
        adopt_historical_pr_finding(
            session,
            package.work_package_id,
            reconciliation_id=receipt["reconciliation_id"],
            root_comment_id=4201,
            principal_review_run_id="principal-adjudication-corrupt-receipt",
            decision="ACCEPTED",
            reason="Corrupt receipts must not create authoritative findings.",
            priority="P1",
            idempotency_key="adopt-corrupt-receipt",
        )

    assert get_work_package(session, package.work_package_id).findings == original_findings


@pytest.mark.parametrize("decision", ["ACCEPTED", "REJECTED"])
def test_historical_orphan_adoption_binds_receipt_and_principal_decision(
    session,
    decision,
):
    view, _source_run, package = create_package(session, review_mode="advisory")
    comment = PullReviewCommentSnapshot(
        4201,
        3201,
        "DEAMBROGGI",
        "Historical orphan finding",
        HEAD,
        "control_plane/remediation.py",
        41,
        "2026-10-01T12:01:00Z",
        side="RIGHT",
    )
    receipt = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(
            view,
            [PullReviewSnapshot(3201, "DEAMBROGGI", "", "DISMISSED", HEAD, None)],
            [comment],
            [PullReviewThreadSnapshot("PRRT_adopt", False, (4201,), 4201)],
        ),
        token="test-installation-token",
    )
    review_run_id = f"principal-adjudication-{decision.lower()}"
    record_plane_review(
        session,
        view.publication_id,
        run_id=review_run_id,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Principal adjudication of the exact current PR head.",
        comments=[],
        idempotency_key=f"record:{review_run_id}",
    )
    complete_plane_review_materialization(
        session,
        view.publication_id,
        run_id=review_run_id,
        provider_review_id=9801,
        receipts=[],
    )

    adopted = adopt_historical_pr_finding(
        session,
        package.work_package_id,
        reconciliation_id=receipt["reconciliation_id"],
        root_comment_id=4201,
        principal_review_run_id=review_run_id,
        decision=decision,
        reason="Principal adjudicated the reconciled source finding.",
        priority="P1",
        idempotency_key=f"adopt:{decision.lower()}",
    )
    repeated = adopt_historical_pr_finding(
        session,
        package.work_package_id,
        reconciliation_id=receipt["reconciliation_id"],
        root_comment_id=4201,
        principal_review_run_id=review_run_id,
        decision=decision,
        reason="Principal adjudicated the reconciled source finding.",
        priority="P1",
        idempotency_key=f"adopt:{decision.lower()}",
    )

    finding = next(
        item for item in adopted.findings if item["finding_id"].startswith("github-human-review:")
    )
    events = load_work_package_events(session, package.work_package_id)
    event = next(item for item in events if item["event_type"] == "HUMAN_PR_FINDING_ADOPTED")
    assert finding["source"]["reconciliation_id"] == receipt["reconciliation_id"]
    assert finding["source"]["provider_thread_id"] == 4201
    assert finding["source"]["provider_review_id"] == 3201
    assert finding["source"]["source_reviewed_head_sha"] == HEAD
    assert finding["source"]["source_actor"] == "DEAMBROGGI"
    assert finding["source"]["body"] == "Historical orphan finding"
    assert finding["principal_decision"]["decision"] == decision
    assert finding["principal_decision"]["actor"] == "principal-reviewer:chatgpt"
    assert event["payload"]["principal_adjudication"]["review_event_hash"]
    assert repeated.findings == adopted.findings
    assert sum(item["event_type"] == "HUMAN_PR_FINDING_ADOPTED" for item in events) == 1
    assert all(item["event_type"] != "IMPLEMENTATION_SUBMITTED" for item in events)


def test_historical_orphan_adoption_rejects_h1_receipt_after_h2(session):
    view, _source_run, package = create_package(session, review_mode="advisory")
    comment = PullReviewCommentSnapshot(
        4201,
        3201,
        "DEAMBROGGI",
        "Historical orphan finding",
        HEAD,
        "control_plane/remediation.py",
        41,
        "2026-10-01T12:01:00Z",
        side="RIGHT",
    )
    source_review = PullReviewSnapshot(3201, "DEAMBROGGI", "", "DISMISSED", HEAD, None)
    source_thread = PullReviewThreadSnapshot("PRRT_adopt_h1_h2", False, (4201,), 4201)
    receipt_h1 = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(view, [source_review], [comment], [source_thread]),
        token="test-installation-token",
    )
    review_run_id = "principal-adjudication-h1"
    record_plane_review(
        session,
        view.publication_id,
        run_id=review_run_id,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Principal adjudication of H1.",
        comments=[],
        idempotency_key=f"record:{review_run_id}",
    )
    complete_plane_review_materialization(
        session,
        view.publication_id,
        run_id=review_run_id,
        provider_review_id=9802,
        receipts=[],
    )
    next_head = "4" * 40
    publish_successor_review(
        session,
        view,
        head=next_head,
        tree="5" * 40,
        marker="b",
        review_id=9202,
        evidence_offset=100,
    )
    current = get_view(session, view.publication_id)
    receipt_h2 = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(
            current,
            [source_review],
            [comment],
            [source_thread],
        ),
        token="test-installation-token",
    )

    assert receipt_h2["remote_head_sha"] == next_head
    with pytest.raises(DomainError, match="receipt is stale"):
        adopt_historical_pr_finding(
            session,
            package.work_package_id,
            reconciliation_id=receipt_h1["reconciliation_id"],
            root_comment_id=4201,
            principal_review_run_id=review_run_id,
            decision="ACCEPTED",
            reason="Principal adjudicated the reconciled source finding.",
            priority="P1",
            idempotency_key="adopt:stale-h1",
        )


def test_historical_implementation_adoption_persists_governed_candidate_proof(session):
    view, _source_run, package = create_package(session, review_mode="advisory")
    claim_work_package(
        session,
        package.work_package_id,
        actor="copilot-implementer",
        idempotency_key="claim-historical-implementation",
    )
    next_head = "4" * 40
    candidate_id, _successor_run = publish_successor_review(
        session,
        view,
        head=next_head,
        tree="5" * 40,
        marker="b",
        review_id=9202,
        evidence_offset=100,
    )
    publication = get_view(session, package.publication_id)
    _reconcile_empty_pr_findings(session, publication)

    with pytest.raises(DomainError, match="does not own the work claim"):
        adopt_historical_implementation(
            session,
            package.work_package_id,
            candidate_id=candidate_id,
            actor="unclaimed-actor",
            reason="A different actor cannot adopt the active implementation claim.",
            summary="Attempt adoption without owning the work claim.",
            idempotency_key="adopt-historical-implementation-unclaimed",
        )
    assert get_work_package(session, package.work_package_id).state is WorkPackageState.IN_PROGRESS

    adopted = adopt_historical_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate_id,
        actor="copilot-implementer",
        reason="The exact governed candidate was published before package submission.",
        summary="Adopt the already published implementation history.",
        idempotency_key="adopt-historical-implementation",
    )
    repeated = adopt_historical_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate_id,
        actor="copilot-implementer",
        reason="The exact governed candidate was published before package submission.",
        summary="Adopt the already published implementation history.",
        idempotency_key="adopt-historical-implementation",
    )

    events = load_work_package_events(session, package.work_package_id)
    event = next(
        item
        for item in events
        if item["event_type"] == "HISTORICAL_IMPLEMENTATION_ADOPTED"
    )
    evidence = event["payload"]["evidence"]
    assert adopted.state is WorkPackageState.IMPLEMENTED
    assert adopted.candidate_id == candidate_id
    assert adopted.implementation_head_sha == next_head
    assert adopted.implementation_evidence_sha256 == event["payload"]["evidence_sha256"]
    assert evidence["candidate"]["candidate_submission_event_hash"]
    assert evidence["candidate"]["candidate_admission_event_hash"]
    assert len(evidence["candidate"]["required_validations"]) == len(
        profile_for_repository(REPOSITORY).required_jobs
    )
    assert all(
        item["status"] == "PASS"
        for item in evidence["candidate"]["required_validations"]
    )
    assert evidence["canonical_pr_identity"]["pull_request_number"] == 13
    assert evidence["current_published_head_sha"] == next_head
    assert [
        item["head_sha"] for item in evidence["descendant_publications"]
    ] == [HEAD, next_head]
    assert evidence["source_findings"] == [
        {
            "finding_id": finding["finding_id"],
            "normalized_identity": finding["normalized_identity"],
        }
        for finding in sorted(package.findings, key=lambda item: item["finding_id"])
    ]
    assert repeated.state is WorkPackageState.IMPLEMENTED
    assert sum(
        item["event_type"] == "HISTORICAL_IMPLEMENTATION_ADOPTED" for item in events
    ) == 1
    assert all(item["event_type"] != "IMPLEMENTATION_SUBMITTED" for item in events)


@pytest.mark.parametrize("outcome", ["FIXED", "NOT_FIXED"])
def test_adopted_human_finding_requires_exact_head_principal_verification_and_artifacts(
    session,
    outcome,
):
    view, _source_run, package = create_package(session, review_mode="advisory")
    claim_work_package(
        session,
        package.work_package_id,
        actor="copilot-implementer",
        idempotency_key="claim-adopted-finding-implementation",
    )
    human_review = PullReviewSnapshot(
        3201,
        "DEAMBROGGI",
        "Historical review",
        "DISMISSED",
        HEAD,
        "2026-09-01T12:00:00Z",
    )
    human_comment = PullReviewCommentSnapshot(
        4201,
        3201,
        "DEAMBROGGI",
        "Historical orphan finding",
        HEAD,
        "control_plane/remediation.py",
        41,
        "2026-09-01T12:01:00Z",
        side="RIGHT",
    )
    codex_review = PullReviewSnapshot(
        3101,
        "chatgpt-codex-connector[bot]",
        "",
        "COMMENTED",
        HEAD,
        "2026-09-01T12:00:00Z",
    )
    codex_comment = PullReviewCommentSnapshot(
        4101,
        3101,
        "chatgpt-codex-connector[bot]",
        "Accepted review finding",
        HEAD,
        "control_plane/service.py",
        20,
        "2026-09-01T12:01:00Z",
        side="RIGHT",
    )
    h1_receipt = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(
            view,
            [codex_review, human_review],
            [codex_comment, human_comment],
            [
                PullReviewThreadSnapshot("PRRT_codex", False, (4101,), 4101),
                PullReviewThreadSnapshot("PRRT_human", False, (4201,), 4201),
            ],
        ),
        token="test-installation-token",
    )
    adjudication_run = "principal-adjudication-for-verification"
    record_plane_review(
        session,
        view.publication_id,
        run_id=adjudication_run,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=HEAD,
        body="Principal adjudication of the historical thread.",
        comments=[],
        idempotency_key=f"record:{adjudication_run}",
    )
    complete_plane_review_materialization(
        session,
        view.publication_id,
        run_id=adjudication_run,
        provider_review_id=9804,
        receipts=[],
    )
    adopt_historical_pr_finding(
        session,
        package.work_package_id,
        reconciliation_id=h1_receipt["reconciliation_id"],
        root_comment_id=4201,
        principal_review_run_id=adjudication_run,
        decision="ACCEPTED",
        reason="The Principal accepted the historical finding.",
        priority="P1",
        idempotency_key="adopt:accepted-for-verification",
    )

    next_head = "4" * 40
    candidate_id, _successor_run = publish_successor_review(
        session,
        view,
        head=next_head,
        tree="5" * 40,
        marker="b",
        review_id=9205,
        evidence_offset=200,
    )
    current = get_view(session, view.publication_id)
    h2_receipt = reconcile_pr_findings(
        session,
        view.publication_id,
        github=_review_thread_gateway(
            current,
            [codex_review, human_review],
            [codex_comment, human_comment],
            [
                PullReviewThreadSnapshot("PRRT_codex", False, (4101,), 4101),
                PullReviewThreadSnapshot("PRRT_human", False, (4201,), 4201),
            ],
        ),
        token="test-installation-token",
    )
    assert h2_receipt["remote_head_sha"] == next_head
    assert all(item["classification"] == "TRACKED" for item in h2_receipt["threads"])
    adopt_historical_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate_id,
        actor="copilot-implementer",
        reason="The validated H2 candidate is the implementation of these findings.",
        summary="Adopt the exact governed H2 implementation.",
        idempotency_key="adopt-historical-implementation-before-verification",
    )

    package_view = get_work_package(session, package.work_package_id)
    accepted_findings = [
        item
        for item in package_view.findings
        if item["principal_decision"]["decision"] == "ACCEPTED"
    ]
    verification_run = f"principal-verification-h2-{outcome.lower()}"
    comments = [
        {
            "finding_id": item["finding_id"],
            "normalized_identity": item["normalized_identity"],
            "priority": item["priority"],
            "path": f"control_plane/verification_{index}.py",
            "line": index + 10,
            "side": "RIGHT",
            "body": f"Principal verification for {item['finding_id']}.",
        }
        for index, item in enumerate(accepted_findings)
    ]
    record_plane_review(
        session,
        view.publication_id,
        run_id=verification_run,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer="principal-reviewer:chatgpt",
        reviewed_head_sha=next_head,
        body="Exact H2 Principal verification of all accepted findings.",
        comments=comments,
        idempotency_key=f"record:{verification_run}",
    )
    provider_review_id = 9805
    complete_plane_review_materialization(
        session,
        view.publication_id,
        run_id=verification_run,
        provider_review_id=provider_review_id,
        receipts=[
            {
                "finding_id": item["finding_id"],
                "provider_comment_id": 9900 + index,
                "provider_review_id": provider_review_id,
                "path": item["path"],
                "line": item["line"],
            }
            for index, item in enumerate(comments)
        ],
    )
    verifying = begin_principal_verification(
        session,
        package.work_package_id,
        review_run_id=verification_run,
        head_sha=next_head,
        idempotency_key=f"begin:{verification_run}",
    )
    assert verifying.principal_verification["candidate_id"] == candidate_id
    assert verifying.principal_verification["head_sha"] == next_head
    for finding in accepted_findings:
        verify_finding(
            session,
            package.work_package_id,
            finding_id=finding["finding_id"],
            outcome=outcome,
            reviewer="principal-reviewer:chatgpt",
            evidence=f"{outcome} on the exact H2 candidate.",
            idempotency_key=f"verify:{outcome}:{finding['finding_id']}",
        )

    final_package = get_work_package(session, package.work_package_id)
    adopted_finding = next(
        item for item in final_package.findings if item["source"].get("kind") == "GITHUB_REVIEW_THREAD"
    )
    assert adopted_finding["verification"]["outcome"] == outcome
    assert adopted_finding["verification"]["head_sha"] == next_head
    assert publication_has_unresolved_remediation_findings(session, view.publication_id)
    with pytest.raises(DomainError, match="approval is blocked"):
        record_review(
            session,
            view.publication_id,
            reviewed_head_sha=next_head,
            decision=ReviewDecision.APPROVED,
        )
    with pytest.raises(DomainError, match="Codex review is blocked"):
        request_codex_review(
            session,
            view.publication_id,
            mode="advisory",
            expected_head_sha=next_head,
        )
    from control_plane.service import record_merged

    with pytest.raises(DomainError, match="merge is blocked"):
        record_merged(
            session,
            view.publication_id,
            head_sha=next_head,
            pull_request_number=13,
            merge_commit_sha="6" * 40,
            source="GITHUB_RECONCILE",
        )


def record_legacy_codex_review_request(session, view, *, head, run_id=None):
    if run_id is None:
        run_id = f"legacy-successor:{view.publication_id}:{head}"
    append_event(
        session,
        view.publication_id,
        EventType.CODEX_REVIEW_REQUESTED,
        {
            "run_id": run_id,
            "provider": "CODEX_CODE_REVIEW",
            "head_sha": head,
            "pull_request_number": view.pull_request_number,
            "mode": "required",
            "attempt": 1,
        },
    )
    session.commit()
    return SimpleNamespace(automated_review_run_id=run_id)


def add_completed_review(
    session,
    view,
    *,
    head=HEAD,
    result=AutomatedReviewStatus.CHANGES_REQUIRED,
    extra_findings=(),
    mode="required",
):
    running = request_codex_review(
        session,
        view.publication_id,
        mode=mode,
        expected_head_sha=head,
    )
    review_findings = (
        [
            {
                "provider_comment_id": 4101,
                "provider_review_id": 3101,
                "path": "control_plane/service.py",
                "line": 20,
                "body": "Accepted review finding",
            },
            *deepcopy(list(extra_findings)),
        ]
        if result is AutomatedReviewStatus.CHANGES_REQUIRED
        else []
    )
    completed = complete_codex_review(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=head,
        result=result,
        findings=review_findings,
        provider_review_ids=[3101],
        provider_comment_ids=[
            item["provider_comment_id"] for item in review_findings
        ],
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
    running = record_legacy_codex_review_request(
        session,
        view,
        head=head,
        run_id=f"legacy-successor:{review_id}:{head}",
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


def create_package(
    session,
    *,
    issue_number=14,
    findings=None,
    extra_review_findings=(),
    review_mode="required",
):
    view = publish(session)
    run_id = add_completed_review(
        session,
        view,
        extra_findings=extra_review_findings,
        mode=review_mode,
    )
    package = create_work_package(
        session,
        publication_id=view.publication_id,
        implementation_issue_number=issue_number,
        review_run_id=run_id,
        review_provider="CODEX_CODE_REVIEW",
        provider_review_id=3101,
        reviewed_head_sha=HEAD,
        findings=initial_findings() if findings is None else findings,
        idempotency_key="issue14-ready",
    )
    return view, run_id, package


def two_provider_findings():
    findings = deepcopy(initial_findings())
    findings[1].update(
        {
            "finding_id": "codex:3101:4102",
            "normalized_identity": "codex:review-3101:comment-4102",
            "source": {
                "kind": "PROVIDER_THREAD",
                "provider": "CODEX_CODE_REVIEW",
                "provider_review_id": 3101,
                "provider_thread_id": 4102,
            },
            "desired_reaction": "+1",
        }
    )
    extra_review_findings = [
        {
            "provider_comment_id": 4102,
            "provider_review_id": 3101,
            "path": "control_plane/service.py",
            "line": 21,
            "body": "Second accepted review finding",
        }
    ]
    return findings, extra_review_findings


def record_principal_review(
    session,
    publication_id,
    *,
    run_id,
    head_sha,
    reviewer_kind="PRINCIPAL_REVIEWER",
    provider_review_id=9301,
):
    reviewer = "principal-reviewer:chatgpt"
    provider_comment_id = provider_review_id + 100
    comment = {
        "finding_id": f"principal:{run_id}",
        "normalized_identity": f"principal:fingerprint:{run_id}",
        "priority": "P1",
        "path": "control_plane/remediation.py",
        "line": 947,
        "side": "RIGHT",
        "body": "Verify the exact implementation candidate.",
    }
    record_plane_review(
        session,
        publication_id,
        run_id=run_id,
        reviewer_kind=reviewer_kind,
        reviewer=reviewer,
        reviewed_head_sha=head_sha,
        body="Principal verification of the exact implementation head.",
        comments=[comment],
        idempotency_key=f"record:{run_id}",
    )
    complete_plane_review_materialization(
        session,
        publication_id,
        run_id=run_id,
        provider_review_id=provider_review_id,
        receipts=[
            {
                "finding_id": comment["finding_id"],
                "provider_comment_id": provider_comment_id,
                "provider_review_id": provider_review_id,
                "path": comment["path"],
                "line": comment["line"],
            }
        ],
    )
    return reviewer


def prepare_principal_implementation(
    session,
    *,
    implementation_head="4" * 40,
    review_run_id="principal-review:implementation",
    reviewer_kind="PRINCIPAL_REVIEWER",
    findings=None,
    extra_review_findings=(),
    provider_review_id=9301,
):
    package_findings = (
        [deepcopy(initial_findings()[0])]
        if findings is None
        else findings
    )
    view, source_run_id, package = create_package(
        session,
        findings=package_findings,
        extra_review_findings=extra_review_findings,
    )
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="principal-implementation-claim",
    )
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(implementation_head, "5" * 40, "b"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=implementation_head,
        summary="Implement the accepted remediation findings.",
        evidence_sha256="d" * 64,
        idempotency_key="principal-implementation-submitted",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 30:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        implementation_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    reviewer = record_principal_review(
        session,
        view.publication_id,
        run_id=review_run_id,
        head_sha=implementation_head,
        reviewer_kind=reviewer_kind,
        provider_review_id=provider_review_id,
    )
    return (
        view,
        source_run_id,
        package,
        candidate.current_candidate.candidate_id,
        reviewer,
    )


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
    running = record_legacy_codex_review_request(
        session,
        view,
        head=successor_head,
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
            {"issues": "write", "pull_requests": "read"},
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


def test_candidate_submission_is_blocked_while_remediation_is_verifying(session):
    view, package, _source_run, _successor_run = prepare_verifying_package(session)
    before = get_view(session, view.publication_id)
    assert get_work_package(session, package.work_package_id).state is WorkPackageState.VERIFYING

    with pytest.raises(
        DomainError,
        match="remediation verification is active",
    ):
        submit_verified_candidate(
            session,
            view.publication_id,
            source("6" * 40, "7" * 40, "c"),
        )

    after = get_view(session, view.publication_id)
    assert after.current_candidate == before.current_candidate
    assert get_work_package(session, package.work_package_id).state is WorkPackageState.VERIFYING


def test_expired_artifact_dispatch_owner_is_fenced_before_remote_write(session):
    view, _source_run, package = create_package(session)
    artifact_key = "finding:codex:3101:4101:reply"
    assert claim_github_artifact_dispatch(
        session,
        package.work_package_id,
        artifact_key=artifact_key,
        lease_id="lease-a",
        lease_seconds=1,
    )
    from control_plane.models import RemediationDispatchRow
    from datetime import datetime, timedelta, timezone
    row = session.query(RemediationDispatchRow).filter_by(
        work_package_id=package.work_package_id, artifact_key=artifact_key
    ).one()
    row.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    session.commit()
    assert claim_github_artifact_dispatch(
        session,
        package.work_package_id,
        artifact_key=artifact_key,
        lease_id="lease-b",
        lease_seconds=60,
    )
    assert not fence_github_artifact_dispatch(
        session,
        package.work_package_id,
        artifact_key=artifact_key,
        lease_id="lease-a",
    )
    assert fence_github_artifact_dispatch(
        session,
        package.work_package_id,
        artifact_key=artifact_key,
        lease_id="lease-b",
    )
    session.rollback()


def test_project_v2_uses_separate_secret_and_fails_closed_when_missing(session):
    view, _source_run, package = create_package(session)
    github = FakeRemediationGitHub(view)
    app_credentials = FakeRemediationTokenProvider()
    materializer = GitHubRemediationMaterializer(
        token_provider=app_credentials,
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
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


def test_review_thread_resolution_uses_separate_secret_and_fails_closed_when_missing(session):
    view, package, _source_run, _successor_run = prepare_verifying_package(session)
    github = FakeRemediationGitHub(view)
    github.head_sha = get_work_package(session, package.work_package_id).successor_head_sha
    finding = next(
        item for item in get_work_package(session, package.work_package_id).findings
        if item["source"].get("provider_thread_id") is not None
    )
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr(""),
    )

    with pytest.raises(
        RemediationMaterializationError,
        match="review-thread credential is not configured",
    ):
        materializer._resolve(
            session,
            get_work_package(session, package.work_package_id),
            finding,
            token="installation-token",
        )
    assert github.resolve_calls == 0
    assert github.review_thread_tokens == []


def test_project_and_codex_credentials_are_masked_and_factory_uses_project_setting(
    monkeypatch,
):
    for field in (
        "REMEDIATION_PROJECT_TOKEN",
        "REMEDIATION_THREAD_TOKEN",
        "CODEX_REVIEW_USER_TOKEN",
    ):
        monkeypatch.delenv(f"CONTROL_PLANE_{field}", raising=False)

    configured = Settings(
        _env_file=None,
        remediation_project_token=SecretStr("project-only-secret"),
        remediation_thread_token=SecretStr("thread-only-secret"),
        codex_review_user_token=SecretStr("codex-trigger-secret"),
    )
    assert "project-only-secret" not in repr(configured)
    assert "thread-only-secret" not in repr(configured)
    assert "codex-trigger-secret" not in repr(configured)
    defaults = Settings(_env_file=None)
    assert defaults.remediation_project_token.get_secret_value() == ""
    assert defaults.remediation_thread_token.get_secret_value() == ""

    monkeypatch.setattr(settings, "remediation_project_token", SecretStr("project-only-secret"))
    monkeypatch.setattr(settings, "remediation_thread_token", SecretStr("thread-only-secret"))
    monkeypatch.setattr(settings, "codex_review_user_token", SecretStr("codex-trigger-secret"))
    dependency = get_remediation_materializer()
    materializer = next(dependency)
    try:
        assert materializer.project_token.get_secret_value() == "project-only-secret"
        assert materializer.review_thread_token.get_secret_value() == "thread-only-secret"
        secrets = {
            materializer.project_token.get_secret_value(),
            materializer.review_thread_token.get_secret_value(),
            settings.codex_review_user_token.get_secret_value(),
        }
        assert len(secrets) == 3
    finally:
        dependency.close()

    monkeypatch.setattr(settings, "remediation_project_token", SecretStr("same-secret"))
    monkeypatch.setattr(settings, "remediation_thread_token", SecretStr("thread-only-secret"))
    monkeypatch.setattr(settings, "codex_review_user_token", SecretStr("same-secret"))
    with pytest.raises(HTTPException) as error:
        next(get_remediation_materializer())
    assert error.value.status_code == 503
    assert "same-secret" not in str(error.value.detail)

    monkeypatch.setattr(settings, "remediation_project_token", SecretStr("project-only-secret"))
    monkeypatch.setattr(settings, "remediation_thread_token", SecretStr("same-thread-secret"))
    monkeypatch.setattr(settings, "codex_review_user_token", SecretStr("same-thread-secret"))
    with pytest.raises(HTTPException):
        next(get_remediation_materializer())


class FakeRemediationGitHub:
    def __init__(self, publication_view):
        self.publication_view = publication_view
        self.head_sha = publication_view.remote_head_sha
        self.reactions = {}
        self.reaction_calls = 0
        self.replies = []
        self.reply_calls = 0
        self.issue_comments = []
        self.comment_targets = []
        self.summary_calls = 0
        self.resolved = set()
        self.resolve_calls = 0
        self.issue_state = "open"
        self.close_calls = 0
        self.fail_close_once = False
        self.drop_issue_response = False
        self.created_issues = []
        self.issue_labels = set()
        self.project_statuses = []
        self.project_tokens = []
        self.review_thread_tokens = []
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
        assert token == "review-user-token"
        self.review_thread_tokens.append(token)
        self.resolve_calls += 1
        self.resolved.add(comment_id)
        return f"PRRT_{comment_id}"

    def list_issue_comments(self, repository, issue_number, token):
        return list(self.issue_comments)

    def add_issue_comment(self, repository, issue_number, body, token):
        self.summary_calls += 1
        self.comment_targets.append((issue_number, body))
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
        if self.fail_close_once:
            self.fail_close_once = False
            raise GitHubApiError("close response unavailable")
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


def test_terminal_projection_happens_only_after_authoritative_done(
    session,
    monkeypatch,
):
    view, package, _source_run, _successor_run = prepare_verifying_package(session)
    github = FakeRemediationGitHub(view)
    github.head_sha = get_work_package(session, package.work_package_id).successor_head_sha
    github.drop_reaction_response = False
    github.drop_reply_response = False
    github.drop_summary_response = False
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )

    import control_plane.remediation_materializer as materializer_module

    def reject_completion(*_args, **_kwargs):
        raise DomainError("authoritative completion rejected")

    monkeypatch.setattr(materializer_module, "complete_work_package", reject_completion)

    with pytest.raises(RemediationMaterializationError):
        materializer.materialize(session, package.work_package_id)

    assert get_work_package(session, package.work_package_id).state is WorkPackageState.VERIFYING
    assert github.issue_state == "open"
    assert github.close_calls == 0
    assert not any(status == "Done" for _item, status in github.project_statuses)
    assert "status:done" not in github.issue_labels


def test_done_projection_recovers_after_crash_following_authoritative_completion(session):
    view, package, _source_run, _successor_run = prepare_verifying_package(session)
    github = FakeRemediationGitHub(view)
    github.head_sha = get_work_package(session, package.work_package_id).successor_head_sha
    github.drop_reaction_response = False
    github.drop_reply_response = False
    github.drop_summary_response = False
    github.fail_close_once = True
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )

    with pytest.raises(RemediationMaterializationError):
        materializer.materialize(session, package.work_package_id)

    authoritative = get_work_package(session, package.work_package_id)
    assert authoritative.state is WorkPackageState.DONE
    assert authoritative.issue_closed is False
    assert github.issue_state == "open"
    assert not any(status == "Done" for _item, status in github.project_statuses)

    converged = materializer.materialize(session, package.work_package_id)
    assert converged.state is WorkPackageState.DONE
    assert converged.issue_closed is True
    assert github.issue_state == "closed"
    assert github.project_statuses[-1] == ("I_kwDO_issue14", "Done")
    assert "status:done" in github.issue_labels


def test_materializer_recovers_lost_responses_without_duplicate_artifacts(session):
    view, package, _source_run, _successor_run = prepare_verifying_package(session)
    github = FakeRemediationGitHub(view)
    github.head_sha = get_work_package(session, package.work_package_id).successor_head_sha
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
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
    assert len(github.replies) == 2
    assert github.reply_calls == 2  # decision reply recovery plus final verification reply
    assert github.resolve_calls == 1
    assert len(github.issue_comments) == 1
    assert github.summary_calls == 1  # recovery found the marker before another comment attempt
    legacy_summary = github.issue_comments[0].body
    assert f"Candidate {result.candidate_id} at {result.implementation_head_sha}" in legacy_summary
    assert (
        f"reviewed by run {result.successor_review_run_id} at {result.successor_head_sha}"
        in legacy_summary
    )
    assert "no code remediation was required" not in legacy_summary.lower()
    assert github.close_calls == 1
    assert github.project_statuses[-1] == ("I_kwDO_issue14", "Done")
    assert len(load_work_package_events(session, package.work_package_id)) == 13
    assert materializer.materialize(session, package.work_package_id) == result
    assert github.reaction_calls == 2
    assert github.reply_calls == 2
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
        review_thread_token=SecretStr("review-user-token"),
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
        review_thread_token=SecretStr("review-user-token"),
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


def test_implementation_submission_projects_candidate_to_issue_and_pr(session):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-candidate-projection",
    )
    candidate_head = "4" * 40
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(candidate_head, "5" * 40, "b"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=candidate_head,
        summary="Implementation candidate for Principal verification.",
        evidence_sha256="c" * 64,
        idempotency_key="candidate-projection-submission",
    )
    github = FakeRemediationGitHub(view)
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )

    with pytest.raises(RemediationMaterializationError):
        materializer.sync_issue_projection(session, package.work_package_id)
    assert len(github.issue_comments) == 1
    assert candidate.current_candidate.candidate_id in github.issue_comments[0].body
    assert candidate_head in github.issue_comments[0].body

    materializer.sync_issue_projection(session, package.work_package_id)
    materializer.sync_issue_projection(session, package.work_package_id)

    projection = get_work_package(session, package.work_package_id).implementation_projection
    assert projection == {
        "candidate_id": candidate.current_candidate.candidate_id,
        "head_sha": candidate_head,
        "issue_comment_id": 900,
        "pull_request_comment_id": 901,
    }
    assert [number for number, _body in github.comment_targets] == [14, 13]
    assert "surface=issue" in github.comment_targets[0][1]
    assert "surface=pull-request" in github.comment_targets[1][1]
    assert len(github.issue_comments) == 2
    projection_events = [
        event
        for event in load_work_package_events(session, package.work_package_id)
        if event["event_type"] == "IMPLEMENTATION_PROJECTION_MATERIALIZED"
    ]
    assert len(projection_events) == 1


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


def test_historical_adoption_routes_require_internal_auth(session):
    _view, _source_run, package = create_package(session)
    original_findings = get_work_package(session, package.work_package_id).findings

    class ProjectionStub:
        def sync_issue_projection(self, _session, work_package_id):
            return get_work_package(session, work_package_id)

    original_overrides = app.dependency_overrides.copy()

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_remediation_materializer] = lambda: ProjectionStub()
    client = TestClient(app)
    try:
        base_path = (
            f"/api/v1/internal/remediation/work-packages/{package.work_package_id}"
        )
        orphan_response = client.post(
            f"{base_path}/pr-findings/adopt",
            json={
                "reconciliation_id": "00000000-0000-4000-8000-000000000001",
                "root_comment_id": 4201,
                "principal_review_run_id": "principal-adjudication-route-auth",
                "decision": "ACCEPTED",
                "reason": "Authorization is required before receipt adoption.",
                "priority": "P1",
                "idempotency_key": "unauthenticated-orphan-adoption",
            },
        )
        implementation_response = client.post(
            f"{base_path}/implementation/adopt-historical",
            json={
                "candidate_id": "00000000-0000-4000-8000-000000000002",
                "actor": "copilot-implementer",
                "reason": "Authorization is required before candidate adoption.",
                "summary": "Historical governed implementation.",
                "idempotency_key": "unauthenticated-implementation-adoption",
            },
        )

        assert orphan_response.status_code == 401
        assert implementation_response.status_code == 401
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)

    assert get_work_package(session, package.work_package_id).findings == original_findings


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


@pytest.mark.parametrize(
    ("decision", "reaction", "expected_resolution"),
    [
        ("ACCEPTED", "+1", "NOT_APPLICABLE"),
        ("REJECTED", "-1", "MATERIALIZED"),
    ],
)
def test_decision_artifacts_materialize_before_implementation(
    session,
    decision,
    reaction,
    expected_resolution,
):
    view = publish(session)
    source_run = add_completed_review(session, view)
    finding = initial_findings()[0]
    finding["principal_decision"] = {
        "decision": decision,
        "actor": "principal-reviewer",
        "reason": "Finding is outside the accepted issue contract."
        if decision == "REJECTED"
        else None,
    }
    finding["desired_reaction"] = reaction
    package = create_work_package(
        session,
        publication_id=view.publication_id,
        implementation_issue_number=14,
        review_run_id=source_run,
        review_provider="CODEX_CODE_REVIEW",
        provider_review_id=3101,
        reviewed_head_sha=HEAD,
        findings=[finding],
        idempotency_key=f"decision-phase-{decision.lower()}",
    )
    github = FakeRemediationGitHub(view)
    github.drop_reaction_response = False
    github.drop_reply_response = False
    github.drop_summary_response = False
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )

    result = materializer.materialize(session, package.work_package_id)

    finding_view = result.findings[0]
    assert result.state is WorkPackageState.READY
    assert finding_view["decision_materialization"]["reaction"] == "MATERIALIZED"
    assert finding_view["decision_materialization"]["reply"] == "MATERIALIZED"
    assert finding_view["decision_materialization"]["resolution"] == expected_resolution
    assert len(github.reactions) == 1
    assert len(github.replies) == 1
    assert github.resolved == ({4101} if decision == "REJECTED" else set())
    assert "candidate" not in github.replies[0].body.lower()


def test_fixed_principal_verification_materializes_incrementally_with_candidate_head(
    session,
):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-principal-fixed",
    )
    implementation_head = "a8187b6103845bcb9ed147df0ae40fac804d2a8a"
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(implementation_head, "5" * 40, "b"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=implementation_head,
        summary="Fix the provider finding and preserve exact candidate evidence.",
        evidence_sha256="d" * 64,
        idempotency_key="implemented-principal-fixed",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 20:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        implementation_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    review_run_id = "principal-fix-review:wp47:h14"
    review_reviewer = "principal-reviewer:chatgpt"
    comments = [
        {
            "finding_id": "principal:fixed-provider-thread",
            "normalized_identity": "principal:fingerprint:fixed-provider-thread",
            "priority": "P1",
            "path": "control_plane/remediation.py",
            "line": 947,
            "side": "RIGHT",
            "body": "Verify the exact candidate before resolving the finding thread.",
        }
    ]
    record_plane_review(
        session,
        view.publication_id,
        run_id=review_run_id,
        reviewer_kind="PRINCIPAL_REVIEWER",
        reviewer=review_reviewer,
        reviewed_head_sha=implementation_head,
        body="Exact-head Principal verification of the implementation candidate.",
        comments=comments,
        idempotency_key="principal-fixed-incremental-record",
    )
    complete_plane_review_materialization(
        session,
        view.publication_id,
        run_id=review_run_id,
        provider_review_id=9301,
        receipts=[
            {
                "finding_id": comments[0]["finding_id"],
                "provider_comment_id": 9401,
                "provider_review_id": 9301,
                "path": comments[0]["path"],
                "line": comments[0]["line"],
            }
        ],
    )
    descendant_head = "3700eac6819ef9a5450acf13d705fdab17cd26e7"
    descendant = submit_verified_candidate(
        session,
        view.publication_id,
        source(descendant_head, "6" * 40, "c"),
    )
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 120:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        descendant_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    _reconcile_empty_pr_findings(
        session,
        get_view(session, view.publication_id),
    )
    github = FakeRemediationGitHub(view)
    github.head_sha = descendant_head
    github.drop_reaction_response = False
    github.drop_reply_response = False
    github.drop_summary_response = False
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )
    original_overrides = app.dependency_overrides.copy()

    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_remediation_materializer] = lambda: materializer
    try:
        response = TestClient(app).post(
            (
                f"/api/v1/internal/remediation/work-packages/"
                f"{package.work_package_id}/principal-verification"
            ),
            headers={"X-Control-Plane-Token": settings.internal_token},
            json={
                "review_run_id": review_run_id,
                "head_sha": implementation_head,
                "idempotency_key": "principal-fixed-incremental-start",
            },
        )
        assert response.status_code == 200
        assert response.json()["state"] == WorkPackageState.VERIFYING.value
        verification_response = TestClient(app).post(
            (
                f"/api/v1/internal/remediation/work-packages/"
                f"{package.work_package_id}/findings/codex:3101:4101/verification"
            ),
            headers={"X-Control-Plane-Token": settings.internal_token},
            json={
                "outcome": "FIXED",
                "evidence": "The exact published candidate contains the correction.",
                "idempotency_key": "principal-fixed-incremental-result",
            },
        )
        assert verification_response.status_code == 200
        verified_finding = next(
            item
            for item in verification_response.json()["findings"]
            if item["finding_id"] == "codex:3101:4101"
        )
        assert verified_finding["verification"]["reviewer"] == review_reviewer
        wrong_reviewer_response = TestClient(app).post(
            (
                f"/api/v1/internal/remediation/work-packages/"
                f"{package.work_package_id}/findings/codex:3101:4101/verification"
            ),
            headers={"X-Control-Plane-Token": settings.internal_token},
            json={
                "outcome": "FIXED",
                "reviewer": "unbound-client-identity",
                "evidence": "The exact published candidate contains the correction.",
                "idempotency_key": "principal-fixed-wrong-reviewer",
            },
        )
        assert wrong_reviewer_response.status_code == 409
        assert "derived from the bound PLANE_REVIEW" in wrong_reviewer_response.json()[
            "detail"
        ]
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)

    verified = get_work_package(session, package.work_package_id)
    assert verified.state is WorkPackageState.VERIFYING

    result = materializer.materialize(session, package.work_package_id)

    fixed = next(
        item for item in result.findings if item["finding_id"] == "codex:3101:4101"
    )
    pending = next(
        item
        for item in result.findings
        if item["finding_id"] == "control-plane:bigint-comment-id"
    )
    assert result.state is WorkPackageState.VERIFYING
    assert _derive_next(session, view.publication_id) == (
        "PRINCIPAL_REVIEWER",
        "REVIEW_REMEDIATION_FIXES",
    )
    assert fixed["verification_materialization"]["reply"] == "MATERIALIZED"
    assert fixed["verification_materialization"]["resolution"] == "MATERIALIZED"
    assert pending["verification"] is None
    assert len(github.replies) == 2
    assert candidate.current_candidate.candidate_id in github.replies[1].body
    assert implementation_head in github.replies[1].body
    assert github.resolved == {4101}
    assert github.resolve_calls == 1
    assert len(github.issue_comments) == 2
    assert all(
        candidate.current_candidate.candidate_id in comment.body
        and implementation_head in comment.body
        for comment in github.issue_comments
    )
    assert not any(
        "Implementation and verification are ready" in comment.body
        for comment in github.issue_comments
    )
    assert github.close_calls == 0


def test_principal_verification_rejects_wrong_run_head_provider_and_reviewer_kind(
    session,
):
    view, source_run_id, package, _candidate_id, reviewer = (
        prepare_principal_implementation(session)
    )
    fallback_run_id = "principal-review:fallback-kind"
    record_principal_review(
        session,
        view.publication_id,
        run_id=fallback_run_id,
        head_sha="4" * 40,
        reviewer_kind="FALLBACK_REVIEWER",
        provider_review_id=9310,
    )
    wrong_review_head = "8" * 40
    submit_verified_candidate(
        session,
        view.publication_id,
        source(wrong_review_head, "9" * 40, "e"),
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 300:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        wrong_review_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    wrong_head_run_id = "principal-review:wrong-head"
    record_principal_review(
        session,
        view.publication_id,
        run_id=wrong_head_run_id,
        head_sha=wrong_review_head,
        provider_review_id=9311,
    )

    invalid_bindings = [
        ("missing-review-run", "4" * 40),
        ("principal-review:implementation", "3" * 40),
        (wrong_head_run_id, "4" * 40),
        (source_run_id, "4" * 40),
        (fallback_run_id, "4" * 40),
    ]
    for index, (run_id, head_sha) in enumerate(invalid_bindings):
        with pytest.raises(DomainError):
            begin_principal_verification(
                session,
                package.work_package_id,
                review_run_id=run_id,
                head_sha=head_sha,
                idempotency_key=f"invalid-principal-binding-{index}",
            )

    started = begin_principal_verification(
        session,
        package.work_package_id,
        review_run_id="principal-review:implementation",
        head_sha="4" * 40,
        idempotency_key="valid-principal-binding-after-rejections",
    )
    assert started.state is WorkPackageState.VERIFYING
    assert started.principal_verification["reviewer"] == reviewer


def test_principal_verification_rejects_wrong_candidate_and_unpublished_implementation(
    session,
):
    view, _source_run_id, package, original_candidate_id, _reviewer = (
        prepare_principal_implementation(session)
    )
    implementation_head = "4" * 40
    mark_implementation_rework_required(
        session,
        package.work_package_id,
        reason="Prepare a replacement-candidate identity check.",
        idempotency_key="replacement-candidate-rework",
    )
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="replacement-candidate-claim",
    )
    replacement = submit_verified_candidate(
        session,
        view.publication_id,
        source(implementation_head, "6" * 40, "c"),
    )
    replacement_candidate_id = replacement.current_candidate.candidate_id
    assert replacement_candidate_id != original_candidate_id
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=replacement_candidate_id,
        head_sha=implementation_head,
        summary="Replacement candidate is not published.",
        evidence_sha256="e" * 64,
        idempotency_key="replacement-candidate-submitted",
    )

    with pytest.raises(DomainError, match="implementation candidate"):
        begin_principal_verification(
            session,
            package.work_package_id,
            review_run_id="principal-review:implementation",
            head_sha=implementation_head,
            idempotency_key="replacement-candidate-principal-start",
        )


def test_principal_materialization_rejects_unrecorded_live_head_before_writes(session):
    view, _source_run_id, package, _candidate_id, reviewer = (
        prepare_principal_implementation(session)
    )
    implementation_head = "4" * 40
    github = FakeRemediationGitHub(view)
    github.head_sha = implementation_head
    github.drop_reaction_response = False
    github.drop_reply_response = False
    github.drop_summary_response = False
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )
    materializer.materialize(session, package.work_package_id)
    begin_principal_verification(
        session,
        package.work_package_id,
        review_run_id="principal-review:implementation",
        head_sha=implementation_head,
        idempotency_key="unrecorded-head-principal-start",
    )
    verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4101",
        outcome="FIXED",
        reviewer=reviewer,
        evidence="The exact candidate is fixed.",
        idempotency_key="unrecorded-head-principal-fixed",
    )
    artifacts_before = (
        github.reaction_calls,
        github.reply_calls,
        github.resolve_calls,
        github.summary_calls,
        len(github.replies),
    )
    github.head_sha = "9" * 40

    with pytest.raises(RemediationMaterializationError):
        materializer.materialize(session, package.work_package_id)

    fixed = get_work_package(session, package.work_package_id).findings[0]
    assert fixed["verification_materialization"]["reply"] == "PENDING"
    assert fixed["verification_materialization"]["resolution"] == "PENDING"
    assert artifacts_before == (
        github.reaction_calls,
        github.reply_calls,
        github.resolve_calls,
        github.summary_calls,
        len(github.replies),
    )


def test_principal_fixed_artifacts_survive_mixed_rework_and_second_implementation(
    session,
):
    findings, extra_review_findings = two_provider_findings()
    first_head = "4" * 40
    first_run_id = "principal-review:mixed-first"
    view, _source_run_id, package, _first_candidate_id, reviewer = (
        prepare_principal_implementation(
            session,
            implementation_head=first_head,
            review_run_id=first_run_id,
            findings=findings,
            extra_review_findings=extra_review_findings,
        )
    )
    github = FakeRemediationGitHub(view)
    github.head_sha = first_head
    github.drop_reaction_response = False
    github.drop_reply_response = False
    github.drop_summary_response = False
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )
    materializer.materialize(session, package.work_package_id)
    started = begin_principal_verification(
        session,
        package.work_package_id,
        review_run_id=first_run_id,
        head_sha=first_head,
        idempotency_key="mixed-principal-first-start",
    )
    assert started.principal_verification["finding_ids"] == [
        "codex:3101:4101",
        "codex:3101:4102",
    ]
    verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4101",
        outcome="FIXED",
        reviewer=reviewer,
        evidence="Finding A is fixed.",
        idempotency_key="mixed-principal-a-fixed",
    )
    rework = verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4102",
        outcome="NOT_FIXED",
        reviewer=reviewer,
        evidence="Finding B still reproduces.",
        idempotency_key="mixed-principal-b-not-fixed",
    )
    assert rework.state is WorkPackageState.REWORK_REQUIRED

    materialized = materializer.materialize(session, package.work_package_id)
    fixed = next(
        item for item in materialized.findings if item["finding_id"] == "codex:3101:4101"
    )
    not_fixed = next(
        item for item in materialized.findings if item["finding_id"] == "codex:3101:4102"
    )
    assert materialized.state is WorkPackageState.REWORK_REQUIRED
    assert fixed["closure_state"] == "FIXED"
    assert fixed["verification_materialization"]["reply"] == "MATERIALIZED"
    assert fixed["verification_materialization"]["resolution"] == "MATERIALIZED"
    assert not_fixed["verification"]["outcome"] == "NOT_FIXED"
    assert not_fixed["verification_history"][-1]["outcome"] == "NOT_FIXED"
    assert not_fixed["verification_materialization"]["reply"] == "PENDING"
    assert not_fixed["verification_materialization"]["resolution"] == "PENDING"
    assert github.resolved == {4101}
    assert 4102 not in github.resolved
    assert github.reaction_calls == 2
    assert github.reply_calls == 3
    assert github.resolve_calls == 1
    assert github.summary_calls == 0

    materializer.materialize(session, package.work_package_id)
    assert github.reaction_calls == 2
    assert github.reply_calls == 3
    assert github.resolve_calls == 1
    assert github.summary_calls == 0

    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="mixed-principal-rework-claim",
    )
    second_head = "6" * 40
    second_candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(second_head, "7" * 40, "f"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=second_candidate.current_candidate.candidate_id,
        head_sha=second_head,
        summary="Fix the remaining finding without reopening A.",
        evidence_sha256="f" * 64,
        idempotency_key="mixed-principal-second-implementation",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 400:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        second_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    second_run_id = "principal-review:mixed-second"
    record_principal_review(
        session,
        view.publication_id,
        run_id=second_run_id,
        head_sha=second_head,
        provider_review_id=9302,
    )
    github.head_sha = second_head
    second_start = begin_principal_verification(
        session,
        package.work_package_id,
        review_run_id=second_run_id,
        head_sha=second_head,
        idempotency_key="mixed-principal-second-start",
    )
    assert second_start.principal_verification["finding_ids"] == ["codex:3101:4102"]
    verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4102",
        outcome="FIXED",
        reviewer=reviewer,
        evidence="Finding B is fixed by the second implementation.",
        idempotency_key="mixed-principal-b-fixed-second-attempt",
    )

    completed = materializer.materialize(session, package.work_package_id)
    fixed_after_rework = next(
        item
        for item in completed.findings
        if item["finding_id"] == "codex:3101:4101"
    )
    assert completed.state is WorkPackageState.DONE
    assert fixed_after_rework["verification"]["review_run_id"] == first_run_id
    assert fixed_after_rework["closure_state"] == "FIXED"
    assert fixed_after_rework["verification_materialization"]["resolution"] == "MATERIALIZED"
    assert github.resolved == {4101, 4102}
    assert github.resolve_calls == 2
    assert github.issue_state == "closed"
    assert github.summary_calls == 1
    summary = github.issue_comments[0].body
    assert second_candidate.current_candidate.candidate_id in summary
    assert second_head in summary
    assert second_run_id in summary
    assert "PLANE_REVIEW" in summary
    assert reviewer in summary
    assert "codex:3101:4101" in summary
    assert "codex:3101:4102" in summary
    assert "no code remediation was required" not in summary.lower()

    materializer.materialize(session, package.work_package_id)
    assert github.summary_calls == 1
    assert github.reply_calls == 4
    assert github.resolve_calls == 2


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
        review_thread_token=SecretStr("review-user-token"),
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
    assert not publication_has_unresolved_remediation_findings(
        session,
        view.publication_id,
    )
    assert list(github.reactions) == [(4101, "-1")]
    assert len(github.replies) == 1
    assert github.resolved == {4101}
    assert github.issue_state == "closed"
    rejected_summary = github.issue_comments[0].body
    assert source_run in rejected_summary
    assert HEAD in rejected_summary
    assert "no code remediation was required" in rejected_summary.lower()

    publication = get_view(session, view.publication_id)
    assert publication.state is PublicationState.IN_REVIEW
    assert publication.automated_review_status is AutomatedReviewStatus.CHANGES_REQUIRED
    assert publication.remediation_cleared_review_run_id == source_run
    assert publication.remediation_cleared_head_sha == HEAD
    adjudication = required_review_adjudication(session, view.publication_id)
    assert adjudication is not None
    assert adjudication["kind"] == "REMEDIATION_CLEARED"
    cleared_event = next(
        event
        for event in load_events(session, view.publication_id)
        if event["event_type"] == "REMEDIATION_CLEARED"
    )
    assert _required_adjudication_time(
        session,
        view.publication_id,
        adjudication,
    ) == _parse_time(cleared_event["occurred_at"])
    approved = record_review(
        session,
        view.publication_id,
        reviewed_head_sha=HEAD,
        decision=ReviewDecision.APPROVED,
        require_codex_review=True,
    )
    assert approved.state is PublicationState.APPROVED


def test_rejected_reason_rejects_reserved_automation_mentions(session):
    view = publish(session, issue_number=811)
    source_run = add_completed_review(session, view)
    findings = initial_findings()
    findings[0]["principal_decision"] = {
        "decision": "REJECTED",
        "actor": "principal-reviewer",
        "reason": "Do not run @codex review from materialized feedback.",
    }
    findings[0]["desired_reaction"] = "-1"

    with pytest.raises(DomainError, match="reserved automation mention"):
        create_work_package(
            session,
            publication_id=view.publication_id,
            implementation_issue_number=811,
            review_run_id=source_run,
            review_provider="CODEX_CODE_REVIEW",
            provider_review_id=3101,
            reviewed_head_sha=HEAD,
            findings=findings,
            idempotency_key="reserved-mention-reason",
        )


def test_human_approval_is_blocked_while_required_remediation_is_unfinished(session):
    view, _source_run, package = create_package(session, issue_number=812)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-open-remediation",
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
        summary="Implementation remains awaiting Principal Reviewer verification.",
        evidence_sha256="d" * 64,
        idempotency_key="implemented-open-remediation",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 30:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        successor_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    running = record_legacy_codex_review_request(
        session,
        view,
        head=successor_head,
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

    with pytest.raises(DomainError, match="unresolved remediation findings"):
        record_review(
            session,
            view.publication_id,
            reviewed_head_sha=successor_head,
            decision=ReviewDecision.APPROVED,
            require_codex_review=True,
        )


def test_remediation_gate_is_scoped_to_its_publication(session):
    view, _source_run, package = create_package(session, issue_number=814)
    unrelated_publication = publish(session, issue_number=815)

    assert publication_has_unresolved_remediation_findings(session, view.publication_id)
    assert not publication_has_unresolved_remediation_findings(
        session,
        unrelated_publication.publication_id,
    )
    assert get_work_package(session, package.work_package_id).state is WorkPackageState.READY


def test_verifying_package_prevents_successor_from_making_completion_stale(session):
    view, package, _source_run, _successor_run = prepare_verifying_package(session)
    for artifact, remote_id in (("reaction", 701), ("reply", 702), ("resolution", "PRRT_stale")):
        record_github_artifact(
            session,
            package.work_package_id,
            finding_id="codex:3101:4101",
            artifact=artifact,
            remote_id=remote_id,
            idempotency_key=f"stale-{artifact}",
        )
    record_summary_comment(
        session,
        package.work_package_id,
        comment_id=703,
        idempotency_key="stale-summary",
    )

    with pytest.raises(DomainError, match="remediation verification is active"):
        submit_verified_candidate(
            session,
            view.publication_id,
            source("6" * 40, "7" * 40, "c"),
        )

    completed = complete_work_package(
        session,
        package.work_package_id,
        idempotency_key="protected-done",
    )
    assert completed.state is WorkPackageState.DONE
    assert get_view(session, view.publication_id).remote_head_sha == completed.successor_head_sha


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


def test_package_accepts_body_only_codex_finding_without_provider_thread(session):
    view = publish(session)
    running = request_codex_review(
        session,
        view.publication_id,
        mode="required",
        expected_head_sha=HEAD,
    )
    title = "Keep ambiguous Codex invocations out of fallback"
    body = (
        "An unmanaged invocation can make the generic exception handler record "
        "CODEX_TRIGGER_UNAVAILABLE and enable fallback."
    )
    finding_id = codex_review_body_finding_id(
        run_id=running.automated_review_run_id,
        head_sha=HEAD,
        review_id=3102,
        priority="P1",
        title=title,
        body=body,
    )
    complete_codex_review(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=HEAD,
        result=AutomatedReviewStatus.CHANGES_REQUIRED,
        findings=[
            {
                "finding_id": finding_id,
                "normalized_identity": finding_id,
                "provider_finding_id": finding_id,
                "source_kind": "REVIEW_BODY",
                "provider_review_id": 3102,
                "priority": "P1",
                "title": title,
                "path": None,
                "line": None,
                "body": body,
                "provider_body_sha256": "a" * 64,
            }
        ],
        provider_review_ids=[3102],
        provider_comment_ids=[],
    )

    package = create_work_package(
        session,
        publication_id=view.publication_id,
        implementation_issue_number=14,
        review_run_id=running.automated_review_run_id,
        review_provider="CODEX_CODE_REVIEW",
        provider_review_id=3102,
        reviewed_head_sha=HEAD,
        findings=[
            {
                "finding_id": finding_id,
                "normalized_identity": finding_id,
                "priority": "P1",
                "source": {
                    "kind": "PROVIDER_REVIEW_BODY",
                    "provider": "CODEX_CODE_REVIEW",
                    "provider_review_id": 3102,
                    "provider_thread_id": None,
                    "provider_finding_id": finding_id,
                },
                "principal_decision": {
                    "decision": "ACCEPTED",
                    "actor": "principal-reviewer",
                    "reason": None,
                },
                "desired_reaction": "none",
            }
        ],
        idempotency_key="body-finding-source",
    )

    assert package.findings[0]["source"]["provider_finding_id"] == finding_id
    assert package.findings[0]["source"]["provider_thread_id"] is None


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


def test_publication_preflight_failure_can_rework_implemented_package_without_overwrite(session):
    view, _source_run, package = create_package(session, issue_number=813)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-preflight-rework",
    )
    first_head = "4" * 40
    first = submit_verified_candidate(
        session,
        view.publication_id,
        source(first_head, "5" * 40, "b"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=first.current_candidate.candidate_id,
        head_sha=first_head,
        summary="First implementation candidate before publication preflight.",
        evidence_sha256="d" * 64,
        idempotency_key="implemented-before-preflight",
    )
    profile = profile_for_repository(REPOSITORY)
    record_validation(
        session,
        view.publication_id,
        job_id=profile.required_jobs[0],
        status=ValidationStatus.FAIL,
        evidence_sha256="e" * 64,
    )
    assert get_view(session, view.publication_id).state is PublicationState.VALIDATION_FAILED

    rework = mark_implementation_rework_required(
        session,
        package.work_package_id,
        reason="Publication preflight rejected the admitted candidate metadata.",
        idempotency_key="publication-preflight-rework",
    )
    assert rework.state is WorkPackageState.REWORK_REQUIRED
    reclaimed = claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-preflight-rework-2",
    )
    assert reclaimed.state is WorkPackageState.IN_PROGRESS

    second_head = "6" * 40
    second = submit_verified_candidate(
        session,
        view.publication_id,
        source(second_head, "7" * 40, "c"),
    )
    replaced = submit_implementation(
        session,
        package.work_package_id,
        candidate_id=second.current_candidate.candidate_id,
        head_sha=second_head,
        summary="Corrected implementation candidate after publication preflight.",
        evidence_sha256="f" * 64,
        idempotency_key="implemented-after-preflight",
    )
    assert replaced.state is WorkPackageState.IMPLEMENTED
    assert replaced.candidate_id == second.current_candidate.candidate_id
    assert replaced.implementation_head_sha == second_head
    submissions = [
        event for event in load_work_package_events(session, package.work_package_id)
        if event["event_type"] == "IMPLEMENTATION_SUBMITTED"
    ]
    assert len(submissions) == 2
    assert submissions[0]["payload"]["candidate_id"] == first.current_candidate.candidate_id
    assert submissions[1]["payload"]["candidate_id"] == second.current_candidate.candidate_id


def test_unavailable_successor_requires_audited_fallback_and_can_complete(session):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-unavailable-fallback",
    )
    successor_head = "8" * 40
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(successor_head, "9" * 40, "a"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=successor_head,
        summary="Candidate requires principal fallback after provider unavailability.",
        evidence_sha256="e" * 64,
        idempotency_key="submit-unavailable-fallback",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 200:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        successor_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    running = record_legacy_codex_review_request(
        session,
        view,
        head=successor_head,
    )
    mark_codex_review_unavailable(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=successor_head,
        reason="Correlated provider usage-limit response.",
    )

    with pytest.raises(DomainError, match="successor review is not complete"):
        begin_successor_verification(
            session,
            package.work_package_id,
            review_run_id=running.automated_review_run_id,
            head_sha=successor_head,
            idempotency_key="missing-unavailable-fallback",
        )

    verifying = begin_successor_verification(
        session,
        package.work_package_id,
        review_run_id=running.automated_review_run_id,
        head_sha=successor_head,
        idempotency_key="bind-unavailable-fallback",
        fallback_reviewer="principal-reviewer:chatgpt",
        fallback_reason="Provider unavailable; exact-head independent review required.",
    )
    assert verifying.state is WorkPackageState.VERIFYING
    assert verifying.successor_fallback == {
        "reviewer": "principal-reviewer:chatgpt",
        "reason": "Provider unavailable; exact-head independent review required.",
        "provider_status": "UNAVAILABLE",
    }

    with pytest.raises(DomainError, match="authorized fallback reviewer"):
        verify_finding(
            session,
            package.work_package_id,
            finding_id="codex:3101:4101",
            outcome="ABSENT",
            reviewer="principal-reviewer:other",
            evidence="A different reviewer must not inherit the recorded fallback authority.",
            idempotency_key="verify-unavailable-wrong-reviewer",
        )

    verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4101",
        outcome="ABSENT",
        reviewer="principal-reviewer:chatgpt",
        evidence="Exact-head fallback review confirms the provider finding is absent.",
        idempotency_key="verify-unavailable-provider-finding",
    )
    verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="ABSENT",
        reviewer="principal-reviewer:chatgpt",
        evidence="Exact-head fallback review confirms the internal finding is absent.",
        idempotency_key="verify-unavailable-internal-finding",
    )
    for artifact, remote_id in (
        ("reaction", 801),
        ("reply", 802),
        ("resolution", "PRRT_unavailable"),
    ):
        record_github_artifact(
            session,
            package.work_package_id,
            finding_id="codex:3101:4101",
            artifact=artifact,
            remote_id=remote_id,
            idempotency_key=f"unavailable-{artifact}",
        )
    record_summary_comment(
        session,
        package.work_package_id,
        comment_id=803,
        idempotency_key="unavailable-summary",
    )
    record_issue_closed(
        session,
        package.work_package_id,
        idempotency_key="unavailable-issue-close",
    )

    done = complete_work_package(
        session,
        package.work_package_id,
        idempotency_key="unavailable-done",
    )
    assert done.state is WorkPackageState.DONE
    publication = get_view(session, view.publication_id)
    assert publication.automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert publication.automated_review_run_id == running.automated_review_run_id


def test_materializer_accepts_exact_unavailable_fallback(session):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-unavailable-materializer",
    )
    successor_head = "8" * 40
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(successor_head, "9" * 40, "a"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=successor_head,
        summary="Exercise materialization under audited provider fallback.",
        evidence_sha256="f" * 64,
        idempotency_key="submit-unavailable-materializer",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 300:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        successor_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    running = record_legacy_codex_review_request(
        session,
        view,
        head=successor_head,
    )
    mark_codex_review_unavailable(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=successor_head,
        reason="Correlated provider usage-limit response.",
    )
    begin_successor_verification(
        session,
        package.work_package_id,
        review_run_id=running.automated_review_run_id,
        head_sha=successor_head,
        idempotency_key="bind-unavailable-materializer",
        fallback_reviewer="principal-reviewer:chatgpt",
        fallback_reason="Provider unavailable; exact-head independent review required.",
    )
    verify_finding(
        session,
        package.work_package_id,
        finding_id="codex:3101:4101",
        outcome="ABSENT",
        reviewer="principal-reviewer:chatgpt",
        evidence="Provider finding is absent under the recorded fallback.",
        idempotency_key="verify-unavailable-materializer-provider",
    )
    verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="ABSENT",
        reviewer="principal-reviewer:chatgpt",
        evidence="Internal finding is absent under the recorded fallback.",
        idempotency_key="verify-unavailable-materializer-internal",
    )

    github = FakeRemediationGitHub(view)
    github.head_sha = successor_head
    github.drop_reaction_response = False
    github.drop_reply_response = False
    github.drop_summary_response = False
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )

    done = materializer.materialize(session, package.work_package_id)

    assert done.state is WorkPackageState.DONE
    assert done.issue_closed is True
    assert get_view(session, view.publication_id).automated_review_status is AutomatedReviewStatus.UNAVAILABLE
    assert github.resolve_calls == 1
    assert len(github.reactions) == 1
    assert len(github.replies) == 2


def test_materializer_rejects_unavailable_successor_without_fallback(session, monkeypatch):
    view, _source_run, package = create_package(session)
    claim_work_package(
        session,
        package.work_package_id,
        actor="general-implementer",
        idempotency_key="claim-unavailable-no-fallback",
    )
    successor_head = "8" * 40
    candidate = submit_verified_candidate(
        session,
        view.publication_id,
        source(successor_head, "9" * 40, "a"),
    )
    submit_implementation(
        session,
        package.work_package_id,
        candidate_id=candidate.current_candidate.candidate_id,
        head_sha=successor_head,
        summary="Construct unavailable state without granting fallback authority.",
        evidence_sha256="f" * 64,
        idempotency_key="submit-unavailable-no-fallback",
    )
    profile = profile_for_repository(REPOSITORY)
    for index, job_id in enumerate(profile.required_jobs, 1):
        record_validation(
            session,
            view.publication_id,
            job_id=job_id,
            status=ValidationStatus.PASS,
            evidence_sha256=f"{index + 400:064x}",
        )
    mark_remote_published(
        session,
        view.publication_id,
        successor_head,
        branch=view.remote_branch,
        base_branch=view.base_branch,
        pull_request_number=view.pull_request_number,
    )
    running = record_legacy_codex_review_request(
        session,
        view,
        head=successor_head,
    )
    mark_codex_review_unavailable(
        session,
        view.publication_id,
        run_id=running.automated_review_run_id,
        reviewed_head_sha=successor_head,
        reason="Correlated provider usage-limit response.",
    )

    package_view = get_work_package(session, package.work_package_id)
    impossible_unbound_view = replace(
        package_view,
        state=WorkPackageState.VERIFYING,
        successor_review_run_id=running.automated_review_run_id,
        successor_head_sha=successor_head,
        successor_fallback=None,
    )

    github = FakeRemediationGitHub(view)
    github.head_sha = successor_head
    materializer = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
        review_thread_token=SecretStr("review-user-token"),
    )

    import control_plane.remediation_materializer as materializer_module

    original_get_work_package = materializer_module.get_work_package

    def fake_get_work_package(current_session, work_package_id):
        if work_package_id == package.work_package_id:
            return impossible_unbound_view
        return original_get_work_package(current_session, work_package_id)

    monkeypatch.setattr(materializer_module, "get_work_package", fake_get_work_package)

    with pytest.raises(
        RemediationMaterializationError,
        match="successor review is no longer current",
    ):
        materializer._verify_current_head(
            session,
            impossible_unbound_view,
            "installation-token",
        )


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
    provider = next(item for item in rework.findings if item["finding_id"] == "codex:3101:4101")
    assert provider["verification"]["outcome"] == "ABSENT"
    assert provider["closure_state"] == "VERIFIED_ABSENT"
    internal = next(item for item in rework.findings if item["finding_id"] == "control-plane:bigint-comment-id")
    assert internal["verification"] is None
    assert internal["closure_state"] == "AWAITING_VERIFICATION"
    assert [item["outcome"] for item in internal["verification_history"]] == ["PERSISTS"]
    github = FakeRemediationGitHub(view)
    github.head_sha = head_one
    github.drop_reaction_response = False
    github.drop_reply_response = False
    projected = GitHubRemediationMaterializer(
        token_provider=FakeRemediationTokenProvider(),
        github=github,
        project_token=SecretStr("project-user-token"),
    ).materialize(session, package.work_package_id)
    assert projected.state is WorkPackageState.REWORK_REQUIRED
    assert len(github.reactions) == 1
    assert len(github.replies) == 1
    assert github.resolve_calls == 0
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
    verifying = verify_finding(
        session,
        package.work_package_id,
        finding_id="control-plane:bigint-comment-id",
        outcome="ABSENT",
        reviewer="principal-reviewer",
        evidence="Finding absent on implementation C.",
        idempotency_key="verify-attempt-two:control-plane:bigint-comment-id",
    )
    assert verifying.state is WorkPackageState.VERIFYING
    internal = next(item for item in verifying.findings if item["finding_id"] == "control-plane:bigint-comment-id")
    assert [item["outcome"] for item in internal["verification_history"]] == ["PERSISTS", "ABSENT"]
    assert internal["verification"]["review_run_id"] == review_two
    provider = next(item for item in verifying.findings if item["finding_id"] == "codex:3101:4101")
    assert provider["verification"]["review_run_id"] == review_one
    assert [item["outcome"] for item in provider["verification_history"]] == ["ABSENT"]
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
    running = record_legacy_codex_review_request(
        session,
        view,
        head=successor_head,
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

