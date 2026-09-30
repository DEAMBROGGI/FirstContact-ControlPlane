import hashlib
import threading
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import control_plane.work as work_module

from control_plane.db import Base
from control_plane.domain import DomainError
from control_plane.models import WorkDependencyRow, WorkItemRow
from control_plane.work import (
    NextAction,
    NextRole,
    WorkState,
    add_dependency,
    claim_next_work,
    claim_work_item,
    complete_work_item,
    create_work_item,
    get_work_item,
    load_work_item_events,
    next_work,
    release_claim,
    release_work_item,
    renew_claim,
    resume_work_item,
    submit_work_implementation,
    suspend_work_item,
)

REPOSITORY = "DEAMBROGGI/FirstContact-ControlPlane"
ACTOR = "implementer:test"
REVIEWER = "reviewer:test"
EVIDENCE = "a" * 64


def create(
    session,
    issue_number,
    *,
    priority=2,
    rank=0,
    parent=None,
    required=True,
    executable=True,
    released=True,
    context=None,
):
    return create_work_item(
        session,
        repository=REPOSITORY,
        issue_number=issue_number,
        context=context or {"title": f"work-{issue_number}"},
        priority=priority,
        rank=rank,
        parent_work_item_id=(parent.work_item_id if parent is not None else None),
        required_for_parent=required,
        executable=executable,
        released=released,
    )


def implement_and_complete(session, view, *, suffix):
    claimed = claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key=f"{suffix}:claim",
    )
    assert claimed.state is WorkState.IN_PROGRESS

    implemented = submit_work_implementation(
        session,
        view.work_item_id,
        actor=ACTOR,
        summary=f"implemented {suffix}",
        evidence_sha256=EVIDENCE,
        idempotency_key=f"{suffix}:implementation",
    )
    assert implemented.state is WorkState.REVIEW

    completed = complete_work_item(
        session,
        view.work_item_id,
        actor=REVIEWER,
        evidence=f"reviewed {suffix}",
        idempotency_key=f"{suffix}:complete",
    )
    assert completed.state is WorkState.DONE
    return completed


def test_released_work_without_blockers_is_ready(session):
    view = create(
        session,
        2501,
        context={
            "title": "first task",
            "instructions": ["change code", "run tests"],
        },
    )

    assert view.state is WorkState.READY
    assert view.next_role is NextRole.IMPLEMENTER
    assert view.next_action is NextAction.CLAIM_WORK
    assert view.context_version == 1
    assert view.context["instructions"] == ["change code", "run tests"]
    assert view.context_digest == hashlib.sha256(
        b'{"instructions":["change code","run tests"],"title":"first task"}'
    ).hexdigest()


def test_dependency_blocks_until_authoritative_dependency_done(session):
    dependency = create(session, 2502, priority=0)
    target = create(session, 2503, priority=0)

    blocked = add_dependency(
        session,
        target.work_item_id,
        dependency.work_item_id,
        idempotency_key="dependency:2503:2502",
    )

    assert blocked.state is WorkState.BLOCKED
    assert blocked.blockers == (f"dependency:{dependency.work_item_id}",)
    assert next_work(session, REPOSITORY).work_item_id == dependency.work_item_id

    implement_and_complete(session, dependency, suffix="dep")

    ready = get_work_item(session, target.work_item_id)
    assert ready.state is WorkState.READY
    assert ready.blockers == ()


def test_claim_next_orders_by_priority_then_explicit_rank(session):
    low = create(session, 2510, priority=2, rank=0)
    p0_later = create(session, 2511, priority=0, rank=9)
    p0_first = create(session, 2512, priority=0, rank=1)

    assert low.state is WorkState.READY
    assert p0_later.state is WorkState.READY
    assert p0_first.state is WorkState.READY

    claimed = claim_next_work(
        session,
        REPOSITORY,
        actor=ACTOR,
        idempotency_key="claim-next:priority-rank",
    )

    assert claimed is not None
    assert claimed.work_item_id == p0_first.work_item_id
    assert claimed.state is WorkState.IN_PROGRESS
    assert claimed.implementer == ACTOR


def test_claim_next_orders_topology_before_explicit_rank(session):
    dependency = create(session, 2513, priority=0, rank=0)
    downstream = create(session, 2514, priority=0, rank=0)
    independent = create(session, 2515, priority=0, rank=99)

    add_dependency(
        session,
        downstream.work_item_id,
        dependency.work_item_id,
        idempotency_key="2514:depends:2513",
    )
    implement_and_complete(session, dependency, suffix="topology-dependency")

    downstream_ready = get_work_item(session, downstream.work_item_id)
    independent_ready = get_work_item(session, independent.work_item_id)

    assert downstream_ready.state is WorkState.READY
    assert independent_ready.state is WorkState.READY
    assert downstream_ready.topology_order == 1
    assert independent_ready.topology_order == 0

    claimed = claim_next_work(
        session,
        REPOSITORY,
        actor=ACTOR,
        idempotency_key="claim-next:topology",
    )

    assert claimed is not None
    assert claimed.work_item_id == independent.work_item_id


def test_claim_next_uses_stable_id_as_final_tie_break(session):
    first = create(session, 2516, priority=0, rank=5)
    second = create(session, 2517, priority=0, rank=5)

    expected = min(first.work_item_id, second.work_item_id)

    claimed = claim_next_work(
        session,
        REPOSITORY,
        actor=ACTOR,
        idempotency_key="claim-next:stable-id",
    )

    assert claimed is not None
    assert claimed.work_item_id == expected


def test_claim_next_retry_is_idempotent_and_specific_second_claim_fails(session):
    view = create(session, 2520, priority=0)

    first = claim_next_work(
        session,
        REPOSITORY,
        actor=ACTOR,
        idempotency_key="claim-next:retry",
    )
    second = claim_next_work(
        session,
        REPOSITORY,
        actor=ACTOR,
        idempotency_key="claim-next:retry",
    )

    assert first is not None
    assert second is not None
    assert first.work_item_id == view.work_item_id
    assert second.work_item_id == view.work_item_id

    with pytest.raises(DomainError, match="not READY"):
        claim_work_item(
            session,
            view.work_item_id,
            actor="implementer:other",
            idempotency_key="claim-specific:other",
        )


def test_implementation_completion_moves_to_review_never_done(session):
    view = create(session, 2530)
    claimed = claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2530:claim",
    )

    implemented = submit_work_implementation(
        session,
        claimed.work_item_id,
        actor=ACTOR,
        summary="code and tests complete",
        evidence_sha256=EVIDENCE,
        idempotency_key="2530:implementation",
    )

    assert implemented.state is WorkState.REVIEW
    assert implemented.next_role is NextRole.REVIEWER
    assert implemented.next_action is NextAction.WAIT_REVIEW
    assert implemented.implementation_summary == "code and tests complete"

    completed = complete_work_item(
        session,
        implemented.work_item_id,
        actor=REVIEWER,
        evidence="accepted independently",
        idempotency_key="2530:complete",
    )

    assert completed.state is WorkState.DONE
    assert completed.next_role is NextRole.NONE
    assert completed.next_action is NextAction.DONE


def test_required_child_recalculates_parent_without_manual_parent_state(session):
    parent = create(
        session,
        2540,
        executable=False,
        released=False,
        context={"title": "umbrella"},
    )
    child = create(
        session,
        2541,
        parent=parent,
        required=True,
        priority=0,
    )

    blocked_parent = get_work_item(session, parent.work_item_id)
    assert blocked_parent.state is WorkState.BLOCKED
    assert blocked_parent.blockers == (f"child:{child.work_item_id}",)

    implement_and_complete(session, child, suffix="child")

    backlog_parent = get_work_item(session, parent.work_item_id)
    assert backlog_parent.state is WorkState.BACKLOG

    review_parent = release_work_item(
        session,
        parent.work_item_id,
        idempotency_key="2540:release",
    )
    assert review_parent.state is WorkState.REVIEW

    done_parent = complete_work_item(
        session,
        parent.work_item_id,
        actor=REVIEWER,
        evidence="all required descendants complete",
        idempotency_key="2540:complete",
    )
    assert done_parent.state is WorkState.DONE


def test_required_child_cannot_be_added_after_parent_execution_starts(session):
    parent = create(session, 2550)
    claim_work_item(
        session,
        parent.work_item_id,
        actor=ACTOR,
        idempotency_key="2550:claim",
    )

    with pytest.raises(
        DomainError,
        match="required child cannot be added",
    ):
        create(
            session,
            2551,
            parent=parent,
            required=True,
        )


def test_blocking_graph_cycle_is_rejected(session):
    first = create(session, 2560, released=False)
    second = create(session, 2561, released=False)

    add_dependency(
        session,
        first.work_item_id,
        second.work_item_id,
        idempotency_key="2560:depends:2561",
    )

    with pytest.raises(DomainError, match="blocking cycle"):
        add_dependency(
            session,
            second.work_item_id,
            first.work_item_id,
            idempotency_key="2561:depends:2560",
        )


def test_claim_can_be_released_and_reclaimed(session):
    view = create(session, 2570)
    claimed = claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2570:claim:one",
    )
    assert claimed.state is WorkState.IN_PROGRESS

    released = release_claim(
        session,
        view.work_item_id,
        actor=ACTOR,
        reason="handoff",
        idempotency_key="2570:release",
    )
    assert released.state is WorkState.READY
    assert released.implementer is None

    reclaimed = claim_work_item(
        session,
        view.work_item_id,
        actor="implementer:two",
        idempotency_key="2570:claim:two",
    )
    assert reclaimed.state is WorkState.IN_PROGRESS
    assert reclaimed.implementer == "implementer:two"


def test_suspend_and_resume_preserve_authoritative_claim(session):
    view = create(session, 2580)
    claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2580:claim",
    )

    suspended = suspend_work_item(
        session,
        view.work_item_id,
        actor="planner:test",
        reason="external dependency",
        idempotency_key="2580:suspend",
    )
    assert suspended.state is WorkState.SUSPENDED

    resumed = resume_work_item(
        session,
        view.work_item_id,
        actor="planner:test",
        idempotency_key="2580:resume",
    )
    assert resumed.state is WorkState.IN_PROGRESS
    assert resumed.implementer == ACTOR


def test_create_is_idempotent_but_conflicting_identity_fails(session):
    first = create(
        session,
        2590,
        context={"title": "stable"},
        priority=1,
        rank=3,
    )
    second = create(
        session,
        2590,
        context={"title": "stable"},
        priority=1,
        rank=3,
    )

    assert first.work_item_id == second.work_item_id

    with pytest.raises(DomainError, match="different immutable identity"):
        create(
            session,
            2590,
            context={"title": "changed"},
            priority=1,
            rank=3,
        )


def test_work_ledger_reconstructs_context_and_lifecycle(session):
    view = create(session, 2600)
    claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2600:claim",
    )
    submit_work_implementation(
        session,
        view.work_item_id,
        actor=ACTOR,
        summary="fresh session can recover this",
        evidence_sha256=EVIDENCE,
        idempotency_key="2600:implementation",
    )

    reconstructed = get_work_item(session, view.work_item_id)
    events = load_work_item_events(session, view.work_item_id)

    assert reconstructed.state is WorkState.REVIEW
    assert reconstructed.context == {"title": "work-2600"}
    assert reconstructed.implementation_summary == "fresh session can recover this"
    assert [event["event_type"] for event in events] == [
        "WORK_CREATED",
        "WORK_RELEASED",
        "WORK_CLAIMED",
        "WORK_IMPLEMENTATION_COMPLETED",
    ]


def test_next_work_returns_none_when_nothing_is_ready(session):
    create(session, 2610, released=False)
    assert next_work(session, REPOSITORY) is None


def test_expired_claim_becomes_ready_and_stale_actor_cannot_submit(session, monkeypatch):
    start = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(work_module, "_utcnow", lambda: start)

    view = create(session, 2620)
    claimed = claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2620:claim:one",
        lease_seconds=60,
    )

    assert claimed.state is WorkState.IN_PROGRESS
    assert claimed.claim_lease_id is not None
    assert claimed.claim_expires_at is not None

    monkeypatch.setattr(
        work_module,
        "_utcnow",
        lambda: start + timedelta(seconds=61),
    )

    expired = get_work_item(session, view.work_item_id)
    assert expired.state is WorkState.READY
    assert expired.implementer is None
    assert expired.claim_lease_id is None
    assert expired.claim_expires_at is None

    with pytest.raises(DomainError, match="IN_PROGRESS"):
        submit_work_implementation(
            session,
            view.work_item_id,
            actor=ACTOR,
            summary="stale actor result",
            evidence_sha256=EVIDENCE,
            idempotency_key="2620:stale-implementation",
        )

    reclaimed = claim_work_item(
        session,
        view.work_item_id,
        actor="implementer:recovery",
        idempotency_key="2620:claim:recovery",
        lease_seconds=60,
    )
    assert reclaimed.state is WorkState.IN_PROGRESS
    assert reclaimed.implementer == "implementer:recovery"
    assert reclaimed.claim_lease_id is not None


def test_claim_renewal_extends_same_lease_identity(session, monkeypatch):
    start = datetime(2026, 9, 30, 13, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(work_module, "_utcnow", lambda: start)

    view = create(session, 2630)
    claimed = claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2630:claim",
        lease_seconds=120,
    )
    original_lease = claimed.claim_lease_id
    original_expiry = datetime.fromisoformat(claimed.claim_expires_at)

    monkeypatch.setattr(
        work_module,
        "_utcnow",
        lambda: start + timedelta(seconds=30),
    )

    renewed = renew_claim(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2630:renew",
        lease_seconds=120,
    )

    assert renewed.state is WorkState.IN_PROGRESS
    assert renewed.claim_lease_id == original_lease
    assert datetime.fromisoformat(renewed.claim_expires_at) > original_expiry

    replay = renew_claim(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2630:renew",
        lease_seconds=120,
    )
    assert replay.claim_lease_id == original_lease
    assert replay.claim_expires_at == renewed.claim_expires_at


def test_dependency_cannot_be_added_after_claim(session):
    dependency = create(session, 2640, released=False)
    target = create(session, 2641)

    claim_work_item(
        session,
        target.work_item_id,
        actor=ACTOR,
        idempotency_key="2641:claim",
    )

    with pytest.raises(
        DomainError,
        match="hard dependencies cannot change",
    ):
        add_dependency(
            session,
            target.work_item_id,
            dependency.work_item_id,
            idempotency_key="2641:depends:2640",
        )


def test_implementation_and_release_commands_are_retry_idempotent(session):
    view = create(session, 2650)
    claimed = claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2650:claim",
    )

    released = release_claim(
        session,
        claimed.work_item_id,
        actor=ACTOR,
        reason="handoff",
        idempotency_key="2650:release",
    )
    replayed_release = release_claim(
        session,
        claimed.work_item_id,
        actor=ACTOR,
        reason="handoff",
        idempotency_key="2650:release",
    )
    assert released.state is WorkState.READY
    assert replayed_release.state is WorkState.READY

    reclaimed = claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2650:reclaim",
    )
    implemented = submit_work_implementation(
        session,
        reclaimed.work_item_id,
        actor=ACTOR,
        summary="retry-safe implementation",
        evidence_sha256=EVIDENCE,
        idempotency_key="2650:implementation",
    )
    replayed_implementation = submit_work_implementation(
        session,
        reclaimed.work_item_id,
        actor=ACTOR,
        summary="retry-safe implementation",
        evidence_sha256=EVIDENCE,
        idempotency_key="2650:implementation",
    )

    assert implemented.state is WorkState.REVIEW
    assert replayed_implementation.state is WorkState.REVIEW

    with pytest.raises(DomainError, match="idempotency key"):
        submit_work_implementation(
            session,
            reclaimed.work_item_id,
            actor=ACTOR,
            summary="different payload",
            evidence_sha256=EVIDENCE,
            idempotency_key="2650:implementation",
        )


def test_resume_and_complete_commands_are_retry_idempotent(session):
    view = create(session, 2660)
    suspend_work_item(
        session,
        view.work_item_id,
        actor="planner:test",
        reason="pause",
        idempotency_key="2660:suspend",
    )

    resumed = resume_work_item(
        session,
        view.work_item_id,
        actor="planner:test",
        idempotency_key="2660:resume",
    )
    replayed_resume = resume_work_item(
        session,
        view.work_item_id,
        actor="planner:test",
        idempotency_key="2660:resume",
    )
    assert resumed.state is WorkState.READY
    assert replayed_resume.state is WorkState.READY

    claim_work_item(
        session,
        view.work_item_id,
        actor=ACTOR,
        idempotency_key="2660:claim",
    )
    submit_work_implementation(
        session,
        view.work_item_id,
        actor=ACTOR,
        summary="done",
        evidence_sha256=EVIDENCE,
        idempotency_key="2660:implementation",
    )

    completed = complete_work_item(
        session,
        view.work_item_id,
        actor=REVIEWER,
        evidence="accepted",
        idempotency_key="2660:complete",
    )
    replayed_complete = complete_work_item(
        session,
        view.work_item_id,
        actor=REVIEWER,
        evidence="accepted",
        idempotency_key="2660:complete",
    )

    assert completed.state is WorkState.DONE
    assert replayed_complete.state is WorkState.DONE


def test_context_is_reconstructed_from_ledger_and_projection_drift_fails_closed(session):
    view = create(
        session,
        2670,
        context={
            "title": "ledger-owned context",
            "instructions": ["one", "two"],
        },
    )

    reconstructed = get_work_item(session, view.work_item_id)
    assert reconstructed.context == {
        "title": "ledger-owned context",
        "instructions": ["one", "two"],
    }

    row = session.get(WorkItemRow, view.work_item_id)
    row.context_data = {"title": "tampered projection"}
    session.commit()

    with pytest.raises(
        RuntimeError,
        match="context projection differs from its ledger",
    ):
        get_work_item(session, view.work_item_id)


def test_parent_required_children_are_derived_from_child_ledger(session):
    parent = create(
        session,
        2680,
        executable=False,
        released=False,
        context={"title": "parent"},
    )
    child = create(
        session,
        2681,
        parent=parent,
        required=True,
        context={"title": "child"},
    )

    before = get_work_item(session, parent.work_item_id)
    assert before.state is WorkState.BLOCKED
    assert before.required_children == (child.work_item_id,)

    child_row = session.get(WorkItemRow, child.work_item_id)
    child_row.parent_work_item_id = None
    session.commit()

    with pytest.raises(
        RuntimeError,
        match="immutable identity differs from its ledger",
    ):
        get_work_item(session, parent.work_item_id)


def test_concurrent_opposite_dependencies_only_one_edge_can_commit(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "work-graph-race.db"
    engine = create_engine(
        "sqlite:///" + str(database_path),
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    with Session() as bootstrap:
        first = create_work_item(
            bootstrap,
            repository=REPOSITORY,
            issue_number=2690,
            context={"title": "first"},
            released=False,
        )
        second = create_work_item(
            bootstrap,
            repository=REPOSITORY,
            issue_number=2691,
            context={"title": "second"},
            released=False,
        )
        first_id = first.work_item_id
        second_id = second.work_item_id

    repository_gate = threading.Lock()
    start_barrier = threading.Barrier(2)
    results: list[str] = []
    result_lock = threading.Lock()

    def serialized_repository_scope(current_session, repository):
        assert repository == REPOSITORY
        repository_gate.acquire()
        released = False
        original_commit = current_session.commit
        original_rollback = current_session.rollback

        def release_once():
            nonlocal released
            if not released:
                released = True
                repository_gate.release()

        def commit():
            try:
                return original_commit()
            finally:
                release_once()

        def rollback():
            try:
                return original_rollback()
            finally:
                release_once()

        current_session.commit = commit
        current_session.rollback = rollback

    monkeypatch.setattr(
        work_module,
        "_lock_scheduler_scope",
        serialized_repository_scope,
    )

    def worker(target_id, dependency_id, key):
        with Session() as current:
            start_barrier.wait()
            try:
                add_dependency(
                    current,
                    target_id,
                    dependency_id,
                    idempotency_key=key,
                )
            except DomainError as exc:
                current.rollback()
                outcome = "CYCLE" if "blocking cycle" in str(exc) else "ERROR"
            else:
                outcome = "COMMITTED"

            with result_lock:
                results.append(outcome)

    first_thread = threading.Thread(
        target=worker,
        args=(first_id, second_id, "2690:depends:2691"),
    )
    second_thread = threading.Thread(
        target=worker,
        args=(second_id, first_id, "2691:depends:2690"),
    )

    first_thread.start()
    second_thread.start()
    first_thread.join(timeout=10)
    second_thread.join(timeout=10)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert sorted(results) == ["COMMITTED", "CYCLE"]

    with Session() as verify:
        edges = list(
            verify.scalars(
                select(WorkDependencyRow).order_by(WorkDependencyRow.id.asc())
            )
        )
        assert len(edges) == 1

        first_view = get_work_item(verify, first_id)
        second_view = get_work_item(verify, second_id)
        assert not (
            first_view.dependencies == (second_id,)
            and second_view.dependencies == (first_id,)
        )
