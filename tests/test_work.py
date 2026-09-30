import hashlib

import pytest

from control_plane.domain import DomainError
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


def test_claim_next_order_is_priority_rank_then_stable_identity(session):
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
        idempotency_key="claim-next:one",
    )

    assert claimed is not None
    assert claimed.work_item_id == p0_first.work_item_id
    assert claimed.state is WorkState.IN_PROGRESS
    assert claimed.implementer == ACTOR


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
