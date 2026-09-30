from fastapi.testclient import TestClient

from control_plane.config import settings
from control_plane.db import get_session
from control_plane.main import app


REPOSITORY = "DEAMBROGGI/FirstContact-ControlPlane"
HEADERS = {"X-Control-Plane-Token": settings.internal_token}


def client_for(session):
    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    return TestClient(app)


def create_item(client, issue_number, **overrides):
    body = {
        "repository": REPOSITORY,
        "issue_number": issue_number,
        "context": {
            "title": f"issue-{issue_number}",
            "acceptance": ["tests pass"],
        },
        "priority": 2,
        "rank": 0,
        "required_for_parent": True,
        "executable": True,
        "released": True,
    }
    body.update(overrides)
    response = client.post(
        "/api/v1/internal/work-items",
        headers=HEADERS,
        json=body,
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_work_api_claim_next_returns_complete_fresh_session_context(session):
    client = client_for(session)
    try:
        create_item(
            client,
            2701,
            priority=1,
            context={
                "title": "implement scheduler",
                "instructions": ["inspect domain", "add regression tests"],
            },
        )
        selected = create_item(
            client,
            2702,
            priority=0,
            rank=4,
            context={
                "title": "implement claim-next",
                "instructions": ["lock", "re-read", "append event"],
            },
        )

        peek = client.get(
            "/api/v1/work/next",
            headers=HEADERS,
            params={"repository": REPOSITORY},
        )
        assert peek.status_code == 200
        assert peek.json()["work_item_id"] == selected["work_item_id"]
        assert peek.json()["next_action"] == "CLAIM_WORK"

        claimed = client.post(
            "/api/v1/work/claim-next",
            headers=HEADERS,
            json={
                "repository": REPOSITORY,
                "actor": "implementer:fresh-session",
                "idempotency_key": "api:claim-next:2702",
            },
        )
        assert claimed.status_code == 200
        payload = claimed.json()
        assert payload["work_item_id"] == selected["work_item_id"]
        assert payload["state"] == "IN_PROGRESS"
        assert payload["next_role"] == "IMPLEMENTER"
        assert payload["next_action"] == "IMPLEMENT"
        assert payload["claim_lease_id"]
        assert payload["claim_expires_at"]
        assert payload["context"]["instructions"] == [
            "lock",
            "re-read",
            "append event",
        ]

        renewed = client.post(
            f"/api/v1/work-items/{payload['work_item_id']}/claim/renew",
            headers=HEADERS,
            json={
                "actor": "implementer:fresh-session",
                "idempotency_key": "api:claim-renew:2702",
            },
        )
        assert renewed.status_code == 200
        assert renewed.json()["claim_lease_id"] == payload["claim_lease_id"]
        assert renewed.json()["state"] == "IN_PROGRESS"
    finally:
        app.dependency_overrides.clear()


def test_work_api_dependency_completion_releases_next_item(session):
    client = client_for(session)
    try:
        dependency = create_item(client, 2710, priority=0)
        target = create_item(client, 2711, priority=0)

        edge = client.post(
            f"/api/v1/internal/work-items/{target['work_item_id']}/dependencies",
            headers=HEADERS,
            json={
                "depends_on_work_item_id": dependency["work_item_id"],
                "idempotency_key": "api:edge:2711:2710",
            },
        )
        assert edge.status_code == 200
        assert edge.json()["state"] == "BLOCKED"

        claim = client.post(
            f"/api/v1/work-items/{dependency['work_item_id']}/claim",
            headers=HEADERS,
            json={
                "actor": "implementer:test",
                "idempotency_key": "api:2710:claim",
            },
        )
        assert claim.status_code == 200
        assert claim.json()["state"] == "IN_PROGRESS"

        implementation = client.post(
            f"/api/v1/work-items/{dependency['work_item_id']}/implementation",
            headers=HEADERS,
            json={
                "actor": "implementer:test",
                "summary": "implemented dependency",
                "evidence_sha256": "a" * 64,
                "idempotency_key": "api:2710:implementation",
            },
        )
        assert implementation.status_code == 200
        assert implementation.json()["state"] == "REVIEW"

        complete = client.post(
            f"/api/v1/internal/work-items/{dependency['work_item_id']}/complete",
            headers=HEADERS,
            json={
                "actor": "reviewer:test",
                "evidence": "accepted",
                "idempotency_key": "api:2710:complete",
            },
        )
        assert complete.status_code == 200
        assert complete.json()["state"] == "DONE"

        target_read = client.get(
            f"/api/v1/work-items/{target['work_item_id']}",
            headers=HEADERS,
        )
        assert target_read.status_code == 200
        assert target_read.json()["state"] == "READY"
        assert target_read.json()["blockers"] == []
    finally:
        app.dependency_overrides.clear()


def test_work_api_rejects_unauthorized_and_conflicting_claim(session):
    client = client_for(session)
    try:
        item = create_item(client, 2720)

        unauthorized = client.get(
            "/api/v1/work/next",
            params={"repository": REPOSITORY},
        )
        assert unauthorized.status_code == 401

        first = client.post(
            f"/api/v1/work-items/{item['work_item_id']}/claim",
            headers=HEADERS,
            json={
                "actor": "implementer:one",
                "idempotency_key": "api:2720:claim:one",
            },
        )
        assert first.status_code == 200

        second = client.post(
            f"/api/v1/work-items/{item['work_item_id']}/claim",
            headers=HEADERS,
            json={
                "actor": "implementer:two",
                "idempotency_key": "api:2720:claim:two",
            },
        )
        assert second.status_code == 409
        assert "not READY" in second.json()["detail"]
    finally:
        app.dependency_overrides.clear()
