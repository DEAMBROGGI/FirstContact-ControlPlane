from fastapi.testclient import TestClient

from control_plane.config import settings
from control_plane.db import get_session
from control_plane.main import app


def test_api_creates_publication_and_keeps_publisher_disabled(session):
    def override_session():
        yield session

    app.dependency_overrides[get_session] = override_session
    client = TestClient(app)
    headers = {"X-Control-Plane-Token": settings.internal_token}
    try:
        created = client.post(
            "/api/v1/publications",
            headers=headers,
            json={"repository": "DEAMBROGGI/FirstContact", "issue_number": 51},
        )
        assert created.status_code == 200
        publication_id = created.json()["publication_id"]

        candidate = client.post(
            f"/api/v1/publications/{publication_id}/candidates",
            headers=headers,
            json={"base_sha": "1" * 40, "head_sha": "2" * 40, "tree_sha": "3" * 40},
        )
        assert candidate.status_code == 200
        assert candidate.json()["state"] == "VALIDATING"

        published = client.post(
            f"/api/v1/internal/publications/{publication_id}/published",
            headers=headers,
            json={"head_sha": "2" * 40},
        )
        assert published.status_code == 503
        assert published.json()["detail"] == "publisher is disabled"
    finally:
        app.dependency_overrides.clear()
