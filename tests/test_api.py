import subprocess

from fastapi.testclient import TestClient

from control_plane.config import settings
from control_plane.db import get_session
from control_plane.main import app, get_quarantine
from control_plane.quarantine import BASE_REF, HEAD_REF, GitCandidateQuarantine


def git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def candidate_bundle(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    git(repo, "config", "user.email", "api-test@example.invalid")
    git(repo, "config", "user.name", "API Test")
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "file.txt")
    git(repo, "commit", "--quiet", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "update-ref", BASE_REF, base)
    (repo / "file.txt").write_text("base\nhead\n", encoding="utf-8")
    git(repo, "add", "file.txt")
    git(repo, "commit", "--quiet", "-m", "head")
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "update-ref", HEAD_REF, head)
    bundle = tmp_path / "candidate.bundle"
    git(repo, "bundle", "create", str(bundle), BASE_REF, HEAD_REF)
    return bundle.read_bytes(), head


def test_api_creates_verified_candidate_and_keeps_publisher_disabled(
    session,
    tmp_path,
):
    def override_session():
        yield session

    quarantine = GitCandidateQuarantine(
        tmp_path / "quarantine",
        max_bundle_bytes=5_000_000,
    )

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_quarantine] = lambda: quarantine
    client = TestClient(app)
    headers = {"X-Control-Plane-Token": settings.internal_token}
    bundle_bytes, head = candidate_bundle(tmp_path)
    try:
        created = client.post(
            "/api/v1/publications",
            headers=headers,
            json={"repository": "DEAMBROGGI/FirstContact", "issue_number": 51},
        )
        assert created.status_code == 200
        publication_id = created.json()["publication_id"]

        candidate = client.post(
            f"/api/v1/publications/{publication_id}/candidate-bundle",
            headers=headers,
            files={
                "bundle": (
                    "candidate.bundle",
                    bundle_bytes,
                    "application/x-git-bundle",
                )
            },
        )
        assert candidate.status_code == 200
        assert candidate.json()["state"] == "VALIDATING"
        assert candidate.json()["current_candidate"]["head_sha"] == head

        old_endpoint = client.post(
            f"/api/v1/publications/{publication_id}/candidates",
            headers=headers,
            json={"base_sha": "1" * 40, "head_sha": "2" * 40, "tree_sha": "3" * 40},
        )
        assert old_endpoint.status_code == 404
        published = client.post(
            f"/api/v1/internal/publications/{publication_id}/published",
            headers=headers,
            json={"head_sha": head},
        )
        assert published.status_code == 503
        assert published.json()["detail"] == "publisher is disabled"
    finally:
        app.dependency_overrides.clear()
