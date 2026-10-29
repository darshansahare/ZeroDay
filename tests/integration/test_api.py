"""
Integration Tests for ZeroDay Arena Backend API Endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.orchestrator import DETERMINISTIC_SECURE_PATCH


import os

@pytest.fixture
def api_client():
    client = TestClient(app)
    client.headers["X-API-Key"] = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")
    return client


def test_health_endpoint(api_client):
    """Verify GET /health returns operational system status."""
    resp = api_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "workspace_root" in data
    assert "sandbox_enabled" in data


def test_create_and_fetch_run_lifecycle(api_client):
    """Verify POST /runs triggers remediation and creates accessible reports and events."""
    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 2,
        "candidate_patch": DETERMINISTIC_SECURE_PATCH,
    }
    resp = api_client.post("/runs", json=payload)
    assert resp.status_code == 201
    summary = resp.json()

    run_id = summary["run_id"]
    assert summary["status"] == "ACCEPTED"
    assert summary["is_verified_remediation"] is True

    # Check GET /runs/{run_id}
    get_resp = api_client.get(f"/runs/{run_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["run_id"] == run_id
    assert get_data["status"] == "ACCEPTED"

    # Check GET /runs/{run_id}/events
    events_resp = api_client.get(f"/runs/{run_id}/events")
    assert events_resp.status_code == 200
    events_data = events_resp.json()
    assert events_data["run_id"] == run_id
    assert events_data["events_count"] >= 5

    # Check GET /runs/{run_id}/report
    report_resp = api_client.get(f"/runs/{run_id}/report")
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert report_data["run_id"] == run_id
    assert report_data["final_status"] == "ACCEPTED"
    assert report_data["is_verified_remediation"] is True
    assert report_data["verification_outcome"]["status"] == "ACCEPTED"


def test_create_run_path_traversal_rejected(api_client):
    """Verify POST /runs strictly rejects target paths attempting directory traversal."""
    payload = {
        "target_path": "../../etc/shadow",
    }
    resp = api_client.post("/runs", json=payload)
    assert resp.status_code == 400
    assert "Security violation" in resp.json()["detail"]


def test_get_nonexistent_run_404(api_client):
    """Verify GET /runs/{nonexistent_id} returns HTTP 404."""
    resp = api_client.get("/runs/nonexistent-run-id-999")
    assert resp.status_code == 404


def test_repo_validation_invalid_url(api_client):
    """Verify POST /repos/validate rejects malformed repository URLs."""
    resp = api_client.post("/repos/validate", json={"url": "not-a-valid-url"})
    assert resp.status_code == 400
    assert "Invalid GitHub repository URL" in resp.json()["detail"]


def test_repo_validation_public_github_url(api_client):
    """Verify POST /repos/validate resolves commit and metadata on public repo without auth."""
    resp = api_client.post("/repos/validate", json={"url": "https://github.com/octocat/Hello-World"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["owner"] == "octocat"
    assert data["repo"] == "Hello-World"
    assert len(data["commit_sha"]) == 40
    assert len(data["pinned_commit"]) == 7


def test_health_endpoint_extended_fields(api_client):
    """Verify GET /health returns truthful readiness indicators."""
    resp = api_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "nebius_status" in data
    assert "tavily_status" in data
    assert "sandbox_status" in data

