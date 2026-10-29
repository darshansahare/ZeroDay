"""
Regression Tests for Application Entry Points, Router Registrations, and Route Consistency (Issue 5).
Verifies:
1. Unification of app.main.app and main.app as a single canonical application instance.
2. Content negotiation consistency for /benchmarks and /benchmarks/{id} (HTML for browser, JSON for API).
3. Privilege parity across canonical (/api/...) and un-prefixed alternate routes.
4. Protection parity across legacy duel endpoints (/api/run, /api/reset, /api/scan, /ws).
5. Canonical run-creation (/api/runs) contract vs legacy singular duel (/api/run).
6. Catch-all routing boundary protection (API 404 vs SPA 404).
"""

import os
import pytest
from fastapi.testclient import TestClient

import main
import app.main
from app.core.auth import SESSION_COOKIE_NAME, create_session

TEST_SECRET_KEY = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def authed_client():
    c = TestClient(main.app)
    c.headers["X-API-Key"] = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")
    return c


def test_app_main_and_main_are_identical_instance():
    """Verify app.main.app aliases the canonical main.app instance."""
    assert app.main.app is main.app
    assert id(app.main.app) == id(main.app)


def test_app_main_serves_all_routes_identically(client):
    """Verify that importing from app.main provides full access to static, SPA, and API routes."""
    app_main_client = TestClient(app.main.app)

    # 1. Health endpoint (API)
    r_health = app_main_client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "healthy"

    # 2. Frontend landing route (SPA)
    r_landing = app_main_client.get("/")
    assert r_landing.status_code == 200
    assert "text/html" in r_landing.headers.get("content-type", "")

    # 3. Status endpoint (Legacy /api/status)
    r_status = app_main_client.get("/api/status")
    assert r_status.status_code == 200
    assert r_status.json()["status"] == "online"

    # 4. Unknown route returns 404
    r_404 = app_main_client.get("/api/completely-bogus-endpoint")
    assert r_404.status_code == 404


def test_benchmarks_route_content_negotiation(client):
    """
    Verify /benchmarks and /benchmarks/{id} resolve route shadowing:
    - Browser navigation (text/html) receives React SPA HTML shell.
    - API client (application/json) receives structured benchmark records.
    """
    # 1. Browser navigation to /benchmarks
    r_browser = client.get("/benchmarks", headers={"Accept": "text/html,application/xhtml+xml"})
    assert r_browser.status_code == 200
    assert "text/html" in r_browser.headers.get("content-type", "")

    # 2. API client to /benchmarks
    r_api = client.get("/benchmarks", headers={"Accept": "application/json"})
    assert r_api.status_code == 200
    assert "application/json" in r_api.headers.get("content-type", "")
    data = r_api.json()
    assert "benchmarks" in data
    assert len(data["benchmarks"]) >= 10

    # 3. Browser navigation to /benchmarks/bench-01
    r_detail_browser = client.get("/benchmarks/bench-01", headers={"Accept": "text/html"})
    assert r_detail_browser.status_code == 200
    assert "text/html" in r_detail_browser.headers.get("content-type", "")

    # 4. API client to /benchmarks/bench-01
    r_detail_api = client.get("/benchmarks/bench-01", headers={"Accept": "application/json"})
    assert r_detail_api.status_code == 200
    assert "application/json" in r_detail_api.headers.get("content-type", "")
    assert r_detail_api.json()["id"].lower() == "bench-01"

    # 5. Canonical prefixed /api/benchmarks always returns JSON
    r_canonical = client.get("/api/benchmarks")
    assert r_canonical.status_code == 200
    assert "application/json" in r_canonical.headers.get("content-type", "")


def test_privilege_parity_across_all_entry_points(client):
    """
    Verify that every state-changing endpoint strictly enforces authentication
    with identical HTTP 401 responses, regardless of whether called via /api or un-prefixed.
    """
    endpoints = [
        ("POST", "/api/config"),
        ("POST", "/config"),
        ("POST", "/api/runs"),
        ("POST", "/runs"),
        ("POST", "/api/cache/clear"),
        ("POST", "/cache/clear"),
        ("POST", "/api/benchmarks"),
        ("POST", "/benchmarks"),
        ("POST", "/api/benchmarks/run"),
        ("POST", "/benchmarks/run"),
        ("POST", "/api/reset"),
        ("POST", "/reset"),
        ("POST", "/api/run"),
        ("POST", "/run"),
        ("POST", "/api/scan"),
        ("POST", "/scan"),
    ]

    for method, path in endpoints:
        resp = client.request(method, path, json={})
        assert resp.status_code == 401, f"{method} {path} failed to require authentication: {resp.status_code}"


def test_canonical_run_creation_vs_legacy_duel(authed_client):
    """
    Verify distinct contracts between canonical multi-target runs (/api/runs)
    and legacy single-file duel triggering (/api/run):
    - /api/runs returns HTTP 201 with full RunSummaryResponse (run_id, execution_mode, events_count).
    - /api/run returns HTTP 200 with background status message.
    """
    # 1. Canonical run creation
    canonical_resp = authed_client.post(
        "/api/runs",
        json={"target_path": "target_app/app.py", "max_repair_attempts": 1},
    )
    assert canonical_resp.status_code == 201
    summary = canonical_resp.json()
    assert "run_id" in summary
    assert "execution_mode" in summary
    assert "is_verified_remediation" in summary

    # 2. Legacy duel triggering
    legacy_resp = authed_client.post("/api/run")
    assert legacy_resp.status_code == 200
    legacy_data = legacy_resp.json()
    assert legacy_data["status"] == "initiated"
    assert "Autonomous duel launched" in legacy_data["message"]


def test_catch_all_api_boundary_defense(client):
    """
    Verify catch-all route strictly protects API namespace and serves React 404 for frontend routes:
    - Paths beginning with api/ return HTTP 404 JSON (not HTML).
    - Paths targeting frontend routes return HTTP 404 HTML.
    """
    # 1. Non-existent API route -> standard 404 JSON
    api_404 = client.get("/api/nonexistent/sub/path")
    assert api_404.status_code == 404
    assert "application/json" in api_404.headers.get("content-type", "")

    # 2. Non-existent frontend route -> SPA 404 HTML
    spa_404 = client.get("/some/unmatched/frontend/path")
    assert spa_404.status_code == 404
    assert "text/html" in spa_404.headers.get("content-type", "")
