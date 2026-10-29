"""
ZeroDay Arena - Public Demo UX and Controlled Demo Path Test Suite.
Verifies:
1. Public visitors can access landing page, health check, masked config, documentation, and benchmarks without admin keys.
2. Pre-approved vulnerable sample repositories execute smoothly under the controlled public demo path with zero authentication.
3. Arbitrary external repository targets, local filesystem targets, and custom candidate patches require administrator authorization.
4. Privileged operations (server configuration, cache clearing, benchmark mutation/runner, run cancellation) remain strictly protected.
5. Public demo rate limits and usage ceilings are enforced safely.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import get_config
from app.main import app
from app.core.governance import governance
from app.api.routes import active_runs


@pytest.fixture(autouse=True)
def reset_governance():
    """Reset rate limiter and token tracking before each test."""
    governance.reset()
    active_runs.clear()
    yield
    governance.reset()
    active_runs.clear()


@pytest.fixture
def unauthed_client():
    """Client with no authentication headers or session cookies."""
    return TestClient(app, base_url="http://testserver", raise_server_exceptions=False)


@pytest.fixture
def admin_client():
    """Client authenticated with the configured server admin API key."""
    cfg = get_config()
    secret = cfg.admin_api_key.get_secret_value() if cfg.admin_api_key else "test-secret"
    return TestClient(
        app,
        base_url="http://testserver",
        headers={"X-API-Key": secret},
        raise_server_exceptions=False,
    )


# ---------------------------------------------------------------------------
# Requirement 1 & 3: Public Landing Page and Read-Only Views
# ---------------------------------------------------------------------------

def test_public_landing_page_accessible(unauthed_client: TestClient):
    """The landing page index must be publicly accessible without authentication."""
    resp = unauthed_client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


def test_public_health_check_accessible(unauthed_client: TestClient):
    """Backend health check must be publicly accessible for monitors and judges."""
    resp = unauthed_client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "healthy"
    assert "sandbox_ready" in data


def test_public_config_masked_and_accessible(unauthed_client: TestClient):
    """GET /api/config must be accessible publicly without leaking server secrets."""
    resp = unauthed_client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "nebius_configured" in data
    assert "tavily_configured" in data
    assert "admin_api_key" not in data
    assert "nebius_api_key" not in data


def test_public_benchmarks_overview_accessible(unauthed_client: TestClient):
    """Benchmarks dashboard must be publicly readable without an admin key."""
    resp = unauthed_client.get("/api/benchmarks")
    assert resp.status_code == 200
    data = resp.json()
    assert "benchmarks" in data
    assert "metrics" in data


def test_public_cache_stats_accessible(unauthed_client: TestClient):
    """Telemetry cache stats must be publicly readable."""
    resp = unauthed_client.get("/api/cache/stats")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Requirement 2 & 5: Controlled Public Demo Path for Pre-Approved Samples
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("repo_url", [
    "https://github.com/darshansahare/zeroday-test-1",
    "https://github.com/darshansahare/zeroday-test-2",
    "https://github.com/darshansahare/zeroday-test-3",
    "https://github.com/darshansahare/zeroday-test-1.git",
    "http://github.com/darshansahare/zeroday-test-1/",
])
def test_public_demo_can_execute_preapproved_samples(unauthed_client: TestClient, repo_url: str):
    """
    Judges can start remediation analyses on pre-approved vulnerable demo repositories
    without being prompted for an admin key or session cookie.
    """
    payload = {
        "repo_url": repo_url,
        "target_path": "app.py",
        "max_repair_attempts": 1,
        "async_mode": True,
    }
    resp = unauthed_client.post("/api/runs", json=payload)
    assert resp.status_code == 201, f"Failed for {repo_url}: {resp.text}"
    data = resp.json()
    assert "run_id" in data
    assert data["status"] in ("CREATED", "INITIATED", "QUEUED", "ANALYZING", "SCANNING", "VERIFIED", "ACCEPTED")

    # Verify read-only run inspections are also accessible publicly
    run_id = data["run_id"]
    status_resp = unauthed_client.get(f"/api/runs/{run_id}")
    assert status_resp.status_code == 200

    events_resp = unauthed_client.get(f"/api/runs/{run_id}/events")
    assert events_resp.status_code == 200


# ---------------------------------------------------------------------------
# Requirement 4 & 5: Protection of Arbitrary Execution & Privileged Actions
# ---------------------------------------------------------------------------

def test_public_demo_rejects_arbitrary_external_repository(unauthed_client: TestClient):
    """
    Arbitrary unapproved repository execution is prohibited in public demo mode
    to prevent unauthenticated code execution in the subprocess sandbox.
    """
    payload = {
        "repo_url": "https://github.com/untrusted-actor/arbitrary-unapproved-repo",
        "target_path": "app.py",
    }
    resp = unauthed_client.post("/api/runs", json=payload)
    assert resp.status_code == 403
    assert "Public demo mode is restricted to pre-approved vulnerable samples" in resp.json().get("detail", "")


def test_public_demo_rejects_local_targets_without_admin(unauthed_client: TestClient):
    """
    Executing against local filesystem targets without a repository URL requires admin authorization.
    """
    payload = {
        "target_path": "target_app/app.py",
    }
    resp = unauthed_client.post("/api/runs", json=payload)
    assert resp.status_code == 401


def test_public_demo_rejects_custom_candidate_patch(unauthed_client: TestClient):
    """
    Injecting a custom candidate patch is a privileged operator action and requires admin authorization.
    """
    payload = {
        "repo_url": "https://github.com/darshansahare/zeroday-test-1",
        "candidate_patch": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x\n+y",
    }
    resp = unauthed_client.post("/api/runs", json=payload)
    assert resp.status_code == 401
    assert "Administrator authorization required for custom candidate patch injection" in resp.json().get("detail", "")


def test_privileged_config_changes_require_admin(unauthed_client: TestClient):
    """Mutating runtime server configuration strictly requires admin authorization."""
    resp = unauthed_client.post("/api/config", json={"llm_provider": "nebius"})
    assert resp.status_code == 401


def test_privileged_cache_clear_requires_admin(unauthed_client: TestClient):
    """Clearing persistent token cache strictly requires admin authorization."""
    resp = unauthed_client.post("/api/cache/clear")
    assert resp.status_code == 401


def test_privileged_benchmark_run_requires_admin(unauthed_client: TestClient):
    """Triggering the complete benchmark suite evaluation requires admin authorization."""
    resp = unauthed_client.post("/api/benchmarks/run")
    assert resp.status_code == 401


def test_privileged_benchmark_mutation_requires_admin(unauthed_client: TestClient):
    """Inserting or updating permanent benchmark cases requires admin authorization."""
    resp = unauthed_client.post("/api/benchmarks", json={"id": "test-case-01"})
    assert resp.status_code == 401


def test_privileged_run_cancellation_requires_admin(unauthed_client: TestClient):
    """Canceling a running analysis requires admin authorization."""
    resp = unauthed_client.post("/api/runs/nonexistent-run/cancel")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Administrator Privileged Access Verification
# ---------------------------------------------------------------------------

def test_admin_can_execute_arbitrary_targets(admin_client: TestClient):
    """
    Authenticated administrators CAN execute arbitrary repositories or local targets.
    """
    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 1,
        "async_mode": True,
    }
    resp = admin_client.post("/api/runs", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert "run_id" in data


# ---------------------------------------------------------------------------
# Rate Limiting & Usage Limits for Public Demo Path
# ---------------------------------------------------------------------------

def test_public_demo_rate_limiting_enforced(unauthed_client: TestClient):
    """
    Public demo mode enforces a sliding window rate limit per client device/IP.
    Excessive run creation attempts receive HTTP 429 Too Many Requests.
    """
    headers = {"X-Device-Id": "judge-test-device-uuid-12345"}
    payload = {
        "repo_url": "https://github.com/darshansahare/zeroday-test-1",
        "target_path": "app.py",
        "max_repair_attempts": 1,
        "async_mode": True,
    }

    # First 10 requests succeed within the hourly limit (clear active_runs registry to simulate sequential completions)
    for _ in range(10):
        resp = unauthed_client.post("/api/runs", json=payload, headers=headers)
        assert resp.status_code == 201
        active_runs.clear()

    # 11th request exceeds the public demo hourly rate limit
    blocked_resp = unauthed_client.post("/api/runs", json=payload, headers=headers)
    assert blocked_resp.status_code == 429
    assert "Public demo rate limit reached" in blocked_resp.json().get("detail", "")
