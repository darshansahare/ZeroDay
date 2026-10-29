"""
Integration Tests for ZeroDay Arena Target Selection, Governance, Rate Limiting, and Secret Security.
"""

import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.governance import governance
from app.config import AppConfig
from app.core.state_machine import RemediationStateMachine, RunState
from app.core.orchestrator import RemediationRun, DETERMINISTIC_SECURE_PATCH


import os

@pytest.fixture
def client():
    governance.reset()
    c = TestClient(app)
    c.headers["X-API-Key"] = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")
    return c


def test_three_sample_repositories_validation(client):
    """Verify all three intentionally vulnerable sample repositories can be validated."""
    samples = [
        "https://github.com/darshansahare/zeroday-test-1",
        "https://github.com/darshansahare/zeroday-test-2",
        "https://github.com/darshansahare/zeroday-test-3",
    ]
    for url in samples:
        resp = client.post("/api/repos/validate", json={"url": url})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["owner"] == "darshansahare"
        assert len(data["commit_sha"]) == 40
        assert len(data["pinned_commit"]) == 7


def test_custom_github_url_validation(client):
    """Verify custom GitHub URL validation: valid public URL vs invalid formats."""
    # Valid GitHub URL
    valid_resp = client.post("/api/repos/validate", json={"url": "https://github.com/octocat/Hello-World"})
    assert valid_resp.status_code == 200
    assert valid_resp.json()["valid"] is True
    assert valid_resp.json()["owner"] == "octocat"
    assert valid_resp.json()["repo"] == "Hello-World"

    # Invalid URL syntax
    invalid_resp = client.post("/api/repos/validate", json={"url": "https://notgithub.com/user/repo"})
    assert invalid_resp.status_code == 400
    assert "Invalid GitHub repository URL" in invalid_resp.json()["detail"]

    # Nonexistent repo URL
    fake_resp = client.post("/api/repos/validate", json={"url": "https://github.com/nonexistent-org-98765/nonexistent-repo-98765"})
    assert fake_resp.status_code == 400
    assert "Unable to access repository" in fake_resp.json()["detail"]


def test_config_endpoint_no_secret_leakage(client):
    """Verify GET /api/config and POST /api/config never expose sensitive secret values."""
    secret_nebius = "neb_test_secret_key_1234567890abcdef"
    secret_tavily = "tvly_test_secret_key_9876543210fedcba"

    # Configure via API
    post_resp = client.post("/api/config", json={
        "nebius_api_key": secret_nebius,
        "tavily_api_key": secret_tavily
    })
    assert post_resp.status_code == 200
    post_data = post_resp.json()
    assert post_data["nebius_configured"] is True
    assert post_data["tavily_configured"] is True

    # Critical security assertion: raw secret string and substrings MUST NOT be in response text
    assert secret_nebius not in post_resp.text
    assert secret_tavily not in post_resp.text
    assert "1234567890" not in post_resp.text
    assert "9876543210" not in post_resp.text

    # Read back via GET /api/config
    get_resp = client.get("/api/config")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["nebius_configured"] is True
    assert get_data["tavily_configured"] is True
    assert secret_nebius not in get_resp.text
    assert secret_tavily not in get_resp.text

    # Clean up test credentials
    from app.api.routes import set_backend_config
    set_backend_config(nebius_key="", tavily_key="")


def test_byok_api_keys_enforced(client):
    """Verify that creating a run without external API keys seamlessly succeeds using deterministic offline fallback."""
    governance.reset()
    from app.api.routes import set_backend_config
    set_backend_config(nebius_key="", tavily_key="")

    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 1,
        "candidate_patch": DETERMINISTIC_SECURE_PATCH,
    }

    # Missing keys should succeed via verified deterministic offline fallback
    resp = client.post("/api/runs", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["execution_mode"] == "deterministic_offline_fallback"
    assert data["is_verified_remediation"] is True

    # Restoring keys also succeeds
    set_backend_config(nebius_key="neb-test-key", tavily_key="tvly-test-key")
    ok_resp = client.post("/api/runs", json=payload)
    assert ok_resp.status_code == 201


def test_rate_limiting_removed(client):
    """Verify that per-device and global rate limiting are completely removed in BYOK mode."""
    governance.reset()
    from app.api.routes import set_backend_config
    set_backend_config(nebius_key="neb-test-key", tavily_key="tvly-test-key")

    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 1,
        "candidate_patch": DETERMINISTIC_SECURE_PATCH,
        "async_mode": False,
    }

    device_header = {"X-Device-Id": "device-test-unit-001"}

    # Repeated requests beyond old 5/hr limit must all succeed with HTTP 201 without 429
    for _ in range(6):
        resp = client.post("/api/runs", json=payload, headers=device_header)
        assert resp.status_code == 201


def test_concurrency_limit_removed(client):
    """Verify that concurrent analyses are not capped with HTTP 429."""
    governance.reset()
    from app.api.routes import active_runs, set_backend_config
    set_backend_config(nebius_key="neb-test-key", tavily_key="tvly-test-key")

    # Mock multiple active runs
    for i in range(5):
        active_runs[f"dummy-run-{i}"] = RemediationRun(target_path="target_app/app.py")

    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 1,
        "candidate_patch": DETERMINISTIC_SECURE_PATCH,
    }

    resp = client.post("/api/runs", json=payload)
    assert resp.status_code == 201

    # Cleanup active runs
    for i in range(5):
        active_runs.pop(f"dummy-run-{i}", None)


def test_budget_protection_disabled(client):
    """Verify that budget threshold does not block analysis in BYOK mode."""
    governance.reset()
    from app.api.routes import set_backend_config
    set_backend_config(nebius_key="neb-test-key", tavily_key="tvly-test-key")

    governance.total_cost_usd = 999999.0

    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 1,
        "candidate_patch": DETERMINISTIC_SECURE_PATCH,
    }

    resp = client.post("/api/runs", json=payload)
    assert resp.status_code == 201
    governance.reset()


def test_analysis_timeout_behavior(client):
    """Verify that an analysis that exceeds deadline reports TIMED_OUT."""
    cfg = AppConfig()
    cfg.analysis_timeout_seconds = 0  # Force immediate timeout

    run = RemediationRun(target_path="target_app/app.py", config=cfg)
    report = run.execute()

    assert run.state_machine.current_state == RunState.TIMED_OUT
    assert report.is_verified_remediation is False
    assert any("TIMED OUT" in r for r in report.failure_reasons)


def test_state_machine_timed_out_terminal():
    """Verify that RunState.TIMED_OUT is recognized as a terminal state."""
    sm = RemediationStateMachine(RunState.CREATED)
    assert sm.is_terminal is False
    sm.transition_to(RunState.TIMED_OUT, reason="Timeout reached")
    assert sm.current_state == RunState.TIMED_OUT
    assert sm.is_terminal is True
