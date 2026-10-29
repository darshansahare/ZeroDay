"""
Security Regression and Authorization Test Suite for ZeroDay Arena Backend API.
Verifies:
1. All privileged mutation endpoints strictly require authentication.
2. Both canonical (/api/...) and un-prefixed duplicate routes are guarded identically against bypasses.
3. Missing or invalid credentials return HTTP 401 Unauthorized.
4. Valid credentials succeed via X-API-Key, Authorization: Bearer, or HttpOnly session cookie.
5. Login and logout session lifecycle behaves securely.
6. WebSocket privileged commands (start_arena, reset_sandbox) require authorization.
7. Public read-only endpoints (health, status, config read, stats, repo validation) remain accessible.
8. No server secrets are ever logged or reflected in responses.
"""

import os
import pytest
from fastapi.testclient import TestClient

from main import app as main_app
from app.main import app as engine_app
from app.core.auth import (
    verify_admin_key,
    create_session,
    validate_session,
    invalidate_session,
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
)
from app.config import resolve_admin_key, ConfigurationError
from app.core.orchestrator import DETERMINISTIC_SECURE_PATCH


TEST_SECRET_KEY = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")


@pytest.fixture
def unauthed_client():
    """Client with zero credentials provided."""
    return TestClient(main_app)


@pytest.fixture
def authed_client():
    """Client authenticated with correct server secret via X-API-Key."""
    c = TestClient(main_app)
    c.headers["X-API-Key"] = TEST_SECRET_KEY
    return c


@pytest.fixture
def bearer_client():
    """Client authenticated via Authorization: Bearer header."""
    c = TestClient(main_app)
    c.headers["Authorization"] = f"Bearer {TEST_SECRET_KEY}"
    return c


# =====================================================================
# 1. UNAUTHENTICATED ACCESS MUST BE REJECTED WITH HTTP 401
# =====================================================================

def test_unauthenticated_api_config_rejected(unauthed_client):
    """POST /api/config without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/config", json={"llm_provider": "nebius"})
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_unauthenticated_alternate_config_rejected(unauthed_client):
    """POST /config without credentials returns HTTP 401 (preventing un-prefixed route bypass)."""
    resp = unauthed_client.post("/config", json={"llm_provider": "nebius"})
    assert resp.status_code == 401


def test_unauthenticated_runs_rejected(unauthed_client):
    """POST /api/runs without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/runs", json={
        "target_path": "target_app/app.py",
        "candidate_patch": DETERMINISTIC_SECURE_PATCH,
    })
    assert resp.status_code == 401


def test_unauthenticated_alternate_runs_rejected(unauthed_client):
    """POST /runs without credentials returns HTTP 401 (preventing un-prefixed route bypass)."""
    resp = unauthed_client.post("/runs", json={
        "target_path": "target_app/app.py",
        "candidate_patch": DETERMINISTIC_SECURE_PATCH,
    })
    assert resp.status_code == 401


def test_unauthenticated_cancel_run_rejected(unauthed_client):
    """POST /api/runs/{run_id}/cancel without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/runs/nonexistent-run-001/cancel")
    assert resp.status_code == 401


def test_unauthenticated_alternate_cancel_run_rejected(unauthed_client):
    """POST /runs/{run_id}/cancel without credentials returns HTTP 401."""
    resp = unauthed_client.post("/runs/nonexistent-run-001/cancel")
    assert resp.status_code == 401


def test_unauthenticated_cache_clear_rejected(unauthed_client):
    """POST /api/cache/clear without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/cache/clear")
    assert resp.status_code == 401


def test_unauthenticated_alternate_cache_clear_rejected(unauthed_client):
    """POST /cache/clear without credentials returns HTTP 401."""
    resp = unauthed_client.post("/cache/clear")
    assert resp.status_code == 401


def test_unauthenticated_benchmarks_mutation_rejected(unauthed_client):
    """POST /api/benchmarks without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/benchmarks", json={"id": "MALICIOUS-MUTATION"})
    assert resp.status_code == 401


def test_unauthenticated_alternate_benchmarks_mutation_rejected(unauthed_client):
    """POST /benchmarks without credentials returns HTTP 401."""
    resp = unauthed_client.post("/benchmarks", json={"id": "MALICIOUS-MUTATION"})
    assert resp.status_code == 401


def test_unauthenticated_benchmarks_run_rejected(unauthed_client):
    """POST /api/benchmarks/run without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/benchmarks/run", json={"suite": "all"})
    assert resp.status_code == 401


def test_unauthenticated_alternate_benchmarks_run_rejected(unauthed_client):
    """POST /benchmarks/run without credentials returns HTTP 401."""
    resp = unauthed_client.post("/benchmarks/run", json={"suite": "all"})
    assert resp.status_code == 401


def test_unauthenticated_main_reset_rejected(unauthed_client):
    """POST /api/reset without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/reset")
    assert resp.status_code == 401


def test_unauthenticated_main_run_rejected(unauthed_client):
    """POST /api/run without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/run")
    assert resp.status_code == 401


def test_unauthenticated_main_scan_rejected(unauthed_client):
    """POST /api/scan without credentials returns HTTP 401."""
    resp = unauthed_client.post("/api/scan")
    assert resp.status_code == 401


# =====================================================================
# 2. INVALID CREDENTIALS MUST BE REJECTED WITH HTTP 401
# =====================================================================

def test_invalid_api_key_header_rejected(unauthed_client):
    """Invalid X-API-Key returns HTTP 401."""
    resp = unauthed_client.post(
        "/api/cache/clear",
        headers={"X-API-Key": "wrong-and-invalid-admin-secret-key"}
    )
    assert resp.status_code == 401
    assert "Invalid authentication credentials" in resp.json().get("detail", "")


def test_invalid_bearer_token_rejected(unauthed_client):
    """Invalid Authorization: Bearer token returns HTTP 401."""
    resp = unauthed_client.post(
        "/api/cache/clear",
        headers={"Authorization": "Bearer totally-bogus-token-xyz"}
    )
    assert resp.status_code == 401
    assert "Invalid authentication credentials" in resp.json().get("detail", "")


def test_forged_session_cookie_rejected():
    """Forged or non-existent session cookie returns HTTP 401."""
    client = TestClient(main_app)
    client.cookies.set(SESSION_COOKIE_NAME, "forged-session-token-9999")
    resp = client.post("/api/cache/clear")
    assert resp.status_code == 401
    assert "Invalid or expired session" in resp.json().get("detail", "")


# =====================================================================
# 3. AUTHORIZED ACCESS VIA HEADER
# =====================================================================

def test_authorized_access_via_x_api_key(authed_client):
    """Requests with valid X-API-Key succeed."""
    resp = authed_client.post("/api/cache/clear")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"

    cfg_resp = authed_client.post("/api/config", json={"llm_provider": "nebius"})
    assert cfg_resp.status_code == 200


def test_authorized_access_via_bearer_token(bearer_client):
    """Requests with valid Bearer secret succeed."""
    resp = bearer_client.post("/api/cache/clear")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


def test_authorized_alternate_unprefixed_routes(authed_client):
    """Authorized requests succeed across un-prefixed routes as well."""
    resp = authed_client.post("/cache/clear")
    assert resp.status_code == 200


# =====================================================================
# 4. FRONTEND LOGIN & SESSION COOKIE LIFECYCLE
# =====================================================================

def test_login_flow_with_invalid_key_fails(unauthed_client):
    """POST /api/auth/login with invalid key returns HTTP 401."""
    resp = unauthed_client.post("/api/auth/login", json={"api_key": "wrong-key"})
    assert resp.status_code == 401
    assert SESSION_COOKIE_NAME not in resp.cookies


def test_login_flow_with_valid_key_issues_cookie_and_authenticates(unauthed_client):
    """
    POST /api/auth/login with valid key:
    - Returns 200 with authenticated=True and csrf_token
    - Sets HttpOnly session cookie and paired CSRF cookie
    - Allows subsequent privileged requests via cookie when double-submit CSRF token is provided
    """
    login_resp = unauthed_client.post("/api/auth/login", json={"api_key": TEST_SECRET_KEY})
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["authenticated"] is True
    assert data["auth_type"] == "session"
    assert "csrf_token" in data
    csrf_token = data["csrf_token"]

    session_cookie = login_resp.cookies.get(SESSION_COOKIE_NAME)
    assert session_cookie is not None
    assert len(session_cookie) > 20

    # Test that subsequent request succeeds using the issued session cookie and CSRF token header
    session_client = TestClient(main_app)
    session_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    clear_resp = session_client.post("/api/cache/clear", headers={"X-CSRF-Token": csrf_token})
    assert clear_resp.status_code == 200
    assert clear_resp.json()["status"] == "success"

    # Test GET /api/auth/status verifies the active session
    status_resp = session_client.get("/api/auth/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["authenticated"] is True
    assert status_resp.json()["auth_type"] == "session"

    # Test POST /api/auth/logout clears session
    logout_resp = session_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout_resp.status_code == 200
    assert logout_resp.json()["authenticated"] is False

    # After logout, the previous session token is invalid and returns 401
    client_after_logout = TestClient(main_app)
    client_after_logout.cookies.set(SESSION_COOKIE_NAME, session_cookie)
    expired_resp = client_after_logout.post("/api/cache/clear", headers={"X-CSRF-Token": csrf_token})
    assert expired_resp.status_code == 401


def test_auth_status_endpoint_unauthenticated(unauthed_client):
    """GET /api/auth/status returns 200 with authenticated=False for anonymous users."""
    resp = unauthed_client.get("/api/auth/status")
    assert resp.status_code == 200
    assert resp.json()["authenticated"] is False


def test_auth_status_endpoint_with_api_key(authed_client):
    """GET /api/auth/status returns 200 with authenticated=True for API key holders."""
    resp = authed_client.get("/api/auth/status")
    assert resp.status_code == 200
    assert resp.json()["authenticated"] is True
    assert resp.json()["auth_type"] == "api_key"


# =====================================================================
# 5. PUBLIC READ-ONLY ENDPOINTS MUST REMAIN ACCESSIBLE
# =====================================================================

def test_public_health_accessible_without_auth(unauthed_client):
    """GET /api/health and /health must remain public."""
    r1 = unauthed_client.get("/api/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "healthy"

    r2 = unauthed_client.get("/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "healthy"


def test_public_arena_status_accessible_without_auth(unauthed_client):
    """GET /api/status, /api/diff, and /api/target/source remain public."""
    r_status = unauthed_client.get("/api/status")
    assert r_status.status_code == 200
    assert "finops" in r_status.json()

    r_diff = unauthed_client.get("/api/diff")
    assert r_diff.status_code == 200

    r_src = unauthed_client.get("/api/target/source")
    assert r_src.status_code == 200
    assert "target_app/app.py" in r_src.json()["filename"]


def test_public_config_read_accessible_without_auth(unauthed_client):
    """GET /api/config and /config return masked config without leaking secrets."""
    r1 = unauthed_client.get("/api/config")
    assert r1.status_code == 200
    cfg = r1.json()
    assert "admin_api_key" not in cfg
    assert "nebius_api_key" not in cfg
    assert "tavily_api_key" not in cfg
    assert "provider" in cfg

    r2 = unauthed_client.get("/config")
    assert r2.status_code == 200


def test_public_cache_stats_accessible_without_auth(unauthed_client):
    """GET /api/cache/stats remains public telemetry."""
    resp = unauthed_client.get("/api/cache/stats")
    assert resp.status_code == 200
    assert "hits" in resp.json()


def test_public_repo_validation_accessible_without_auth(unauthed_client):
    """POST /api/repos/validate and /repos/validate remain public inspectors."""
    resp1 = unauthed_client.post("/api/repos/validate", json={"url": "https://github.com/octocat/Hello-World"})
    assert resp1.status_code == 200
    assert resp1.json()["valid"] is True

    resp2 = unauthed_client.post("/repos/validate", json={"url": "https://github.com/octocat/Hello-World"})
    assert resp2.status_code == 200
    assert resp2.json()["valid"] is True


def test_public_benchmarks_overview_accessible_without_auth(unauthed_client):
    """GET /api/benchmarks and single benchmark inspection remain public."""
    resp = unauthed_client.get("/api/benchmarks")
    assert resp.status_code == 200
    assert "benchmarks" in resp.json()

    single_resp = unauthed_client.get("/api/benchmarks/BENCH-01")
    assert single_resp.status_code == 200
    assert single_resp.json()["id"].lower() == "bench-01"


def test_public_frontend_routes_accessible_without_auth(unauthed_client):
    """All React SPA navigation routes remain accessible."""
    for path in ["/", "/arena", "/benchmarks", "/documentation", "/hackathon"]:
        resp = unauthed_client.get(path)
        assert resp.status_code == 200


# =====================================================================
# 6. WEBSOCKET PRIVILEGED ACTION PROTECTION
# =====================================================================

def test_websocket_unauthenticated_privileged_command_rejected():
    """Unauthenticated WebSocket client attempting start_arena receives authorization error."""
    client = TestClient(main_app)
    with client.websocket_connect("/ws") as ws:
        # Initial greeting is received
        greeting = ws.receive_json()
        assert greeting["event_type"] == "SYSTEM_CONNECT"

        # Public ping works
        ws.send_text('{"action": "ping"}')
        pong = ws.receive_json()
        assert pong["event_type"] == "PONG"

        # Privileged action start_arena is rejected
        ws.send_text('{"action": "start_arena"}')
        error = ws.receive_json()
        assert error["event_type"] == "ERROR"
        assert error["status"] == "unauthorized"

        # Privileged action reset_sandbox is rejected
        ws.send_text('{"action": "reset_sandbox"}')
        error2 = ws.receive_json()
        assert error2["event_type"] == "ERROR"
        assert error2["status"] == "unauthorized"


def test_websocket_authenticated_privileged_command_accepted():
    """Authenticated WebSocket connection via X-API-Key header can invoke privileged actions."""
    client = TestClient(main_app)
    with client.websocket_connect("/ws", headers={"X-API-Key": TEST_SECRET_KEY}) as ws:
        greeting = ws.receive_json()
        assert greeting["event_type"] == "SYSTEM_CONNECT"

        # Privileged action reset_sandbox succeeds and broadcasts SANDBOX_RESET
        ws.send_text('{"action": "reset_sandbox"}')
        reset_event = ws.receive_json()
        assert reset_event["event_type"] == "SANDBOX_RESET"
        assert reset_event["status"] == "completed"


def test_websocket_authenticated_via_session_cookie():
    """WebSocket connection with valid session cookie can invoke privileged actions."""
    session_token, _ = create_session()
    client = TestClient(main_app, cookies={SESSION_COOKIE_NAME: session_token})
    with client.websocket_connect("/ws") as ws:
        greeting = ws.receive_json()
        assert greeting["event_type"] == "SYSTEM_CONNECT"

        ws.send_text('{"action": "reset_sandbox"}')
        reset_event = ws.receive_json()
        assert reset_event["event_type"] == "SANDBOX_RESET"
        assert reset_event["status"] == "completed"


def test_websocket_query_string_api_key_rejected():
    """Credentials in query strings (?api_key=...) are strictly rejected to avoid URL logging."""
    client = TestClient(main_app)
    with client.websocket_connect(f"/ws?api_key={TEST_SECRET_KEY}") as ws:
        greeting = ws.receive_json()
        assert greeting["event_type"] == "SYSTEM_CONNECT"

        # Privileged action fails because query string credentials are ignored
        ws.send_text('{"action": "reset_sandbox"}')
        resp = ws.receive_json()
        assert resp["event_type"] == "ERROR"
        assert resp["status"] == "unauthorized"


# =====================================================================
# 7. CSRF PROTECTION & COOKIE SECURITY ATTRIBUTES
# =====================================================================

def test_cookie_authenticated_mutation_requires_csrf_token(unauthed_client):
    """Mutating state via session cookie without X-CSRF-Token must return HTTP 403 Forbidden."""
    login_resp = unauthed_client.post("/api/auth/login", json={"api_key": TEST_SECRET_KEY})
    assert login_resp.status_code == 200
    session_cookie = login_resp.cookies.get(SESSION_COOKIE_NAME)

    session_client = TestClient(main_app)
    session_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    # Missing X-CSRF-Token header
    resp = session_client.post("/api/cache/clear")
    assert resp.status_code == 403
    assert "CSRF validation failed" in resp.json().get("detail", "")


def test_cookie_authenticated_mutation_rejects_mismatched_csrf_token(unauthed_client):
    """Mutating state via session cookie with incorrect X-CSRF-Token must return HTTP 403 Forbidden."""
    login_resp = unauthed_client.post("/api/auth/login", json={"api_key": TEST_SECRET_KEY})
    assert login_resp.status_code == 200
    session_cookie = login_resp.cookies.get(SESSION_COOKIE_NAME)

    session_client = TestClient(main_app)
    session_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    # Forged / mismatched X-CSRF-Token header
    resp = session_client.post("/api/cache/clear", headers={"X-CSRF-Token": "attacker-forged-csrf-token"})
    assert resp.status_code == 403
    assert "CSRF" in resp.json().get("detail", "")


def test_cookie_authenticated_mutation_rejects_untrusted_origin(unauthed_client):
    """Mutating state with session cookie and valid CSRF token but untrusted Origin returns HTTP 403."""
    login_resp = unauthed_client.post("/api/auth/login", json={"api_key": TEST_SECRET_KEY})
    assert login_resp.status_code == 200
    session_cookie = login_resp.cookies.get(SESSION_COOKIE_NAME)
    csrf_token = login_resp.json()["csrf_token"]

    session_client = TestClient(main_app)
    session_client.cookies.set(SESSION_COOKIE_NAME, session_cookie)

    # Origin from external untrusted host
    resp = session_client.post(
        "/api/cache/clear",
        headers={
            "X-CSRF-Token": csrf_token,
            "Origin": "https://malicious-cross-origin.example.com",
        },
    )
    assert resp.status_code == 403
    assert "Origin validation failed" in resp.json().get("detail", "")


def test_cookie_security_attributes(unauthed_client):
    """Login must set HttpOnly session cookie and non-HttpOnly CSRF cookie with SameSite=lax."""
    login_resp = unauthed_client.post("/api/auth/login", json={"api_key": TEST_SECRET_KEY})
    assert login_resp.status_code == 200

    set_cookie_headers = login_resp.headers.get_list("set-cookie") if hasattr(login_resp.headers, "get_list") else [login_resp.headers.get("set-cookie", "")]
    raw_cookies = "; ".join(set_cookie_headers)

    assert SESSION_COOKIE_NAME in raw_cookies
    assert CSRF_COOKIE_NAME in raw_cookies
    assert "samesite=lax" in raw_cookies.lower()
    assert "httponly" in raw_cookies.lower()


# =====================================================================
# 8. PUBLIC ENDPOINTS HARDENING (SOURCE RETRIEVAL, SSRF, RATE LIMITING)
# =====================================================================

def test_source_retrieval_blocks_hidden_and_sensitive_files(authed_client, unauthed_client):
    """Source code retrieval must reject path traversal, hidden files, and project secrets."""
    # Create or retrieve a run ID
    run_resp = authed_client.post("/api/runs", json={
        "target_path": "target_app/app.py",
        "async_mode": True,
    })
    assert run_resp.status_code in (200, 201)
    run_id = run_resp.json()["run_id"]

    # 1. Reject path traversal
    r_traversal = unauthed_client.get(f"/api/runs/{run_id}/source?file_path=../../main.py")
    assert r_traversal.status_code in (400, 403)

    # 2. Reject hidden dotfiles
    r_env = unauthed_client.get(f"/api/runs/{run_id}/source?file_path=.env")
    assert r_env.status_code in (400, 403)

    r_admin_key = unauthed_client.get(f"/api/runs/{run_id}/source?file_path=.zd_admin_key")
    assert r_admin_key.status_code in (400, 403)

    # 3. Reject sensitive app configs outside the run target
    r_cfg = unauthed_client.get(f"/api/runs/{run_id}/source?file_path=app/config.py")
    assert r_cfg.status_code in (400, 403, 404)

    # 4. Comparison endpoint also blocks sensitive files
    r_comp = unauthed_client.get(f"/api/runs/{run_id}/comparison?file_path=.env")
    assert r_comp.status_code in (400, 403)


def test_repo_validation_ssrf_and_argument_injection_defense(unauthed_client):
    """Repo validation must reject internal cloud metadata endpoints and argument injection."""
    # 1. Non-GitHub / SSRF target
    r_ssrf = unauthed_client.post("/api/repos/validate", json={"url": "http://169.254.169.254/latest/meta-data"})
    assert r_ssrf.status_code in (200, 400)
    if r_ssrf.status_code == 200:
        assert r_ssrf.json()["valid"] is False

    # 2. Argument injection attempt via repo name
    r_inj = unauthed_client.post("/api/repos/validate", json={"url": "https://github.com/--upload-pack=sleep/repo"})
    assert r_inj.status_code in (200, 400)
    if r_inj.status_code == 200:
        assert r_inj.json()["valid"] is False


def test_repo_validation_rate_limiting(unauthed_client):
    """Excessive validation requests trigger HTTP 429 Too Many Requests."""
    from unittest.mock import MagicMock, patch
    mock_res = MagicMock(returncode=0, stdout="a1b2c3d4e5f6\tHEAD\n")
    with patch("subprocess.run", return_value=mock_res), patch("urllib.request.urlopen"):
        throttled = False
        for _ in range(35):
            resp = unauthed_client.post("/api/repos/validate", json={"url": "https://github.com/octocat/Hello-World"})
            if resp.status_code == 429:
                throttled = True
                assert "rate limit" in resp.json().get("detail", "").lower()
                break
        assert throttled, "Rate limiter did not throttle excessive repository validation requests."


# =====================================================================
# 9. EPHEMERAL ADMIN KEY GENERATION & FAIL-SAFE
# =====================================================================

def test_ephemeral_admin_key_initialization_and_failsafe(tmp_path, monkeypatch):
    """When no admin key env var exists, resolve_admin_key initializes .zd_admin_key with 0o600 permissions."""
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    monkeypatch.delenv("ZERODAY_API_KEY", raising=False)

    key_file = tmp_path / ".zd_admin_key"
    assert not key_file.exists()

    generated_key = resolve_admin_key(tmp_path)
    assert len(generated_key) >= 32
    assert key_file.exists()

    # Re-reading uses the persisted key
    read_key = resolve_admin_key(tmp_path)
    assert read_key == generated_key

    # Fail safely if directory cannot be written
    from unittest.mock import patch
    with patch("builtins.open", side_effect=OSError("Read-only filesystem")):
        with pytest.raises(ConfigurationError):
            resolve_admin_key(tmp_path / "nonexistent_sub")


# =====================================================================
# 10. FRONTEND CATCH-ALL PATH TRAVERSAL PREVENTED
# =====================================================================

def test_frontend_catch_all_path_traversal_prevention(unauthed_client):
    """Catch-all static server rejects directory traversal and dotfile requests."""
    for bad_path in ["/../main.py", "/.env", "/.zd_admin_key", "/api/../.env"]:
        resp = unauthed_client.get(bad_path)
        assert resp.status_code == 404

