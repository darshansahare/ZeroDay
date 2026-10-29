"""
Authentication and Authorization Module for ZeroDay Arena.
Provides secure constant-time API key validation, HttpOnly session cookie lifecycle,
Double-Submit CSRF protection, and FastAPI dependencies for protecting privileged operations.
"""

from __future__ import annotations

import hmac
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request, Response, WebSocket, status
from pydantic import BaseModel

from app.config import AppConfig, get_config

SESSION_COOKIE_NAME = "zd_session"
CSRF_COOKIE_NAME = "zd_csrf"
SESSION_LIFETIME = timedelta(hours=24)


class SessionEntry:
    """In-memory representation of an authenticated administrative session."""
    __slots__ = ("token", "csrf_token", "expires_at")

    def __init__(self, token: str, csrf_token: str, expires_at: datetime):
        self.token = token
        self.csrf_token = csrf_token
        self.expires_at = expires_at


# Thread-safe in-memory session registry for single-user administrative sessions
_sessions_lock = threading.Lock()
_active_sessions: Dict[str, SessionEntry] = {}


def create_session() -> Tuple[str, str]:
    """
    Create a new secure random session token and paired CSRF token with a 24-hour expiration.
    Returns:
        (session_token, csrf_token)
    """
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + SESSION_LIFETIME
    entry = SessionEntry(token=session_token, csrf_token=csrf_token, expires_at=expires_at)

    with _sessions_lock:
        now = datetime.now(timezone.utc)
        expired = [t for t, s in _active_sessions.items() if s.expires_at < now]
        for t in expired:
            _active_sessions.pop(t, None)
        _active_sessions[session_token] = entry

    return session_token, csrf_token


def get_session(token: Optional[str]) -> Optional[SessionEntry]:
    """Retrieve session entry if valid and not expired."""
    if not token or not isinstance(token, str):
        return None
    with _sessions_lock:
        entry = _active_sessions.get(token)
        if not entry:
            return None
        if entry.expires_at < datetime.now(timezone.utc):
            _active_sessions.pop(token, None)
            return None
        return entry


def validate_session(token: Optional[str]) -> bool:
    """Validate whether an in-memory session token is active and not expired."""
    return get_session(token) is not None


def invalidate_session(token: Optional[str]) -> None:
    """Revoke an active session token."""
    if token:
        with _sessions_lock:
            _active_sessions.pop(token, None)


def verify_admin_key(candidate: Optional[str], config: Optional[AppConfig] = None) -> bool:
    """
    Secure constant-time comparison of a user-supplied key against the configured server secret.
    Guarantees timing-attack resistance using hmac.compare_digest.
    """
    if not candidate or not isinstance(candidate, str):
        return False

    app_cfg = config or get_config()
    if not app_cfg.admin_api_key:
        return False

    expected_secret = app_cfg.admin_api_key.get_secret_value()
    if not expected_secret:
        return False

    return hmac.compare_digest(candidate.strip(), expected_secret.strip())


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    """Safely extract token from Authorization: Bearer <token> header."""
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.strip().split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def is_request_https(request: Request) -> bool:
    """
    Determine whether request arrived via HTTPS.
    Supports direct TLS, reverse-proxy headers (X-Forwarded-Proto), and explicit configuration.
    Localhost HTTP development exception: defaults to False for localhost without TLS.
    """
    if request.url.scheme == "https":
        return True
    if request.headers.get("x-forwarded-proto", "").lower() == "https":
        return True
    if os.getenv("SECURE_COOKIES", "false").lower() in ("true", "1", "yes"):
        return True
    return False


def verify_origin(request: Request) -> bool:
    """
    Validate that request Origin or Referer matches request Host or recognized localhost origins.
    Protects against Cross-Site Request Forgery (CSRF).
    """
    origin = request.headers.get("origin")
    if not origin:
        origin = request.headers.get("referer")
    if not origin:
        # Same-origin requests where browser omits Origin on same-origin non-cross requests
        return True

    host = request.headers.get("host")
    parsed = urlparse(origin)
    origin_netloc = parsed.netloc or parsed.path.split("/")[0]

    if host and origin_netloc.lower() == host.lower():
        return True

    allowed_dev = {"localhost", "127.0.0.1", "localhost:5173", "127.0.0.1:5173", "localhost:8000", "127.0.0.1:8000"}
    if origin_netloc.lower() in allowed_dev:
        return True

    return False


async def require_admin_auth(request: Request) -> Dict[str, str]:
    """
    FastAPI dependency enforcing authentication and CSRF protection for privileged endpoints.
    Accepts:
    1. X-API-Key header with valid server secret (programmatic API access)
    2. Authorization: Bearer <secret> with valid server secret
    3. zd_session HttpOnly cookie with valid active session (browser SPA access)
       - For state-changing methods (POST, PUT, DELETE, PATCH), strictly enforces Origin
         validation and X-CSRF-Token header matching the session CSRF token.

    Raises:
    - HTTP 401 if credentials are missing or invalid
    - HTTP 403 if CSRF validation fails on cookie-authenticated requests
    """
    # 1. Check X-API-Key header (programmatic / CLI / automated tests)
    api_key = request.headers.get("x-api-key")
    if api_key:
        if verify_admin_key(api_key):
            return {"auth_type": "api_key"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Check Authorization: Bearer <key> header
    auth_header = request.headers.get("authorization")
    bearer_token = extract_bearer_token(auth_header)
    if bearer_token:
        # Check if bearer matches admin API key
        if verify_admin_key(bearer_token):
            return {"auth_type": "api_key"}
        # Check if bearer is a session token
        session = get_session(bearer_token)
        if session:
            # If using session token via Bearer, verify origin on mutating requests
            if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                if not verify_origin(request):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Cross-origin request rejected: Origin validation failed.",
                    )
            return {"auth_type": "session"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Check HttpOnly session cookie
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if session_cookie:
        session = get_session(session_cookie)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session. Please re-authenticate.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # CSRF Protection on cookie-authenticated state-changing operations
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # 3a. Origin / Referer check
            if not verify_origin(request):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-origin request rejected: Origin validation failed.",
                )

            # 3b. Anti-CSRF Token check (Double-Submit / Session CSRF Token)
            csrf_header = request.headers.get("x-csrf-token")
            if not csrf_header or not hmac.compare_digest(csrf_header.strip(), session.csrf_token.strip()):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF validation failed: missing or invalid X-CSRF-Token header.",
                )

        return {"auth_type": "session"}

    # Missing credentials entirely
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide valid API key via X-API-Key header or login session.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def is_authenticated_admin(request: Request) -> bool:
    """
    Check whether the request carries valid administrative credentials (API key or active session cookie),
    without raising an HTTPException. Returns True if authenticated as administrator, False otherwise.
    """
    try:
        # 1. Check X-API-Key header
        api_key = request.headers.get("x-api-key")
        if api_key and verify_admin_key(api_key):
            return True

        # 2. Check Authorization: Bearer header
        auth_header = request.headers.get("authorization")
        bearer_token = extract_bearer_token(auth_header)
        if bearer_token:
            if verify_admin_key(bearer_token) or validate_session(bearer_token):
                return True

        # 3. Check HttpOnly session cookie
        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if session_cookie and validate_session(session_cookie):
            return True

        return False
    except Exception:
        return False


def verify_websocket_auth(websocket: WebSocket) -> bool:
    """
    Verify credentials on WebSocket connections for privileged actions.
    Supported mechanisms:
    1. zd_session HttpOnly cookie
    2. X-API-Key header
    3. Authorization: Bearer <key/token> header

    Security Note: Query string API keys (?api_key=...) are intentionally disabled
    because URLs are logged in access logs, proxy logs, and browser history.
    """
    # 1. Check authenticated session cookie
    session_cookie = websocket.cookies.get(SESSION_COOKIE_NAME)
    if validate_session(session_cookie):
        return True

    # 2. Check X-API-Key header
    api_key = websocket.headers.get("x-api-key")
    if api_key and verify_admin_key(api_key):
        return True

    # 3. Check Authorization: Bearer header
    auth_header = websocket.headers.get("authorization")
    bearer_token = extract_bearer_token(auth_header)
    if bearer_token and (verify_admin_key(bearer_token) or validate_session(bearer_token)):
        return True

    return False


# Auth Request / Response Schemas
class LoginRequest(BaseModel):
    api_key: str


class AuthStatusResponse(BaseModel):
    authenticated: bool
    auth_type: Optional[str] = None
    csrf_token: Optional[str] = None
    message: str = ""
