"""
Targeted Adversarial Regression Tests for Sandbox Isolation and Host Safety (Issue 7).
Audits credential scrubbing, working directory isolation, cleanup reliability,
SSRF containment, path traversal defense, and bounded resource limits.
"""

import os
import sys
import tempfile
import pytest
from app.sandbox.target_manager import (
    TargetSandbox,
    is_sensitive_env_variable,
    STRIP_ENV_VARS,
)
from app.verification.workspace_manager import IsolatedWorkspace
from app.verification.patch_integrity import PatchValidator
from app.core.errors import SandboxError, ExecutionTimeoutError, PatchIntegrityError


def test_sandbox_environment_scrubbing():
    """Verify that sensitive cloud credentials, tokens, and database passwords are identified and scrubbed."""
    secrets = [
        "NEBIUS_API_KEY",
        "TAVILY_API_KEY",
        "ADMIN_API_KEY",
        "ZERODAY_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "CUSTOM_APP_SECRET",
        "JWT_SECRET",
        "SESSION_TOKEN",
        "PGPASSWORD",
        "MYSQL_PWD",
        "DB_PASSWD",
        "CLIENT_CREDENTIALS",
        "PRIVATE_KEY_PEM",
        "SENTRY_DSN",
        "AUTHORIZATION_BEARER",
    ]
    for s in secrets:
        assert is_sensitive_env_variable(s) is True, f"Expected {s} to be classified as sensitive"

    # Verify essential system runtime variables are NOT scrubbed
    system_vars = ["PATH", "PATHEXT", "PYTHONPATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]
    for v in system_vars:
        assert is_sensitive_env_variable(v) is False, f"Expected system var {v} to be preserved"


def test_sandbox_subprocess_runs_with_isolated_cwd():
    """Verify that TargetSandbox launches child subprocess inside disposable temp directory."""
    with TargetSandbox() as sandbox:
        assert sandbox._is_active is True
        assert sandbox.temp_dir is not None
        assert os.path.exists(sandbox.temp_dir)
        # Ensure database is housed in the disposable directory
        assert sandbox.db_path.startswith(sandbox.temp_dir)


def test_sandbox_rejects_ssrf_and_absolute_urls():
    """Verify that execute_request rejects absolute URLs, preventing SSRF against unrelated services."""
    with TargetSandbox() as sandbox:
        with pytest.raises(SandboxError, match="must be relative"):
            sandbox.execute_request("GET", "http://169.254.169.254/latest/meta-data")

        with pytest.raises(SandboxError, match="must be relative"):
            sandbox.execute_request("GET", "https://example.com/api")

        with pytest.raises(SandboxError, match="must be relative"):
            sandbox.execute_request("GET", "//127.0.0.1:8000/api/config")


def test_sandbox_cleanup_on_unhandled_exception():
    """Verify that an exception inside TargetSandbox context manager reliably terminates process and cleans temp directory."""
    temp_dir_path = None
    try:
        with TargetSandbox() as sandbox:
            temp_dir_path = sandbox.temp_dir
            assert os.path.exists(temp_dir_path)
            raise RuntimeError("Simulated unhandled evaluation failure")
    except RuntimeError:
        pass

    assert temp_dir_path is not None
    assert not os.path.exists(temp_dir_path), "Sandbox temp_dir was not cleaned up after exception"


def test_isolated_workspace_blocks_path_traversal_escape():
    """Verify that IsolatedWorkspace.apply_patch rejects paths attempting to write outside temp_dir."""
    with tempfile.TemporaryDirectory() as src_root:
        dummy_file = os.path.join(src_root, "app.py")
        with open(dummy_file, "w", encoding="utf-8") as f:
            f.write("print('hello')\n")

        valid_patch = """--- a/app.py
+++ b/app.py
@@ -1,1 +1,1 @@
-print('hello')
+print('world')
"""

        with IsolatedWorkspace(workspace_root=src_root) as ws:
            with pytest.raises(PatchIntegrityError, match="escapes isolated workspace"):
                ws.apply_patch(valid_patch, "../../escaped.py")


def test_patch_validator_blocks_windows_drive_letters():
    """Verify that PatchValidator rejects patches targeting absolute Windows drive letters."""
    drive_patch = """--- a/C:/Windows/System32/calc.exe
+++ b/C:/Windows/System32/calc.exe
@@ -1,1 +1,1 @@
-old
+new
"""
    validator = PatchValidator()
    result = validator.validate_patch(drive_patch)
    assert result.is_valid is False
    assert "Path traversal detected" in result.rejection_reason


def test_patch_validator_blocks_env_and_config_files():
    """Verify that PatchValidator rejects patches modifying .env or configuration files."""
    env_patch = """--- a/.env
+++ b/.env
@@ -1,1 +1,1 @@
-KEY=old
+KEY=new
"""
    validator = PatchValidator()
    result = validator.validate_patch(env_patch)
    assert result.is_valid is False
    assert "Tampering detected" in result.rejection_reason


def test_sandbox_response_size_bounding():
    """Verify that responses exceeding max_response_bytes are strictly truncated."""
    with TargetSandbox(max_response_bytes=30) as sandbox:
        resp = sandbox.execute_request("GET", "/api/products")
        assert resp.status_code == 200
        assert len(resp.text) <= 30
