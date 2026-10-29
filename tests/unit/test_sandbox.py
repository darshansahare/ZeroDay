"""
Unit Tests for Target Sandbox Subsystem.
Verifies sandbox lifecycle, isolated database creation, and cleanup.
"""

import os
import pytest
from app.sandbox.target_manager import TargetSandbox, SandboxResponse
from app.core.errors import SandboxError


def test_sandbox_lifecycle_and_cleanup():
    """Verify that TargetSandbox initializes a temp DB and cleans it up completely on exit."""
    sandbox = TargetSandbox()
    assert sandbox._is_active is False
    assert sandbox.temp_dir is None

    with sandbox:
        assert sandbox._is_active is True
        assert sandbox.temp_dir is not None
        assert os.path.exists(sandbox.temp_dir)
        assert sandbox.db_path is not None
        assert os.path.exists(sandbox.db_path)

        # Execute legitimate request
        resp = sandbox.execute_request("GET", "/api/health")
        assert resp.status_code == 200
        assert resp.json_data is not None
        assert resp.json_data["status"] == "healthy"

    # Verify complete cleanup
    assert sandbox._is_active is False
    assert sandbox.temp_dir is None
    assert sandbox.db_path is None


def test_sandbox_isolated_state_per_instance():
    """Verify each sandbox instance has an independent isolated database."""
    with TargetSandbox() as sb1:
        with TargetSandbox() as sb2:
            assert sb1.db_path != sb2.db_path
            assert sb1.temp_dir != sb2.temp_dir
            assert os.path.exists(sb1.db_path)
            assert os.path.exists(sb2.db_path)


def test_sandbox_payload_truncation():
    """Verify that oversized responses are truncated according to max_response_bytes."""
    with TargetSandbox(max_response_bytes=20) as sandbox:
        resp = sandbox.execute_request("GET", "/api/products")
        assert resp.status_code == 200
        assert len(resp.text) <= 20


def test_sandbox_inactive_error():
    """Verify that executing a request on an inactive sandbox raises SandboxError."""
    sandbox = TargetSandbox()
    with pytest.raises(SandboxError, match="Sandbox is not active"):
        sandbox.execute_request("GET", "/api/health")
