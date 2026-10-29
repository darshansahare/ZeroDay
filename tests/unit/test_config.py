"""
Unit tests for app.config.AppConfig.
Verifies path validation, secret masking, and environment constraints.
"""

import os
from pathlib import Path
import pytest

from app.config import AppConfig
from app.core.errors import ConfigurationError, SecurityViolationError


def test_config_defaults(tmp_path):
    """Verify default configuration loads with a valid workspace directory."""
    config = AppConfig(workspace_root=tmp_path)
    assert config.workspace_root == tmp_path.resolve()
    assert config.max_repair_attempts == 3
    assert config.execution_timeout_seconds == 30
    assert config.nebius_base_url == "https://api.tokenfactory.nebius.com/v1/"
    assert config.nebius_model == "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"


def test_config_invalid_workspace_root():
    """Verify non-existent workspace root raises ConfigurationError."""
    fake_path = Path("D:/non_existent_path_xyz_12345")
    with pytest.raises(ConfigurationError) as exc_info:
        AppConfig(workspace_root=fake_path)
    assert "workspace_root does not exist" in str(exc_info.value)


def test_config_invalid_repair_attempts(tmp_path):
    """Verify boundary checking on max_repair_attempts."""
    with pytest.raises(ConfigurationError):
        AppConfig(workspace_root=tmp_path, max_repair_attempts=0)

    with pytest.raises(ConfigurationError):
        AppConfig(workspace_root=tmp_path, max_repair_attempts=11)


def test_secret_masking(tmp_path):
    """Verify to_safe_dict never exposes plaintext secrets."""
    os.environ["NEBIUS_API_KEY"] = "super-secret-nebius-token-999"
    try:
        config = AppConfig(workspace_root=tmp_path)
        safe_dict = config.to_safe_dict()
        assert "super-secret-nebius-token-999" not in str(safe_dict)
        assert safe_dict["nebius_configured"] is True
    finally:
        os.environ.pop("NEBIUS_API_KEY", None)


def test_validate_path_within_workspace_success(tmp_path):
    """Verify valid subpaths within workspace are permitted."""
    config = AppConfig(workspace_root=tmp_path)
    sub_dir = tmp_path / "sub" / "file.py"
    resolved = config.validate_path_within_workspace(sub_dir)
    assert resolved == sub_dir.resolve()


def test_validate_path_traversal_rejected(tmp_path):
    """Verify directory traversal raises SecurityViolationError."""
    config = AppConfig(workspace_root=tmp_path)
    traversal_path = tmp_path / ".." / "other_folder"
    with pytest.raises(SecurityViolationError) as exc_info:
        config.validate_path_within_workspace(traversal_path)
    assert "Path traversal detected" in str(exc_info.value)
