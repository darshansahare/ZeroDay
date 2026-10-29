"""
Security tests for path traversal prevention across analysis components.
Ensures that scanners and target managers can never access files outside workspace_root.
"""

from pathlib import Path
import pytest

from app.config import AppConfig
from app.analysis.ast_scanner import ASTReconScanner
from app.analysis.dependency_scanner import DependencyScanner
from app.core.errors import SecurityViolationError


def test_ast_scanner_blocks_path_traversal(tmp_path):
    """Verify AST scanner blocks relative traversal outside workspace root."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    secret_file = secret_dir / "secret.py"
    secret_file.write_text("password = '123'\n", encoding="utf-8")

    config = AppConfig(workspace_root=workspace)
    scanner = ASTReconScanner(config=config)

    # Attempt relative traversal: ../secret/secret.py
    with pytest.raises(SecurityViolationError) as exc_info:
        scanner.scan_path(workspace / ".." / "secret" / "secret.py")
    assert "Path traversal detected" in str(exc_info.value)


def test_ast_scanner_blocks_absolute_external_path(tmp_path):
    """Verify AST scanner blocks absolute paths pointing outside workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external_file = tmp_path / "external.py"
    external_file.write_text("x = 1\n", encoding="utf-8")

    config = AppConfig(workspace_root=workspace)
    scanner = ASTReconScanner(config=config)

    with pytest.raises(SecurityViolationError) as exc_info:
        scanner.scan_path(external_file)
    assert "Path traversal detected" in str(exc_info.value)


def test_dependency_scanner_blocks_path_traversal(tmp_path):
    """Verify dependency scanner blocks traversal to external manifests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external_manifest = tmp_path / "requirements.txt"
    external_manifest.write_text("sqlparse==0.4.4\n", encoding="utf-8")

    config = AppConfig(workspace_root=workspace)
    scanner = DependencyScanner(config=config)

    with pytest.raises(SecurityViolationError) as exc_info:
        scanner.scan_manifest(workspace / ".." / "requirements.txt")
    assert "Path traversal detected" in str(exc_info.value)
