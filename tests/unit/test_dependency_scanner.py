"""
Unit tests for app.analysis.dependency_scanner.DependencyScanner.
Verifies manifest parsing, version range comparison, and advisory correlation.
"""

from pathlib import Path
import pytest

from app.config import AppConfig
from app.analysis.dependency_scanner import DependencyScanner
from app.analysis.findings import Severity


@pytest.fixture
def scanner():
    root = Path(__file__).parent.parent.parent.resolve()
    config = AppConfig(workspace_root=root)
    return DependencyScanner(config=config)


def test_pinned_vulnerable_version_confirmed(scanner, tmp_path):
    """Verify pinned vulnerable package correlates with CONFIRMED_MATCH confidence."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sqlparse==0.4.4\nrequests==2.31.0\n", encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = DependencyScanner(config=custom_config)

    findings = custom_scanner.scan_manifest(manifest)
    assert len(findings) == 1
    f = findings[0]
    assert f.package_name == "sqlparse"
    assert f.matched_advisory_id == "CVE-2024-4340"
    assert f.confidence == "CONFIRMED_MATCH"
    assert f.is_pinned is True
    assert f.advisory_severity == Severity.HIGH


def test_unpinned_version_uncertain(scanner, tmp_path):
    """Verify range/unpinned specifier correlates with UNCERTAIN confidence."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sqlparse>=0.4.0\n", encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = DependencyScanner(config=custom_config)

    findings = custom_scanner.scan_manifest(manifest)
    assert len(findings) == 1
    f = findings[0]
    assert f.package_name == "sqlparse"
    assert f.confidence == "UNCERTAIN"
    assert f.is_pinned is False


def test_safe_version_no_findings(scanner, tmp_path):
    """Verify patched/safe version yields zero findings."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sqlparse==0.5.0\n", encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = DependencyScanner(config=custom_config)

    findings = custom_scanner.scan_manifest(manifest)
    assert len(findings) == 0


def test_malformed_and_comment_lines(scanner, tmp_path):
    """Verify scanner handles comments, empty lines, and pip flags without error."""
    manifest_content = """
# Primary production dependencies
-r base.txt
--extra-index-url https://example.com/pypi

jinja2==3.1.2 # Known XSS vulnerable version
   
invalid line with no operators
"""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(manifest_content, encoding="utf-8")

    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = DependencyScanner(config=custom_config)

    findings = custom_scanner.scan_manifest(manifest)
    assert len(findings) == 1
    assert findings[0].package_name == "jinja2"
    assert findings[0].matched_advisory_id == "CVE-2024-22195"
    assert findings[0].confidence == "CONFIRMED_MATCH"


def test_missing_manifest_returns_empty(scanner, tmp_path):
    """Verify scanning non-existent manifest returns empty list."""
    custom_config = AppConfig(workspace_root=tmp_path)
    custom_scanner = DependencyScanner(config=custom_config)
    findings = custom_scanner.scan_manifest(tmp_path / "does_not_exist.txt")
    assert findings == []
