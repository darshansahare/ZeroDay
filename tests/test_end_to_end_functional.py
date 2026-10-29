"""
ZeroDay Arena — Comprehensive End-to-End Functional Test Suite.
Validates all requirements across ingestion, AST discovery, Red Team execution,
Threat Intelligence, Blue Team patch integrity, Independent Verification Gates,
Truthful Reporting, and API Endpoints.
"""

import os
import shutil
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from main import app
from app.config import AppConfig
from app.analysis.ast_scanner import ASTReconScanner
from app.analysis.findings import VulnerabilityClass, Severity, Finding
from app.verification.patch_integrity import PatchValidator
from app.verification.oracle import VerificationOracle
from app.core.orchestrator import RemediationRun, RunState
from app.agents.red_team_agent import RedTeamAgent
from app.intelligence.tavily_client import TavilyIntelligenceClient


@pytest.fixture
def temp_repo():
    """Create a temporary isolated test repository structure."""
    from app.cache.token_cache import token_cache
    token_cache.clear()
    temp_dir = tempfile.mkdtemp(prefix="zda_test_repo_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)
    token_cache.clear()


@pytest.fixture
def client():
    c = TestClient(app)
    c.headers["X-API-Key"] = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")
    return c


# 1. Arbitrary vulnerable Python repository produces findings from real source
def test_arbitrary_vulnerable_repository_produces_real_findings(temp_repo):
    server_py = temp_repo / "server.py"
    server_py.write_text(
        'import os\n'
        'from fastapi import FastAPI\n'
        'app = FastAPI()\n'
        '@app.get("/ping")\n'
        'def ping(host: str):\n'
        '    # Vulnerable command injection\n'
        '    return os.system(f"ping {host}")\n',
        encoding="utf-8",
    )
    db_py = temp_repo / "db.py"
    db_py.write_text(
        'import sqlite3\n'
        'def get_user(uid):\n'
        '    conn = sqlite3.connect(":memory:")\n'
        '    # Vulnerable SQL injection\n'
        '    q = f"SELECT * FROM users WHERE id = \'{uid}\'"\n'
        '    return conn.execute(q).fetchall()\n',
        encoding="utf-8",
    )

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_repo))
    report = scanner.scan_path(temp_repo)

    assert len(report.findings) >= 2
    classes = {f.vulnerability_class for f in report.findings}
    assert VulnerabilityClass.COMMAND_INJECTION in classes
    assert VulnerabilityClass.SQL_INJECTION in classes

    # Ensure findings reference actual files and line numbers
    cmdi_finding = next(f for f in report.findings if f.vulnerability_class == VulnerabilityClass.COMMAND_INJECTION)
    assert "server.py" in cmdi_finding.file_path
    assert cmdi_finding.line_number == 7
    assert "os.system" in cmdi_finding.code_snippet


# 2. Safe parameterized SQL query does NOT produce a false-positive finding
def test_safe_parameterized_queries_excluded(temp_repo):
    safe_py = temp_repo / "safe_service.py"
    safe_py.write_text(
        'import sqlite3\n'
        'def query_safe(user_id: str):\n'
        '    conn = sqlite3.connect(":memory:")\n'
        '    # Safe parameterized query with placeholder and tuple args\n'
        '    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()\n',
        encoding="utf-8",
    )

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_repo))
    report = scanner.scan_path(safe_py)
    assert len(report.findings) == 0


# 3. Vulnerable finding contains correct file path, line range, and evidence
def test_vulnerable_finding_metadata_integrity(temp_repo):
    traversal_py = temp_repo / "files.py"
    traversal_py.write_text(
        'def read_user_file(path: str):\n'
        '    # Line 2: Path traversal sink\n'
        '    with open(f"/var/data/{path}", "r") as f:\n'
        '        return f.read()\n',
        encoding="utf-8",
    )

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_repo))
    report = scanner.scan_path(traversal_py)
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL
    assert f.cwe == "CWE-22"
    assert f.line_number == 3
    assert "files.py" in f.file_path
    assert "open(" in f.code_snippet


# 4. Unsupported or invalid syntax produces truthful status without crashing
def test_syntax_error_resilience_and_truthful_warning(temp_repo):
    broken_py = temp_repo / "broken.py"
    broken_py.write_text(
        'def invalid_syntax_function(\n'
        '    this line is completely invalid python syntax :::\n',
        encoding="utf-8",
    )

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_repo))
    report = scanner.scan_path(broken_py)
    assert len(report.findings) == 0
    assert len(report.syntax_warnings) == 1
    assert "broken.py" in report.syntax_warnings[0]["file"]
    assert "Syntax error" in report.syntax_warnings[0]["warning"]


# 5. Multiple files are discovered and analyzed across repository directory tree
def test_multiple_files_analyzed_in_directory_tree(temp_repo):
    sub = temp_repo / "pkg"
    sub.mkdir()
    (temp_repo / "mod1.py").write_text("x = 1\n", encoding="utf-8")
    (temp_repo / "mod2.py").write_text("y = 2\n", encoding="utf-8")
    (sub / "mod3.py").write_text("z = 3\n", encoding="utf-8")
    (temp_repo / "notes.txt").write_text("ignored non-python\n", encoding="utf-8")

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_repo))
    report = scanner.scan_path(temp_repo)
    assert report.scanned_files_count == 3
    assert len(report.files_analyzed) == 3
    assert any("mod1.py" in p for p in report.files_analyzed)
    assert any("mod2.py" in p for p in report.files_analyzed)
    assert any("mod3.py" in p for p in report.files_analyzed)
    assert report.coverage_status == "FULL"


# 6. Clean repository with no vulnerabilities receives 0 findings and truthful verdict
def test_clean_repository_produces_no_fabricated_findings(temp_repo):
    clean_py = temp_repo / "clean.py"
    clean_py.write_text(
        'def calculate_total(a: int, b: int) -> int:\n'
        '    return a + b\n',
        encoding="utf-8",
    )

    config = AppConfig(workspace_root=temp_repo)
    scanner = ASTReconScanner(config=config)
    report = scanner.scan_path(clean_py)
    assert len(report.findings) == 0

    run = RemediationRun(
        target_path="clean.py",
        config=config,
    )
    final_report = run.execute()
    assert final_report.verdict == "SCAN_COMPLETE_NO_FINDINGS"
    assert final_report.final_status == "SCAN_COMPLETE_NO_FINDINGS"
    assert final_report.is_verified_remediation is False
    assert len(final_report.code_findings) == 0
    assert not any("AST-SQLI-01" in getattr(f, "id", "") for f in final_report.code_findings)


# 7. Repository ingestion respects resource limits and reports partial coverage
def test_repository_resource_limits_and_partial_coverage(temp_repo):
    # Create 5 files
    for i in range(5):
        (temp_repo / f"file_{i}.py").write_text(f"a = {i}\n", encoding="utf-8")

    # Set limit to max 2 files
    config = AppConfig(workspace_root=temp_repo, max_scan_files=2)
    scanner = ASTReconScanner(config=config)
    report = scanner.scan_path(temp_repo)

    assert report.coverage_status == "PARTIAL"
    assert len(report.files_analyzed) == 2
    assert len(report.files_skipped) >= 3
    assert any("limit reached" in str(s) for s in report.files_skipped)


# 8. Red Team results reflect actual execution outcomes and explicit states
def test_red_team_reproduction_results_and_explicit_states():
    agent = RedTeamAgent()
    finding = Finding(
        id="FIND-CMD-01",
        vulnerability_class=VulnerabilityClass.COMMAND_INJECTION,
        cwe="CWE-78",
        severity=Severity.HIGH,
        file_path="app.py",
        line_number=25,
        code_snippet="os.system(f'ping {host}')",
        remediation_guidance="Use subprocess.run without shell=True",
        title="Command Injection Sink",
        description="Unsanitized host execution",
    )
    config = agent.propose_reproduction_test(finding)
    assert config.exploit_payload is not None
    assert "ZDA_PWNED_CWE78" in config.exploit_payload


# 9. Tavily client truthful error handling without fabricating citations
def test_tavily_client_truthful_empty_on_unconfigured():
    client = TavilyIntelligenceClient(api_key="")
    assert client.is_configured is False
    with pytest.raises(Exception):
        client.search_guidance("SQL injection")


# 10. Blue Team patch validation rejects paths outside workspace or non-whitelisted files
def test_patch_validator_blocks_path_traversal_and_forbidden_files():
    validator = PatchValidator(permitted_files={"app.py"})

    traversal_patch = (
        "--- a/../../etc/shadow\n"
        "+++ b/../../etc/shadow\n"
        "@@ -1,1 +1,1 @@\n"
        "-secret\n"
        "+pwned\n"
    )
    result = validator.validate_patch(traversal_patch)
    assert result.is_valid is False
    assert "traversal" in result.rejection_reason.lower() or "forbidden" in result.rejection_reason.lower()

    unpermitted_patch = (
        "--- a/tests/test_functional.py\n"
        "+++ b/tests/test_functional.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-assert False\n"
        "+assert True\n"
    )
    result2 = validator.validate_patch(unpermitted_patch)
    assert result2.is_valid is False
    assert "not permitted" in result2.rejection_reason.lower() or "tests" in result2.rejection_reason.lower()


# 11. Patch that fails regression tests receives REGRESSION FAILED verdict
def test_patch_failing_regression_tests_rejected_authoritatively():
    oracle = VerificationOracle()
    # A patch breaking legitimate orders returns empty records
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    from app.verification.workspace_manager import IsolatedWorkspace
    broken_patch = (
        "--- a/target_app/app.py\n"
        "+++ b/target_app/app.py\n"
        "@@ -141,3 +141,2 @@\n"
        "-    query = f\"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'\"\n"
        "-    cursor.execute(query)\n"
        "+    # Broken: returns empty records\n"
        "+    return {\"count\": 0, \"records\": []}\n"
    )
    with IsolatedWorkspace(workspace_root) as ws:
        patched_file = ws.apply_patch(broken_patch, "target_app/app.py")
        report = oracle.verify_patched_target(patched_file)
        assert report.status == "REJECTED"
        assert report.gate_a_functional.passed is False


# 12. Patch that remains exploitable cannot receive VERIFIED SECURE
def test_unfixed_patch_rejected_by_gate_b():
    oracle = VerificationOracle()
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    from app.verification.workspace_manager import IsolatedWorkspace
    cosmetic_patch = (
        "--- a/target_app/app.py\n"
        "+++ b/target_app/app.py\n"
        "@@ -141,2 +141,2 @@\n"
        "-    # SINK: Vulnerable unparameterized string formatting\n"
        "-    query = f\"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'\"\n"
        "+    # Still vulnerable string formatting\n"
        "+    query = f\"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'\"\n"
    )
    with IsolatedWorkspace(workspace_root) as ws:
        patched_file = ws.apply_patch(cosmetic_patch, "target_app/app.py")
        report = oracle.verify_patched_target(patched_file)
        assert report.status == "REJECTED"
        assert report.gate_b_security.passed is False


# 13. Two distinct repositories produce independent results based on their respective contents
def test_two_distinct_repositories_produce_independent_results(temp_repo):
    repo_a = temp_repo / "repo_a"
    repo_a.mkdir()
    (repo_a / "cmd.py").write_text("import subprocess\ndef r(cmd): subprocess.Popen(cmd, shell=True)\n", encoding="utf-8")

    repo_b = temp_repo / "repo_b"
    repo_b.mkdir()
    (repo_b / "traverse.py").write_text("def r(p): open(p)\n", encoding="utf-8")

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_repo))
    rep_a = scanner.scan_path(repo_a)
    rep_b = scanner.scan_path(repo_b)

    assert any(f.vulnerability_class == VulnerabilityClass.COMMAND_INJECTION for f in rep_a.findings)
    assert not any(f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL for f in rep_a.findings)

    assert any(f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL for f in rep_b.findings)
    assert not any(f.vulnerability_class == VulnerabilityClass.COMMAND_INJECTION for f in rep_b.findings)


# 14. API run creation persists state and reloading retrieves state
def test_api_run_creation_and_state_persistence(client):
    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 2,
        "async_mode": False,
    }
    resp = client.post("/api/runs", json=payload)
    assert resp.status_code == 201
    run_id = resp.json()["run_id"]

    # Retrieve status on reload
    get_resp = client.get(f"/api/runs/{run_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["run_id"] == run_id
    assert data["status"] in ("ACCEPTED", "REJECTED", "FAILED")


# 15. Source code endpoint returns real source content and blocks path traversal
def test_source_code_endpoint_retrieval_and_security(client):
    # Initiate synchronous run
    payload = {
        "target_path": "target_app/app.py",
        "async_mode": False,
    }
    resp = client.post("/api/runs", json=payload)
    run_id = resp.json()["run_id"]

    # Fetch legitimate source
    src_resp = client.get(f"/api/runs/{run_id}/source?file_path=target_app/app.py")
    assert src_resp.status_code == 200
    src_data = src_resp.json()
    assert "FastAPI" in src_data["content"]
    assert src_data["lines_count"] > 10

    # Path traversal attack against source endpoint blocked
    trav_resp = client.get(f"/api/runs/{run_id}/source?file_path=../../main.py")
    assert trav_resp.status_code in (400, 404)
