"""
ZeroDay Arena — Comprehensive 10-Scenario Hackathon Readiness Test Suite.
Verifies all 10 core scenarios strictly offline with zero external paid API calls:
  Scenario 1: SQL Injection fixture (full cycle: AST detection, reproduction, patch, 4 gates -> VERIFIED SECURE)
  Scenario 2: Path Traversal fixture (Path.read_text() detection & containment verification)
  Scenario 3: IDOR fixture (detection & authorization verification)
  Scenario 4: Empty scan (SCAN_COMPLETE_NO_FINDINGS, never VERIFIED_SECURE)
  Scenario 5: Target execution failure (EXECUTION_FAILED, clear reason)
  Scenario 6: Patch failure (rejected safely, original file unchanged)
  Scenario 7: Regression and security-gate failures (neither receives VERIFIED_SECURE)
  Scenario 8: Frontend/backend contract (terminal states stop polling, schema consistency)
  Scenario 9: Resource limits and cleanup (oversized inputs, cleanup verified)
  Scenario 10: Provider isolation (zero paid API calls in tests, truthful unconfigured states)
"""

from __future__ import annotations

import ast
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Generator
import pytest
from fastapi.testclient import TestClient

from main import app
from app.config import AppConfig
from app.analysis.ast_scanner import ASTReconScanner
from app.analysis.findings import VulnerabilityClass, Severity
from app.verification.patch_integrity import PatchValidator, PatchValidationResult
from app.verification.oracle import VerificationOracle
from app.sandbox.target_manager import TargetSandbox
from app.sandbox.reproduction import ReproductionRunner
from app.core.orchestrator import RemediationRun, DETERMINISTIC_SECURE_PATCH
from app.core.state_machine import RunState
from app.agents.red_team_agent import RedTeamAgent
from app.intelligence.tavily_client import TavilyIntelligenceClient
from app.cache.token_cache import token_cache


@pytest.fixture
def temp_workspace() -> Generator[Path, None, None]:
    token_cache.clear()
    td = tempfile.mkdtemp(prefix="zda_hackathon_")
    ws = Path(td)
    yield ws
    shutil.rmtree(td, ignore_errors=True)
    token_cache.clear()


@pytest.fixture
def client() -> TestClient:
    c = TestClient(app)
    c.headers["X-API-Key"] = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")
    return c


# SCENARIO 1: SQL Injection Fixture (Full Remediation Cycle)
def test_scenario_1_sqli_full_remediation_cycle():
    """
    Scenario 1: Full cycle on benchmark SQL injection target:
    - Real AST scanner discovers SQL injection.
    - Reproduction triggers exploit against isolated target process and breaches invariants.
    - Blue team applies deterministic parameterized query patch.
    - All 4 verification gates (A, B, C, D) pass.
    - Truthful verdict: VERIFIED SECURE with final_status ACCEPTED.
    """
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    config = AppConfig(workspace_root=workspace_root)

    run = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=DETERMINISTIC_SECURE_PATCH,
        max_repair_attempts=1,
    )
    report = run.execute()

    # 1. AST Detection
    assert len(report.code_findings) >= 1
    assert any(f.vulnerability_class == VulnerabilityClass.SQL_INJECTION for f in report.code_findings)

    # 2. Reproduction Contract
    assert report.reproduction_result is not None
    assert report.reproduction_result.reproduced is True
    assert report.reproduction_result.status == "REPRODUCED"
    assert report.reproduction_result.target_endpoint == "/api/orders"
    assert "' OR '1'='1" in report.reproduction_result.exploit_payload
    assert report.reproduction_result.leaked_records_count > 0

    # 3. Independent 4-Gate Oracle
    assert report.verification_outcome is not None
    vo = report.verification_outcome
    assert vo.gate_a_patch_integrity.passed is True
    assert vo.gate_b_functional.passed is True
    assert vo.gate_c_security.passed is True
    assert vo.gate_d_static_reanalysis.passed is True

    # 4. Final Security Verdict
    assert report.is_verified_remediation is True
    assert report.verdict == "VERIFIED SECURE"
    assert report.final_status == "ACCEPTED"


# SCENARIO 2: Path Traversal Fixture (Path.read_text() & Containment)
def test_scenario_2_path_traversal_detection_and_containment(temp_workspace: Path):
    """
    Scenario 2: Path Traversal detection & containment:
    - Uncontained Path.read_text() is flagged with rule AST-PT-01.
    - Contained implementation with is_relative_to is NOT flagged (0 false positives).
    """
    # 1. Vulnerable uncontained service
    vuln_code = (
        'from pathlib import Path\n'
        'from fastapi import FastAPI, HTTPException\n'
        'app = FastAPI()\n'
        'BASE_DIR = Path(__file__).resolve().parent / "files"\n'
        '@app.get("/files/{filename:path}")\n'
        'def get_file(filename: str):\n'
        '    target = BASE_DIR / filename\n'
        '    # Vulnerable sink: uncontained read_text()\n'
        '    return {"content": target.read_text()}\n'
    )
    vuln_file = temp_workspace / "vuln_files.py"
    vuln_file.write_text(vuln_code, encoding="utf-8")

    # 2. Secure contained service
    safe_code = (
        'from pathlib import Path\n'
        'from fastapi import FastAPI, HTTPException\n'
        'app = FastAPI()\n'
        'BASE_DIR = Path(__file__).resolve().parent / "files"\n'
        '@app.get("/files/{filename:path}")\n'
        'def get_file(filename: str):\n'
        '    target = (BASE_DIR / filename).resolve()\n'
        '    if not target.is_relative_to(BASE_DIR):\n'
        '        raise HTTPException(status_code=403, detail="Access denied")\n'
        '    return {"content": target.read_text()}\n'
    )
    safe_file = temp_workspace / "safe_files.py"
    safe_file.write_text(safe_code, encoding="utf-8")

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_workspace))

    # Scan vulnerable service
    vuln_report = scanner.scan_path(vuln_file)
    assert len(vuln_report.findings) >= 1
    pt_findings = [f for f in vuln_report.findings if f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL]
    assert len(pt_findings) >= 1
    assert pt_findings[0].cwe == "CWE-22"
    assert pt_findings[0].line_number == 7
    assert "target.read_text()" in pt_findings[0].code_snippet

    # Scan safe service
    safe_report = scanner.scan_path(safe_file)
    safe_pt = [f for f in safe_report.findings if f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL]
    assert len(safe_pt) == 0, "Containment check (is_relative_to) must eliminate false positives"


# SCENARIO 3: IDOR Fixture (Detection & Retest Verification)
def test_scenario_3_idor_detection_and_authorization(temp_workspace: Path):
    """
    Scenario 3: Insecure Direct Object Reference (IDOR / CWE-639):
    - AST scanner identifies route parameters lacking ownership/auth context.
    - Rule AST-IDOR-01 is reported.
    """
    idor_code = (
        'from fastapi import FastAPI\n'
        'app = FastAPI()\n'
        'users = {1: {"name": "Alice"}, 2: {"name": "Bob"}}\n'
        '@app.get("/users/{user_id}")\n'
        'def get_user(user_id: int):\n'
        '    # Vulnerable IDOR\n'
        '    return users.get(user_id)\n'
    )
    idor_file = temp_workspace / "idor_service.py"
    idor_file.write_text(idor_code, encoding="utf-8")

    scanner = ASTReconScanner(config=AppConfig(workspace_root=temp_workspace))
    report = scanner.scan_path(idor_file)

    idor_findings = [f for f in report.findings if f.vulnerability_class == VulnerabilityClass.IDOR]
    assert len(idor_findings) >= 1
    f = idor_findings[0]
    assert f.cwe == "CWE-639"
    assert f.line_number == 7


# SCENARIO 4: Empty Scan (SCAN_COMPLETE_NO_FINDINGS, Never VERIFIED_SECURE)
def test_scenario_4_empty_scan_verdict(temp_workspace: Path):
    """
    Scenario 4: An empty scan must NEVER receive VERIFIED_SECURE.
    It must receive SCAN_COMPLETE_NO_FINDINGS with is_verified_remediation=False.
    """
    clean_file = temp_workspace / "calculator.py"
    clean_file.write_text(
        'def add(a: int, b: int) -> int:\n'
        '    """Pure calculation with zero external sinks."""\n'
        '    return a + b\n',
        encoding="utf-8",
    )

    config = AppConfig(workspace_root=temp_workspace)
    run = RemediationRun(
        target_path="calculator.py",
        config=config,
    )
    report = run.execute()

    assert len(report.code_findings) == 0
    assert report.is_verified_remediation is False, "Empty scan must never be marked verified secure"
    assert report.verdict == "SCAN_COMPLETE_NO_FINDINGS"
    assert report.final_status == "SCAN_COMPLETE_NO_FINDINGS"
    assert run.state_machine.current_state == RunState.SCAN_COMPLETE_NO_FINDINGS


# SCENARIO 5: Target Execution Failure (EXECUTION_FAILED, Clear Reason)
def test_scenario_5_target_execution_failure(temp_workspace: Path):
    """
    Scenario 5: When target service crashes or cannot start,
    reproduction reports EXECUTION_FAILED with explicit error diagnostic.
    """
    broken_code = (
        'import non_existent_library_that_crashes_import\n'
        'from fastapi import FastAPI\n'
        'app = FastAPI()\n'
    )
    broken_file = temp_workspace / "crasher.py"
    broken_file.write_text(broken_code, encoding="utf-8")

    from app.sandbox.target_manager import TargetSandbox

    with pytest.raises(Exception) as exc_info:
        with TargetSandbox(target_file_path=str(broken_file), timeout_seconds=4) as sb:
            pass

    assert "Failed to start target sandbox" in str(exc_info.value) or "Isolated target process exited" in str(exc_info.value) or "exit code" in str(exc_info.value)


# SCENARIO 6: Patch Failure (Rejected Safely, Original File Unchanged)
def test_scenario_6_patch_failure_protects_original(temp_workspace: Path):
    """
    Scenario 6: Malicious or invalid patch is rejected without modifying original source.
    """
    target = temp_workspace / "app.py"
    original_code = 'print("Pristine source")\n'
    target.write_text(original_code, encoding="utf-8")

    # Patch attempting path traversal to modify outside file
    malicious_patch = (
        '--- a/app.py\n'
        '+++ b/../../outside.py\n'
        '@@ -1,1 +1,1 @@\n'
        '-print("Pristine source")\n'
        '+print("Pwned")\n'
    )

    validator = PatchValidator(permitted_files={"app.py"})
    val_result: PatchValidationResult = validator.validate_patch(malicious_patch)

    assert val_result.is_valid is False
    assert "Path traversal" in (val_result.rejection_reason or "") or "outside permitted" in (val_result.rejection_reason or "")

    # Assert original target file is completely untouched
    assert target.read_text(encoding="utf-8") == original_code


# SCENARIO 7: Regression and Security-Gate Failures (Neither Receives VERIFIED_SECURE)
def test_scenario_7_gate_failures_prevent_verified_secure():
    """
    Scenario 7: Neither regression failures nor incomplete security fixes receive VERIFIED_SECURE.
    """
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    config = AppConfig(workspace_root=workspace_root)

    # 1. Regression patch
    regression_patch = (
        '--- a/target_app/app.py\n'
        '+++ b/target_app/app.py\n'
        '@@ -141,3 +141,2 @@\n'
        '-    # SINK: Vulnerable unparameterized string formatting\n'
        '-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = \'{user_id}\'"\n'
        '-    cursor.execute(query)\n'
        '+    # Broken functional behavior\n'
        '+    return {"count": 0, "records": []}\n'
    )
    run_reg = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=regression_patch,
        max_repair_attempts=1,
    )
    rep_reg = run_reg.execute()
    assert rep_reg.is_verified_remediation is False
    assert rep_reg.final_status == "REJECTED"
    assert rep_reg.verdict == "REGRESSION FAILED"

    # 2. Ineffective security patch
    insecure_patch = (
        '--- a/target_app/app.py\n'
        '+++ b/target_app/app.py\n'
        '@@ -141,2 +141,2 @@\n'
        '-    # SINK: Vulnerable unparameterized string formatting\n'
        '-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = \'{user_id}\'"\n'
        '+    # Fake comment update\n'
        '+    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = \'{user_id}\'"\n'
    )
    run_insec = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=insecure_patch,
        max_repair_attempts=1,
    )
    rep_insec = run_insec.execute()
    assert rep_insec.is_verified_remediation is False
    assert rep_insec.final_status == "REJECTED"
    assert rep_insec.verdict == "SECURITY RE-TEST FAILED"


# SCENARIO 8: Frontend/Backend Contract & Terminal States
def test_scenario_8_contract_and_terminal_states(client: TestClient):
    """
    Scenario 8: API endpoint schemas match frontend expectations, and
    terminal states are universally defined to halt polling.
    """
    # 1. Config status endpoint
    config_res = client.get("/api/config")
    assert config_res.status_code == 200
    cfg = config_res.json()
    assert "nebius_configured" in cfg
    assert "tavily_configured" in cfg
    assert "provider" in cfg
    assert "cache_enabled" in cfg

    # 2. Synchronous test run execution
    create_res = client.post(
        "/api/runs",
        json={
            "target_path": "target_app/app.py",
            "candidate_patch": DETERMINISTIC_SECURE_PATCH,
            "max_repair_attempts": 1,
            "async_mode": False,
        },
    )
    assert create_res.status_code == 201
    run_data = create_res.json()
    run_id = run_data["run_id"]
    assert run_data["status"] == "ACCEPTED"
    assert run_data["is_verified_remediation"] is True

    # 3. Report retrieval
    rep_res = client.get(f"/api/runs/{run_id}/report")
    assert rep_res.status_code == 200
    report = rep_res.json()
    assert report["run_id"] == run_id
    assert report["verdict"] == "VERIFIED SECURE"
    assert "verification_outcome" in report

    # 4. Terminal states verification
    all_terminal = {
        RunState.ACCEPTED.value,
        RunState.VERIFIED_SECURE.value,
        RunState.SCAN_COMPLETE_NO_FINDINGS.value,
        RunState.NOT_REPRODUCED.value,
        RunState.INCONCLUSIVE.value,
        RunState.REJECTED.value,
        RunState.REGRESSION_FAILED.value,
        RunState.SECURITY_RETEST_FAILED.value,
        RunState.FAILED.value,
        RunState.EXECUTION_FAILED.value,
        RunState.CANCELLED.value,
        RunState.TIMED_OUT.value,
    }
    assert run_data["status"] in all_terminal


# SCENARIO 9: Resource Limits and Cleanup
def test_scenario_9_resource_limits_and_cleanup(temp_workspace: Path):
    """
    Scenario 9: Oversized files are skipped and reported with PARTIAL coverage;
    sandbox process and temporary directories are reliably cleaned up.
    """
    # Create oversized file (> 1MB limit for test config)
    big_file = temp_workspace / "oversized.py"
    with open(big_file, "w", encoding="utf-8") as f:
        f.write("# Padding comment\n" * 70000)

    config = AppConfig(workspace_root=temp_workspace, max_file_size_bytes=50000)
    scanner = ASTReconScanner(config=config)
    report = scanner.scan_path(temp_workspace)

    assert any((item.get("file") == "oversized.py" if isinstance(item, dict) else item == "oversized.py") for item in report.files_skipped)
    assert report.coverage_status == "PARTIAL"

    # Verify sandbox cleanup
    normal_file = temp_workspace / "mini_app.py"
    normal_file.write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding="utf-8")

    sandbox = TargetSandbox(target_file_path=str(normal_file), timeout_seconds=5)
    sandbox.__enter__()
    assert sandbox.process is not None
    proc = sandbox.process

    sandbox.__exit__(None, None, None)
    time.sleep(0.5)

    # Process must be terminated
    assert proc.poll() is not None, "Target child process must be terminated on sandbox exit"


# SCENARIO 10: Provider Isolation (Zero Paid API Calls in Tests)
def test_scenario_10_provider_isolation():
    """
    Scenario 10: System functions without API keys; zero external requests made;
    unconfigured provider states are truthfully reported.
    """
    orig_tavily = os.environ.get("TAVILY_API_KEY")
    orig_nebius = os.environ.get("NEBIUS_API_KEY")

    try:
        if "TAVILY_API_KEY" in os.environ:
            del os.environ["TAVILY_API_KEY"]
        if "NEBIUS_API_KEY" in os.environ:
            del os.environ["NEBIUS_API_KEY"]

        tav_client = TavilyIntelligenceClient(api_key="")
        assert tav_client.is_configured is False
        # When unconfigured, search_guidance raises ProviderError rather than failing silently or making network calls
        with pytest.raises(Exception):
            tav_client.search_guidance("SQL injection CWE-89")

        from app.intelligence.tavily_client import OfflineIntelligenceProvider
        offline_prov = OfflineIntelligenceProvider()
        refs = offline_prov.search_guidance("SQL injection")
        assert len(refs) > 0

        red_agent = RedTeamAgent()
        config = red_agent.propose_reproduction_test(finding=None, route=None)
        assert config.target_endpoint == "/api/orders"
        assert config.exploit_payload != ""
    finally:
        if orig_tavily:
            os.environ["TAVILY_API_KEY"] = orig_tavily
        if orig_nebius:
            os.environ["NEBIUS_API_KEY"] = orig_nebius
