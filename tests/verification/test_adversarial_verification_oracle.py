"""
Targeted Adversarial Regression Tests for Verification Oracle & Remediation Pipeline.
Audits Gate A, Gate B, Gate C, Gate D, sandbox isolation, and authoritative verdict determination.
"""

import os
import tempfile
import pytest
from app.config import AppConfig
from app.core.orchestrator import RemediationRun
from app.core.state_machine import RunState
from app.analysis.findings import Finding, VulnerabilityClass, Severity
from app.sandbox.reproduction import ReproductionTestConfig
from app.verification.oracle import (
    VerificationOracle,
    VerificationReport,
    GateResult,
)


class MockResponse:
    def __init__(self, status_code: int = 200, json_data=None, text: str = ""):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.text = text if text else (str(json_data) if json_data else "")

    def json(self):
        return self._json_data


class MockHttpClient:
    def __init__(self, get_fn=None, post_fn=None):
        self._get_fn = get_fn or (lambda path, **kw: MockResponse(200))
        self._post_fn = post_fn or (lambda path, **kw: MockResponse(200))

    def get(self, path: str, **kwargs):
        return self._get_fn(path, **kwargs)

    def post(self, path: str, **kwargs):
        return self._post_fn(path, **kwargs)


def make_finding(
    fid="FIND-001",
    v_class=VulnerabilityClass.SQL_INJECTION,
    cwe="CWE-89",
    title="SQL Injection",
    line_number=10,
    file_path="app.py",
) -> Finding:
    return Finding(
        id=fid,
        vulnerability_class=v_class,
        cwe=cwe,
        title=title,
        description=f"Description for {title}",
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=line_number,
        code_snippet="vulnerable_code()",
        remediation_guidance="Use parameterized queries",
    )


def test_gate_c_fails_closed_on_zero_checks():
    """Verify Gate C fails closed (passed=False) when no security invariant checks can be executed."""
    oracle = VerificationOracle()
    client = MockHttpClient()
    routes = {"/unmatched/custom/route"}

    result = oracle.run_gate_c_security(client, routes)
    assert result.passed is False
    assert result.check_count >= 1
    assert any("No security invariant re-test could be executed" in reason for reason in result.failed_checks)


def test_gate_b_fails_closed_on_zero_checks():
    """Verify Gate B fails closed (passed=False) when no functional regression checks can be executed."""
    oracle = VerificationOracle()
    client = MockHttpClient()
    routes = set()

    result = oracle.run_gate_b_functional(client, routes)
    assert result.passed is False
    assert result.check_count >= 1
    assert any("No functional regression checks could be executed" in reason for reason in result.failed_checks)


def test_gate_c_replays_exploit_config_and_rejects_insecure_target():
    """Verify Gate C re-runs reproduction config against target and rejects unmitigated exploit."""
    config = ReproductionTestConfig(
        http_method="POST",
        target_endpoint="/login",
        param_name="username",
        exploit_payload="admin' --",
        target_secret_marker="",
        target_unauthorized_user="admin",
        vulnerability_class="SQL_INJECTION",
    )
    oracle = VerificationOracle(reproduction_config=config)

    def post_handler(path, **kw):
        data = kw.get("json", {})
        if data.get("username") == "admin' --":
            return MockResponse(200, {"username": "admin", "role": "admin"})
        return MockResponse(200, {"username": "aman"})

    client = MockHttpClient(post_fn=post_handler)
    routes = {"/login"}

    result = oracle.run_gate_c_security(client, routes)
    assert result.passed is False
    assert any("SQL injection active" in reason for reason in result.failed_checks)


def test_gate_c_catches_idor_on_non_admin_user():
    """Verify Gate C flags IDOR when non-admin user object is leaked unauthenticated."""
    oracle = VerificationOracle()

    def get_handler(path, **kw):
        if path == "/users/2":
            return MockResponse(200, {"id": 2, "username": "bob", "email": "bob@example.com"})
        return MockResponse(200, {"id": 1, "username": "alice"})

    client = MockHttpClient(get_fn=get_handler)
    routes = {"/users/{id}"}

    result = oracle.run_gate_c_security(client, routes)
    assert result.passed is False
    assert any("IDOR vulnerability active" in reason for reason in result.failed_checks)


def test_gate_c_catches_command_injection():
    """Verify Gate C flags command injection when exploit marker is returned."""
    finding = make_finding(
        fid="FIND-CMD-001",
        v_class=VulnerabilityClass.COMMAND_INJECTION,
        cwe="CWE-78",
        title="Command Injection",
        line_number=20,
    )
    oracle = VerificationOracle(findings=[finding])

    def get_handler(path, **kw):
        params = kw.get("params", {})
        if "ZDA_PWNED_CWE78" in params.get("cmd", ""):
            return MockResponse(200, text="root:x:0:0\nZDA_PWNED_CWE78\n")
        return MockResponse(200, text="OK")

    client = MockHttpClient(get_fn=get_handler)
    routes = {"/exec"}

    result = oracle.run_gate_c_security(client, routes)
    assert result.passed is False
    assert any("Command injection active" in reason for reason in result.failed_checks)


def test_gate_d_rejects_newly_introduced_vulnerability():
    """Verify Gate D rejects a patch that introduces a new vulnerability sink."""
    with tempfile.TemporaryDirectory() as td:
        vulnerable_code = """
import os
def run_command(user_input):
    os.system(user_input)
"""
        patched_file = os.path.join(td, "app.py")
        with open(patched_file, "w", encoding="utf-8") as f:
            f.write(vulnerable_code)

        orig_finding = make_finding(
            fid="FIND-SQL-001",
            v_class=VulnerabilityClass.SQL_INJECTION,
            cwe="CWE-89",
            title="SQL Injection",
            line_number=10,
        )
        oracle = VerificationOracle(findings=[orig_finding])
        gate_d = oracle.run_gate_d_static_reanalysis(patched_file)

        assert gate_d.passed is False
        assert any("newly introduced" in reason or "CWE-78" in reason for reason in gate_d.failed_checks)


def test_sandbox_startup_crash_reports_execution_failed():
    """Verify that when a target crashes on startup in the sandbox, verdict is EXECUTION FAILED."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    config = AppConfig(workspace_root=workspace_root)

    run = RemediationRun(
        target_path="target_app/app.py",
        config=config,
    )
    run.code_findings = [make_finding()]
    run.state_machine._current_state = RunState.REJECTED
    gate_a = GateResult(passed=True, check_count=2, details="Gate A passed")
    gate_b = GateResult(passed=False, check_count=1, failed_checks=["Target execution failed: Subprocess crashed with exit code 1"], details="Gate B FAILED")
    gate_c = GateResult(passed=False, check_count=1, failed_checks=["Target execution failed: Subprocess crashed with exit code 1"], details="Gate C FAILED")
    gate_d = GateResult(passed=True, check_count=1, details="Gate D passed")

    run.verification_report = VerificationReport(
        status="REJECTED",
        gate_a_patch_integrity=gate_a,
        gate_b_functional=gate_b,
        gate_c_security=gate_c,
        gate_d_static_reanalysis=gate_d,
        gate_a_functional=gate_b,
        gate_b_security=gate_c,
        patch_hash="crash123",
        failure_reasons=["Target execution failed: Subprocess crashed with exit code 1"],
    )

    report = run._finalize_report()
    assert report.verdict == "EXECUTION FAILED"
    assert report.final_status == "FAILED"


def test_final_verdicts_truthfully_distinguish_outcomes():
    """Verify _finalize_report distinguishes VERIFIED SECURE, REGRESSION FAILED, SECURITY RE-TEST FAILED, and INCONCLUSIVE."""
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    config = AppConfig(workspace_root=workspace_root)

    # 1. VERIFIED SECURE
    run1 = RemediationRun(target_path="target_app/app.py", config=config)
    run1.code_findings = [make_finding()]
    run1.state_machine._current_state = RunState.ACCEPTED
    passing_gate = GateResult(passed=True, check_count=3, details="Passed")
    run1.verification_report = VerificationReport(
        status="ACCEPTED",
        gate_a_patch_integrity=passing_gate,
        gate_b_functional=passing_gate,
        gate_c_security=passing_gate,
        gate_d_static_reanalysis=passing_gate,
        gate_a_functional=passing_gate,
        gate_b_security=passing_gate,
        patch_hash="good123",
    )
    rep1 = run1._finalize_report()
    assert rep1.verdict == "VERIFIED SECURE"
    assert rep1.final_status == "ACCEPTED"
    assert rep1.is_verified_remediation is True

    # 2. SECURITY RE-TEST FAILED
    run2 = RemediationRun(target_path="target_app/app.py", config=config)
    run2.code_findings = [make_finding()]
    run2.state_machine._current_state = RunState.REJECTED
    sec_failed_gate = GateResult(passed=False, check_count=3, failed_checks=["Exploit reproduced"], details="Gate C Failed")
    run2.verification_report = VerificationReport(
        status="REJECTED",
        gate_a_patch_integrity=passing_gate,
        gate_b_functional=passing_gate,
        gate_c_security=sec_failed_gate,
        gate_d_static_reanalysis=passing_gate,
        gate_a_functional=passing_gate,
        gate_b_security=sec_failed_gate,
        patch_hash="badsec123",
        failure_reasons=["Exploit reproduced"],
    )
    rep2 = run2._finalize_report()
    assert rep2.verdict == "SECURITY RE-TEST FAILED"
    assert rep2.final_status == "REJECTED"
    assert rep2.is_verified_remediation is False

    # 3. REGRESSION FAILED
    run3 = RemediationRun(target_path="target_app/app.py", config=config)
    run3.code_findings = [make_finding()]
    run3.state_machine._current_state = RunState.REJECTED
    reg_failed_gate = GateResult(passed=False, check_count=3, failed_checks=["Legitimate user orders broken"], details="Gate B Failed")
    run3.verification_report = VerificationReport(
        status="REJECTED",
        gate_a_patch_integrity=passing_gate,
        gate_b_functional=reg_failed_gate,
        gate_c_security=passing_gate,
        gate_d_static_reanalysis=passing_gate,
        gate_a_functional=reg_failed_gate,
        gate_b_security=passing_gate,
        patch_hash="badreg123",
        failure_reasons=["Legitimate user orders broken"],
    )
    rep3 = run3._finalize_report()
    assert rep3.verdict == "REGRESSION FAILED"
    assert rep3.final_status == "REJECTED"
    assert rep3.is_verified_remediation is False

    # 4. INCONCLUSIVE
    run4 = RemediationRun(target_path="target_app/app.py", config=config)
    run4.state_machine._current_state = RunState.INCONCLUSIVE
    rep4 = run4._finalize_report()
    assert rep4.verdict == "INCONCLUSIVE"
    assert rep4.final_status == "REJECTED"


def test_insecure_patch_rejected_by_gate_c_in_sandbox():
    """Verify that an unfixed patch executed against TargetSandbox fails Gate C."""
    from app.verification.workspace_manager import IsolatedWorkspace
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    insecure_patch = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,2 +141,2 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
+    # Fake fix: cosmetic comment change, query remains vulnerable
+    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
"""

    with IsolatedWorkspace(workspace_root) as ws:
        patched_file = ws.apply_patch(insecure_patch, "target_app/app.py")
        oracle = VerificationOracle(patch_hash="insecure_test_123")
        report = oracle.verify_patched_target(patched_file)

        assert report.status == "REJECTED"
        assert report.gate_b_functional.passed is True
        assert report.gate_c_security.passed is False
        assert any("CRITICAL: Patch failed" in r or "SQL injection active" in r for r in report.failure_reasons)


def test_overly_restrictive_functional_breakage_rejected_by_gate_b_in_sandbox():
    """Verify that a patch breaking customer queries executed against TargetSandbox fails Gate B."""
    from app.verification.workspace_manager import IsolatedWorkspace
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    regression_patch = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,3 +141,2 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
-    cursor.execute(query)
+    # Broken logic: always returns empty list, breaking legitimate customer queries
+    return {"count": 0, "records": []}
"""

    with IsolatedWorkspace(workspace_root) as ws:
        patched_file = ws.apply_patch(regression_patch, "target_app/app.py")
        oracle = VerificationOracle(patch_hash="regression_test_456")
        report = oracle.verify_patched_target(patched_file)

        assert report.status == "REJECTED"
        assert report.gate_b_functional.passed is False
        assert any("Alice's orders" in r for r in report.failure_reasons)
