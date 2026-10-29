"""
ZeroDay Arena Benchmark Suite.
Measures reproduction rate, verified repair rate, regression prevention, and latency.
"""

import os
import time
import pytest
from typing import Dict, Any, List

from app.config import AppConfig
from app.core.orchestrator import RemediationRun, DETERMINISTIC_SECURE_PATCH
from app.core.state_machine import RunState


REGRESSION_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,3 +141,2 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
-    cursor.execute(query)
+    # Broken functional behavior
+    return {"count": 0, "records": []}
"""

SECURITY_FAILURE_PATCH = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,2 +141,2 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
+    # Fake comment update
+    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
"""


def test_benchmark_full_remediation_evaluation():
    """
    Executes a labelled benchmark across 3 distinct scenarios:
    1. Valid Remediation (Positive Case):
       - Target: vulnerable target_app/app.py
       - Patch: Valid parameterized query
       - Expected: Reproduced = True, Verified = True, Status = ACCEPTED
    2. Regression Failure (Negative Case A):
       - Target: vulnerable target_app/app.py
       - Patch: Breaks business logic
       - Expected: Reproduced = True, Gate A fails, Status = REJECTED
    3. Ineffective Security Fix (Negative Case B):
       - Target: vulnerable target_app/app.py
       - Patch: Leaves SQL injection active
       - Expected: Reproduced = True, Gate B fails, Status = REJECTED
    """
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    config = AppConfig(workspace_root=workspace_root)

    benchmark_results: List[Dict[str, Any]] = []

    # Scenario 1: Valid Remediation
    t0 = time.perf_counter()
    run_valid = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=DETERMINISTIC_SECURE_PATCH,
    )
    report_valid = run_valid.execute()
    t_valid = time.perf_counter() - t0
    benchmark_results.append({
        "scenario": "valid_remediation",
        "reproduced": report_valid.reproduction_result.reproduced if report_valid.reproduction_result else False,
        "status": report_valid.final_status,
        "verified": report_valid.is_verified_remediation,
        "latency_sec": t_valid,
    })

    # Scenario 2: Regression Failure
    t0 = time.perf_counter()
    run_regression = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=REGRESSION_PATCH,
        max_repair_attempts=1,
    )
    report_regression = run_regression.execute()
    t_reg = time.perf_counter() - t0
    benchmark_results.append({
        "scenario": "regression_failure",
        "reproduced": report_regression.reproduction_result.reproduced if report_regression.reproduction_result else False,
        "status": report_regression.final_status,
        "verified": report_regression.is_verified_remediation,
        "latency_sec": t_reg,
    })

    # Scenario 3: Ineffective Security Fix
    t0 = time.perf_counter()
    run_insecure = RemediationRun(
        target_path="target_app/app.py",
        config=config,
        candidate_patch=SECURITY_FAILURE_PATCH,
        max_repair_attempts=1,
    )
    report_insecure = run_insecure.execute()
    t_insecure = time.perf_counter() - t0
    benchmark_results.append({
        "scenario": "ineffective_fix",
        "reproduced": report_insecure.reproduction_result.reproduced if report_insecure.reproduction_result else False,
        "status": report_insecure.final_status,
        "verified": report_insecure.is_verified_remediation,
        "latency_sec": t_insecure,
    })

    # Compute Benchmark Metrics
    total_cases = len(benchmark_results)
    reproduced_count = sum(1 for r in benchmark_results if r["reproduced"])
    verified_repair_count = sum(1 for r in benchmark_results if r["verified"])
    rejection_accuracy_count = sum(
        1 for r in benchmark_results if (r["scenario"] != "valid_remediation" and r["status"] == "REJECTED")
    )
    avg_latency = sum(r["latency_sec"] for r in benchmark_results) / total_cases

    # Rigorous Metric Assertions
    assert reproduced_count == 3, f"Expected 100% reproduction (3/3), got {reproduced_count}"
    assert verified_repair_count == 1, f"Expected exactly 1 verified repair, got {verified_repair_count}"
    assert avg_latency < 20.0, f"Average execution latency {avg_latency:.2f}s exceeded bound of 20.0s"


# =====================================================================
# BENCHMARK SUITE INTEGRITY & HONEST MEASUREMENT TESTS
# =====================================================================

from app.benchmarks.benchmark_store import (
    execute_benchmark_suite,
    get_benchmarks_overview,
    load_benchmarks,
    load_benchmark_runs,
)
from fastapi.testclient import TestClient
from main import app as main_app


def test_benchmark_execution_derives_metrics_from_actual_outcomes():
    """
    POST /api/benchmarks/run and execute_benchmark_suite must derive all metrics
    directly from actual scanner execution outcomes and invariant verification.
    No metrics (duration, findings, false positives, pass rates) may be hardcoded.
    """
    result = execute_benchmark_suite()
    assert result["status"] == "SUCCESS"
    run = result["run"]

    # Provenance must be explicitly marked as live measured execution
    assert run["provenance"] == "measured_runtime_execution"

    # Execution counts must match the registry
    assert run["test_cases_executed"] == 20
    assert run["vulnerable_targets_executed"] == 14
    assert run["clean_baselines_executed"] == 6

    # Findings must match actual AST reconnaissance results (14 detected, 0 undetected)
    assert run["findings_detected"] == 14
    assert run["undetected_cases"] == 0
    assert run["verified_fixes"] == 14
    assert run["clean_baselines_verified"] == 6
    assert run["false_positives"] == 0

    # Recall must be computed mathematically: 14 / 14 * 100 = 100.0%
    assert run["detection_recall_percent"] == 100.0

    # Precision must be mathematically computed: 14 / (14 + 0) = 100.0%
    assert run["precision_percent"] == 100.0
    assert run["false_positive_rate_percent"] == 0.0

    # Duration must be genuinely measured (not hardcoded string "1.2s")
    duration_str = run["duration"]
    assert duration_str.endswith("s")
    duration_val = float(duration_str[:-1])
    assert 0.0 < duration_val < 30.0

    # Outcome must be VERIFIED_SECURE because all 14 fixtures are verified secure with 0 false positives
    assert run["outcome"] == "VERIFIED_SECURE"


def test_benchmark_handles_failed_errored_incomplete_cases_honestly():
    """
    Failed, incomplete, syntax-errored, and false-positive cases must be reported honestly.
    They must never default to 100% scores or be counted as passing.
    """
    synthetic_cases = [
        # 1. Syntax Error in vulnerable code
        {
            "id": "syn-err",
            "title": "Syntax Error Test",
            "cwe": "CWE-89",
            "vulnerable_code": "def broken_syntax(x\n    return x",
            "patched_code": "def broken_syntax(x): return x",
            "is_secure_baseline": False,
        },
        # 2. Incomplete / Missing Source
        {
            "id": "syn-incomplete",
            "title": "Missing Code Test",
            "cwe": "CWE-78",
            "vulnerable_code": "",
            "patched_code": "",
            "is_secure_baseline": False,
        },
        # 3. Clean baseline that produces a false positive (simulated by injecting SQL sink)
        {
            "id": "syn-fp",
            "title": "False Positive Control",
            "cwe": "CLEAN",
            "vulnerable_code": "import sqlite3\ndef clean(u):\n    c = sqlite3.connect(':memory:').cursor()\n    c.execute(f'SELECT * FROM u WHERE id={u}')\n",
            "patched_code": "",
            "is_secure_baseline": True,
        },
        # 4. Valid detected and remediated case
        {
            "id": "syn-valid",
            "title": "Valid SQL Injection",
            "cwe": "CWE-89",
            "vulnerable_code": "import sqlite3\ndef run_q(u):\n    c = sqlite3.connect(':memory:').cursor()\n    c.execute(f'SELECT * FROM u WHERE id={u}')\n",
            "patched_code": "import sqlite3\ndef run_q(u):\n    c = sqlite3.connect(':memory:').cursor()\n    c.execute('SELECT * FROM u WHERE id=?', (u,))\n",
            "is_secure_baseline": False,
        },
    ]

    res = execute_benchmark_suite(benchmarks=synthetic_cases)
    run = res["run"]

    # 1. Syntax error case handled honestly
    case_err = next(c for c in synthetic_cases if c["id"] == "syn-err")
    assert case_err["status"] == "ERROR"
    assert case_err["detection_result"] == "Scan Error"
    assert case_err["is_verified_remediation"] is False

    # 2. Incomplete case handled honestly
    case_inc = next(c for c in synthetic_cases if c["id"] == "syn-incomplete")
    assert case_inc["status"] == "INCOMPLETE"
    assert "Incomplete" in case_inc["detection_result"]
    assert case_inc["is_verified_remediation"] is False

    # 3. False positive case increments false_positives count
    case_fp = next(c for c in synthetic_cases if c["id"] == "syn-fp")
    assert case_fp["status"] == "FALSE_POSITIVE"
    assert case_fp["detection_result"] == "Detected"
    assert run["false_positives"] == 1

    # 4. Only 1 valid case was detected and fixed out of 3 vulnerable targets
    assert run["findings_detected"] == 1
    assert run["verified_fixes"] == 1
    # Recall = 1 / 3 = 33.3%
    assert run["detection_recall_percent"] == 33.3

    # Precision drops due to false positive: 1 / (1 + 1) * 100 = 50.0%
    assert run["precision_percent"] == 50.0

    # Overall outcome cannot be VERIFIED_SECURE
    assert run["outcome"] == "PARTIAL"


def test_empty_benchmark_suite_does_not_default_to_100_percent():
    """Empty or unexecuted benchmark suites must report 0.0% metrics, not 100.0%."""
    res = execute_benchmark_suite(benchmarks=[])
    run = res["run"]

    assert run["test_cases_executed"] == 0
    assert run["detection_recall_percent"] == 0.0
    assert run["precision_percent"] == 0.0
    assert run["false_positive_rate_percent"] == 0.0
    assert run["security_test_pass_rate"] == 0.0
    assert run["regression_test_pass_rate"] == 0.0


def test_seeded_versus_measured_records_provenance():
    """Stored benchmark records and runs must clearly identify seeded demo vs live measured provenance."""
    benchmarks = load_benchmarks()
    runs = load_benchmark_runs()

    # All benchmarks in the repository must have an explicit provenance tag
    for b in benchmarks:
        assert "provenance" in b
        assert b["provenance"] in ("seeded_reference", "measured_runtime_execution")

    # Historical runs must be marked as seeded/reference baseline or measured execution
    for r in runs:
        assert "provenance" in r
        assert r["provenance"] in ("seeded_reference_baseline", "measured_runtime_execution")


def test_api_trigger_benchmark_run_endpoint_integrity():
    """POST /api/benchmarks/run returns truthful measured metrics via the authenticated API."""
    secret = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")
    client = TestClient(main_app)

    resp = client.post("/api/benchmarks/run", headers={"X-API-Key": secret})
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "SUCCESS"
    assert "Benchmark suite executed 20 test cases" in data["message"]
    run = data["run"]
    assert run["provenance"] == "measured_runtime_execution"
    assert run["test_cases_executed"] == 20
    assert run["detection_recall_percent"] == 100.0
    assert run["precision_percent"] == 100.0
    assert run["duration"] != "1.2s"
