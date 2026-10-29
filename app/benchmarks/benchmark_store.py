"""
ZeroDay Persistent Benchmark Store.
Stores explicitly configured benchmark targets and immutable execution audits.
Only benchmark targets registered by the user appear in the active registry.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
BENCHMARK_FILE = DATA_DIR / "benchmarks.json"
RUNS_FILE = DATA_DIR / "benchmark_runs.json"


def ensure_storage_ready() -> None:
    """Ensure data directory, benchmarks.json, and benchmark_runs.json exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not BENCHMARK_FILE.exists():
        with open(BENCHMARK_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
    if not RUNS_FILE.exists():
        with open(RUNS_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)


def load_benchmarks() -> List[Dict[str, Any]]:
    """Load all explicitly configured benchmark cases from disk."""
    ensure_storage_ready()
    try:
        with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []


get_all_benchmarks = load_benchmarks


def save_benchmarks(benchmarks: List[Dict[str, Any]]) -> None:
    """Save benchmark cases to disk atomically."""
    ensure_storage_ready()
    tmp_file = DATA_DIR / "benchmarks.json.tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(benchmarks, f, indent=2, ensure_ascii=False)
    if os.path.exists(BENCHMARK_FILE):
        os.remove(BENCHMARK_FILE)
    os.rename(tmp_file, BENCHMARK_FILE)


def load_benchmark_runs() -> List[Dict[str, Any]]:
    """Load historical benchmark execution runs from disk."""
    ensure_storage_ready()
    try:
        with open(RUNS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []


def save_benchmark_runs(runs: List[Dict[str, Any]]) -> None:
    """Save historical benchmark runs to disk atomically."""
    ensure_storage_ready()
    tmp_file = DATA_DIR / "benchmark_runs.json.tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(runs, f, indent=2, ensure_ascii=False)
    if os.path.exists(RUNS_FILE):
        os.remove(RUNS_FILE)
    os.rename(tmp_file, RUNS_FILE)


def record_benchmark_run(run_data: Dict[str, Any]) -> Dict[str, Any]:
    """Append a new execution run to the benchmark run history."""
    runs = load_benchmark_runs()
    runs.insert(0, run_data)
    save_benchmark_runs(runs)
    return run_data


def get_benchmark_by_id(benchmark_id: str) -> Optional[Dict[str, Any]]:
    """Find a benchmark by ID (supports exact match or normalized bench-id)."""
    norm_id = benchmark_id.strip().lower()
    benchmarks = load_benchmarks()
    for b in benchmarks:
        b_id = str(b.get("id", "")).strip().lower()
        if b_id == norm_id:
            return b
        if norm_id.replace("bench-", "") == b_id.replace("bench-", ""):
            return b
    return None


def add_or_update_benchmark(benchmark_data: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or update a benchmark case in the persistent registry."""
    benchmarks = load_benchmarks()
    target_id = benchmark_data.get("id")
    if not target_id:
        target_id = f"bench-{len(benchmarks) + 1:02d}"
        benchmark_data["id"] = target_id

    updated = False
    for idx, b in enumerate(benchmarks):
        if str(b.get("id", "")).strip().lower() == str(target_id).strip().lower():
            benchmarks[idx] = benchmark_data
            updated = True
            break

    if not updated:
        benchmarks.append(benchmark_data)

    save_benchmarks(benchmarks)
    return benchmark_data


def get_benchmarks_overview() -> Dict[str, Any]:
    """
    Calculate truthful metrics derived exclusively from configured and executed benchmarks.
    No unconfigured placeholder classes or fabricated pass rates.
    """
    benchmarks = load_benchmarks()
    runs = load_benchmark_runs()

    configured_count = len(benchmarks)

    # Executed benchmarks: benchmarks that have recorded a detection result or execution timestamp
    executed_cases = [
        b for b in benchmarks
        if b.get("last_execution") or b.get("detection_result") not in (None, "", "Not run", "Not tested")
    ]
    executed_count = len(executed_cases)

    # Partition between vulnerable targets and clean security baselines
    vulnerable_cases = [
        b for b in executed_cases
        if not (b.get("is_secure_baseline") or b.get("cwe") in ("CLEAN", "NONE", None))
    ]
    clean_cases = [
        b for b in executed_cases
        if b.get("is_secure_baseline") or b.get("cwe") in ("CLEAN", "NONE", None)
    ]

    # Detection recall: proportion of executed vulnerable cases correctly detected
    detected_count = sum(
        1 for b in vulnerable_cases
        if b.get("detection_result") == "Detected" or b.get("status") in ("VERIFIED_SECURE", "ACCEPTED")
    )
    detection_recall = (
        round((detected_count / len(vulnerable_cases)) * 100, 1)
        if len(vulnerable_cases) > 0 else 0.0
    )

    # Verified remediations: cases that independently passed regression & security gates
    verified_count = sum(
        1 for b in vulnerable_cases
        if b.get("is_verified_remediation") or b.get("remediation_result") == "Remediation verified"
    )
    verified_rate = (
        round((verified_count / len(vulnerable_cases)) * 100, 1)
        if len(vulnerable_cases) > 0 else 0.0
    )

    # Clean baselines verified: clean cases with 0 findings detected
    clean_verified_count = sum(
        1 for b in clean_cases
        if b.get("detection_result") in ("No vulnerabilities found", "No Vulnerability found")
        or b.get("status") in ("SCAN_COMPLETE_NO_FINDINGS", "NO_VULNERABILITIES_FOUND")
    )

    # False positives: clean cases that were mistakenly flagged as vulnerable
    false_positives = sum(
        1 for b in clean_cases
        if b.get("detection_result") == "Detected"
    )
    false_positive_rate = (
        round((false_positives / len(clean_cases)) * 100, 1)
        if len(clean_cases) > 0 else 0.0
    )

    precision = (
        round((detected_count / (detected_count + false_positives)) * 100, 1)
        if (detected_count + false_positives) > 0 else 0.0
    )

    latest_run = runs[0] if runs else None
    latest_provenance = latest_run.get("provenance", "seeded_reference") if latest_run else "seeded_reference"

    return {
        "metrics": {
            "configured_benchmarks": configured_count,
            "executed_test_cases": executed_count,
            "vulnerable_targets_count": len(vulnerable_cases),
            "clean_baselines_count": len(clean_cases),
            "clean_baselines_verified": clean_verified_count,
            "detected_vulnerabilities_count": detected_count,
            "undetected_vulnerabilities_count": len(vulnerable_cases) - detected_count,
            "detection_recall_percent": detection_recall,
            "verified_remediations_count": verified_count,
            "verified_remediation_rate_percent": verified_rate,
            "false_positives_count": false_positives,
            "false_positive_rate_percent": false_positive_rate,
            "precision_percent": precision,
            "provenance": latest_provenance,
        },
        "benchmarks": benchmarks,
        "recent_runs": runs,
        "engine_info": {
            "llm_engine": "nvidia/nemotron-3-super-120b-a12b (Nebius Token Factory)",
            "intelligence_engine": "Tavily Search Grounded RAG",
            "verification_oracle": "Deterministic 4-Gate Invariant Oracle",
            "execution_provenance": latest_provenance,
        },
    }


def execute_benchmark_suite(
    benchmarks: Optional[List[Dict[str, Any]]] = None,
    scanner: Optional[Any] = None,
    persist: bool = False,
) -> Dict[str, Any]:
    """
    Execute genuine AST reconnaissance and invariant patch verification against benchmark cases.
    Measures real execution duration and calculates truthful metrics from actual test outcomes.
    Does not hardcode or fabricate any detection, verification, false-positive, or latency metrics.
    """
    import time
    from datetime import datetime, timezone
    from app.analysis.ast_scanner import ASTReconScanner
    from app.config import get_config

    suite_t0 = time.perf_counter()
    bench_list = benchmarks if benchmarks is not None else load_benchmarks()
    active_scanner = scanner or ASTReconScanner(config=get_config())

    total_tested = len(bench_list)
    vulnerable_cases: List[Dict[str, Any]] = []
    clean_cases: List[Dict[str, Any]] = []

    for b in bench_list:
        case_t0 = time.perf_counter()
        target_file = b.get("target_file", "app.py")
        is_clean = bool(b.get("is_secure_baseline") or b.get("cwe") in ("CLEAN", "NONE", None))
        vuln_code = b.get("vulnerable_code", "")
        patched_code = b.get("patched_code", "")

        # Check for empty / missing source code
        if not vuln_code or not isinstance(vuln_code, str) or not vuln_code.strip():
            b["detection_result"] = "Incomplete (no source code provided)"
            b["status"] = "INCOMPLETE"
            b["is_verified_remediation"] = False
            b["actual_finding"] = "Benchmark fixture missing source code snippet."
            b["remediation_result"] = "Not tested"
            b["execution_duration"] = f"{round((time.perf_counter() - case_t0) * 1000, 1)}ms"
            b["last_execution"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            b["provenance"] = "measured_runtime_execution"
            if is_clean:
                clean_cases.append(b)
            else:
                vulnerable_cases.append(b)
            continue

        # Execute AST scan on vulnerable/target code
        try:
            routes_v, findings_v, warn_v = active_scanner._analyze_source(vuln_code, Path(target_file), target_file)
        except Exception as e:
            b["detection_result"] = "Scan Error"
            b["status"] = "ERROR"
            b["is_verified_remediation"] = False
            b["actual_finding"] = f"AST scanner exception: {str(e)}"
            b["remediation_result"] = "Error"
            b["execution_duration"] = f"{round((time.perf_counter() - case_t0) * 1000, 1)}ms"
            b["last_execution"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            b["provenance"] = "measured_runtime_execution"
            if is_clean:
                clean_cases.append(b)
            else:
                vulnerable_cases.append(b)
            continue

        if warn_v:
            b["syntax_warning"] = warn_v.get("warning")
            b["detection_result"] = "Scan Error"
            b["status"] = "ERROR"
            b["is_verified_remediation"] = False
            b["actual_finding"] = warn_v.get("warning")
            b["remediation_result"] = "Error"
            b["execution_duration"] = f"{round((time.perf_counter() - case_t0) * 1000, 1)}ms"
            b["last_execution"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            b["provenance"] = "measured_runtime_execution"
            if is_clean:
                clean_cases.append(b)
            else:
                vulnerable_cases.append(b)
            continue

        if is_clean:
            clean_cases.append(b)
            if len(findings_v) == 0:
                b["detection_result"] = "No vulnerabilities found"
                b["status"] = "SCAN_COMPLETE_NO_FINDINGS"
                b["is_verified_remediation"] = False
                b["remediation_result"] = "No remediation required (clean baseline)"
                b["actual_finding"] = "Zero vulnerable sinks detected across AST inspection."
            else:
                b["detection_result"] = "Detected"
                b["status"] = "FALSE_POSITIVE"
                b["is_verified_remediation"] = False
                b["remediation_result"] = "Unnecessary remediation flagged"
                b["actual_finding"] = f"Clean baseline incorrectly flagged: {[f.title for f in findings_v]}"
        else:
            vulnerable_cases.append(b)
            if len(findings_v) > 0:
                b["detection_result"] = "Detected"
                top_finding = findings_v[0]
                b["actual_finding"] = f"AST Sink Detected ({top_finding.cwe}): {top_finding.title} at line {top_finding.line_number}"

                # Test patch verification if patched code is supplied
                if patched_code and isinstance(patched_code, str) and patched_code.strip():
                    try:
                        routes_p, findings_p, warn_p = active_scanner._analyze_source(patched_code, Path(target_file), target_file)
                        orig_cwes = {f.cwe for f in findings_v}
                        rem_cwes = {f.cwe for f in findings_p}
                        if not warn_p and not orig_cwes.intersection(rem_cwes):
                            b["remediation_result"] = "Remediation verified"
                            b["is_verified_remediation"] = True
                            b["status"] = "VERIFIED_SECURE"
                        else:
                            b["remediation_result"] = "Patch failed verification (vulnerable sink persists)"
                            b["is_verified_remediation"] = False
                            b["status"] = "DETECTED"
                    except Exception as e:
                        b["remediation_result"] = f"Patch verification error: {str(e)}"
                        b["is_verified_remediation"] = False
                        b["status"] = "DETECTED"
                else:
                    b["remediation_result"] = "No patch provided"
                    b["is_verified_remediation"] = False
                    b["status"] = "DETECTED"
            else:
                # Vulnerable target was not flagged by the static AST sink detector
                b["detection_result"] = "Not detected"
                b["status"] = "UNDETECTED"
                b["is_verified_remediation"] = False
                b["remediation_result"] = "Not remediated (sink undetected)"
                b["actual_finding"] = "No AST sink detected by static reconnaissance scanner."

        b["execution_duration"] = f"{round((time.perf_counter() - case_t0) * 1000, 1)}ms"
        b["last_execution"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        b["provenance"] = "measured_runtime_execution"

    suite_duration_sec = time.perf_counter() - suite_t0
    duration_str = f"{suite_duration_sec:.2f}s"

    # Compute actual derived metrics
    detected_count = sum(1 for b in vulnerable_cases if b.get("detection_result") == "Detected")
    undetected_count = len(vulnerable_cases) - detected_count
    verified_fixes = sum(1 for b in vulnerable_cases if b.get("is_verified_remediation") is True)
    false_positives = sum(1 for b in clean_cases if b.get("detection_result") == "Detected")
    clean_verified = sum(1 for b in clean_cases if b.get("detection_result") in ("No vulnerabilities found", "No Vulnerability found"))

    recall_pct = round((detected_count / len(vulnerable_cases)) * 100, 1) if vulnerable_cases else 0.0
    fp_rate_pct = round((false_positives / len(clean_cases)) * 100, 1) if clean_cases else 0.0
    precision_pct = round((detected_count / (detected_count + false_positives)) * 100, 1) if (detected_count + false_positives) > 0 else 0.0
    verified_rate_pct = round((verified_fixes / len(vulnerable_cases)) * 100, 1) if vulnerable_cases else 0.0
    security_pass_rate = verified_rate_pct
    regression_pass_rate = round((clean_verified / len(clean_cases)) * 100, 1) if clean_cases else 0.0

    outcome = "VERIFIED_SECURE" if (verified_fixes == len(vulnerable_cases) and false_positives == 0 and undetected_count == 0) else "PARTIAL"

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_record = {
        "run_id": f"BENCH-RUN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        "timestamp": now_iso,
        "scanner_version": "ZeroDay AST Security Scanner v2.0 (Measured Execution)",
        "provenance": "measured_runtime_execution",
        "test_cases_executed": total_tested,
        "vulnerable_targets_executed": len(vulnerable_cases),
        "clean_baselines_executed": len(clean_cases),
        "findings_detected": detected_count,
        "undetected_cases": undetected_count,
        "verified_fixes": verified_fixes,
        "clean_baselines_verified": clean_verified,
        "false_positives": false_positives,
        "duration": duration_str,
        "outcome": outcome,
        "detection_recall_percent": recall_pct,
        "precision_percent": precision_pct,
        "false_positive_rate_percent": fp_rate_pct,
        "security_test_pass_rate": security_pass_rate,
        "regression_test_pass_rate": regression_pass_rate,
    }

    if persist and len(bench_list) > 0:
        save_benchmarks(bench_list)
        record_benchmark_run(run_record)

    return {
        "status": "SUCCESS",
        "message": f"Benchmark suite executed {total_tested} test cases: {detected_count} vulnerabilities detected, {verified_fixes} verified remediations, {false_positives} false positives in {duration_str}.",
        "run": run_record,
    }