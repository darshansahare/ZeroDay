"""
Independent Verification Oracle.
Enforces four mandatory independent verification gates:
Gate A - Patch Integrity & AST Syntax
Gate B - Functional Integrity (Baseline Regression Suite)
Gate C - Vulnerability-Specific Security Retest (Invariant Replay)
Gate D - Static Re-Analysis (AST Rescan)
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.sandbox.target_manager import TargetSandbox, SandboxResponse
from app.analysis.ast_scanner import ASTReconScanner
from app.sandbox.reproduction import ReproductionTestConfig, ReproductionRunner


class GateResult(BaseModel):
    """Result of an individual verification gate."""
    passed: bool = Field(..., description="Whether the gate criteria were fully satisfied")
    check_count: int = Field(0, description="Total individual assertions executed")
    failed_checks: List[str] = Field(default_factory=list, description="Descriptions of failed assertions")
    details: str = Field("", description="Summary description of the gate run")


class VerificationReport(BaseModel):
    """Comprehensive, machine-readable outcome from all independent verification gates."""
    status: str = Field(..., description="'ACCEPTED' or 'REJECTED'")

    # Four Independent Verification Gates
    gate_a_patch_integrity: GateResult = Field(..., description="Gate A patch integrity & syntax outcome")
    gate_b_functional: GateResult = Field(..., description="Gate B functional regression outcome")
    gate_c_security: GateResult = Field(..., description="Gate C vulnerability-specific security retest outcome")
    gate_d_static_reanalysis: GateResult = Field(..., description="Gate D static re-analysis outcome")

    # Backward compatibility aliases
    gate_a_functional: GateResult = Field(..., description="Alias to Gate B for backward compatibility")
    gate_b_security: GateResult = Field(..., description="Alias to Gate C for backward compatibility")

    patch_hash: str = Field(..., description="SHA-256 of the evaluated patch")
    elapsed_seconds: float = Field(0.0, description="Total verification duration")
    failure_reasons: List[str] = Field(default_factory=list, description="Explicit failure reasons if rejected")


class ClientAdapter:
    """Provides a uniform HTTP request interface over TargetSandbox or TestClient."""

    def __init__(self, target: Any, routes: Optional[Set[str]] = None) -> None:
        self.target = target
        self.routes = routes or set()

    def get(self, path: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
        if hasattr(self.target, "execute_request"):
            resp = self.target.execute_request("GET", path, params=params, headers=headers)
            return self._wrap(resp)
        resp = self.target.get(path, params=params, headers=headers)
        return resp

    def post(self, path: str, json: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
        if hasattr(self.target, "execute_request"):
            resp = self.target.execute_request("POST", path, json_data=json, params=params, headers=headers)
            return self._wrap(resp)
        resp = self.target.post(path, json=json, params=params, headers=headers)
        return resp

    def _wrap(self, r: SandboxResponse):
        class Wrapped:
            def __init__(self, sr: SandboxResponse):
                self.status_code = sr.status_code
                self.text = sr.text
                self.headers = sr.headers
                self._json = sr.json_data

            def json(self):
                if self._json is not None:
                    return self._json
                import json
                try:
                    return json.loads(self.text)
                except Exception:
                    return {}
        return Wrapped(r)


class VerificationOracle:
    """
    Executes deterministic verification of patched targets across 4 independent gates.
    Operates strictly via programmatic assertions—never relies on LLM self-evaluation.
    """

    SECRET_MARKER = "CLASSIFIED: ZeroDay bounty escrow vault allocation"
    SUPERADMIN_ORDER = "ORD-9099"
    SUPERADMIN_USER = "USR-103"

    def __init__(
        self,
        patch_hash: str = "",
        findings: Optional[List[Any]] = None,
        reproduction_config: Optional[ReproductionTestConfig] = None,
    ) -> None:
        self.patch_hash = patch_hash
        self.findings = findings or []
        self.reproduction_config = reproduction_config

    def run_gate_a_integrity(self, patched_file_path: str) -> GateResult:
        """
        Gate A: Patch Integrity & AST Syntax.
        Asserts the file exists, is non-empty, and parses into a valid Python AST without syntax errors.
        """
        failed: List[str] = []
        checks = 0

        checks += 1
        if not os.path.exists(patched_file_path):
            failed.append(f"Patched target file '{patched_file_path}' does not exist on disk.")
            return GateResult(passed=False, check_count=checks, failed_checks=failed, details="Gate A FAILED: File missing")

        checks += 1
        try:
            target_p = Path(patched_file_path).resolve()
            content = target_p.read_text(encoding="utf-8", errors="replace")

            if not content.strip():
                failed.append("Patched target file is completely empty.")
            else:
                ast.parse(content, filename=str(target_p))

            if not self.patch_hash:
                self.patch_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        except SyntaxError as se:
            failed.append(f"SyntaxError in patched code at line {se.lineno}: {se.msg}")
        except Exception as e:
            failed.append(f"Failed to verify patched file integrity: {e}")

        passed = len(failed) == 0
        details = (
            f"Gate A PASSED ({checks}/{checks} integrity and AST syntax assertions verified)"
            if passed
            else f"Gate A FAILED ({len(failed)}/{checks} checks failed: {failed})"
        )
        return GateResult(passed=passed, check_count=checks, failed_checks=failed, details=details)

    def run_gate_b_functional(
        self,
        client: Any,
        routes: Set[str],
        sandbox: Optional[TargetSandbox] = None,
    ) -> GateResult:
        """
        Gate B: Functional Integrity (Baseline Regression Suite).
        Asserts standard business workflows still succeed. Fails closed.
        """
        failed: List[str] = []
        checks = 0

        # Method A: Baseline functional check from reproduction config
        if self.reproduction_config:
            checks += 1
            try:
                runner = ReproductionRunner(config=self.reproduction_config)
                baseline_url, _ = runner._resolve_urls()
                if self.reproduction_config.http_method == "POST":
                    r = client.post(
                        baseline_url,
                        json={
                            "username": self.reproduction_config.legitimate_user_id or "aman",
                            "password": f"{self.reproduction_config.legitimate_user_id or 'aman'}-demo",
                        },
                    )
                else:
                    if "{" in self.reproduction_config.target_endpoint:
                        r = client.get(baseline_url)
                    else:
                        r = client.get(
                            baseline_url,
                            params={self.reproduction_config.param_name: self.reproduction_config.legitimate_user_id or "1"},
                        )
                if r.status_code >= 500:
                    failed.append(f"Legitimate baseline functional check on {baseline_url} failed with HTTP {r.status_code}")
            except Exception as e:
                failed.append(f"Legitimate baseline functional check threw exception: {e}")

        # Suite 1: Login microservice (e.g. zeroday-test-1)
        if "/login" in routes:
            # Check 1: Legitimate regular user login
            checks += 1
            try:
                r = client.post("/login", json={"username": "aman", "password": "aman-demo"})
                if r.status_code != 200:
                    failed.append(f"Legitimate user login returned HTTP {r.status_code} (expected 200)")
                elif r.json().get("username") != "aman":
                    failed.append(f"Legitimate user login returned unexpected payload: {r.json()}")
            except Exception as e:
                failed.append(f"User login threw exception: {e}")

            # Check 2: Legitimate admin user login
            checks += 1
            try:
                r = client.post("/login", json={"username": "admin", "password": "admin-demo"})
                if r.status_code != 200:
                    failed.append(f"Legitimate admin login returned HTTP {r.status_code} (expected 200)")
                elif r.json().get("username") != "admin":
                    failed.append(f"Legitimate admin login returned unexpected payload: {r.json()}")
            except Exception as e:
                failed.append(f"Admin login threw exception: {e}")

            # Check 3: Invalid password rejected
            checks += 1
            try:
                r = client.post("/login", json={"username": "aman", "password": "wrong-password"})
                if r.status_code != 401:
                    failed.append(f"Invalid password returned HTTP {r.status_code} (expected 401)")
            except Exception as e:
                failed.append(f"Invalid password check threw exception: {e}")

            # Check 4: Non-existent user rejected
            checks += 1
            try:
                r = client.post("/login", json={"username": "nonexistent_usr", "password": "any"})
                if r.status_code != 401:
                    failed.append(f"Non-existent user query returned HTTP {r.status_code} (expected 401)")
            except Exception as e:
                failed.append(f"Non-existent user check threw exception: {e}")

        # Suite 2: Orders microservice (target_app/app.py benchmark)
        if "/api/orders" in routes or "/api/products" in routes:
            checks += 1
            try:
                r = client.get("/api/health")
                if r.status_code != 200:
                    failed.append(f"Health check returned HTTP {r.status_code} (expected 200)")
            except Exception as e:
                failed.append(f"Health check threw exception: {e}")

            checks += 1
            try:
                r = client.get("/api/products")
                if r.status_code != 200:
                    failed.append(f"Products endpoint returned HTTP {r.status_code} (expected 200)")
                else:
                    data = r.json()
                    if not isinstance(data, list) or len(data) < 3:
                        failed.append(f"Products catalog incomplete: got {len(data) if isinstance(data, list) else 0} items")
            except Exception as e:
                failed.append(f"Products check threw exception: {e}")

            checks += 1
            try:
                r = client.post("/api/orders/create", json={"user_id": "USR-101", "product_id": "PROD-01", "quantity": 1})
                if r.status_code != 201:
                    failed.append(f"Order creation returned HTTP {r.status_code} (expected 201)")
            except Exception as e:
                failed.append(f"Order creation threw exception: {e}")

            checks += 1
            try:
                r = client.get("/api/orders", params={"user_id": "USR-101"})
                if r.status_code != 200:
                    failed.append(f"Legitimate order query returned HTTP {r.status_code} (expected 200)")
                else:
                    data = r.json()
                    records = data.get("records", [])
                    alice_orders = [rec for rec in records if rec.get("user_id") == "USR-101"]
                    if len(alice_orders) < 1:
                        failed.append("Legitimate user query failed to return Alice's orders")
            except Exception as e:
                failed.append(f"Legitimate order query threw exception: {e}")

            checks += 1
            try:
                r = client.get("/api/orders", params={"user_id": "USR-UNKNOWN-999"})
                if r.status_code != 200:
                    failed.append(f"Unknown user query returned HTTP {r.status_code} (expected 200)")
                else:
                    records = r.json().get("records", [])
                    if len(records) != 0:
                        failed.append(f"Unknown user query expected 0 records, got {len(records)}")
            except Exception as e:
                failed.append(f"Unknown user query threw exception: {e}")

        # Suite 3: Files Microservice (e.g. zeroday-test-2)
        any_file_route = any("files" in rt for rt in routes)
        if any_file_route:
            checks += 1
            try:
                r = client.get("/files/test.txt")
                if r.status_code != 200:
                    failed.append(f"Legitimate file retrieval returned HTTP {r.status_code} (expected 200)")
            except Exception as e:
                failed.append(f"File check threw exception: {e}")

        # Suite 4: Users Profile Microservice (e.g. zeroday-test-3)
        any_user_route = any("users" in rt for rt in routes)
        if any_user_route:
            checks += 1
            try:
                r = client.get("/users/1")
                if r.status_code in (401, 403, 422):
                    r = client.get("/users/1", headers={"X-User-ID": "1", "user-id": "1", "Authorization": "Bearer 1"})
                if r.status_code != 200:
                    failed.append(f"Legitimate user profile retrieval returned HTTP {r.status_code} (expected 200)")
            except Exception as e:
                failed.append(f"User profile check threw exception: {e}")

        # Suite 5: Generic arbitrary route checks
        for r_path in sorted(routes):
            if r_path in ("/docs", "/openapi.json", "/redoc") or not r_path.startswith("/") or "{" in r_path:
                continue
            if "/login" in routes and r_path == "/login":
                continue
            if any_file_route and "files" in r_path:
                continue
            if any_user_route and "users" in r_path:
                continue
            if ("/api/orders" in routes or "/api/products" in routes) and ("/orders" in r_path or "/products" in r_path or "/health" in r_path):
                continue
            checks += 1
            try:
                r = client.get(r_path)
                if r.status_code >= 500:
                    failed.append(f"Route {r_path} crashed with HTTP {r.status_code}")
            except Exception as e:
                failed.append(f"Route {r_path} threw unhandled exception: {e}")

        if checks == 0:
            failed.append("No functional regression checks could be executed against target")
            return GateResult(
                passed=False,
                check_count=1,
                failed_checks=failed,
                details="Gate B FAILED: Zero functional assertions executed",
            )

        passed = len(failed) == 0 and checks > 0
        details = (
            f"Gate B PASSED ({checks}/{checks} functional checks succeeded)"
            if passed
            else f"Gate B FAILED ({len(failed)}/{checks} functional checks failed: {failed})"
        )
        return GateResult(passed=passed, check_count=checks, failed_checks=failed, details=details)

    def run_gate_c_security(
        self,
        client: Any,
        routes: Set[str],
        sandbox: Optional[TargetSandbox] = None,
    ) -> GateResult:
        """
        Gate C: Vulnerability-Specific Security Retest.
        Replays controlled adversarial vectors against the patched target.
        Fails closed: requires at least one executed assertion.
        """
        failed: List[str] = []
        checks = 0

        # Method A: Dynamic Exploit Reproduction Replay if reproduction_config and sandbox are available
        if self.reproduction_config and sandbox is not None:
            try:
                runner = ReproductionRunner(config=self.reproduction_config)
                rep_res = runner.run_reproduction(sandbox)
                checks += 1
                if rep_res.reproduced:
                    failed.append(
                        f"CRITICAL: Exploit vector still reproduced against patched target: {rep_res.summary}"
                    )
                elif rep_res.status == "EXECUTION_FAILED":
                    failed.append(
                        f"Target crashed or threw execution error during exploit attempt: {rep_res.summary}"
                    )
                elif rep_res.status == "INCONCLUSIVE":
                    failed.append(
                        f"Security invariant retest inconclusive: preflight check failed ({rep_res.summary})"
                    )
            except Exception as e:
                checks += 1
                failed.append(f"Dynamic exploit re-test threw exception: {e}")

        # Method B: Dynamic Exploit Replay via client adapter when sandbox is None
        elif self.reproduction_config and client is not None:
            try:
                runner = ReproductionRunner(config=self.reproduction_config)
                baseline_url, exploit_url = runner._resolve_urls()
                checks += 1
                if self.reproduction_config.http_method == "POST":
                    r = client.post(
                        exploit_url,
                        json={
                            self.reproduction_config.param_name: self.reproduction_config.exploit_payload,
                            "password": "wrong",
                        },
                    )
                else:
                    if "{" in self.reproduction_config.target_endpoint:
                        r = client.get(exploit_url)
                    else:
                        r = client.get(
                            exploit_url,
                            params={self.reproduction_config.param_name: self.reproduction_config.exploit_payload},
                        )
                if r.status_code == 500:
                    failed.append(f"Target crashed with HTTP 500 on exploit payload: {self.reproduction_config.exploit_payload}")
                elif self.reproduction_config.target_secret_marker and self.reproduction_config.target_secret_marker in r.text:
                    failed.append(f"CRITICAL: Secret marker leaked on exploit payload: {self.reproduction_config.target_secret_marker}")
                elif "ZDA_PWNED" in self.reproduction_config.exploit_payload and "ZDA_PWNED_CWE78" in r.text:
                    failed.append("CRITICAL: Command injection active: arbitrary command output observed")
                elif r.status_code == 200 and self.reproduction_config.vulnerability_class == "SQL_INJECTION":
                    # If SQLi returned 200 without auth, flag failure
                    if "/login" in exploit_url:
                        failed.append("CRITICAL: SQL injection active: authentication was bypassed")
            except Exception as e:
                checks += 1
                failed.append(f"Dynamic security retest threw exception: {e}")

        # Suite 1: Login microservice (e.g. zeroday-test-1)
        if "/login" in routes:
            # Payload 1: Admin comment bypass
            checks += 1
            try:
                r = client.post("/login", json={"username": "admin' --", "password": "wrong"})
                if r.status_code == 500:
                    failed.append("Target crashed with HTTP 500 when receiving injection payload")
                elif r.status_code == 200:
                    failed.append("CRITICAL: SQL injection active: authentication was bypassed via admin' --")
                elif r.status_code != 401:
                    failed.append(f"Unexpected status code {r.status_code} on injection payload (expected 401)")
            except Exception as e:
                failed.append(f"Security invariant check threw exception: {e}")

            # Payload 2: OR 1=1 comment bypass
            checks += 1
            try:
                r = client.post("/login", json={"username": "' OR 1=1 --", "password": "wrong"})
                if r.status_code == 500:
                    failed.append("Target crashed with HTTP 500 on comment injection payload")
                elif r.status_code == 200:
                    failed.append("CRITICAL: SQL injection active: authentication was bypassed via ' OR 1=1 --")
                elif r.status_code != 401:
                    failed.append(f"Unexpected status code {r.status_code} on injection payload (expected 401)")
            except Exception as e:
                failed.append(f"Comment injection check threw exception: {e}")

            # Payload 3: Password parameter injection
            checks += 1
            try:
                r = client.post("/login", json={"username": "admin", "password": "' OR '1'='1"})
                if r.status_code == 500:
                    failed.append("Target crashed with HTTP 500 on password injection payload")
                elif r.status_code == 200:
                    failed.append("CRITICAL: SQL injection active: authentication was bypassed via password injection")
                elif r.status_code != 401:
                    failed.append(f"Unexpected status code {r.status_code} on injection payload (expected 401)")
            except Exception as e:
                failed.append(f"Password injection check threw exception: {e}")

        # Suite 2: Orders microservice (target_app/app.py benchmark)
        if "/api/orders" in routes:
            checks += 1
            try:
                r = client.get("/api/orders", params={"user_id": "USR-101' OR '1'='1"})
                if r.status_code == 500:
                    failed.append("Target crashed with HTTP 500 when receiving injection payload")
                elif r.status_code in (200, 400, 404, 422):
                    text = r.text
                    if self.SECRET_MARKER in text:
                        failed.append("CRITICAL: Patch failed to neutralize SQL injection; secret marker was leaked")
                    if self.SUPERADMIN_ORDER in text or self.SUPERADMIN_USER in text:
                        failed.append(f"CRITICAL: Unauthorized order {self.SUPERADMIN_ORDER} leaked in response")
                    if r.status_code == 200:
                        data = r.json() if hasattr(r, "json") else {}
                        records = data.get("records", []) if isinstance(data, dict) else []
                        if len(records) > 1:
                            failed.append(f"SQL injection active: query returned {len(records)} records (table dump)")
                else:
                    failed.append(f"Unexpected status code {r.status_code} on injection payload")
            except Exception as e:
                failed.append(f"Security invariant check threw exception: {e}")

            checks += 1
            try:
                r = client.get("/api/orders", params={"user_id": "USR-101' OR 1=1 --"})
                if r.status_code == 500:
                    failed.append("Target crashed with HTTP 500 on comment injection payload")
                elif self.SECRET_MARKER in r.text or self.SUPERADMIN_ORDER in r.text:
                    failed.append("CRITICAL: Patch failed on comment injection payload; secret was leaked")
            except Exception as e:
                failed.append(f"Comment injection check threw exception: {e}")

        # Suite 3: Files Microservice (e.g. zeroday-test-2)
        any_file_route = any("files" in rt for rt in routes)
        if any_file_route:
            checks += 1
            try:
                r = client.get("/files/%2E%2E/app.py")
                if r.status_code == 200 and ("from fastapi" in r.text or "FastAPI" in r.text):
                    failed.append("CRITICAL: Path traversal vulnerability active: arbitrary source file returned")
                elif r.status_code == 500:
                    failed.append("Target crashed with HTTP 500 on traversal probe")
            except Exception as e:
                failed.append(f"Security invariant check threw exception: {e}")

        # Suite 4: Users Profile Microservice (e.g. zeroday-test-3)
        any_user_route = any("users" in rt for rt in routes)
        if any_user_route:
            checks += 1
            try:
                # Attack attempt 1: Unauthenticated request accessing user 2
                r = client.get("/users/2")
                r_json = r.json() if hasattr(r, "json") else {}
                if not isinstance(r_json, dict):
                    r_json = {}
                if r.status_code == 200 and (
                    "admin" in r.text
                    or "admin.dev@gmail.com" in r.text
                    or r_json.get("id") == 2
                    or r_json.get("user_id") == 2
                    or bool(r_json.get("username"))
                ):
                    failed.append("CRITICAL: IDOR vulnerability active: unauthorized object accessed without credentials")

                # Attack attempt 2: User 1 credentials attempting horizontal privilege escalation into user 2
                r2 = client.get("/users/2", headers={"X-User-ID": "1", "user-id": "1", "Authorization": "Bearer 1"})
                r2_json = r2.json() if hasattr(r2, "json") else {}
                if not isinstance(r2_json, dict):
                    r2_json = {}
                if r2.status_code == 200 and (
                    "admin" in r2.text
                    or "admin.dev@gmail.com" in r2.text
                    or r2_json.get("id") == 2
                    or r2_json.get("user_id") == 2
                    or bool(r2_json.get("username"))
                ):
                    failed.append("CRITICAL: IDOR vulnerability active: horizontal privilege escalation allowed")
            except Exception as e:
                failed.append(f"IDOR invariant check threw exception: {e}")

        # Suite 5: Command Injection check (CWE-78)
        has_cmd_inj = any(
            getattr(f, "vulnerability_class", None) == "COMMAND_INJECTION"
            or getattr(f, "cwe", "") == "CWE-78"
            for f in self.findings
        )
        if has_cmd_inj and not self.reproduction_config:
            checks += 1
            cmd_ep = next((rt for rt in routes if "exec" in rt or "cmd" in rt), None) or (list(routes)[0] if routes else "/")
            try:
                r = client.get(cmd_ep, params={"cmd": "; echo ZDA_PWNED_CWE78"})
                if "ZDA_PWNED_CWE78" in r.text:
                    failed.append("CRITICAL: Command injection active: arbitrary command output observed")
                elif r.status_code == 500:
                    failed.append("Target crashed with HTTP 500 on command injection probe")
            except Exception as e:
                failed.append(f"Command injection check threw exception: {e}")

        if checks == 0:
            failed.append("No security invariant re-test could be executed against target")
            return GateResult(
                passed=False,
                check_count=1,
                failed_checks=failed,
                details="Gate C FAILED: Zero security assertions executed",
            )

        passed = len(failed) == 0 and checks > 0
        details = (
            f"Gate C PASSED ({checks}/{checks} security invariants satisfied)"
            if passed
            else f"Gate C FAILED ({len(failed)}/{checks} security invariants violated: {failed})"
        )
        return GateResult(passed=passed, check_count=checks, failed_checks=failed, details=details)

    def run_gate_d_static_reanalysis(self, patched_file_path: str) -> GateResult:
        """
        Gate D: Static Re-analysis.
        Runs AST scanner against the patched file and ensures previous security sinks are eliminated.
        Fails if any original finding remains or if new vulnerabilities were introduced.
        """
        failed: List[str] = []
        checks = 1

        try:
            from pathlib import Path
            from app.config import AppConfig
            p_obj = Path(patched_file_path).resolve()
            ws_root = p_obj.parent.parent if "target_app" in p_obj.parts else p_obj.parent
            cfg = AppConfig(workspace_root=ws_root)
            scanner = ASTReconScanner(config=cfg)
            ast_rep = scanner.scan_path(patched_file_path)

            if self.findings:
                # 1. Verify original findings are eliminated
                for orig in self.findings:
                    for current in ast_rep.findings:
                        if (
                            current.vulnerability_class == getattr(orig, "vulnerability_class", None)
                            and abs(current.line_number - getattr(orig, "line_number", 0)) <= 8
                        ):
                            failed.append(
                                f"Static re-analysis failed: {current.cwe} still detected in patched code at line {current.line_number}"
                            )
                            break

                # 2. Verify no new vulnerabilities were introduced
                for current in ast_rep.findings:
                    is_orig = any(
                        current.vulnerability_class == getattr(orig, "vulnerability_class", None)
                        and abs(current.line_number - getattr(orig, "line_number", 0)) <= 8
                        for orig in self.findings
                    )
                    if not is_orig:
                        failed.append(
                            f"Static re-analysis detected newly introduced {current.cwe} at line {current.line_number}"
                        )
            elif ast_rep.findings:
                for f in ast_rep.findings:
                    failed.append(f"Static re-analysis detected {f.cwe} at line {f.line_number} in patched code")
        except Exception as e:
            failed.append(f"Static re-analysis scan threw exception: {e}")

        passed = len(failed) == 0
        details = (
            "Gate D PASSED (Static re-analysis verified vulnerability eliminated)"
            if passed
            else f"Gate D FAILED ({len(failed)} findings remain: {failed})"
        )
        return GateResult(passed=passed, check_count=checks, failed_checks=failed, details=details)

    def verify_patched_target(self, patched_file_path: str) -> VerificationReport:
        """
        Execute all four independent verification gates against the patched target in an isolated environment.
        All gates must pass for the patch to be ACCEPTED.
        """
        start_time = time.monotonic()
        reasons: List[str] = []

        # Gate A: Patch Integrity & AST Syntax
        gate_a = self.run_gate_a_integrity(patched_file_path)
        if not gate_a.passed:
            gate_b = GateResult(passed=False, check_count=1, failed_checks=["SyntaxError prevents functional execution"], details="Gate B FAILED (Syntax error)")
            gate_c = GateResult(passed=False, check_count=1, failed_checks=["SyntaxError prevents security retest"], details="Gate C FAILED")
            gate_d = GateResult(passed=False, check_count=1, failed_checks=["SyntaxError in patched code"], details="Gate D FAILED")
            reasons.extend(gate_a.failed_checks)
            elapsed = time.monotonic() - start_time
            return VerificationReport(
                status="REJECTED",
                gate_a_patch_integrity=gate_a,
                gate_b_functional=gate_b,
                gate_c_security=gate_c,
                gate_d_static_reanalysis=gate_d,
                gate_a_functional=gate_b,
                gate_b_security=gate_c,
                patch_hash=self.patch_hash,
                elapsed_seconds=elapsed,
                failure_reasons=reasons,
            )

        # Extract routes statically
        routes: Set[str] = set()
        try:
            target_p = Path(patched_file_path).resolve()
            content = target_p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(target_p))
            scanner = ASTReconScanner()
            extracted = scanner._extract_routes(tree)
            routes = {r.path for r in extracted}
        except Exception:
            pass

        # Execute functional and security gates in disposable TargetSandbox
        try:
            with TargetSandbox(target_file_path=patched_file_path) as sandbox:
                adapter = ClientAdapter(sandbox, routes=routes)
                gate_b = self.run_gate_b_functional(adapter, routes, sandbox=sandbox)
                gate_c = self.run_gate_c_security(adapter, routes, sandbox=sandbox)
        except Exception as e:
            # Fallback if target cannot be loaded as standalone HTTP service
            gate_b = GateResult(passed=False, check_count=1, failed_checks=[f"Target execution failed: {e}"], details="Gate B FAILED: Target execution failed")
            gate_c = GateResult(passed=False, check_count=1, failed_checks=[f"Target execution failed: {e}"], details="Gate C FAILED: Target execution failed")

        # Gate D: Static Re-analysis
        gate_d = self.run_gate_d_static_reanalysis(patched_file_path)

        if not gate_b.passed:
            reasons.extend(gate_b.failed_checks)
        if not gate_c.passed:
            reasons.extend(gate_c.failed_checks)
        if not gate_d.passed:
            reasons.extend(gate_d.failed_checks)

        all_passed = gate_a.passed and gate_b.passed and gate_c.passed and gate_d.passed
        status = "ACCEPTED" if all_passed else "REJECTED"
        elapsed = time.monotonic() - start_time

        return VerificationReport(
            status=status,
            gate_a_patch_integrity=gate_a,
            gate_b_functional=gate_b,
            gate_c_security=gate_c,
            gate_d_static_reanalysis=gate_d,
            gate_a_functional=gate_b,
            gate_b_security=gate_c,
            patch_hash=self.patch_hash,
            elapsed_seconds=elapsed,
            failure_reasons=reasons,
        )
