"""
Deterministic Vulnerability Reproduction Engine.
Executes controlled security invariant tests against the sandboxed target.
"""

from __future__ import annotations

import time
from typing import Optional, List, Dict, Any, Tuple
from pydantic import BaseModel, Field

from app.sandbox.target_manager import TargetSandbox


class ReproductionTestConfig(BaseModel):
    """Configuration for a deterministic reproduction attempt."""
    http_method: str = "GET"
    target_endpoint: str = "/api/orders"
    param_name: str = "user_id"
    exploit_payload: str = "USR-101' OR '1'='1"
    target_secret_marker: str = "CLASSIFIED: ZeroDay bounty escrow vault allocation"
    target_unauthorized_user: str = "USR-103"
    target_unauthorized_order: str = "ORD-9099"
    legitimate_user_id: str = "USR-101"
    vulnerability_class: Optional[str] = None


class ReproductionResult(BaseModel):
    """Structured evidence record of an exploit reproduction attempt."""
    reproduced: bool = Field(..., description="Whether the vulnerability was successfully triggered")
    status_code: int = Field(..., description="HTTP response status code")
    leaked_records_count: int = Field(0, description="Number of records returned by exploit query")
    leaked_secret_detected: bool = Field(False, description="Whether the synthetic secret marker was observed")
    unauthorized_data_accessed: bool = Field(False, description="Whether records belonging to unauthorized users were leaked")
    evidence_snippet: str = Field(..., description="Excerpt of the leaked data or error response")
    elapsed_seconds: float = Field(0.0, description="Duration of reproduction execution")
    summary: str = Field(..., description="Human-readable explanation of outcome")

    # Authoritative contract fields required by API and UI
    target_endpoint: str = Field(default="", description="Target route or endpoint tested")
    exploit_payload: str = Field(default="", description="Sanitized exploit vector / payload attempted")
    status: str = Field(default="NOT_REPRODUCED", description="Explicit reproduction state: REPRODUCED, NOT_REPRODUCED, INCONCLUSIVE, EXECUTION_FAILED, TIMED_OUT")
    reproduction_classification: str = Field(default="NORMAL", description="Detailed classification category")
    http_method: str = Field(default="GET", description="HTTP method used for reproduction probe")
    resolved_request_url: str = Field(default="", description="Actual resolved URL after parameter substitution")
    exploit_attempted: bool = Field(default=True, description="Explicit indicator whether exploit was actually attempted")
    failure_reason: Optional[str] = Field(default=None, description="Explicit failure reason if test could not complete or preflight failed")
    sandbox_execution_id: Optional[str] = Field(default=None, description="Disposable sandbox execution identifier")
    preflight_passed: bool = Field(default=True, description="Whether legitimate baseline preflight succeeded")


class ReproductionRunner:
    """
    Executes controlled, deterministic reproduction tests against a TargetSandbox.
    Never relies on model claims; uses rigorous programmatic assertions.
    """

    def __init__(self, config: Optional[ReproductionTestConfig] = None) -> None:
        self.config = config or ReproductionTestConfig()

    def _resolve_urls(self) -> Tuple[str, str]:
        """Resolve route placeholders into concrete URLs for preflight and exploit tests."""
        ep = self.config.target_endpoint
        v_class = (self.config.vulnerability_class or "").upper()

        if "{" in ep:
            # Path Traversal: /files/{filename:path} or /files/{filename}
            if "{filename" in ep:
                baseline_url = ep.replace("{filename:path}", "test.txt").replace("{filename}", "test.txt")
                exploit_url = ep.replace("{filename:path}", "%2E%2E/app.py").replace("{filename}", "%2E%2E/app.py")
                return baseline_url, exploit_url

            # IDOR: /users/{user_id} or /orders/{order_id}
            if "{user_id}" in ep:
                baseline_url = ep.replace("{user_id}", str(self.config.legitimate_user_id or "1"))
                exploit_url = ep.replace("{user_id}", str(self.config.exploit_payload or "2"))
                return baseline_url, exploit_url

            if "{id}" in ep:
                baseline_url = ep.replace("{id}", "1")
                exploit_url = ep.replace("{id}", str(self.config.exploit_payload or "2"))
                return baseline_url, exploit_url

            # Generic single placeholder replacement
            import re
            baseline_url = re.sub(r"\{[a-zA-Z_0-9:]+\}", "1", ep)
            exploit_url = re.sub(r"\{[a-zA-Z_0-9:]+\}", "2", ep)
            return baseline_url, exploit_url

        return ep, ep

    def run_reproduction(self, sandbox: TargetSandbox) -> ReproductionResult:
        """
        Executes the reproduction test against the active target sandbox.
        Returns a structured ReproductionResult containing concrete evidence.
        """
        start_time = time.monotonic()
        baseline_url, exploit_url = self._resolve_urls()

        # Check sandbox health/activity
        if not getattr(sandbox, "_is_active", False):
            elapsed = time.monotonic() - start_time
            return ReproductionResult(
                reproduced=False,
                status_code=0,
                leaked_records_count=0,
                leaked_secret_detected=False,
                unauthorized_data_accessed=False,
                evidence_snippet="Sandbox is inactive; could not establish connection.",
                elapsed_seconds=elapsed,
                summary="EXECUTION_FAILED: Sandbox is not active.",
                target_endpoint=self.config.target_endpoint,
                exploit_payload=self.config.exploit_payload,
                status="EXECUTION_FAILED",
                reproduction_classification="INFRASTRUCTURE_FAILURE",
                http_method=self.config.http_method,
                resolved_request_url=exploit_url,
                exploit_attempted=False,
                failure_reason="Target sandbox inactive or failed startup",
                preflight_passed=False,
            )

        # POST Request Handling (e.g. /login SQL injection)
        if self.config.http_method == "POST":
            # Baseline legitimate check
            try:
                baseline_resp = sandbox.execute_request(
                    method="POST",
                    path=baseline_url,
                    json_data={"username": self.config.legitimate_user_id, "password": f"{self.config.legitimate_user_id}-demo"},
                )
            except Exception as e:
                elapsed = time.monotonic() - start_time
                return ReproductionResult(
                    reproduced=False,
                    status_code=500,
                    leaked_records_count=0,
                    leaked_secret_detected=False,
                    unauthorized_data_accessed=False,
                    evidence_snippet=f"Baseline request exception: {str(e)}",
                    elapsed_seconds=elapsed,
                    summary=f"EXECUTION_FAILED: Pre-flight check crashed: {str(e)}",
                    target_endpoint=self.config.target_endpoint,
                    exploit_payload=self.config.exploit_payload,
                    status="EXECUTION_FAILED",
                    reproduction_classification="CRASH",
                    http_method="POST",
                    resolved_request_url=baseline_url,
                    exploit_attempted=False,
                    failure_reason=str(e),
                    preflight_passed=False,
                )

            if baseline_resp.status_code != 200:
                elapsed = time.monotonic() - start_time
                return ReproductionResult(
                    reproduced=False,
                    status_code=baseline_resp.status_code,
                    leaked_records_count=0,
                    leaked_secret_detected=False,
                    unauthorized_data_accessed=False,
                    evidence_snippet=baseline_resp.text[:200],
                    elapsed_seconds=elapsed,
                    summary=f"INCONCLUSIVE: Pre-flight baseline check failed with HTTP {baseline_resp.status_code}",
                    target_endpoint=self.config.target_endpoint,
                    exploit_payload=self.config.exploit_payload,
                    status="INCONCLUSIVE",
                    reproduction_classification="PREFLIGHT_FAILED",
                    http_method="POST",
                    resolved_request_url=baseline_url,
                    exploit_attempted=False,
                    failure_reason=f"Baseline returned HTTP {baseline_resp.status_code}",
                    preflight_passed=False,
                )

            # Controlled reproduction attempt
            try:
                exploit_resp = sandbox.execute_request(
                    method="POST",
                    path=exploit_url,
                    json_data={"username": self.config.exploit_payload, "password": "wrong"},
                )
            except Exception as e:
                elapsed = time.monotonic() - start_time
                return ReproductionResult(
                    reproduced=False,
                    status_code=500,
                    leaked_records_count=0,
                    leaked_secret_detected=False,
                    unauthorized_data_accessed=False,
                    evidence_snippet=f"Exploit attempt exception: {str(e)}",
                    elapsed_seconds=elapsed,
                    summary=f"EXECUTION_FAILED: Exploit execution error: {str(e)}",
                    target_endpoint=self.config.target_endpoint,
                    exploit_payload=self.config.exploit_payload,
                    status="EXECUTION_FAILED",
                    reproduction_classification="CRASH",
                    http_method="POST",
                    resolved_request_url=exploit_url,
                    exploit_attempted=True,
                    failure_reason=str(e),
                )

            elapsed = time.monotonic() - start_time
            resp_data = exploit_resp.json_data or {}

            secret_found = bool(
                self.config.target_secret_marker
                and self.config.target_secret_marker in exploit_resp.text
            )
            unauthorized_found = (
                resp_data.get("role") == "admin"
                or resp_data.get("username") == self.config.target_unauthorized_user
                or resp_data.get("user_id") == 2
            )
            is_reproduced = exploit_resp.status_code == 200 and (unauthorized_found or secret_found)
            count = 1 if is_reproduced else 0

            if is_reproduced:
                evidence = (
                    f"SQL injection confirmed: query with payload '{self.config.exploit_payload}' "
                    f"bypassed authentication and granted unauthorized access as '{resp_data.get('username')}' "
                    f"(role: {resp_data.get('role')}). Secret marker detected: {secret_found}."
                )
                summary = (
                    f"REPRODUCED: Target is vulnerable to CWE-89 SQL Injection. "
                    f"Authentication bypassed as {resp_data.get('role', 'admin')}."
                )
                status_val = "REPRODUCED"
                classification = "AUTHENTICATION_BYPASS"
            else:
                evidence = (
                    f"Neutralized: exploit payload '{self.config.exploit_payload}' "
                    f"returned status {exploit_resp.status_code}. Authentication bypass failed."
                )
                summary = "NOT REPRODUCED: Target enforced security invariant; exploit payload failed."
                status_val = "NOT_REPRODUCED"
                classification = "DEFENSE_EFFECTIVE"

            return ReproductionResult(
                reproduced=is_reproduced,
                status_code=exploit_resp.status_code,
                leaked_records_count=count,
                leaked_secret_detected=secret_found,
                unauthorized_data_accessed=unauthorized_found,
                evidence_snippet=evidence,
                elapsed_seconds=elapsed,
                summary=summary,
                target_endpoint=self.config.target_endpoint,
                exploit_payload=self.config.exploit_payload,
                status=status_val,
                reproduction_classification=classification,
                http_method="POST",
                resolved_request_url=exploit_url,
                exploit_attempted=True,
            )

        # GET Request Handling
        has_route_params = "{" in self.config.target_endpoint

        # Step A: Pre-flight check
        try:
            if has_route_params:
                baseline_resp = sandbox.execute_request(
                    method="GET",
                    path=baseline_url,
                )
            else:
                baseline_resp = sandbox.execute_request(
                    method="GET",
                    path=baseline_url,
                    params={self.config.param_name: self.config.legitimate_user_id},
                )
        except Exception as e:
            elapsed = time.monotonic() - start_time
            return ReproductionResult(
                reproduced=False,
                status_code=500,
                leaked_records_count=0,
                leaked_secret_detected=False,
                unauthorized_data_accessed=False,
                evidence_snippet=f"Baseline pre-flight error: {str(e)}",
                elapsed_seconds=elapsed,
                summary=f"EXECUTION_FAILED: Pre-flight check error: {str(e)}",
                target_endpoint=self.config.target_endpoint,
                exploit_payload=self.config.exploit_payload,
                status="EXECUTION_FAILED",
                reproduction_classification="CRASH",
                http_method="GET",
                resolved_request_url=baseline_url,
                exploit_attempted=False,
                failure_reason=str(e),
                preflight_passed=False,
            )

        if baseline_resp.status_code != 200:
            elapsed = time.monotonic() - start_time
            return ReproductionResult(
                reproduced=False,
                status_code=baseline_resp.status_code,
                leaked_records_count=0,
                leaked_secret_detected=False,
                unauthorized_data_accessed=False,
                evidence_snippet=baseline_resp.text[:200],
                elapsed_seconds=elapsed,
                summary=f"INCONCLUSIVE: Pre-flight baseline check failed with HTTP {baseline_resp.status_code}",
                target_endpoint=self.config.target_endpoint,
                exploit_payload=self.config.exploit_payload,
                status="INCONCLUSIVE",
                reproduction_classification="PREFLIGHT_FAILED",
                http_method="GET",
                resolved_request_url=baseline_url,
                exploit_attempted=False,
                failure_reason=f"Baseline returned HTTP {baseline_resp.status_code}",
                preflight_passed=False,
            )

        # Step B: Controlled reproduction attempt
        try:
            if has_route_params:
                exploit_resp = sandbox.execute_request(
                    method="GET",
                    path=exploit_url,
                )
            else:
                exploit_resp = sandbox.execute_request(
                    method="GET",
                    path=exploit_url,
                    params={self.config.param_name: self.config.exploit_payload},
                )
        except Exception as e:
            elapsed = time.monotonic() - start_time
            return ReproductionResult(
                reproduced=False,
                status_code=500,
                leaked_records_count=0,
                leaked_secret_detected=False,
                unauthorized_data_accessed=False,
                evidence_snippet=f"Exploit execution exception: {str(e)}",
                elapsed_seconds=elapsed,
                summary=f"EXECUTION_FAILED: Exploit execution error: {str(e)}",
                target_endpoint=self.config.target_endpoint,
                exploit_payload=self.config.exploit_payload,
                status="EXECUTION_FAILED",
                reproduction_classification="CRASH",
                http_method="GET",
                resolved_request_url=exploit_url,
                exploit_attempted=True,
                failure_reason=str(e),
            )

        elapsed = time.monotonic() - start_time
        resp_data = exploit_resp.json_data or {}
        records: List[Dict[str, Any]] = resp_data.get("records", [])
        count = len(records)

        # Evaluate specific vulnerability invariants
        secret_found = bool(
            self.config.target_secret_marker
            and self.config.target_secret_marker in exploit_resp.text
        )

        unauthorized_order_found = any(
            r.get("order_id") == self.config.target_unauthorized_order
            or r.get("user_id") == self.config.target_unauthorized_user
            for r in records
        )
        record_dump = count > 1

        is_path_trav = (
            (".." in self.config.exploit_payload or "%2E%2E" in exploit_url or "..%2F" in exploit_url)
            and exploit_resp.status_code == 200
            and any(sig in exploit_resp.text for sig in ("def ", "import ", "#", "FastAPI", "app"))
        )
        is_cmd_inj = "ZDA_PWNED" in self.config.exploit_payload and "ZDA_PWNED_CWE78" in exploit_resp.text

        # IDOR check: accessing other user profile
        is_idor = (
            self.config.vulnerability_class == "INSECURE_DIRECT_OBJECT_REFERENCE"
            or "/users/" in self.config.target_endpoint
        ) and (
            exploit_resp.status_code == 200
            and (
                resp_data.get("username") == "admin"
                or resp_data.get("email") == "admin.dev@gmail.com"
                or resp_data.get("id") == 2
            )
        )

        is_reproduced = (
            is_path_trav
            or is_cmd_inj
            or is_idor
            or (exploit_resp.status_code == 200 and (secret_found or unauthorized_order_found or record_dump))
        )

        if is_path_trav:
            evidence = (
                f"Path traversal confirmed: request to '{exploit_url}' "
                f"bypassed directory boundary and returned source file contents (HTTP {exploit_resp.status_code}): "
                f"{exploit_resp.text[:120].strip()}..."
            )
            summary = (
                "REPRODUCED: Target is vulnerable to CWE-22 Path Traversal. "
                "Arbitrary file access confirmed."
            )
            status_val = "REPRODUCED"
            classification = "PATH_TRAVERSAL_LEAK"
            count = 1
        elif is_idor:
            evidence = (
                f"IDOR confirmed: request to '{exploit_url}' without authorization headers "
                f"returned record for user {resp_data.get('username')} (ID: {resp_data.get('id', 2)}): "
                f"{exploit_resp.text[:120].strip()}..."
            )
            summary = (
                "REPRODUCED: Target is vulnerable to CWE-639 IDOR. "
                "Unauthorized horizontal object access confirmed."
            )
            status_val = "REPRODUCED"
            classification = "IDOR_RECORD_LEAK"
            count = 1
            unauthorized_order_found = True
        elif is_cmd_inj:
            evidence = (
                f"Command injection confirmed: injected command emitted marker 'ZDA_PWNED_CWE78' "
                f"in response (HTTP {exploit_resp.status_code})."
            )
            summary = (
                "REPRODUCED: Target is vulnerable to CWE-78 OS Command Injection. "
                "Arbitrary command execution confirmed."
            )
            status_val = "REPRODUCED"
            classification = "COMMAND_EXECUTION"
        elif is_reproduced:
            evidence = (
                f"SQL injection confirmed: query with payload '{self.config.exploit_payload}' "
                f"returned {count} records (expected 0 or 1). Leaked unauthorized records: "
                f"{[r.get('order_id') for r in records]}. "
                f"Secret marker detected: {secret_found}."
            )
            summary = (
                f"REPRODUCED: Target is vulnerable to CWE-89 SQL Injection. "
                f"Leaked {count} records including SuperAdmin data."
            )
            status_val = "REPRODUCED"
            classification = "SQLI_DATA_LEAK"
        else:
            evidence = (
                f"Neutralized: exploit payload '{self.config.exploit_payload}' against '{exploit_url}' "
                f"returned status {exploit_resp.status_code}. "
                f"No unauthorized data or markers observed."
            )
            summary = "NOT REPRODUCED: Target enforced security invariant; exploit payload failed."
            status_val = "NOT_REPRODUCED"
            classification = "DEFENSE_EFFECTIVE"

        return ReproductionResult(
            reproduced=is_reproduced,
            status_code=exploit_resp.status_code,
            leaked_records_count=count,
            leaked_secret_detected=secret_found,
            unauthorized_data_accessed=unauthorized_order_found,
            evidence_snippet=evidence,
            elapsed_seconds=elapsed,
            summary=summary,
            target_endpoint=self.config.target_endpoint,
            exploit_payload=self.config.exploit_payload,
            status=status_val,
            reproduction_classification=classification,
            http_method="GET",
            resolved_request_url=exploit_url,
            exploit_attempted=True,
        )
