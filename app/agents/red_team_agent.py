"""
Autonomous Red-Team Reproduction Agent.
Proposes bounded, structured reproduction payloads against designated local targets.
"""

from __future__ import annotations

from typing import Optional

from app.agents.base_agent import InferenceProvider
from app.analysis.findings import Finding, RouteInfo, VulnerabilityClass
from app.sandbox.reproduction import ReproductionTestConfig


class RedTeamAgent:
    """
    Proposes structured, bounded exploit payloads targeting the identified sinks.
    """

    def __init__(self, provider: Optional[InferenceProvider] = None) -> None:
        self.provider = provider

    def propose_reproduction_test(
        self,
        finding: Finding,
        route: Optional[RouteInfo] = None,
    ) -> ReproductionTestConfig:
        """
        Formulate a reproduction test targeting the vulnerable route parameter.
        Uses deterministic security heuristics or model guidance.
        """
        endpoint = (route.path if route else None) or (finding.metadata.get("route") if finding and finding.metadata else None) or "/api/orders"
        snippet = finding.code_snippet.lower() if finding and finding.code_snippet else ""
        cwe = finding.cwe if finding else "CWE-89"
        v_class = finding.vulnerability_class if finding else VulnerabilityClass.SQL_INJECTION
        primary_param = "user_id" if endpoint == "/api/orders" else "id"
        if route and route.parameters:
            primary_param = route.parameters[0]
        elif finding and finding.source_expression:
            primary_param = finding.source_expression

        # Live Adversarial Exploit Payload Generation via NVIDIA Nemotron
        live_payload = None
        if self.provider and getattr(self.provider, "is_configured", True) and self.provider.__class__.__name__ != "DeterministicTestModelClient":
            try:
                import json
                import re
                prompt = (
                    f"You are an adversarial Red Team penetration tester.\n"
                    f"Vulnerability: {cwe} ({v_class.value if hasattr(v_class, 'value') else v_class})\n"
                    f"Endpoint: {endpoint}\n"
                    f"Parameter: {primary_param}\n"
                    f"Vulnerable Code:\n{finding.code_snippet if finding else ''}\n\n"
                    f"Formulate a minimal exploit payload targeting this parameter.\n"
                    f"Return ONLY a JSON object: {{\"exploit_payload\": \"<string>\"}}"
                )
                resp = self.provider.complete(
                    prompt=prompt,
                    system_message="You are an autonomous adversarial penetration testing agent. Output only valid JSON.",
                    temperature=0.0,
                    max_tokens=256,
                )
                if resp and resp.content:
                    m = re.search(r'\{\s*"exploit_payload"\s*:\s*"([^"]+)"\s*\}', resp.content)
                    if m:
                        live_payload = m.group(1)
            except Exception:
                live_payload = None

        # 1. Path Traversal (CWE-22)
        if v_class == VulnerabilityClass.PATH_TRAVERSAL or cwe == "CWE-22" or "filename" in endpoint or "/files" in endpoint or "path" in snippet:
            return ReproductionTestConfig(
                http_method=route.method if route else "GET",
                target_endpoint=endpoint if ("/files" in endpoint or "{" in endpoint) else "/files/{filename:path}",
                param_name=primary_param if primary_param in ("filename", "path", "file", "filepath", "target") else "filename",
                exploit_payload=live_payload or "../../app.py",
                target_secret_marker="FastAPI",
                target_unauthorized_user="",
                target_unauthorized_order="",
                legitimate_user_id="test.txt",
                vulnerability_class="PATH_TRAVERSAL",
            )

        # 2. Insecure Direct Object Reference / IDOR (CWE-639)
        if v_class == VulnerabilityClass.IDOR or cwe == "CWE-639" or "/users" in endpoint or "{user_id}" in endpoint:
            return ReproductionTestConfig(
                http_method=route.method if route else "GET",
                target_endpoint=endpoint if ("/users" in endpoint or "{" in endpoint) else "/users/{user_id}",
                param_name=primary_param if primary_param not in ("username", "") else "user_id",
                exploit_payload=live_payload or "2",
                target_secret_marker="",
                target_unauthorized_user="admin",
                target_unauthorized_order="",
                legitimate_user_id="1",
                vulnerability_class="INSECURE_DIRECT_OBJECT_REFERENCE",
            )

        # 3. Command Injection (CWE-78)
        if v_class == VulnerabilityClass.COMMAND_INJECTION or cwe == "CWE-78":
            return ReproductionTestConfig(
                http_method=route.method if route else "GET",
                target_endpoint=endpoint,
                param_name=primary_param if primary_param not in ("id", "") else "cmd",
                exploit_payload=live_payload or "; echo ZDA_PWNED_CWE78",
                target_secret_marker="ZDA_PWNED_CWE78",
                target_unauthorized_user="",
                target_unauthorized_order="",
                legitimate_user_id="echo safe",
                vulnerability_class="COMMAND_INJECTION",
            )

        # 4. SQL Injection (CWE-89)
        if endpoint == "/login" or "login" in snippet or ("username" in snippet and "password" in snippet):
            return ReproductionTestConfig(
                http_method="POST",
                target_endpoint="/login",
                param_name="username",
                exploit_payload=live_payload or "admin' --",
                target_secret_marker="",
                target_unauthorized_user="admin",
                target_unauthorized_order="",
                legitimate_user_id="aman",
                vulnerability_class="SQL_INJECTION",
            )

        return ReproductionTestConfig(
            http_method=route.method if route else "GET",
            target_endpoint=endpoint,
            param_name=primary_param if primary_param not in ("username", "") else "user_id",
            exploit_payload=live_payload or "USR-101' OR '1'='1",
            target_secret_marker="CLASSIFIED: ZeroDay bounty escrow vault allocation",
            target_unauthorized_user="USR-103",
            target_unauthorized_order="ORD-9099",
            legitimate_user_id="USR-101",
            vulnerability_class="SQL_INJECTION",
        )
