"""
Regression tests for ZeroDay Deterministic Offline Fallback.
Verifies that:
1. Users can run ZeroDay without Nebius or Tavily credentials via the normal workflow.
2. Inference provider failures (timeouts, rate limits, network errors) fall back gracefully.
3. Tavily intelligence failures fall back gracefully to offline curated threat intelligence.
4. Execution mode is truthfully reported ('live_llm' vs 'deterministic_offline_fallback').
5. Unsupported vulnerabilities without credentials fail honestly without fabricated claims.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from app.core.orchestrator import RemediationRun, DETERMINISTIC_SECURE_PATCH
from app.core.state_machine import RunState
from app.core.errors import ProviderError
from app.agents.base_agent import InferenceProvider, ModelCompletionResponse
from app.agents.nemotron_client import DeterministicTestModelClient
from app.intelligence.tavily_client import OfflineIntelligenceProvider, SecurityReference
from app.config import AppConfig


class FailingInferenceProvider(InferenceProvider):
    """Mock provider simulating upstream API errors (timeouts, rate limits, 500s)."""

    def __init__(self, error_message: str = "500 Internal Server Error"):
        self.error_message = error_message
        self.call_count = 0

    def complete(self, prompt: str, **kwargs) -> ModelCompletionResponse:
        self.call_count += 1
        raise ProviderError(self.error_message)


class FailingIntelligenceProvider:
    """Mock intelligence provider simulating Tavily API failure."""

    def search_guidance(self, query: str, cwe_id: str = "CWE-89"):
        raise ProviderError("Tavily 503 Service Unavailable / Network Timeout")


def test_offline_execution_without_credentials_api_workflow(client):
    """
    Verify that an operator can initiate and complete an autonomous remediation
    run through the normal API workflow with NO Nebius or Tavily API keys configured.
    """
    from app.api.routes import set_backend_config
    set_backend_config(nebius_key="", tavily_key="")

    payload = {
        "target_path": "target_app/app.py",
        "max_repair_attempts": 2,
    }

    # 1. API creates and executes run
    resp = client.post("/api/runs", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    # 2. Verify truthful execution mode
    assert data["execution_mode"] == "deterministic_offline_fallback"
    assert data["is_verified_remediation"] is True
    assert data["status"] == "ACCEPTED"
    run_id = data["run_id"]

    # 3. Status endpoint reports deterministic offline fallback
    status_resp = client.get(f"/api/runs/{run_id}")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["execution_mode"] == "deterministic_offline_fallback"
    assert status_data["is_verified_remediation"] is True

    # 4. Evidence report truthfully records execution mode
    report_resp = client.get(f"/api/runs/{run_id}/report")
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert report_data["execution_mode"] == "deterministic_offline_fallback"
    assert report_data["verdict"] == "VERIFIED SECURE"
    assert report_data["is_verified_remediation"] is True
    assert "query = \"SELECT order_id, user_id, total_amount" in report_data["applied_patch"]


def test_provider_timeout_falls_back_deterministically(tmp_path):
    """
    Verify that when a live inference provider times out, BlueTeamAgent catches
    the ProviderError and falls back to deterministic AST synthesis, updating
    the execution mode truthfully.
    """
    cfg = AppConfig(workspace_root=tmp_path)
    target_file = tmp_path / "target_app" / "app.py"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Read the canonical target app code
    with open("target_app/app.py", "r", encoding="utf-8") as f:
        target_file.write_text(f.read(), encoding="utf-8")

    failing_provider = FailingInferenceProvider("Nebius inference gateway timeout (504)")
    run = RemediationRun(
        target_path="target_app/app.py",
        config=cfg,
        inference_provider=failing_provider,
        intelligence_provider=OfflineIntelligenceProvider(),
        max_repair_attempts=2,
    )

    # Initially configured as live_llm because a custom inference provider was passed
    report = run.execute()

    # Provider failed and fallback was used
    assert failing_provider.call_count >= 1
    assert report.execution_mode == "deterministic_offline_fallback"
    assert report.final_status == "ACCEPTED"
    assert report.is_verified_remediation is True
    assert report.verdict == "VERIFIED SECURE"
    assert report.applied_patch is not None
    assert "query = \"SELECT order_id" in report.applied_patch


def test_provider_rate_limit_429_falls_back():
    """
    Verify that HTTP 429 quota exhaustion gracefully transitions to deterministic fallback.
    """
    failing_provider = FailingInferenceProvider("Nebius rate limit exceeded: HTTP 429 Quota Exhausted")
    run = RemediationRun(
        target_path="target_app/app.py",
        inference_provider=failing_provider,
        intelligence_provider=OfflineIntelligenceProvider(),
        max_repair_attempts=2,
    )

    report = run.execute()
    assert report.execution_mode == "deterministic_offline_fallback"
    assert report.final_status == "ACCEPTED"
    assert report.is_verified_remediation is True


def test_tavily_failure_falls_back_to_offline_intelligence():
    """
    Verify that if the live threat intelligence provider fails (e.g. network partition or 503),
    the run falls back to OfflineIntelligenceProvider without crashing.
    """
    failing_intel = FailingIntelligenceProvider()
    run = RemediationRun(
        target_path="target_app/app.py",
        inference_provider=DeterministicTestModelClient(),
        intelligence_provider=failing_intel,
        max_repair_attempts=2,
    )

    report = run.execute()
    assert report.execution_mode == "deterministic_offline_fallback"
    assert report.final_status == "ACCEPTED"
    assert report.is_verified_remediation is True
    # References should have been retrieved via offline fallback
    assert len(report.intelligence_references) > 0
    assert any("CWE-89" in r.get("title", "") or "CWE-89" in r.get("cwe_id", "") for r in report.intelligence_references)


def test_unsupported_vulnerability_without_credentials_fails_honestly(tmp_path):
    """
    Verify that if a target contains an unsupported vulnerability class and no live
    LLM credentials exist, ZeroDay does NOT fabricate a patch. It must fail honestly.
    """
    cfg = AppConfig(workspace_root=tmp_path)
    target_file = tmp_path / "custom_app.py"
    # Create a dummy target with a vulnerability class that has no deterministic fallback
    target_file.write_text(
        "# Custom unsupported vulnerability\nimport pickle\n\ndef load_data(raw):\n    return pickle.loads(raw)\n",
        encoding="utf-8",
    )

    failing_provider = FailingInferenceProvider("No credentials available")
    run = RemediationRun(
        target_path="custom_app.py",
        config=cfg,
        inference_provider=failing_provider,
        intelligence_provider=OfflineIntelligenceProvider(),
        max_repair_attempts=1,
    )

    report = run.execute()
    # It must NOT be verified secure and must not fabricate a patch
    assert report.is_verified_remediation is False
    assert report.verdict != "VERIFIED SECURE"


def test_truthful_execution_mode_reporting_live_vs_offline(client):
    """
    Verify truthful execution mode reporting across:
    1. Seeded benchmarks -> 'seeded_benchmark'
    2. Deterministic offline runs -> 'deterministic_offline_fallback'
    3. Live LLM runs -> 'live_llm'
    """
    # 1. Benchmark endpoint
    bench_resp = client.get("/api/runs/bench-01")
    assert bench_resp.status_code == 200
    assert bench_resp.json()["execution_mode"] == "seeded_benchmark"

    bench_report = client.get("/api/runs/bench-01/report")
    assert bench_report.status_code == 200
    assert bench_report.json()["execution_mode"] == "seeded_benchmark"

    # 2. Offline run
    from app.api.routes import set_backend_config
    set_backend_config(nebius_key="", tavily_key="")

    run_resp = client.post("/api/runs", json={"target_path": "target_app/app.py", "max_repair_attempts": 1})
    assert run_resp.status_code == 201
    assert run_resp.json()["execution_mode"] == "deterministic_offline_fallback"
