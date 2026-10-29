"""
Unit Tests for Agent Subsystem: Deterministic Double, Blue Team, and Red Team.
"""

import os
from unittest.mock import MagicMock
import pytest

from app.core.errors import ProviderError
from app.agents.nemotron_client import (
    DeterministicTestModelClient,
    NemotronNebiusClient,
    CANONICAL_DIFF_REPAIR,
)
from app.agents.blue_team_agent import BlueTeamAgent
from app.agents.red_team_agent import RedTeamAgent
from app.analysis.findings import Finding, Severity, VulnerabilityClass


def test_deterministic_model_client_completion():
    client = DeterministicTestModelClient()
    resp = client.complete("Test prompt")
    assert resp.content == CANONICAL_DIFF_REPAIR
    assert resp.model_name == "deterministic-test-double"
    assert resp.provider_name == "offline_test"
    assert resp.total_tokens == 185
    assert client.call_count == 1


def test_blue_team_agent_extracts_clean_diff():
    # Model returns diff enclosed in markdown fences
    fenced_response = f"```diff\n{CANONICAL_DIFF_REPAIR}\n```"
    client = DeterministicTestModelClient(canned_response=fenced_response)
    agent = BlueTeamAgent(provider=client)

    diff, metrics = agent.synthesize_patch(
        target_path="target_app/app.py",
        vulnerable_code="query = f'SELECT ...'",
        findings=[],
    )

    assert diff.startswith("--- a/target_app/app.py")
    assert "```" not in diff
    assert metrics.total_tokens == 185


def test_red_team_agent_proposes_valid_config():
    agent = RedTeamAgent()
    dummy_finding = Finding(
        id="FIND-01",
        vulnerability_class=VulnerabilityClass.SQL_INJECTION,
        cwe="CWE-89",
        severity=Severity.HIGH,
        file_path="target_app/app.py",
        line_number=141,
        code_snippet="query = f'SELECT ...'",
        remediation_guidance="Use parameterized queries",
        title="SQL Injection Sink",
        description="Vulnerable unparameterized query",
    )

    config = agent.propose_reproduction_test(dummy_finding)
    assert config.target_endpoint == "/api/orders"
    assert config.param_name == "user_id"
    assert "OR '1'='1" in config.exploit_payload
    assert "CLASSIFIED" in config.target_secret_marker


def test_nemotron_nebius_client_unconfigured_raises_error():
    client = NemotronNebiusClient(api_key="")
    assert client.is_configured is False
    with pytest.raises(ProviderError, match="Nebius API key is not configured"):
        client.complete("Test prompt")


def test_nemotron_nebius_client_with_mocked_completion():
    client = NemotronNebiusClient(api_key="mock_key_123")
    mock_openai = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "--- a/file\n+++ b/file\n"
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    mock_resp.usage.prompt_tokens = 50
    mock_resp.usage.completion_tokens = 25
    mock_resp.usage.total_tokens = 75
    mock_openai.chat.completions.create.return_value = mock_resp
    client._client = mock_openai

    resp = client.complete("Hello")
    assert resp.content == "--- a/file\n+++ b/file\n"
    assert resp.prompt_tokens == 50
    assert resp.completion_tokens == 25
    assert resp.total_tokens == 75
    assert resp.provider_name == "nebius_token_factory"
