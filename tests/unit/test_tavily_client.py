"""
Unit Tests for Tavily Threat Intelligence Client.
"""

from unittest.mock import MagicMock
import pytest

from app.core.errors import ProviderError
from app.intelligence.tavily_client import (
    OfflineIntelligenceProvider,
    TavilyIntelligenceClient,
    OFFLINE_SECURITY_REFERENCES,
)


def test_offline_provider_returns_static_advisories():
    provider = OfflineIntelligenceProvider()
    refs = provider.search_guidance("SQL injection")
    assert len(refs) == len(OFFLINE_SECURITY_REFERENCES)
    assert refs[0].cwe_id == "CWE-89"
    assert "cwe.mitre.org" in refs[0].source_url


def test_tavily_client_unconfigured_raises_provider_error():
    client = TavilyIntelligenceClient(api_key="")
    assert client.is_configured is False
    with pytest.raises(ProviderError, match="Tavily API key is not configured"):
        client.search_guidance("SQL injection")


def test_tavily_client_with_mocked_results():
    client = TavilyIntelligenceClient(api_key="mock_test_key_123")
    mock_tavily = MagicMock()
    mock_tavily.search.return_value = {
        "results": [
            {
                "url": "https://owasp.org/sqli",
                "title": "OWASP SQLi Guide",
                "content": "Defense in depth requires parameterized statements.",
            }
        ]
    }
    client._client = mock_tavily

    refs = client.search_guidance("SQL injection")
    assert len(refs) == 1
    assert refs[0].source_url == "https://owasp.org/sqli"
    assert refs[0].title == "OWASP SQLi Guide"
    assert "parameterized statements" in refs[0].excerpt
    mock_tavily.search.assert_called_once()
