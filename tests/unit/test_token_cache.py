"""
Comprehensive Unit Tests for Token Optimization and Multi-Tier Caching.
Validates LLM reasoning caching, document context optimization, threat intel caching,
FinOps token savings calculation, and cache lifecycle.
"""

import os
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.cache.token_cache import TokenOptimizationCache
from app.cache.optimizer import DocumentTokenOptimizer
from app.agents.base_agent import ModelCompletionResponse
from app.intelligence.evidence_normalizer import SecurityReference
from app.analysis.findings import AnalysisReport, Finding, RouteInfo, VulnerabilityClass, Severity, EvidenceStatus
from app.core.governance import GovernanceManager
from main import app


@pytest.fixture
def temp_cache_dir(tmp_path: Path):
    return tmp_path / ".cache"


@pytest.fixture
def isolated_cache(temp_cache_dir: Path):
    return TokenOptimizationCache(cache_dir=temp_cache_dir, ttl_seconds=3600, enabled=True)


def test_completion_cache_miss_and_hit(isolated_cache: TokenOptimizationCache):
    key = isolated_cache.make_completion_key(
        model="nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
        prompt="Fix SQL injection in login",
        system_message="You are an AppSec engineer",
        messages=[{"role": "user", "content": "Fix login"}],
        temperature=0.0,
    )

    # Initial lookup: Miss
    assert isolated_cache.get_completion(key) is None
    stats = isolated_cache.get_stats()
    assert stats["misses"] == 1
    assert stats["hits"] == 0

    # Store completion response
    mock_resp = ModelCompletionResponse(
        content="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@",
        prompt_tokens=500,
        completion_tokens=200,
        total_tokens=700,
        model_name="nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
        provider_name="nebius_token_factory",
        elapsed_seconds=1.5,
    )
    isolated_cache.set_completion(key, mock_resp)

    # Subsequent lookup: Hit
    cached = isolated_cache.get_completion(key)
    assert cached is not None
    assert cached.cached is True
    assert cached.tokens_saved == 700
    assert cached.content == mock_resp.content

    stats = isolated_cache.get_stats()
    assert stats["hits"] == 1
    assert stats["tokens_saved"] == 700
    assert stats["cost_saved_usd"] > 0


def test_completion_cache_ttl_expiration(temp_cache_dir: Path):
    # Short TTL of 1 second
    cache = TokenOptimizationCache(cache_dir=temp_cache_dir, ttl_seconds=1, enabled=True)
    key = cache.make_completion_key("model", "prompt")

    resp = ModelCompletionResponse(
        content="diff",
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        model_name="model",
        provider_name="test",
    )
    cache.set_completion(key, resp)

    # Immediate lookup: Hit
    assert cache.get_completion(key) is not None

    # Wait for TTL to expire
    time.sleep(1.1)
    assert cache.get_completion(key) is None


def test_cache_disk_persistence(temp_cache_dir: Path):
    cache1 = TokenOptimizationCache(cache_dir=temp_cache_dir, ttl_seconds=3600, enabled=True)
    key = cache1.make_completion_key("model-x", "fix vulnerability")
    resp = ModelCompletionResponse(
        content="patch-x",
        prompt_tokens=1000,
        completion_tokens=400,
        total_tokens=1400,
        model_name="model-x",
        provider_name="nebius",
    )
    cache1.set_completion(key, resp)

    # Verify persistent file exists
    assert (temp_cache_dir / "zeroday_token_cache.json").exists()

    # Load in new cache instance
    cache2 = TokenOptimizationCache(cache_dir=temp_cache_dir, ttl_seconds=3600, enabled=True)
    cached = cache2.get_completion(key)
    assert cached is not None
    assert cached.content == "patch-x"
    assert cached.tokens_saved == 1400


def test_threat_intelligence_caching(isolated_cache: TokenOptimizationCache):
    query = "SQL injection CWE-89"
    cwe_id = "CWE-89"

    assert isolated_cache.get_intel(query, cwe_id) is None

    refs = [
        SecurityReference(
            source_url="https://cwe.mitre.org/data/definitions/89.html",
            title="CWE-89 SQLi",
            excerpt="Use parameterized queries",
            cwe_id="CWE-89",
            relationship="remediation_guidance",
        )
    ]
    isolated_cache.set_intel(query, cwe_id, refs)

    cached_refs = isolated_cache.get_intel(query, cwe_id)
    assert cached_refs is not None
    assert len(cached_refs) == 1
    assert cached_refs[0].source_url == refs[0].source_url
    assert cached_refs[0].title == refs[0].title


def test_ast_document_caching(isolated_cache: TokenOptimizationCache):
    file_path = "app.py"
    content_hash = "abc123hash"

    assert isolated_cache.get_ast(file_path, content_hash) is None

    dummy_report = AnalysisReport(
        target_path=file_path,
        scanned_files_count=1,
        total_loc=50,
        findings=[
            Finding(
                id="FIND-1",
                vulnerability_class=VulnerabilityClass.SQL_INJECTION,
                cwe="CWE-89",
                title="SQL Injection",
                description="Test",
                severity=Severity.CRITICAL,
                evidence_status=EvidenceStatus.STATIC_SUSPICION,
                file_path=file_path,
                line_number=20,
                sink_line=25,
                source_expression="q",
                code_snippet="q = f'SELECT {x}'",
                remediation_guidance="Bind parameters",
            )
        ],
        routes=[
            RouteInfo(name="login", path="/login", method="POST", line_start=15, line_end=35)
        ],
        syntax_warnings=[],
        scan_duration_ms=5.0,
    )

    isolated_cache.set_ast(file_path, content_hash, dummy_report)

    cached = isolated_cache.get_ast(file_path, content_hash)
    assert cached is not None
    assert len(cached.findings) == 1
    assert cached.findings[0].id == "FIND-1"
    assert cached.routes[0].path == "/login"


def test_document_token_optimizer():
    # Test short document is not truncated
    short_doc = "def foo():\n    return 42\n"
    opt_short = DocumentTokenOptimizer.optimize_document_context(short_doc)
    assert opt_short == short_doc

    # Test long document extracts context around finding
    long_lines = [f"# line {i}" for i in range(100)]
    long_lines[50] = "def vulnerable_endpoint():"
    long_lines[55] = "    query = f'SELECT {param}'"
    long_doc = "\n".join(long_lines)

    finding = Finding(
        id="FIND-1",
        vulnerability_class=VulnerabilityClass.SQL_INJECTION,
        cwe="CWE-89",
        title="SQLi",
        description="test",
        severity=Severity.CRITICAL,
        evidence_status=EvidenceStatus.STATIC_SUSPICION,
        file_path="app.py",
        line_number=55,
        sink_line=55,
        source_expression="param",
        code_snippet="query = ...",
        remediation_guidance="fix",
    )

    optimized = DocumentTokenOptimizer.optimize_document_context(long_doc, finding=finding, max_context_lines=40)
    assert "vulnerable_endpoint" in optimized
    assert "query = f'SELECT {param}'" in optimized
    assert len(optimized.splitlines()) < len(long_lines)

    # Test reference excerpt optimization
    refs = [
        SecurityReference(
            source_url="http://example.com",
            title="Ref",
            excerpt="A" * 500,
            cwe_id="CWE-89",
            relationship="remediation_guidance",
        )
    ]
    opt_refs = DocumentTokenOptimizer.optimize_security_references(refs, max_excerpt_chars=100)
    assert len(opt_refs[0].excerpt) <= 103  # 100 + "..."


def test_governance_cache_tracking():
    gov = GovernanceManager()
    gov.reset()

    gov.record_cache_miss()
    assert gov.cache_misses == 1

    gov.record_cache_hit(prompt_tokens=1000, completion_tokens=500)
    assert gov.cache_hits == 1
    assert gov.total_cached_prompt_tokens == 1000
    assert gov.total_cached_completion_tokens == 500
    assert gov.total_cost_saved_usd > 0

    summary = gov.get_finops_summary()
    assert summary["cache_hits"] == 1
    assert summary["cache_misses"] == 1
    assert summary["cache_hit_rate_pct"] == 50.0
    assert summary["total_tokens_saved"] == 1500


def test_cache_api_routes():
    client = TestClient(app)

    # Check /api/cache/stats
    resp = client.get("/api/cache/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "hits" in data
    assert "misses" in data
    assert "tokens_saved" in data
    assert "cost_saved_usd" in data

    # Check /api/cache/clear
    admin_key = os.getenv("ADMIN_API_KEY", "test-admin-secret-key-for-zeroday-testing-only")
    clear_resp = client.post("/api/cache/clear", headers={"X-API-Key": admin_key})
    assert clear_resp.status_code == 200
    assert clear_resp.json()["status"] == "success"
