"""
Unit Tests for Evidence Normalizer and Security Reference Handling.
"""

from app.intelligence.evidence_normalizer import EvidenceNormalizer, SecurityReference


def test_clean_text_strips_html_and_collapses_whitespace():
    raw_html = "<p>This is a <b>critical</b> SQL injection <script>alert(1)</script> vulnerability.   </p>"
    cleaned = EvidenceNormalizer.clean_text(raw_html, max_length=100)
    assert "<script>" not in cleaned
    assert "<b>" not in cleaned
    assert "This is a critical SQL injection alert(1) vulnerability." == cleaned


def test_clean_text_truncates_oversized_content():
    long_text = "A" * 600
    cleaned = EvidenceNormalizer.clean_text(long_text, max_length=50)
    assert len(cleaned) <= 53  # 50 chars + "..."
    assert cleaned.endswith("...")


def test_normalize_tavily_result():
    raw_data = {
        "url": "https://example.com/cve-2024-sqli",
        "title": "Advisory for SQL Injection",
        "content": "Use <code>parameterized queries</code> to prevent attacks.",
    }
    ref = EvidenceNormalizer.normalize_tavily_result(raw_data, cwe_id="CWE-89")
    assert ref.source_url == "https://example.com/cve-2024-sqli"
    assert ref.title == "Advisory for SQL Injection"
    assert "parameterized queries" in ref.excerpt
    assert "<code>" not in ref.excerpt
    assert ref.cwe_id == "CWE-89"
    assert ref.relationship == "remediation_guidance"
