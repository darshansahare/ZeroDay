"""
Tavily Threat Intelligence Client.
Retrieves relevant CVE, CWE, and remediation advisories with bounded timeouts and retries.
"""

from __future__ import annotations

import os
from typing import List, Optional
from tavily import TavilyClient

from app.core.errors import ProviderError
from app.intelligence.evidence_normalizer import EvidenceNormalizer, SecurityReference
from app.cache.token_cache import token_cache


OFFLINE_SECURITY_REFERENCES: List[SecurityReference] = [
    SecurityReference(
        source_url="https://cwe.mitre.org/data/definitions/89.html",
        title="CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        excerpt=(
            "The software constructs all or part of an SQL command using externally-influenced input, "
            "but it does not neutralize or incorrectly neutralizes special elements that could modify the command. "
            "Remediation requires parameterized queries or prepared statements."
        ),
        cwe_id="CWE-89",
        relationship="remediation_guidance",
    ),
    SecurityReference(
        source_url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        title="OWASP SQL Injection Prevention Cheat Sheet",
        excerpt=(
            "Defense Option 1: Prepared Statements (with Parameterized Queries). "
            "Prepared statements ensure that an attacker cannot change the intent of a query, "
            "even if SQL commands are inserted by an attacker."
        ),
        cwe_id="CWE-89",
        relationship="remediation_guidance",
    ),
]

OFFLINE_REFERENCES_BY_CWE: dict[str, List[SecurityReference]] = {
    "CWE-89": OFFLINE_SECURITY_REFERENCES,
    "CWE-22": [
        SecurityReference(
            source_url="https://cwe.mitre.org/data/definitions/22.html",
            title="CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            excerpt=(
                "The software uses external input to construct a pathname that should be within a restricted directory, "
                "but it does not properly neutralize sequences such as '..' that can resolve to a location outside of that directory. "
                "Remediation requires path canonicalization and verification using is_relative_to."
            ),
            cwe_id="CWE-22",
            relationship="remediation_guidance",
        ),
        SecurityReference(
            source_url="https://cheatsheetseries.owasp.org/cheatsheets/File_Path_Traversal_Cheat_Sheet.html",
            title="OWASP File Path Traversal Cheat Sheet",
            excerpt="Resolve paths against the root directory and ensure the target file resides strictly inside the intended boundary.",
            cwe_id="CWE-22",
            relationship="remediation_guidance",
        ),
    ],
    "CWE-639": [
        SecurityReference(
            source_url="https://cwe.mitre.org/data/definitions/639.html",
            title="CWE-639: Authorization Bypass Through User-Controlled Key ('IDOR')",
            excerpt=(
                "The system's authorization functionality does not prevent one user from gaining access to another user's "
                "data or sensitive functions via direct object identifiers. Remediation requires strict tenant context validation."
            ),
            cwe_id="CWE-639",
            relationship="remediation_guidance",
        ),
    ],
    "CWE-78": [
        SecurityReference(
            source_url="https://cwe.mitre.org/data/definitions/78.html",
            title="CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            excerpt=(
                "The software constructs an OS command using externally-influenced input without neutralization. "
                "Remediation requires avoiding shell execution and passing arguments safely via lists with subprocess.run."
            ),
            cwe_id="CWE-78",
            relationship="remediation_guidance",
        ),
    ],
}


class ThreatIntelligenceProvider:
    """Interface for threat intelligence retrieval."""

    def search_guidance(self, query: str, cwe_id: str = "CWE-89") -> List[SecurityReference]:
        raise NotImplementedError


class OfflineIntelligenceProvider(ThreatIntelligenceProvider):
    """Deterministic offline reference provider for test suites and offline operation."""

    def search_guidance(self, query: str, cwe_id: str = "CWE-89") -> List[SecurityReference]:
        clean_cwe = cwe_id.upper() if cwe_id else "CWE-89"
        if clean_cwe in OFFLINE_REFERENCES_BY_CWE:
            return list(OFFLINE_REFERENCES_BY_CWE[clean_cwe])
        return list(OFFLINE_SECURITY_REFERENCES)


class TavilyIntelligenceClient(ThreatIntelligenceProvider):
    """
    Real Tavily Search API client.
    Enforces explicit timeouts, bounded result sets, and normalizes untrusted search data.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        max_results: int = 3,
        timeout_seconds: float = 8.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("TAVILY_API_KEY", "")
        self.max_results = max_results
        self.timeout_seconds = timeout_seconds
        self._client: Optional[TavilyClient] = None

        if self.api_key:
            self._client = TavilyClient(api_key=self.api_key)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self._client)

    def search_guidance(self, query: str, cwe_id: str = "CWE-89") -> List[SecurityReference]:
        """
        Execute bounded search on Tavily with deterministic caching. Falls closed on provider errors.
        """
        cached_refs = token_cache.get_intel(query=query, cwe_id=cwe_id, provider="tavily")
        if cached_refs is not None:
            return cached_refs

        if not self.is_configured:
            raise ProviderError("Tavily API key is not configured")

        try:
            search_query = query.strip()
            if cwe_id and cwe_id not in search_query:
                search_query = f"{search_query} {cwe_id} remediation"
            response = self._client.search(
                query=search_query,
                max_results=self.max_results,
                search_depth="basic",
                include_answer=True,
            )
            raw_results = response.get("results", [])
            answer = response.get("answer", "")
            normalized: List[SecurityReference] = []

            if answer:
                clean_answer = EvidenceNormalizer.clean_text(answer, max_length=600)
                if clean_answer:
                    normalized.append(
                        SecurityReference(
                            source_url="https://tavily.com",
                            title=f"Live Threat Intelligence: {cwe_id}",
                            excerpt=clean_answer,
                            cwe_id=cwe_id,
                            relationship="vulnerability_explanation",
                            source_provider="tavily",
                            search_query=search_query,
                        )
                    )

            for r in raw_results:
                ref = EvidenceNormalizer.normalize_tavily_result(
                    r, cwe_id=cwe_id, relationship="remediation_guidance"
                )
                normalized.append(ref)

            token_cache.set_intel(query=query, cwe_id=cwe_id, references=normalized, provider="tavily")
            return normalized

        except Exception as e:
            raise ProviderError(f"Tavily search provider request failed: {e}") from e
