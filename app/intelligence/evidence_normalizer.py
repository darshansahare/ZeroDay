"""
Evidence Normalization for External Threat Intelligence.
Sanitizes and normalizes untrusted search results into safe, structured records.
"""

from __future__ import annotations

import datetime
import html
import re
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class SecurityReference(BaseModel):
    """Normalized, safe security intelligence reference."""
    source_url: str = Field(..., description="Source URL of security reference")
    title: str = Field(..., description="Document or advisory title")
    excerpt: str = Field(..., description="Bounded, sanitized text excerpt")
    retrieved_at: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    cwe_id: Optional[str] = "CWE-89"
    relationship: str = "remediation_guidance"
    source_provider: str = Field("threat_intelligence", description="Provider origin: tavily, etc.")
    search_query: Optional[str] = Field(None, description="Search query or finding context")


class EvidenceNormalizer:
    """
    Sanitizes raw search snippets into untrusted-safe data structures.
    Never executes or evaluates external content.
    """

    TAG_CLEANER = re.compile(r"<[^>]+>")

    @classmethod
    def clean_text(cls, text: str, max_length: int = 500) -> str:
        """Strip HTML tags, unescape entities, and bound text length."""
        if not text:
            return ""
        stripped = cls.TAG_CLEANER.sub("", text)
        unescaped = html.unescape(stripped).strip()
        # Collapse excessive whitespace
        collapsed = " ".join(unescaped.split())
        if len(collapsed) > max_length:
            return collapsed[:max_length] + "..."
        return collapsed

    @classmethod
    def normalize_tavily_result(
        cls,
        raw_result: Dict[str, Any],
        cwe_id: str = "CWE-89",
        relationship: str = "remediation_guidance",
        search_query: Optional[str] = None,
    ) -> SecurityReference:
        """Normalize a raw Tavily search result dict into a SecurityReference."""
        url = str(raw_result.get("url", "")).strip()
        title = cls.clean_text(str(raw_result.get("title", "Advisory Reference")), max_length=150)
        content = cls.clean_text(str(raw_result.get("content", "")))

        return SecurityReference(
            source_url=url,
            title=title,
            excerpt=content,
            cwe_id=cwe_id,
            relationship=relationship,
            source_provider="tavily",
            search_query=search_query,
        )


