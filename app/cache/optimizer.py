"""
Document Context Token Optimizer.
Reduces prompt token expenditure by extracting surgical vulnerability context,
normalizing threat intelligence references, and eliminating redundant document overhead.
"""

from __future__ import annotations

import re
from typing import List, Optional
from app.analysis.findings import Finding
from app.intelligence.evidence_normalizer import SecurityReference


class DocumentTokenOptimizer:
    """
    Optimizes document context and prompt content sent to LLMs,
    minimizing token waste while retaining full semantic fidelity for patch synthesis.
    """

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Heuristic token estimation (~4 characters per token)."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    @classmethod
    def optimize_document_context(
        cls,
        document_text: str,
        finding: Optional[Finding] = None,
        max_context_lines: int = 60,
    ) -> str:
        """
        Extract focused context window around the vulnerable sink/finding in a document.
        For smaller files (< 80 lines), returns the full document to avoid missing imports.
        For larger documents, returns imports + the enclosing vulnerable function/block.
        """
        lines = document_text.splitlines()
        total_lines = len(lines)

        # If document is already compact, preserve in full
        if total_lines <= 80 or not finding:
            return document_text

        target_line = finding.line_number or finding.sink_line or 1
        # 1-indexed to 0-indexed
        target_idx = max(0, min(total_lines - 1, target_line - 1))

        # Capture top-level imports (first 25 lines)
        import_lines = []
        for i, l in enumerate(lines[:25]):
            if l.startswith("import ") or l.startswith("from ") or l.startswith("#"):
                import_lines.append(l)

        # Calculate context window bounds
        half_window = max_context_lines // 2
        start_idx = max(0, target_idx - half_window)
        end_idx = min(total_lines, target_idx + half_window)

        # Adjust start_idx backwards to catch function/class definition if nearby
        for k in range(start_idx, max(0, start_idx - 15), -1):
            if lines[k].startswith("def ") or lines[k].startswith("class ") or lines[k].startswith("@"):
                start_idx = k
                break

        body_lines = lines[start_idx:end_idx]

        optimized_parts = []
        if import_lines and start_idx > 25:
            optimized_parts.append("\n".join(import_lines))
            optimized_parts.append("\n# ... [Unrelated code omitted for token efficiency] ...\n")

        optimized_parts.append("\n".join(body_lines))

        if end_idx < total_lines:
            optimized_parts.append("\n# ... [Remaining document omitted for token efficiency] ...\n")

        return "\n".join(optimized_parts)

    @classmethod
    def optimize_security_references(
        cls,
        references: Optional[List[SecurityReference]],
        max_refs: int = 3,
        max_excerpt_chars: int = 220,
    ) -> List[SecurityReference]:
        """
        Curb token waste in threat intelligence by capping references count
        and truncating verbose web excerpts to core remediation guidance.
        """
        if not references:
            return []

        optimized: List[SecurityReference] = []
        for ref in references[:max_refs]:
            excerpt = ref.excerpt.strip()
            # Collapse internal whitespace
            excerpt = re.sub(r"\s+", " ", excerpt)
            if len(excerpt) > max_excerpt_chars:
                excerpt = excerpt[:max_excerpt_chars].rstrip() + "..."

            optimized.append(
                SecurityReference(
                    source_url=ref.source_url,
                    title=ref.title,
                    excerpt=excerpt,
                    cwe_id=ref.cwe_id,
                    relationship=ref.relationship,
                )
            )
        return optimized
