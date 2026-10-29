"""
Patch Integrity and Safety Validation.
Ensures patches are well-formed unified diffs, adhere to file whitelists,
and strictly prevent modification of test suites, configs, or external paths.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Set, Optional
from pydantic import BaseModel, Field


class PatchValidationResult(BaseModel):
    """Structured result of patch integrity validation."""
    is_valid: bool = Field(..., description="Whether the patch conforms to all integrity rules")
    patch_hash: str = Field(..., description="SHA-256 hex digest of the patch text")
    target_files: List[str] = Field(default_factory=list, description="Files affected by the patch")
    rejection_reason: Optional[str] = Field(None, description="Detailed explanation if rejected")


class PatchValidator:
    """
    Validates patch format, permitted file scope, and prevents tampering with test suites.
    """

    DIFF_HEADER_REGEX = re.compile(r"^--- (?:a/)?([^\s\t\n]+)", re.MULTILINE)
    DIFF_PLUS_HEADER_REGEX = re.compile(r"^\+\+\+ (?:b/)?([^\s\t\n]+)", re.MULTILINE)

    FORBIDDEN_PREFIXES = (
        "tests/",
        "tests\\",
        ".git/",
        ".git\\",
        ".github/",
        "app/verification/",
        "app/verification\\",
        "app/core/",
        "app/core\\",
    )

    def __init__(self, permitted_files: Optional[Set[str]] = None) -> None:
        self.permitted_files = permitted_files

    def calculate_hash(self, patch_content: str) -> str:
        """Calculate deterministic SHA-256 digest of the patch."""
        return hashlib.sha256(patch_content.strip().encode("utf-8")).hexdigest()

    def extract_target_files(self, patch_content: str) -> List[str]:
        """Extract all target file paths referenced in the diff headers."""
        plus_matches = self.DIFF_PLUS_HEADER_REGEX.findall(patch_content)
        # Normalize paths (forward slashes, strip dev/null)
        normalized = []
        for path in plus_matches:
            clean = path.replace("\\", "/").strip()
            if clean and clean != "/dev/null" and clean not in normalized:
                normalized.append(clean)
        return normalized

    def validate_patch(self, patch_content: str) -> PatchValidationResult:
        """
        Perform rigorous validation on patch content.
        Fails closed on any ambiguity, path traversal, or forbidden target.
        """
        patch_hash = self.calculate_hash(patch_content)

        if not patch_content or not patch_content.strip():
            return PatchValidationResult(
                is_valid=False,
                patch_hash=patch_hash,
                target_files=[],
                rejection_reason="Empty or whitespace-only patch content"
            )

        # Check for diff structure
        if "--- " not in patch_content or "+++ " not in patch_content:
            return PatchValidationResult(
                is_valid=False,
                patch_hash=patch_hash,
                target_files=[],
                rejection_reason="Malformed patch: missing standard unified diff headers (--- / +++)"
            )

        if "@@" not in patch_content:
            return PatchValidationResult(
                is_valid=False,
                patch_hash=patch_hash,
                target_files=[],
                rejection_reason="Malformed patch: missing unified diff hunk header (@@)"
            )

        target_files = self.extract_target_files(patch_content)
        if not target_files:
            return PatchValidationResult(
                is_valid=False,
                patch_hash=patch_hash,
                target_files=[],
                rejection_reason="No target files identified in unified diff headers"
            )

        for target in target_files:
            # 1. Path traversal and absolute path check (including Windows drive letters)
            if ".." in target or target.startswith("/") or target.startswith("\\") or ":" in target:
                return PatchValidationResult(
                    is_valid=False,
                    patch_hash=patch_hash,
                    target_files=target_files,
                    rejection_reason=f"Path traversal detected in patch target: '{target}'"
                )

            # 2. Forbidden files and directories (tests, verification engine, git internal, configs)
            normalized_target = target.lower()
            if normalized_target in (".env", ".env.local", ".env.production", "config.py") or any(
                normalized_target.endswith("/" + s) or normalized_target.endswith("\\" + s)
                for s in (".env", "config.py")
            ):
                return PatchValidationResult(
                    is_valid=False,
                    patch_hash=patch_hash,
                    target_files=target_files,
                    rejection_reason=f"Tampering detected: patches may not modify configuration or environment files ('{target}')"
                )

            for forbidden in self.FORBIDDEN_PREFIXES:
                if normalized_target.startswith(forbidden.lower()):
                    return PatchValidationResult(
                        is_valid=False,
                        patch_hash=patch_hash,
                        target_files=target_files,
                        rejection_reason=(
                            f"Tampering detected: patches may not modify verification files, "
                            f"tests, or engine logic ('{target}')"
                        )
                    )

            # 3. Whitelist enforcement
            if self.permitted_files is not None:
                # Normalize permitted files for robust matching
                permitted_normalized = {p.replace("\\", "/").lower() for p in self.permitted_files}
                permitted_basenames = {p.split("/")[-1] for p in permitted_normalized}
                target_norm = target.lower()
                target_base = target_norm.split("/")[-1]
                if target_norm not in permitted_normalized and target_base not in permitted_basenames:
                    return PatchValidationResult(
                        is_valid=False,
                        patch_hash=patch_hash,
                        target_files=target_files,
                        rejection_reason=(
                            f"Target file '{target}' is not in the permitted remediation whitelist: "
                            f"{list(self.permitted_files)}"
                        )
                    )

        return PatchValidationResult(
            is_valid=True,
            patch_hash=patch_hash,
            target_files=target_files,
            rejection_reason=None
        )
