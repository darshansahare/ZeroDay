"""
ZeroDay Arena Dependency Scanner.
Parses dependency manifests (requirements.txt, pyproject.toml) and correlates
packages against known security advisories with explicit confidence levels.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import AppConfig, get_config
from app.analysis.findings import DependencyFinding, Severity
from app.core.errors import DependencyAnalysisError


# Deterministic offline advisory database for Python package ecosystems
# Contains confirmed vulnerable version bounds for security benchmarks
OFFLINE_ADVISORY_DB: Dict[str, List[Dict[str, Any]]] = {
    "sqlparse": [
        {
            "id": "CVE-2024-4340",
            "vulnerable_versions": ["<0.5.0"],
            "severity": Severity.HIGH,
            "description": "Recursion depth limit bypass leading to denial of service in sqlparse parsing.",
            "remediation": "Upgrade sqlparse to >=0.5.0",
        }
    ],
    "cryptography": [
        {
            "id": "CVE-2023-49083",
            "vulnerable_versions": ["<41.0.6"],
            "severity": Severity.MEDIUM,
            "description": "NULL-pointer dereference in PKCS7 parsing.",
            "remediation": "Upgrade cryptography to >=41.0.6",
        }
    ],
    "urllib3": [
        {
            "id": "CVE-2023-45803",
            "vulnerable_versions": ["<2.0.7", ">=1.0.0,<1.26.18"],
            "severity": Severity.MEDIUM,
            "description": "Request body not stripped on HTTP 303 redirect leading to credential leak.",
            "remediation": "Upgrade urllib3 to >=2.0.7 or >=1.26.18",
        }
    ],
    "jinja2": [
        {
            "id": "CVE-2024-22195",
            "vulnerable_versions": ["<3.1.3"],
            "severity": Severity.HIGH,
            "description": "Cross-site scripting (XSS) vulnerability via xmlattr filter.",
            "remediation": "Upgrade jinja2 to >=3.1.3",
        }
    ],
}


class DependencyScanner:
    """
    Deterministic manifest scanner.
    Parses pinned and range dependencies without executing setup scripts.
    """

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config = config or get_config()

    def scan_manifest(self, manifest_path: Path | str) -> List[DependencyFinding]:
        """
        Scan a manifest file within the workspace root.
        Supports requirements.txt format.
        """
        validated_path = self.config.validate_path_within_workspace(manifest_path)
        if not validated_path.exists():
            return []

        rel_path = str(validated_path.relative_to(self.config.workspace_root))
        findings: List[DependencyFinding] = []

        try:
            with open(validated_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            raise DependencyAnalysisError(
                f"Failed to read dependency manifest {rel_path}: {e}",
                details={"file": rel_path},
            )

        for line_idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            # Ignore empty lines, comments, and pip flags
            if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
                continue

            parsed = self._parse_requirement_line(line)
            if not parsed:
                continue

            package_name, version_spec, is_pinned, exact_version = parsed
            correlated = self._correlate_advisory(
                package_name, version_spec, is_pinned, exact_version, rel_path, line_idx
            )
            if correlated:
                findings.append(correlated)

        return findings

    def _parse_requirement_line(
        self, line: str
    ) -> Optional[Tuple[str, str, bool, Optional[str]]]:
        """
        Parse requirement string: package==1.2.3, package>=1.2.3, or package.
        Returns: (name, version_spec, is_pinned, exact_version)
        """
        # Strip inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        # Match package name and specifier
        # PEP 508 basic pattern
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=><~^!].*)?$", line)
        if not match:
            return None

        pkg_name = match.group(1).lower().replace("_", "-")
        raw_spec = match.group(2).strip() if match.group(2) else ""

        is_pinned = False
        exact_version: Optional[str] = None

        if raw_spec.startswith("=="):
            is_pinned = True
            exact_version = raw_spec[2:].strip()

        return pkg_name, raw_spec, is_pinned, exact_version

    def _correlate_advisory(
        self,
        package_name: str,
        version_spec: str,
        is_pinned: bool,
        exact_version: Optional[str],
        manifest_path: str,
        line_number: int,
    ) -> Optional[DependencyFinding]:
        """Correlate package against advisory database."""
        if package_name not in OFFLINE_ADVISORY_DB:
            return None

        advisories = OFFLINE_ADVISORY_DB[package_name]
        for adv in advisories:
            # If version is pinned, we can make an exact deterministic evaluation
            if is_pinned and exact_version:
                is_vulnerable = self._is_version_in_ranges(exact_version, adv["vulnerable_versions"])
                if is_vulnerable:
                    return DependencyFinding(
                        id=f"DEP-{adv['id']}",
                        package_name=package_name,
                        installed_version_spec=f"=={exact_version}",
                        is_pinned=True,
                        manifest_file=manifest_path,
                        line_number=line_number,
                        matched_advisory_id=adv["id"],
                        advisory_severity=adv["severity"],
                        confidence="CONFIRMED_MATCH",
                        description=adv["description"],
                        remediation=adv["remediation"],
                    )
            elif version_spec:
                # Range specifier (e.g. >=1.0.0 or ~=2.1): uncertain match
                return DependencyFinding(
                    id=f"DEP-{adv['id']}",
                    package_name=package_name,
                    installed_version_spec=version_spec,
                    is_pinned=False,
                    manifest_file=manifest_path,
                    line_number=line_number,
                    matched_advisory_id=adv["id"],
                    advisory_severity=adv["severity"],
                    confidence="UNCERTAIN",
                    description=f"Potential advisory match: {adv['description']}",
                    remediation=adv["remediation"],
                )
        return None

    def _is_version_in_ranges(self, version: str, ranges: List[str]) -> bool:
        """Simple version comparator for standard SemVer/CalVer tuples."""
        try:
            v_tuple = tuple(int(x) for x in re.split(r"[\.\-]", version)[:3] if x.isdigit())
        except Exception:
            return False

        for r in ranges:
            if r.startswith("<"):
                bound = r[1:].strip()
                bound_tuple = tuple(int(x) for x in re.split(r"[\.\-]", bound)[:3] if x.isdigit())
                if v_tuple < bound_tuple:
                    return True
        return False
