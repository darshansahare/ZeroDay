"""
Structured findings and evidence status models for ZeroDay Arena.
Strictly distinguishes between static suspicion, confirmed reproduction, and verified patches.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    """
    Measurable lifecycle status of a vulnerability finding.
    These states are strictly NOT interchangeable.
    """
    STATIC_SUSPICION = "STATIC_SUSPICION"         # Static AST or manifest pattern matched; unconfirmed
    CONFIRMED_REPRODUCED = "CONFIRMED_REPRODUCED" # Actively proven exploitable in controlled sandbox
    PATCH_SYNTHESIZED = "PATCH_SYNTHESIZED"       # Patch code proposed; unverified
    PATCH_VERIFIED = "PATCH_VERIFIED"             # Independently passed regression & security gates
    REJECTED = "REJECTED"                         # Failed regression, failed neutralization, or malformed


class Severity(str, Enum):
    """Vulnerability severity tier."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VulnerabilityClass(str, Enum):
    """Taxonomy of security vulnerability classes."""
    SQL_INJECTION = "SQL_INJECTION"               # CWE-89
    COMMAND_INJECTION = "COMMAND_INJECTION"       # CWE-78
    PATH_TRAVERSAL = "PATH_TRAVERSAL"             # CWE-22
    UNSAFE_DESERIALIZATION = "UNSAFE_DESERIALIZATION" # CWE-502
    SSRF = "SSRF"                                 # CWE-918
    IDOR = "INSECURE_DIRECT_OBJECT_REFERENCE"     # CWE-639
    HARDCODED_SECRET = "HARDCODED_SECRET"         # CWE-798
    WEAK_CRYPTO = "WEAK_CRYPTOGRAPHY"             # CWE-327 / CWE-328
    OPEN_REDIRECT = "OPEN_REDIRECT"               # CWE-601
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION" # CWE-942
    DEBUG_MODE_ENABLED = "DEBUG_MODE_ENABLED"     # CWE-489
    INSECURE_COOKIE = "INSECURE_COOKIE"           # CWE-614 / CWE-1004
    DEPENDENCY_VULNERABILITY = "DEPENDENCY_VULN"  # CWE-1395
    UNVALIDATED_INPUT = "UNVALIDATED_INPUT"       # CWE-20
    UNKNOWN = "UNKNOWN"


class Finding(BaseModel):
    """A structured finding emitted by the analysis engine."""
    id: str = Field(description="Deterministic finding identifier, e.g. FIND-CWE-89-001")
    vulnerability_class: VulnerabilityClass
    cwe: str = Field(description="Common Weakness Enumeration identifier, e.g. CWE-89")
    title: str
    description: str
    severity: Severity
    evidence_status: EvidenceStatus = Field(default=EvidenceStatus.STATIC_SUSPICION)
    file_path: str = Field(description="Relative path within workspace root")
    line_number: int
    sink_line: Optional[int] = None
    source_expression: Optional[str] = None
    code_snippet: str
    remediation_guidance: str
    confidence: str = Field(default="HIGH", description="'CONFIRMED', 'HIGH', 'MEDIUM', 'CANDIDATE'")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DependencyFinding(BaseModel):
    """A vulnerability finding correlated with a third-party dependency."""
    id: str
    package_name: str
    installed_version_spec: str
    is_pinned: bool
    manifest_file: str
    line_number: int
    matched_advisory_id: Optional[str] = None
    advisory_severity: Optional[Severity] = None
    confidence: str = Field(description="'CONFIRMED_MATCH' if exact version affected, else 'UNCERTAIN'")
    description: str
    remediation: str


class RouteInfo(BaseModel):
    """Statically extracted FastAPI / API route metadata."""
    name: str
    method: str
    path: str
    line_start: int
    line_end: int
    parameters: List[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    """Comprehensive, machine-readable output of Phase 1 static analysis."""
    target_path: str
    scanned_files_count: int
    total_loc: int
    routes: List[RouteInfo] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    dependency_findings: List[DependencyFinding] = Field(default_factory=list)
    syntax_warnings: List[Dict[str, Any]] = Field(default_factory=list)
    files_discovered: List[str] = Field(default_factory=list)
    files_analyzed: List[str] = Field(default_factory=list)
    files_skipped: List[Dict[str, str]] = Field(default_factory=list)
    coverage_status: str = Field(default="FULL")
    scanner_rules_executed: List[str] = Field(default_factory=list)
    summary: Dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total_findings": 0,
        }
    )
    scan_duration_ms: float = 0.0
