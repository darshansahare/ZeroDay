"""
Evidence Report Schema and Generator for ZeroDay Arena.
Produces comprehensive, machine-readable JSON reports detailing every step of the remediation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.analysis.findings import Finding, DependencyFinding
from app.sandbox.reproduction import ReproductionResult
from app.verification.oracle import VerificationReport


class ModelUsageRecord(BaseModel):
    """Execution telemetry for AI model invocations."""
    provider: Optional[str] = None
    model: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    cached: bool = False
    tokens_saved: int = 0


class EvidenceReport(BaseModel):
    """Final, machine-readable remediation outcome report."""
    run_id: str
    target_path: str
    repo_url: Optional[str] = None
    pinned_commit: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None
    final_status: str  # ACCEPTED, REJECTED, FAILED, CANCELLED
    execution_mode: str = "live_llm"  # live_llm, deterministic_offline_fallback, seeded_benchmark
    is_verified_remediation: bool = False
    verdict: str = "INCONCLUSIVE"  # VERIFIED SECURE, REGRESSION FAILED, SECURITY RE-TEST FAILED, INCONCLUSIVE, EXECUTION FAILED, PARTIAL
    coverage_status: str = "FULL"  # FULL, PARTIAL
    
    # Repository Ingestion & Discovery
    files_discovered: List[str] = Field(default_factory=list)
    files_analyzed: List[str] = Field(default_factory=list)
    files_skipped: List[Dict[str, str]] = Field(default_factory=list)
    scanner_rules_executed: List[str] = Field(default_factory=list)

    # Analysis & Intelligence
    code_findings: List[Finding] = Field(default_factory=list)
    dependency_findings: List[DependencyFinding] = Field(default_factory=list)
    intelligence_references: List[Dict[str, Any]] = Field(default_factory=list)

    # Reproduction
    reproduction_result: Optional[ReproductionResult] = None

    # Patch & Verification
    applied_patch: Optional[str] = None
    patch_hash: Optional[str] = None
    changed_files: List[str] = Field(default_factory=list)
    verification_outcome: Optional[VerificationReport] = None

    # Code Evidence (Red Team vs Blue Team)
    vulnerable_code: Optional[str] = None
    vulnerable_lines: List[int] = Field(default_factory=list)
    patched_code: Optional[str] = None
    patched_lines: List[int] = Field(default_factory=list)

    # Operational metrics
    repair_attempts: int = 0
    max_repair_attempts: int = 3
    execution_time_seconds: float = 0.0
    model_usage: Optional[ModelUsageRecord] = None
    failure_reasons: List[str] = Field(default_factory=list)
    summary: str = ""
