"""
Pydantic API Schemas for ZeroDay Arena Backend Operations.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from app.core.events import ExecutionEvent


class HealthResponse(BaseModel):
    """System health and environment configuration report."""
    status: str = "healthy"
    version: str = "1.0.0"
    workspace_root: str
    sandbox_enabled: bool
    max_repair_attempts: int
    llm_provider: str = "nebius"
    search_provider: str = "tavily"
    nebius_configured: bool = False
    tavily_configured: bool = False
    sandbox_ready: bool = True
    nebius_status: str = "Not configured"
    tavily_status: str = "Not configured"
    sandbox_status: str = "Ready"
    cache_enabled: bool = True
    cache_hits: int = 0
    tokens_saved: int = 0


class RepoValidationRequest(BaseModel):
    """Payload to validate and pin a public GitHub repository."""
    url: str = Field(..., description="Public GitHub repository URL")


class RepoValidationResponse(BaseModel):
    """Resolved repository status, pinned commit, and language support information."""
    valid: bool
    url: str
    owner: str = ""
    repo: str = ""
    commit_sha: str = ""
    pinned_commit: str = ""
    default_branch: str = ""
    language: str = ""
    supported: bool = True
    message: str = ""


class CreateRunRequest(BaseModel):
    """Parameters to initiate an autonomous remediation run."""
    target_path: str = Field("target_app/app.py", description="Target repository file path to analyze and patch")
    repo_url: Optional[str] = Field(None, description="Public GitHub repository URL")
    commit_sha: Optional[str] = Field(None, description="Pinned commit SHA")
    max_repair_attempts: int = Field(3, ge=1, le=10, description="Maximum bounded repair attempts")
    candidate_patch: Optional[str] = Field(None, description="Optional unified diff patch for deterministic testing")
    async_mode: bool = Field(False, description="Whether to execute the run asynchronously in background")


class RunSummaryResponse(BaseModel):
    """High-level summary of a remediation run."""
    run_id: str
    target_path: str
    repo_url: Optional[str] = None
    commit_sha: Optional[str] = None
    status: str
    execution_mode: str = "live_llm"  # live_llm, deterministic_offline_fallback, seeded_benchmark
    created_at: str
    completed_at: Optional[str] = None
    is_verified_remediation: bool
    repair_attempts: int
    events_count: int
    summary: str


class EventsResponse(BaseModel):
    """Collection of observable execution events for a run."""
    run_id: str
    events_count: int
    events: List[ExecutionEvent]


class ConfigUpdateRequest(BaseModel):
    """Payload to configure providers and API keys server-side."""
    llm_provider: Optional[str] = Field("nebius", description="Active LLM provider: 'nebius'")
    search_provider: Optional[str] = Field("tavily", description="Active search provider: 'tavily'")
    nebius_api_key: Optional[str] = Field(None, description="Nebius Token Factory API key for NVIDIA Nemotron")
    tavily_api_key: Optional[str] = Field(None, description="Tavily API key for threat intelligence research")


class ConfigStatusResponse(BaseModel):
    """Runtime configuration status without secret leakage."""
    llm_provider: str = "nebius"
    search_provider: str = "tavily"
    nebius_configured: bool
    tavily_configured: bool
    model: str
    provider: str
    base_url: str
    per_device_rate_limit: int
    global_rate_limit: int
    analysis_timeout_seconds: int
    test_execution_timeout_seconds: int
    max_repository_size_mb: int
    max_concurrent_analyses: int
    nebius_budget_usd: float
    nebius_budget_safety_threshold: float
    current_estimated_cost_usd: float
    total_tokens_used: int
    cache_enabled: bool = True
    tokens_saved: int = 0
    cost_saved_usd: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0


class CacheStatsResponse(BaseModel):
    """Detailed multi-tier token optimization and document cache telemetry."""
    enabled: bool
    hits: int
    misses: int
    hit_rate_pct: float
    tokens_saved: int
    cost_saved_usd: float
    active_entries_count: int
    cache_file: str


class ClearCacheResponse(BaseModel):
    """Response payload confirming cache invalidation."""
    status: str = "success"
    message: str = "Token optimization and document cache cleared successfully"


class SourceCodeResponse(BaseModel):
    """Source code snippet and metadata for a repository file."""
    run_id: str
    file_path: str
    content: str
    lines_count: int



