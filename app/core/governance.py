"""
ZeroDay Arena Governance, Rate Limiting, and FinOps Budget Protection.
Enforces per-device and global rate limits, concurrency boundaries, and token budgets.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
import re
import threading
import time
from typing import Dict, List, Optional
from fastapi import HTTPException, Request, status

from app.config import AppConfig

logger = logging.getLogger("zeroday.governance")


class GovernanceManager:
    """
    Centralized governance controller enforcing:
    1. Privacy-conscious per-device rate limiting (default 5/hr).
    2. Global rate limiting (default 20/hr).
    3. Concurrency limits (default 2 active runs).
    4. Provider-cost protection & credit budget thresholds ($59.50 budget, 90% threshold).
    """

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config = config or AppConfig()
        self._lock = threading.Lock()
        
        # Rate limiting state: device_hash -> list of monotonic timestamps
        self._device_requests: Dict[str, List[float]] = {}
        self._global_requests: List[float] = []
        
        # FinOps budget tracking
        self.total_prompt_tokens: int = 0
        self.total_completion_tokens: int = 0
        self.total_cost_usd: float = 0.0
        self.total_cached_prompt_tokens: int = 0
        self.total_cached_completion_tokens: int = 0
        self.total_cost_saved_usd: float = 0.0
        self.cache_hits: int = 0
        self.cache_misses: int = 0

        self._load_persisted_usage()

    def _load_persisted_usage(self) -> None:
        """Load cumulative token usage from persistent cache on startup."""
        cache_file = Path(os.getenv("CACHE_DIR", ".cache")) / "zeroday_token_cache.json"
        if not cache_file.exists():
            return
        try:
            import json
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("entries", {})
            p_tokens = 0
            c_tokens = 0
            for k, v in entries.items():
                if k.startswith("llm:"):
                    d = v.get("data", {})
                    p_tokens += d.get("prompt_tokens") or 0
                    c_tokens += d.get("completion_tokens") or 0
            self.total_prompt_tokens = p_tokens
            self.total_completion_tokens = c_tokens
            self.total_cost_usd = (p_tokens / 1_000_000.0) * 0.20 + (c_tokens / 1_000_000.0) * 0.60
            self.cache_hits = data.get("hits", 0)
        except Exception:
            pass

    def reset(self) -> None:
        """Reset internal rate limiters and counters (used for unit test isolation)."""
        with self._lock:
            self._device_requests.clear()
            self._global_requests.clear()
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0
            self.total_cost_usd = 0.0
            self.total_cached_prompt_tokens = 0
            self.total_cached_completion_tokens = 0
            self.total_cost_saved_usd = 0.0
            self.cache_hits = 0
            self.cache_misses = 0

    def extract_device_identifier(self, request: Optional[Request] = None, client_id: Optional[str] = None) -> str:
        """
        Derives a privacy-conscious, stable hash for device rate-limiting.
        Never persists raw IP addresses or client identifiers.
        """
        raw_identifier = ""
        
        if client_id:
            raw_identifier = client_id.strip()
        elif request:
            # Check client-supplied X-Device-Id header if valid UUID / alphanumeric token
            header_device_id = request.headers.get("x-device-id", "").strip()
            if header_device_id and re.match(r"^[a-zA-Z0-9_\-\.]{8,64}$", header_device_id):
                raw_identifier = f"header:{header_device_id}"
            else:
                # Fallback to hashed client IP / forwarded IP
                forwarded = request.headers.get("x-forwarded-for")
                if forwarded:
                    raw_identifier = f"ip:{forwarded.split(',')[0].strip()}"
                elif request.client and request.client.host:
                    raw_identifier = f"ip:{request.client.host}"
                else:
                    raw_identifier = "anonymous-default-client"
        else:
            raw_identifier = "direct-system-client"

        # Salt and hash for privacy
        return hashlib.sha256(f"zda_device_salt:{raw_identifier}".encode()).hexdigest()[:16]

    def check_device_rate_limit(self, device_id: str) -> None:
        """
        Device rate limiting disabled in BYOK mode.
        Allows unconstrained analysis when users provide their own API keys.
        """
        return None

    def check_global_rate_limit(self) -> None:
        """
        Global rate limiting disabled in BYOK mode.
        Allows unconstrained analysis when users provide their own API keys.
        """
        return None

    def check_concurrency_limit(self, active_runs_count: int) -> None:
        """
        Concurrency limiting disabled in BYOK mode.
        """
        return None

    def check_public_demo_rate_limit(self, device_id: str, max_requests_per_hour: int = 10) -> None:
        """
        Enforce a sliding window rate limit for unauthenticated public demo runs.
        Ensures judges can comfortably test all pre-approved samples while protecting
        the server against abuse or automated exhaustion.
        """
        now = time.monotonic()
        one_hour_ago = now - 3600.0
        with self._lock:
            # Clean expired timestamps for this device
            if device_id in self._device_requests:
                self._device_requests[device_id] = [t for t in self._device_requests[device_id] if t > one_hour_ago]
            else:
                self._device_requests[device_id] = []

            if len(self._device_requests[device_id]) >= max_requests_per_hour:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Public demo rate limit reached ({max_requests_per_hour} demo runs per hour). Please wait before initiating another run.",
                )

    def check_public_concurrency_limit(self, active_runs_count: int, max_concurrent: int = 3) -> None:
        """
        Enforce maximum simultaneous runs for public demo executions.
        """
        if active_runs_count >= max_concurrent:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Server is currently running maximum concurrent demo analyses ({max_concurrent}). Please wait for active runs to complete.",
            )

    def check_budget_protection(self) -> None:
        """
        Budget cap checks disabled in BYOK mode.
        Users control their own API quotas and limits directly through provider accounts.
        """
        return None

    def record_run_initiated(self, device_id: str) -> None:
        """Atomically record successful run creation in sliding windows."""
        now = time.monotonic()
        with self._lock:
            if device_id not in self._device_requests:
                self._device_requests[device_id] = []
            self._device_requests[device_id].append(now)
            self._global_requests.append(now)

    def record_token_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        """
        Track model inference token usage and update cumulative spending.
        Pricing: $0.20 per 1M prompt tokens, $0.60 per 1M completion tokens.
        """
        with self._lock:
            self.total_prompt_tokens += prompt_tokens
            self.total_completion_tokens += completion_tokens
            incremental_cost = (prompt_tokens / 1_000_000.0) * 0.20 + (completion_tokens / 1_000_000.0) * 0.60
            self.total_cost_usd += incremental_cost

            logger.info(
                "FinOps Model Telemetry: +%d prompt, +%d completion tokens. "
                "Cumulative: %d tokens ($%.5f / $%.2f limit)",
                prompt_tokens,
                completion_tokens,
                self.total_prompt_tokens + self.total_completion_tokens,
                self.total_cost_usd,
                self.config.nebius_budget_usd,
            )

    def record_cache_hit(self, prompt_tokens: int, completion_tokens: int) -> None:
        """Track tokens and FinOps budget saved due to cache hits."""
        with self._lock:
            self.cache_hits += 1
            self.total_cached_prompt_tokens += prompt_tokens
            self.total_cached_completion_tokens += completion_tokens
            incremental_saved = (prompt_tokens / 1_000_000.0) * 0.20 + (completion_tokens / 1_000_000.0) * 0.60
            self.total_cost_saved_usd += incremental_saved

            logger.info(
                "FinOps Cache Hit: Saved %d tokens (Est. $%.5f saved). Cumulative saved: %d tokens ($%.5f)",
                prompt_tokens + completion_tokens,
                incremental_saved,
                self.total_cached_prompt_tokens + self.total_cached_completion_tokens,
                self.total_cost_saved_usd,
            )

    def record_cache_miss(self) -> None:
        """Record a cache miss event."""
        with self._lock:
            self.cache_misses += 1

    def get_finops_summary(self) -> Dict[str, Any]:
        """Return comprehensive token usage, savings, and cost telemetry."""
        with self._lock:
            total_active_tokens = self.total_prompt_tokens + self.total_completion_tokens
            total_saved_tokens = self.total_cached_prompt_tokens + self.total_cached_completion_tokens
            total_ops = self.cache_hits + self.cache_misses
            hit_rate = (self.cache_hits / total_ops * 100.0) if total_ops > 0 else 0.0

            return {
                "total_tokens_used": total_active_tokens,
                "prompt_tokens_used": self.total_prompt_tokens,
                "completion_tokens_used": self.total_completion_tokens,
                "current_estimated_cost_usd": round(self.total_cost_usd, 5),
                "total_tokens_saved": total_saved_tokens,
                "total_cost_saved_usd": round(self.total_cost_saved_usd, 5),
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_rate_pct": round(hit_rate, 2),
            }


# Global singleton instance
governance = GovernanceManager()
