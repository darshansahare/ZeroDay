"""
Deterministic Multi-Tier Token Optimization and Document Cache.
Caches AI reasoning completions, threat intelligence documents, and AST analysis
to eliminate redundant token expenditures, reduce latency, and prevent budget waste.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.agents.base_agent import ModelCompletionResponse
from app.intelligence.evidence_normalizer import SecurityReference
from app.analysis.findings import AnalysisReport

logger = logging.getLogger("zeroday.cache")


class TokenOptimizationCache:
    """
    Thread-safe, multi-tier cache with in-memory fast path and persistent disk backing.
    Tracks token savings and FinOps cost reductions.
    """

    def __init__(
        self,
        cache_dir: Optional[str | Path] = None,
        ttl_seconds: int = 86400,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        
        # In-memory storage: key -> (data_dict, timestamp_float, ttl_seconds)
        self._memory_cache: Dict[str, Tuple[Dict[str, Any], float, int]] = {}

        # Telemetry metrics
        self._hits: int = 0
        self._misses: int = 0
        self._tokens_saved: int = 0
        self._cost_saved_usd: float = 0.0

        # Persistence setup
        if cache_dir is None:
            cache_dir = Path(".cache")
        self.cache_dir = Path(cache_dir)
        self.disk_file = self.cache_dir / "zeroday_token_cache.json"

        if self.enabled:
            self._load_from_disk()

    # Hashing & Key Generation

    @staticmethod
    def hash_text(text: str) -> str:
        """Generate SHA-256 digest of input text."""
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def make_completion_key(
        self,
        model: str,
        prompt: str,
        system_message: str = "",
        messages: Optional[List[Dict[str, str]]] = None,
        temperature: float = 0.0,
        provider: str = "",
    ) -> str:
        """Construct deterministic cache key for LLM inference requests."""
        payload = {
            "provider": provider.strip().lower(),
            "model": model,
            "prompt": prompt.strip(),
            "system_message": system_message.strip(),
            "messages": messages or [],
            "temperature": round(temperature, 2),
        }
        serialized = json.dumps(payload, sort_keys=True)
        return f"llm:{self.hash_text(serialized)}"

    def make_intel_key(self, query: str, cwe_id: str = "CWE-89", provider: str = "") -> str:
        """Construct deterministic cache key for threat intelligence searches."""
        norm_query = f"{provider.strip().lower()}:{query.strip().lower()}:{cwe_id.strip().upper()}"
        return f"intel:{self.hash_text(norm_query)}"

    def make_ast_key(self, file_path: str, content_hash: str) -> str:
        """Construct deterministic cache key for AST document analysis."""
        norm_path = str(file_path).replace("\\", "/").strip().lower()
        return f"ast:{self.hash_text(f'{norm_path}:{content_hash}')}"

    # Persistence Helpers

    def _load_from_disk(self) -> None:
        """Load persistent cache entries from disk on startup."""
        with self._lock:
            if not self.disk_file.exists():
                return
            try:
                with open(self.disk_file, "r", encoding="utf-8") as f:
                    payload = json.load(f)

                now = time.time()
                loaded_count = 0
                for k, v in payload.get("entries", {}).items():
                    ts = v.get("ts", 0)
                    ttl = v.get("ttl", self.ttl_seconds)
                    if now - ts < ttl:
                        self._memory_cache[k] = (v.get("data", {}), ts, ttl)
                        loaded_count += 1

                self._tokens_saved = payload.get("tokens_saved", 0)
                self._cost_saved_usd = payload.get("cost_saved_usd", 0.0)
                self._hits = payload.get("hits", 0)

                logger.info(
                    "TokenOptimizationCache: Loaded %d valid entries from %s (%d tokens previously saved)",
                    loaded_count,
                    self.disk_file,
                    self._tokens_saved,
                )
            except Exception as e:
                logger.warning("TokenOptimizationCache: Failed to load cache from %s: %s", self.disk_file, e)

    def _save_to_disk(self) -> None:
        """Persist memory cache entries to disk."""
        if not self.enabled:
            return
        with self._lock:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                payload = {
                    "version": "1.0",
                    "updated_at": time.time(),
                    "hits": self._hits,
                    "tokens_saved": self._tokens_saved,
                    "cost_saved_usd": self._cost_saved_usd,
                    "entries": {
                        k: {"data": d, "ts": ts, "ttl": ttl}
                        for k, (d, ts, ttl) in self._memory_cache.items()
                    },
                }
                tmp_file = self.disk_file.with_suffix(".tmp")
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                try:
                    tmp_file.replace(self.disk_file)
                except PermissionError:
                    try:
                        with open(self.disk_file, "w", encoding="utf-8") as f:
                            json.dump(payload, f, indent=2)
                        if tmp_file.exists():
                            tmp_file.unlink()
                    except Exception:
                        pass
            except Exception as e:
                logger.warning("TokenOptimizationCache: Failed to persist cache to disk: %s", e)

    # Core Cache Accessors

    def _get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve unexpired entry by key."""
        if not self.enabled:
            return None
        with self._lock:
            if key not in self._memory_cache:
                self._misses += 1
                return None

            data, ts, ttl = self._memory_cache[key]
            if time.time() - ts >= ttl:
                del self._memory_cache[key]
                self._misses += 1
                return None

            self._hits += 1
            return data

    def _set(self, key: str, data: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Store entry with TTL."""
        if not self.enabled:
            return
        with self._lock:
            entry_ttl = ttl if ttl is not None else self.ttl_seconds
            self._memory_cache[key] = (data, time.time(), entry_ttl)
            self._save_to_disk()

    # AI Reasoning / Model Completion Caching

    def get_completion(self, key: str) -> Optional[ModelCompletionResponse]:
        """Retrieve cached model completion response if present."""
        data = self._get(key)
        if not data:
            return None

        prompt_tokens = data.get("prompt_tokens", 0) or 0
        completion_tokens = data.get("completion_tokens", 0) or 0
        total_tokens = data.get("total_tokens", 0) or (prompt_tokens + completion_tokens)

        # Update saved token FinOps metrics
        with self._lock:
            self._tokens_saved += total_tokens
            incremental_saved_cost = (prompt_tokens / 1_000_000.0) * 0.20 + (completion_tokens / 1_000_000.0) * 0.60
            self._cost_saved_usd += incremental_saved_cost

        return ModelCompletionResponse(
            content=data["content"],
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model_name=data.get("model_name", "cached-model"),
            provider_name=data.get("provider_name", "nebius_token_factory"),
            elapsed_seconds=0.001,
            cached=True,
            tokens_saved=total_tokens,
        )

    def set_completion(self, key: str, response: ModelCompletionResponse) -> None:
        """Cache model completion response."""
        data = {
            "content": response.content,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "total_tokens": response.total_tokens,
            "model_name": response.model_name,
            "provider_name": response.provider_name,
        }
        self._set(key, data)

    # Threat Intelligence Document Caching

    def get_intel(self, query: str, cwe_id: str = "CWE-89", provider: str = "") -> Optional[List[SecurityReference]]:
        """Retrieve cached threat intelligence references for query."""
        key = self.make_intel_key(query, cwe_id, provider=provider)
        data = self._get(key)
        if not data or "references" not in data:
            return None

        refs: List[SecurityReference] = []
        for r in data["references"]:
            try:
                refs.append(SecurityReference(**r))
            except Exception:
                pass
        return refs if refs else None

    def set_intel(self, query: str, cwe_id: str, references: List[SecurityReference], provider: str = "") -> None:
        """Cache threat intelligence references."""
        key = self.make_intel_key(query, cwe_id, provider=provider)
        data = {
            "provider": provider,
            "query": query,
            "cwe_id": cwe_id,
            "references": [r.model_dump() for r in references],
        }
        self._set(key, data)

    # AST Document Analysis Caching

    def get_ast(self, file_path: str, content_hash: str) -> Optional[AnalysisReport]:
        """Retrieve cached AST analysis report for document."""
        key = self.make_ast_key(file_path, content_hash)
        data = self._get(key)
        if not data or "report" not in data:
            return None
        try:
            return AnalysisReport(**data["report"])
        except Exception:
            return None

    def set_ast(self, file_path: str, content_hash: str, report: AnalysisReport) -> None:
        """Cache AST analysis report for document."""
        key = self.make_ast_key(file_path, content_hash)
        data = {
            "file_path": file_path,
            "content_hash": content_hash,
            "report": report.model_dump(),
        }
        self._set(key, data)

    # Telemetry and Invalidation

    def get_stats(self) -> Dict[str, Any]:
        """Return comprehensive cache telemetry and token savings statistics."""
        with self._lock:
            total_ops = self._hits + self._misses
            hit_rate = (self._hits / total_ops * 100.0) if total_ops > 0 else 0.0
            return {
                "enabled": self.enabled,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_pct": round(hit_rate, 2),
                "tokens_saved": self._tokens_saved,
                "cost_saved_usd": round(self._cost_saved_usd, 5),
                "active_entries_count": len(self._memory_cache),
                "cache_file": str(self.disk_file),
            }

    def clear(self) -> None:
        """Invalidate all cache entries in memory and on disk."""
        with self._lock:
            self._memory_cache.clear()
            self._hits = 0
            self._misses = 0
            self._tokens_saved = 0
            self._cost_saved_usd = 0.0
            if self.disk_file.exists():
                try:
                    self.disk_file.unlink()
                except Exception:
                    pass
            logger.info("TokenOptimizationCache: Cache cleared completely.")


# Global singleton instance
token_cache = TokenOptimizationCache()
