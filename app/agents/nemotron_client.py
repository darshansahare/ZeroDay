"""
NVIDIA Nemotron Provider via Nebius Token Factory & Deterministic Test Double.
"""

from __future__ import annotations

import os
import time
from typing import Optional
from openai import OpenAI

from app.core.errors import ProviderError
from app.agents.base_agent import InferenceProvider, ModelCompletionResponse
from app.cache.token_cache import token_cache
from app.core.governance import governance


CANONICAL_DIFF_REPAIR = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -141,3 +141,3 @@
-    # SINK: Vulnerable unparameterized string formatting
-    query = f"SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = '{user_id}'"
-    cursor.execute(query)
+    # SECURE: Parameterized SQL query
+    query = "SELECT order_id, user_id, total_amount, credit_card, ssn_last4, secret_notes FROM orders WHERE user_id = ?"
+    cursor.execute(query, (user_id,))
"""


class DeterministicTestModelClient(InferenceProvider):
    """
    Deterministic test double for CI/CD and offline test suites.
    Provides verified reproducible responses without network calls or fabricated claims.
    """

    def __init__(self, canned_response: Optional[str] = None) -> None:
        self.canned_response = canned_response or CANONICAL_DIFF_REPAIR
        self.call_count = 0

    def complete(
        self,
        prompt: str,
        system_message: str = "",
        temperature: float = 0.1,
        max_tokens: int = 1024,
        messages: Optional[List[Dict[str, str]]] = None,
    ) -> ModelCompletionResponse:
        self.call_count += 1
        return ModelCompletionResponse(
            content=self.canned_response,
            prompt_tokens=120,
            completion_tokens=65,
            total_tokens=185,
            model_name="deterministic-test-double",
            provider_name="offline_test",
            elapsed_seconds=0.01,
        )


class NemotronNebiusClient(InferenceProvider):
    """
    Real NVIDIA Nemotron client hosted on Nebius Token Factory.
    Uses OpenAI-compatible protocol with bounded timeouts and error handling.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("NEBIUS_API_KEY", "")
        self.base_url = (
            base_url
            or os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
        )
        self.model = (
            model
            or os.environ.get("NEBIUS_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
        )
        self.timeout_seconds = timeout_seconds

        self._client: Optional[OpenAI] = None
        if self.api_key:
            self._client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
                timeout=self.timeout_seconds,
            )

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self._client)

    def complete(
        self,
        prompt: str,
        system_message: str = "",
        temperature: float = 0.1,
        max_tokens: int = 1024,
        messages: Optional[List[Dict[str, str]]] = None,
    ) -> ModelCompletionResponse:
        """
        Send completion request to Nebius Token Factory endpoint.
        """
        if not self.is_configured:
            raise ProviderError("Nebius API key is not configured")

        if not messages:
            messages = []
            if system_message:
                messages.append({"role": "system", "content": system_message})
            messages.append({"role": "user", "content": prompt})

        # Deterministic cache lookup
        cache_key = token_cache.make_completion_key(
            model=self.model,
            prompt=prompt,
            system_message=system_message,
            messages=messages,
            temperature=temperature,
            provider="nebius_token_factory",
        )

        cached_response = token_cache.get_completion(cache_key)
        if cached_response is not None:
            governance.record_cache_hit(
                prompt_tokens=cached_response.prompt_tokens or 0,
                completion_tokens=cached_response.completion_tokens or 0,
            )
            return cached_response

        governance.record_cache_miss()
        start_time = time.monotonic()

        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            elapsed = time.monotonic() - start_time

            choice = resp.choices[0]
            content = choice.message.content or ""
            if not content and hasattr(choice.message, "reasoning") and choice.message.reasoning:
                content = choice.message.reasoning or ""

            usage = getattr(resp, "usage", None)
            p_tokens = getattr(usage, "prompt_tokens", None) if usage else None
            c_tokens = getattr(usage, "completion_tokens", None) if usage else None
            t_tokens = getattr(usage, "total_tokens", None) if usage else None

            # Track token usage and FinOps budget telemetry
            if p_tokens or c_tokens:
                governance.record_token_usage(p_tokens or 0, c_tokens or 0)

            model_response = ModelCompletionResponse(
                content=content,
                prompt_tokens=p_tokens,
                completion_tokens=c_tokens,
                total_tokens=t_tokens,
                model_name=self.model,
                provider_name="nebius_token_factory",
                elapsed_seconds=elapsed,
                cached=False,
                tokens_saved=0,
            )

            # Persist to multi-tier token optimization cache
            token_cache.set_completion(cache_key, model_response)
            return model_response

        except Exception as e:
            raise ProviderError(f"Nebius Nemotron inference request failed: {e}") from e
