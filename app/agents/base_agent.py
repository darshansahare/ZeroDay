"""
Model-Independent Inference Abstraction.
Defines unified request and telemetry response formats.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ModelCompletionResponse(BaseModel):
    """Normalized response from an AI inference provider."""
    content: str = Field(..., description="Generated text content")
    prompt_tokens: Optional[int] = Field(None, description="Input token count if reported")
    completion_tokens: Optional[int] = Field(None, description="Output token count if reported")
    total_tokens: Optional[int] = Field(None, description="Total tokens if reported")
    model_name: str = Field(..., description="Identifier of the executing model")
    provider_name: str = Field(..., description="Provider name (e.g., 'nebius', 'test_double')")
    elapsed_seconds: float = 0.0
    cached: bool = Field(False, description="Whether response was served from cache")
    tokens_saved: int = Field(0, description="Tokens saved by cache hit")


class InferenceProvider:
    """Abstract interface for LLM inference providers."""

    def complete(
        self,
        prompt: str,
        system_message: str = "",
        temperature: float = 0.1,
        max_tokens: int = 1024,
        messages: Optional[List[Dict[str, str]]] = None,
    ) -> ModelCompletionResponse:
        """Generate text completion from prompt or messages list."""
        raise NotImplementedError
