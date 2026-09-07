"""
pre/llm/client.py — LLM client with model digest pinning and disk cache.

Supports Ollama and vLLM backends with:
- Model digest pinning for reproducibility
- Temperature 0 (deterministic)
- Optional seed for repeatability
- Disk cache keyed by SHA256(model_digest, prompt)
- No-live-calls mode for CI/replay testing
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx


@dataclass(frozen=True)
class LLMResponse:
    """Response from LLM call."""

    text: str
    model_digest: str
    cached: bool
    tokens_used: int


class LLMClient:
    """LLM client with model pinning and disk cache."""

    def __init__(
        self,
        cache_dir: str | Path = ".llm_cache",
        live_calls_enabled: bool = True,
    ):
        """Initialize LLM client.

        Args:
            cache_dir: Directory for disk cache
            live_calls_enabled: False to disable live calls (cache-only mode for CI)
        """
        self.cache_dir = Path(cache_dir)
        self.live_calls_enabled = live_calls_enabled
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def call(
        self,
        prompt: str,
        model_digest: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 2000,
        seed: Optional[int] = None,
    ) -> LLMResponse:
        """Call LLM with model pinning and caching.

        Args:
            prompt: User prompt
            model_digest: Model identifier (e.g., "ollama:llama3.1:abc123")
            system_prompt: Optional system prompt
            max_tokens: Max tokens to generate
            seed: Optional seed for reproducibility

        Returns:
            LLMResponse with text, model digest, cache status, token count
        """
        cache_key = self._cache_key(model_digest, prompt, system_prompt)

        # Try cache first
        cached_response = self._load_cache(cache_key)
        if cached_response is not None:
            return cached_response

        # If live calls disabled, fail
        if not self.live_calls_enabled:
            raise RuntimeError(
                f"Live calls disabled and cache miss for {cache_key[:16]}... "
                "(in no-live-calls mode, all responses must be cached)"
            )

        # Make live call
        response = self._make_live_call(
            prompt=prompt,
            model_digest=model_digest,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            seed=seed,
        )

        # Save to cache
        self._save_cache(cache_key, response)

        return response

    def _cache_key(
        self,
        model_digest: str,
        prompt: str,
        system_prompt: Optional[str],
    ) -> str:
        """Compute SHA256 cache key from model and prompt."""
        combined = f"{model_digest}\n{system_prompt or ''}\n{prompt}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def _load_cache(self, cache_key: str) -> Optional[LLMResponse]:
        """Load response from disk cache."""
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text())
                return LLMResponse(
                    text=data["text"],
                    model_digest=data["model_digest"],
                    cached=True,
                    tokens_used=data["tokens_used"],
                )
            except Exception:
                pass
        return None

    def _save_cache(self, cache_key: str, response: LLMResponse) -> None:
        """Save response to disk cache."""
        cache_file = self.cache_dir / f"{cache_key}.json"
        data = {
            "text": response.text,
            "model_digest": response.model_digest,
            "tokens_used": response.tokens_used,
        }
        cache_file.write_text(json.dumps(data))

    def _make_live_call(
        self,
        prompt: str,
        model_digest: str,
        system_prompt: Optional[str],
        max_tokens: int,
        seed: Optional[int],
    ) -> LLMResponse:
        """Make actual live call to LLM backend."""
        # Parse model_digest to extract backend and model name
        backend, model, digest = model_digest.split(":")

        if backend == "ollama":
            return self._call_ollama(prompt, model, system_prompt, max_tokens, seed)
        elif backend == "vllm":
            return self._call_vllm(prompt, model, system_prompt, max_tokens, seed)
        else:
            raise ValueError(f"Unknown backend: {backend}")

    def _call_ollama(
        self,
        prompt: str,
        model: str,
        system_prompt: Optional[str],
        max_tokens: int,
        seed: Optional[int],
    ) -> LLMResponse:
        """Call Ollama endpoint."""
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.0,  # Deterministic
            "num_predict": max_tokens,
        }

        if seed is not None:
            payload["seed"] = seed

        try:
            response = httpx.post(
                f"{base_url}/api/chat",
                json=payload,
                timeout=120.0,
            )
            response.raise_for_status()
            data = response.json()

            text = data.get("message", {}).get("content", "")
            tokens = data.get("eval_count", 0)

            return LLMResponse(
                text=text,
                model_digest=f"ollama:{model}",
                cached=False,
                tokens_used=tokens,
            )
        except Exception as e:
            raise RuntimeError(f"Ollama call failed: {e}")

    def _call_vllm(
        self,
        prompt: str,
        model: str,
        system_prompt: Optional[str],
        max_tokens: int,
        seed: Optional[int],
    ) -> LLMResponse:
        """Call vLLM endpoint."""
        base_url = os.getenv("VLLM_BASE_URL", "http://localhost:8000").rstrip("/")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": max_tokens,
        }

        if seed is not None:
            payload["seed"] = seed

        try:
            response = httpx.post(
                f"{base_url}/v1/chat/completions",
                json=payload,
                timeout=120.0,
            )
            response.raise_for_status()
            data = response.json()

            text = data["choices"][0]["message"]["content"]
            tokens = data["usage"]["completion_tokens"]

            return LLMResponse(
                text=text,
                model_digest=f"vllm:{model}",
                cached=False,
                tokens_used=tokens,
            )
        except Exception as e:
            raise RuntimeError(f"vLLM call failed: {e}")
