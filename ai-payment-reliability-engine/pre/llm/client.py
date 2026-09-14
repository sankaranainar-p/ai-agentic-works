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


def _parse_model_digest(model_digest: str) -> tuple[str, str, str]:
    """Parse "backend:model[@digest]" -> (backend, model, digest).

    The model name may itself contain colons (Ollama tags like
    "qwen3.8:27b", "llama3.1:latest"), so the optional content digest is
    separated with "@", not ":". digest is "" when absent.
    """
    backend, sep, rest = model_digest.partition(":")
    if not sep or not rest:
        raise ValueError(
            f"model_digest must be 'backend:model[@digest]', got {model_digest!r}"
        )
    model, _, digest = rest.partition("@")
    return backend, model, digest


@dataclass(frozen=True)
class LLMResponse:
    """Response from LLM call."""

    text: str
    model_digest: str
    cached: bool
    tokens_used: int
    truncated: bool = False  # generation stopped at the token limit, not naturally


class LLMClient:
    """LLM client with model pinning and disk cache."""

    def __init__(
        self,
        cache_dir: str | Path = ".llm_cache",
        live_calls_enabled: bool = True,
        http_capture: Optional[str | Path] = None,
    ):
        """Initialize LLM client.

        Args:
            cache_dir: Directory for disk cache
            live_calls_enabled: False to disable live calls (cache-only mode for CI)
            http_capture: if set, every LIVE request/response is appended to this
                JSONL file (verbatim URL + bodies) — for showing the real wire
                traffic and checking response field names.
        """
        self.cache_dir = Path(cache_dir)
        self.live_calls_enabled = live_calls_enabled
        self.http_capture = Path(http_capture) if http_capture else None
        self.total_tokens = 0  # cumulative generated-token count across call()s
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if self.http_capture:
            self.http_capture.parent.mkdir(parents=True, exist_ok=True)

    def _capture(self, url: str, req_body: dict, resp) -> None:
        if not self.http_capture:
            return
        try:
            resp_body = resp.json()
        except Exception:
            resp_body = {"_raw_text": resp.text}
        rec = {
            "url": url,
            "request": req_body,
            "response_status": resp.status_code,
            "response": resp_body,
        }
        with open(self.http_capture, "a") as f:
            f.write(json.dumps(rec) + "\n")

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
            model_digest: "backend:model[@digest]" (e.g. "ollama:llama3.1",
                "ollama:qwen3.8:27b", "vllm:mymodel@sha256abc")
            system_prompt: Optional system prompt
            max_tokens: Max tokens to generate
            seed: Optional seed for reproducibility

        Returns:
            LLMResponse with text, model digest, cache status, token count
        """
        cache_key = self._cache_key(model_digest, prompt, system_prompt, max_tokens)

        # Try cache first
        cached_response = self._load_cache(cache_key)
        if cached_response is not None:
            self.total_tokens += cached_response.tokens_used
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
        self.total_tokens += response.tokens_used

        return response

    def _cache_key(
        self,
        model_digest: str,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int = 2000,
    ) -> str:
        """Compute SHA256 cache key from model, prompt, and token budget.

        `max_tokens` is part of the key: two calls with different budgets are
        different calls, and a retry with a bigger budget must not read back a
        cached truncated response.
        """
        combined = f"{model_digest}\n{system_prompt or ''}\n{prompt}\nmax_tokens={max_tokens}"
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
                    truncated=data.get("truncated", False),
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
            "truncated": response.truncated,
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
        backend, model, _digest = _parse_model_digest(model_digest)

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

        # Ollama's /api/chat takes generation params under "options", not at
        # the top level, and streams NDJSON unless stream=False.
        options = {"temperature": 0.0, "num_predict": max_tokens}
        if seed is not None:
            options["seed"] = seed
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": options,
        }

        url = f"{base_url}/api/chat"
        try:
            response = httpx.post(url, json=payload, timeout=180.0)
            self._capture(url, payload, response)
            response.raise_for_status()
            data = response.json()

            text = data.get("message", {}).get("content", "")
            # Ollama /api/chat field names (verified against a live response):
            # eval_count = generated tokens, prompt_eval_count = input tokens.
            tokens = data.get("eval_count", 0)

            return LLMResponse(
                text=text,
                model_digest=f"ollama:{model}",
                cached=False,
                tokens_used=tokens,
                truncated=data.get("done_reason") == "length",
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

        url = f"{base_url}/v1/chat/completions"
        try:
            response = httpx.post(url, json=payload, timeout=120.0)
            self._capture(url, payload, response)
            response.raise_for_status()
            data = response.json()

            choice = data["choices"][0]
            text = choice["message"]["content"]
            # OpenAI-compatible: usage.completion_tokens / usage.prompt_tokens.
            tokens = data["usage"]["completion_tokens"]

            return LLMResponse(
                text=text,
                model_digest=f"vllm:{model}",
                cached=False,
                tokens_used=tokens,
                truncated=choice.get("finish_reason") == "length",
            )
        except Exception as e:
            raise RuntimeError(f"vLLM call failed: {e}")
