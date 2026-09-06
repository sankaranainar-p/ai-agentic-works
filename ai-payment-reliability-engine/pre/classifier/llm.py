"""
pre/classifier/llm.py — LLM-based payment alert classifier.

Provider priority:
  1. Groq  (cloud)  — when GROQ_API_KEY is set
  2. Ollama (local) — when OLLAMA_BASE_URL is set
  3. None           — ML-only fallback

The system prompt's allowed category list is generated from the shared
fault taxonomy in data/taxonomy.yaml (via pre/classifier/taxonomy.py), the
same source pre/classifier/model.py trains against. This guarantees the
LLM can never name a category the ML classifier does not also support.

Environment variables:
    GROQ_API_KEY      Groq API key  (activates Groq provider)
    GROQ_MODEL        Groq model tag (default: llama3-8b-8192)
    OLLAMA_BASE_URL   Base URL of the local Ollama server (default: http://localhost:11434)
    OLLAMA_MODEL      Ollama model tag (default: llama3.1)
"""

from __future__ import annotations

import json
import os
from typing import Optional

import httpx

from pre.classifier.taxonomy import UNKNOWN_CATEGORY, all_categories


# ---------------------------------------------------------------------------
# Provider config
# ---------------------------------------------------------------------------

def _groq_api_key() -> str:
    return os.getenv("GROQ_API_KEY", "")

def _groq_configured() -> bool:
    return bool(_groq_api_key())

def _groq_url() -> str:
    return "https://api.groq.com/openai/v1/chat/completions"

def _groq_model() -> str:
    return os.getenv("GROQ_MODEL", "llama3-8b-8192")

def _ollama_configured() -> bool:
    return bool(os.getenv("OLLAMA_BASE_URL"))

def _ollama_url() -> str:
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    return f"{base}/v1/chat/completions"

def _ollama_model() -> str:
    return os.getenv("OLLAMA_MODEL", "llama3.1")


# ---------------------------------------------------------------------------
# Shared result type
# ---------------------------------------------------------------------------

class MLResult:
    """Structured classification result returned by both ML and LLM classifiers."""

    def __init__(self, category: str, severity: str, confidence: float, reasoning: str = "") -> None:
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.reasoning = reasoning

    def __repr__(self) -> str:
        return (
            f"MLResult(category={self.category!r}, severity={self.severity!r}, "
            f"confidence={self.confidence:.2f})"
        )


# ---------------------------------------------------------------------------
# Normalisation tables — sourced from the shared taxonomy
# ---------------------------------------------------------------------------

CATEGORIES = set(all_categories())

_CATEGORY_ALIASES: dict[str, str] = {
    "cpu_saturation": "cpu", "high_cpu": "cpu",
    "memory_leak": "memory", "oom": "memory", "out_of_memory": "memory",
    "disk_saturation": "disk", "disk_exhaustion": "disk",
    "socket_exhaustion": "socket", "connection_exhaustion": "socket",
    "network_delay": "delay", "latency": "delay", "latency_degradation": "delay",
    "packet_loss": "loss",
    "logic_bug": "logic_error", "bug": "logic_error",
    "race_condition": "concurrency_issue", "deadlock": "concurrency_issue",
    "api_mismatch": "api_compatibility_issue", "version_mismatch": "api_compatibility_issue",
    "bottleneck": "performance_bottleneck", "slow_query": "performance_bottleneck",
    "unhandled_exception": "exception_handling_error", "crash": "exception_handling_error",
    "misconfiguration": "configuration_error", "config_error": "configuration_error",
    "upstream_failure": "dependency_failure", "third_party_outage": "dependency_failure",
    **{c: c for c in CATEGORIES},
}

SEVERITY_MAP: dict[str, str] = {
    "cpu": "SEV-2", "memory": "SEV-2", "disk": "SEV-2", "socket": "SEV-2",
    "delay": "SEV-2", "loss": "SEV-3",
    "logic_error": "SEV-1", "concurrency_issue": "SEV-2",
    "api_compatibility_issue": "SEV-2", "performance_bottleneck": "SEV-3",
    "exception_handling_error": "SEV-1", "configuration_error": "SEV-2",
    "dependency_failure": "SEV-1", UNKNOWN_CATEGORY: "SEV-3",
}

_SEVERITY_ALIASES: dict[str, str] = {
    "critical": "SEV-1", "p1": "SEV-1", "high": "SEV-1",
    "major": "SEV-2", "p2": "SEV-2", "medium-high": "SEV-2",
    "minor": "SEV-3", "p3": "SEV-3", "medium": "SEV-3", "low": "SEV-3",
    "p4": "SEV-4", "info": "SEV-4", "informational": "SEV-4",
    "SEV-1": "SEV-1", "SEV-2": "SEV-2", "SEV-3": "SEV-3", "SEV-4": "SEV-4",
}


def _normalize_category(raw: str) -> Optional[str]:
    key = raw.strip().lower().replace(" ", "_").replace("-", "_")
    return _CATEGORY_ALIASES.get(key)


def _normalize_severity(raw: str, category: str) -> str:
    normalised = _SEVERITY_ALIASES.get(raw.strip()) or _SEVERITY_ALIASES.get(raw.strip().lower())
    return normalised if normalised else SEVERITY_MAP.get(category, "SEV-3")


# ---------------------------------------------------------------------------
# System prompt — category list generated from data/taxonomy.yaml so the
# LLM can never name a fault_class the ML classifier doesn't also support.
# ---------------------------------------------------------------------------

def _build_system_prompt() -> str:
    categories = ", ".join(all_categories())
    return f"""You are a payment reliability expert. Classify the given payment system alert.

Respond with ONLY a valid JSON object in this exact format:
{{
  "category": "<one of: {categories}>",
  "severity": "<one of: SEV-1, SEV-2, SEV-3, SEV-4>",
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<one sentence explaining the classification>"
}}

Category guidance:
- cpu: sustained CPU saturation / throttling on payment services
- memory: memory leaks, OOM kills, heap pressure
- disk: disk space exhaustion, disk I/O saturation
- socket: connection pool / file-descriptor / socket exhaustion
- delay: elevated latency, slow responses, injected network delay
- loss: packet loss, dropped connections
- logic_error: incorrect business logic, elevated HTTP 5xx from bad code paths
- concurrency_issue: deadlocks, race conditions, duplicate processing
- api_compatibility_issue: version/schema mismatches between services
- performance_bottleneck: throughput degradation, consumer lag, slow queries
- exception_handling_error: unhandled/uncaught exceptions crashing a service
- configuration_error: misconfiguration, expired certs, bad env vars
- dependency_failure: upstream/downstream/third-party service unavailable
- unknown: cannot determine from available information

Severity rules (apply the FIRST matching rule):
- SEV-1: logic_error, exception_handling_error, dependency_failure (always)
- SEV-1: delay AND alert mentions latency above 3000ms
- SEV-1: loss AND alert mentions packet loss above 10%
- SEV-2: cpu, memory, disk, socket, concurrency_issue, api_compatibility_issue, configuration_error
- SEV-3: performance_bottleneck, loss, default when uncertain

Do not include any text outside the JSON object."""


SYSTEM_PROMPT = _build_system_prompt()


# ---------------------------------------------------------------------------
# Shared HTTP call + response parsing
# ---------------------------------------------------------------------------

def _call_llm(url: str, headers: dict, model: str, alert_text: str, source: str) -> Optional[MLResult]:
    """POST to any OpenAI-compatible /v1/chat/completions endpoint and return MLResult."""
    provider = "Groq" if "groq.com" in url else "Ollama"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Alert from {source}:\n{alert_text}"},
        ],
        "stream": False,
    }

    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=30.0)
        resp.raise_for_status()
    except httpx.TimeoutException:
        print(f"[llm] {provider} request timed out", flush=True)
        return None
    except httpx.HTTPStatusError as exc:
        print(f"[llm] {provider} HTTP {exc.response.status_code}: {exc.response.text[:200]}", flush=True)
        return None
    except httpx.RequestError as exc:
        print(f"[llm] {provider} unreachable: {exc}", flush=True)
        return None

    try:
        content = resp.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        print(f"[llm] {provider} unexpected response shape: {exc}", flush=True)
        return None

    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        content = "\n".join(l for l in lines[1:] if l.strip() not in ("```", "```json")).strip()

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        print(f"[llm] {provider} JSON parse failed: {exc} — content: {content[:300]}", flush=True)
        return None

    try:
        raw_category = str(parsed["category"])
        raw_severity = str(parsed["severity"])
        confidence = float(parsed["confidence"])
    except (KeyError, TypeError, ValueError) as exc:
        print(f"[llm] {provider} missing field: {exc}", flush=True)
        return None

    category = _normalize_category(raw_category)
    if category is None:
        print(f"[llm] {provider} unrecognised category {raw_category!r} — deferring to ML", flush=True)
        return None

    return MLResult(
        category=category,
        severity=_normalize_severity(raw_severity, category),
        confidence=confidence,
        reasoning=str(parsed.get("reasoning", "")),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_with_llm(alert_text: str, source: str) -> Optional[MLResult]:
    """Classify a payment alert via Groq (cloud) or Ollama (local), or return None.

    Provider priority:
      1. Groq  — GROQ_API_KEY is set
      2. Ollama — OLLAMA_BASE_URL is set
      3. None  — ML-only fallback
    """
    if _groq_configured():
        return _call_llm(
            url=_groq_url(),
            headers={"Authorization": f"Bearer {_groq_api_key()}"},
            model=_groq_model(),
            alert_text=alert_text,
            source=source,
        )

    if _ollama_configured():
        return _call_llm(
            url=_ollama_url(),
            headers={},
            model=_ollama_model(),
            alert_text=alert_text,
            source=source,
        )

    return None
