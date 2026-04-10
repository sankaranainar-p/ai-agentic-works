"""
app/classifier/llm.py — LLM-based payment alert classifier.

Provider priority:
  1. Groq  (cloud)  — when GROQ_API_KEY is set
  2. Ollama (local) — when OLLAMA_BASE_URL is set
  3. None           — ML-only fallback

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
# Normalisation tables
# ---------------------------------------------------------------------------

CATEGORIES = {
    "http_500_spike", "ddos_attack", "availability_drop",
    "performance_degradation", "database", "authentication", "network", "unknown",
}

_CATEGORY_ALIASES: dict[str, str] = {
    "error_rate": "http_500_spike", "500_error": "http_500_spike", "http_error": "http_500_spike",
    "ddos": "ddos_attack", "dos_attack": "ddos_attack", "denial_of_service": "ddos_attack",
    "availability": "availability_drop", "service_down": "availability_drop", "outage": "availability_drop",
    "perf": "performance_degradation", "latency": "performance_degradation", "slow": "performance_degradation",
    "db": "database", "database_error": "database",
    **{c: c for c in CATEGORIES},
}

SEVERITY_MAP: dict[str, str] = {
    "http_500_spike": "SEV-1", "ddos_attack": "SEV-1", "availability_drop": "SEV-1",
    "performance_degradation": "SEV-2", "database": "SEV-2", "authentication": "SEV-2",
    "network": "SEV-3", "unknown": "SEV-3",
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
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a payment reliability expert. Classify the given payment system alert.

Respond with ONLY a valid JSON object in this exact format:
{
  "category": "<one of: http_500_spike, ddos_attack, availability_drop, performance_degradation, database, authentication, network, unknown>",
  "severity": "<one of: SEV-1, SEV-2, SEV-3, SEV-4>",
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<one sentence explaining the classification>"
}

Category guidance:
- ddos_attack: volumetric attacks, request floods, botnet traffic, requests/min spikes, WAF triggers — NOT generic network issues
- http_500_spike: elevated HTTP 5xx error rates, server-side failures
- availability_drop: service unreachable, uptime percentage drops, health-check failures
- performance_degradation: elevated latency, slow responses, throughput reduction
- database: DB connection errors, query failures, replication lag
- authentication: auth failures, token errors, certificate issues
- network: packet loss, DNS failures, generic connectivity issues (not volumetric attacks)
- unknown: cannot determine from available information

Severity rules (apply the FIRST matching rule):
- SEV-1: ddos_attack (always)
- SEV-1: availability_drop AND alert mentions availability below 99.9%
- SEV-1: http_500_spike AND alert mentions error rate above 5%
- SEV-2: http_500_spike, availability_drop, database, authentication (when SEV-1 conditions not met)
- SEV-3: performance_degradation, infrastructure, network
- SEV-3: default when uncertain

Do not include any text outside the JSON object."""


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
