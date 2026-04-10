"""
app/rca.py — Root Cause Analysis generator for payment reliability incidents.

Provider priority:
  1. Groq  (cloud)  — when GROQ_API_KEY is set
  2. Ollama (local) — when OLLAMA_BASE_URL is set
  3. Template / default fallback

Environment variables:
    GROQ_API_KEY      Groq API key  (activates Groq provider)
    GROQ_MODEL        Groq model tag (default: llama3-8b-8192)
    OLLAMA_BASE_URL   Base URL of the local Ollama server (default: http://localhost:11434)
    OLLAMA_MODEL      Ollama model tag (default: llama3.1)
"""

from __future__ import annotations

import json
import os
from typing import Tuple

import httpx

# ---------------------------------------------------------------------------
# Config
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
# System prompt — do not modify
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a payment systems reliability expert performing root cause analysis.

Given an incident alert, provide a structured RCA in JSON format:
{
  "probable_cause": "<concise technical root cause>",
  "contributing_factors": ["<factor 1>", "<factor 2>", "<factor 3>"],
  "immediate_actions": ["<action 1>", "<action 2>", "<action 3>"],
  "long_term_fixes": ["<fix 1>", "<fix 2>"],
  "impact_assessment": "<description of customer/business impact>",
  "estimated_resolution_time": "<e.g. 15-30 minutes, 1-2 hours>"
}

Focus on payment-specific issues: transaction processing, gateway connectivity,
database performance, authentication services, and network reliability.
Respond with ONLY the JSON object — no markdown, no explanation."""


# ---------------------------------------------------------------------------
# Fallback data — do not modify
# ---------------------------------------------------------------------------

TEMPLATE_RCA: dict[str, dict] = {
    "latency": {
        "probable_cause": "Increased response times detected in payment processing pipeline",
        "contributing_factors": [
            "Database query performance degradation",
            "Network congestion between services",
            "Increased transaction volume",
        ],
        "immediate_actions": [
            "Check database query execution plans",
            "Monitor network latency between payment services",
            "Review recent deployments for performance regressions",
        ],
        "long_term_fixes": [
            "Implement query result caching",
            "Add circuit breakers for downstream services",
        ],
        "impact_assessment": "Payment processing delays affecting customer checkout experience",
        "estimated_resolution_time": "30-60 minutes",
    },
    "error_rate": {
        "probable_cause": "Elevated error rates in payment transaction processing",
        "contributing_factors": [
            "Payment gateway connectivity issues",
            "Invalid request format changes",
            "Downstream service failures",
        ],
        "immediate_actions": [
            "Check payment gateway status page",
            "Review error logs for specific failure patterns",
            "Verify API contract compliance with payment processors",
        ],
        "long_term_fixes": [
            "Implement comprehensive error monitoring",
            "Add retry logic with exponential backoff",
        ],
        "impact_assessment": "Payment failures directly impacting revenue and customer trust",
        "estimated_resolution_time": "15-45 minutes",
    },
    "timeout": {
        "probable_cause": "Payment service timeouts exceeding configured thresholds",
        "contributing_factors": [
            "Slow external payment processor responses",
            "Resource contention in payment service",
            "Network packet loss",
        ],
        "immediate_actions": [
            "Check external payment processor status",
            "Review thread pool and connection pool utilisation",
            "Analyse network performance metrics",
        ],
        "long_term_fixes": [
            "Tune timeout configurations based on SLA requirements",
            "Implement bulkhead pattern to isolate payment flows",
        ],
        "impact_assessment": "Customer transactions timing out causing failed payments",
        "estimated_resolution_time": "20-40 minutes",
    },
    "authentication": {
        "probable_cause": "Authentication service failures blocking payment authorisation",
        "contributing_factors": [
            "Identity provider availability issues",
            "Certificate or token expiry",
            "Configuration drift in auth service",
        ],
        "immediate_actions": [
            "Verify identity provider health",
            "Check certificate expiry dates",
            "Review authentication service logs",
        ],
        "long_term_fixes": [
            "Implement certificate rotation automation",
            "Add authentication service redundancy",
        ],
        "impact_assessment": "Customers unable to authenticate for payment processing",
        "estimated_resolution_time": "15-30 minutes",
    },
    "database": {
        "probable_cause": "Database performance issues impacting payment data operations",
        "contributing_factors": [
            "Query performance degradation",
            "Connection pool exhaustion",
            "Disk I/O bottleneck",
        ],
        "immediate_actions": [
            "Check active database connections and queries",
            "Identify and terminate long-running queries",
            "Review database resource utilisation",
        ],
        "long_term_fixes": [
            "Optimise slow queries and add indexes",
            "Implement read replicas for reporting queries",
        ],
        "impact_assessment": "Payment data operations degraded affecting transaction reliability",
        "estimated_resolution_time": "30-60 minutes",
    },
    "network": {
        "probable_cause": (
            "Network packet loss or routing instability between payment service nodes. "
            "Likely caused by a BGP route change, physical link degradation, or firewall rule modification."
        ),
        "contributing_factors": [
            "Recent network configuration change",
            "Physical link degradation",
            "BGP route instability",
        ],
        "immediate_actions": [
            "Check BGP route table for unexpected changes",
            "Verify physical link status on affected network path",
            "Review firewall rule change history in the last 24 hours",
        ],
        "long_term_fixes": [
            "Implement redundant network paths for payment service traffic",
            "Add automated BGP route monitoring with alerting",
        ],
        "impact_assessment": (
            "Inter-service communication degraded. Payment processing latency increased "
            "for all services crossing the affected network path."
        ),
        "estimated_resolution_time": "1-3 minutes from packet loss threshold breach",
    },
    "performance_degradation": {
        "probable_cause": (
            "Latency degradation caused by resource contention or downstream bottleneck. "
            "Cache miss rate increase or CPU throttling forcing requests to slower code paths."
        ),
        "contributing_factors": [
            "Cache hit rate degradation",
            "CPU throttling under load",
            "Downstream service response time increase",
        ],
        "immediate_actions": [
            "Check cache hit rate and flush stale cache keys if degraded",
            "Review CPU utilisation and throttling events on payment service hosts",
            "Trace slowest downstream calls via distributed tracing",
        ],
        "long_term_fixes": [
            "Increase cache TTL and warm cache on deployment",
            "Right-size CPU limits for payment service pods",
        ],
        "impact_assessment": "All API consumers experiencing degraded response times.",
        "estimated_resolution_time": "5-10 minutes from p99 threshold breach",
    },
}

DEFAULT_RCA: dict = {
    "probable_cause": "Payment system anomaly detected requiring investigation",
    "contributing_factors": [
        "Multiple potential contributing factors identified",
        "System behaviour outside normal parameters",
        "Root cause requires further analysis",
    ],
    "immediate_actions": [
        "Engage on-call payment reliability engineer",
        "Collect logs from all affected payment services",
        "Monitor key payment metrics for trend changes",
    ],
    "long_term_fixes": [
        "Conduct thorough post-incident review",
        "Improve observability for faster root cause identification",
    ],
    "impact_assessment": "Payment system reliability impact — scope under assessment",
    "estimated_resolution_time": "Under investigation",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_rca(
    alert_text: str,
    category: str,
    severity: str,
) -> Tuple[dict, str]:
    """Generate a root cause analysis for a payment reliability incident.

    Resolution order:
      1. LLM path (Ollama) — when OLLAMA_BASE_URL is set and Ollama responds
      2. Template path     — when a template exists for the given category
      3. Default path      — catch-all

    Args:
        alert_text: Raw alert text describing the incident.
        category:   Incident category (e.g. "latency", "error_rate").
        severity:   Incident severity (e.g. "critical", "high").

    Returns:
        (rca_dict, source) where source is "llm", "template", or "default".
    """
    if _groq_configured() or _ollama_configured():
        try:
            rca = _call_llm(alert_text, category, severity)
            if rca is not None:
                return rca, "llm"
        except Exception as exc:
            print(f"[rca] LLM path failed, falling through to template: {exc}", flush=True)

    # Template fallback
    if category in TEMPLATE_RCA:
        return TEMPLATE_RCA[category], "template"

    return DEFAULT_RCA, "default"


# ---------------------------------------------------------------------------
# Private: Ollama call
# ---------------------------------------------------------------------------

def _call_llm(alert_text: str, category: str, severity: str) -> dict | None:
    """POST to Groq or Ollama and return the parsed RCA dict, or None on any failure."""
    if _groq_configured():
        url = _groq_url()
        headers = {"Authorization": f"Bearer {_groq_api_key()}"}
        model = _groq_model()
        provider = "Groq"
    else:
        url = _ollama_url()
        headers = {}
        model = _ollama_model()
        provider = "Ollama"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Incident category: {category}\n"
                    f"Severity: {severity}\n"
                    f"Alert: {alert_text}"
                ),
            },
        ],
        "stream": False,
    }

    resp = httpx.post(url, json=payload, headers=headers, timeout=30.0)
    resp.raise_for_status()

    data = resp.json()
    content: str = data["choices"][0]["message"]["content"].strip()

    # Strip accidental markdown fences
    if content.startswith("```"):
        lines = content.splitlines()
        content = "\n".join(
            l for l in lines[1:] if l.strip() not in ("```", "```json")
        ).strip()

    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected JSON object from {provider}, got {type(parsed).__name__}")

    return parsed
