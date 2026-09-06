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
# Fallback data — keyed on the shared fault_class taxonomy
# (data/taxonomy.yaml, see pre/classifier/taxonomy.py)
# ---------------------------------------------------------------------------

TEMPLATE_RCA: dict[str, dict] = {
    "cpu": {
        "probable_cause": "Sustained CPU saturation on payment service nodes throttling request processing",
        "contributing_factors": [
            "Traffic spike beyond provisioned capacity",
            "Inefficient hot-path code consuming excess CPU",
            "Missing or misconfigured horizontal autoscaling",
        ],
        "immediate_actions": [
            "Check CPU utilisation and throttling metrics on affected nodes",
            "Trigger manual horizontal scale-out if autoscaler has not reacted",
            "Identify top CPU-consuming code paths via profiler/flame graph",
        ],
        "long_term_fixes": [
            "Tune horizontal pod autoscaler thresholds and cooldowns",
            "Optimise the hottest CPU-bound code paths",
        ],
        "impact_assessment": "Payment request processing slowed or dropped due to CPU contention",
        "estimated_resolution_time": "10-20 minutes",
    },
    "memory": {
        "probable_cause": "Memory leak or undersized heap causing OOM kills in payment service pods",
        "contributing_factors": [
            "Unbounded cache or connection object growth",
            "Recent deployment introducing a memory leak",
            "Memory limits set below actual working-set size",
        ],
        "immediate_actions": [
            "Restart affected pods to recover immediately",
            "Capture a heap dump before the next restart for analysis",
            "Review recent deployments for suspect memory-growth changes",
        ],
        "long_term_fixes": [
            "Fix the underlying leak (unbounded cache/collection)",
            "Right-size memory limits and add proactive alerting before OOM",
        ],
        "impact_assessment": "Payment worker pods crash-looping, dropping in-flight transactions",
        "estimated_resolution_time": "10-30 minutes",
    },
    "disk": {
        "probable_cause": "Disk space or I/O saturation on a payment service or database host",
        "contributing_factors": [
            "Uncontrolled log growth filling the disk",
            "Large batch job producing temp files without cleanup",
            "Underlying storage volume I/O throughput exhausted",
        ],
        "immediate_actions": [
            "Free space via emergency log rotation / temp file cleanup",
            "Check disk I/O wait metrics for the affected volume",
            "Migrate hot data to a faster storage tier if I/O-bound",
        ],
        "long_term_fixes": [
            "Add automated log rotation and retention policies",
            "Provision storage with headroom and set proactive disk alerts",
        ],
        "impact_assessment": "Write failures or degraded throughput on payment persistence layer",
        "estimated_resolution_time": "15-30 minutes",
    },
    "socket": {
        "probable_cause": "Connection pool or socket/file-descriptor exhaustion in the payment service",
        "contributing_factors": [
            "Connections not returned to the pool after use (leak)",
            "Traffic spike exceeding provisioned pool size",
            "Slow downstream holding connections open longer than expected",
        ],
        "immediate_actions": [
            "Reset the connection pool and terminate idle long-running connections",
            "Check for a recent deployment that stopped closing connections properly",
            "Temporarily raise the pool size limit if traffic is the cause",
        ],
        "long_term_fixes": [
            "Fix the connection leak at its source",
            "Add pool utilisation alerting before exhaustion occurs",
        ],
        "impact_assessment": "New payment requests rejected or queued once the pool is exhausted",
        "estimated_resolution_time": "10-20 minutes",
    },
    "delay": {
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
    "logic_error": {
        "probable_cause": "Elevated error rates in payment transaction processing from a code-level logic defect",
        "contributing_factors": [
            "Recent deployment introducing a regression",
            "Invalid request/response format changes upstream",
            "Untested edge case in business logic",
        ],
        "immediate_actions": [
            "Roll back the most recent deployment if timeline correlates",
            "Review error logs for specific failure patterns",
            "Verify API contract compliance with payment processors",
        ],
        "long_term_fixes": [
            "Add regression tests for the failing code path",
            "Add retry logic with exponential backoff for transient failures",
        ],
        "impact_assessment": "Payment failures directly impacting revenue and customer trust",
        "estimated_resolution_time": "15-45 minutes",
    },
    "concurrency_issue": {
        "probable_cause": "Lock contention, deadlocks, or race conditions in concurrent payment transaction processing",
        "contributing_factors": [
            "Lock contention on shared payment ledger state",
            "Deadlock between concurrent order-processing transactions",
            "Race condition allowing duplicate processing",
        ],
        "immediate_actions": [
            "Identify and release stuck locks / roll back deadlocked transactions",
            "Review thread pool and connection pool utilisation",
            "Check for duplicate charge/side-effect due to a race condition",
        ],
        "long_term_fixes": [
            "Add idempotency keys to prevent duplicate processing",
            "Reduce lock scope / adopt optimistic concurrency control",
        ],
        "impact_assessment": "Customer transactions timing out or double-processing due to contention",
        "estimated_resolution_time": "20-40 minutes",
    },
    "api_compatibility_issue": {
        "probable_cause": "A version or schema mismatch between the payment service and an integration partner",
        "contributing_factors": [
            "Upstream/downstream service deployed a breaking API change",
            "Client pinned to a deprecated API version",
            "Contract test coverage gap for the integration",
        ],
        "immediate_actions": [
            "Pin the client to the last known-good API version",
            "Confirm the breaking change with the integration owner",
            "Review recent changelog/release notes for the dependency",
        ],
        "long_term_fixes": [
            "Add contract tests for the integration boundary",
            "Negotiate a deprecation/versioning policy with the provider",
        ],
        "impact_assessment": "Requests to/from the integration failing or returning malformed data",
        "estimated_resolution_time": "20-60 minutes",
    },
    "configuration_error": {
        "probable_cause": "A misconfiguration (expired certificate, bad env var, wrong feature flag) is blocking payment processing",
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
        "impact_assessment": "Payment requests failing due to a misconfigured dependency or service",
        "estimated_resolution_time": "15-30 minutes",
    },
    "exception_handling_error": {
        "probable_cause": "An unhandled or improperly caught exception crashed the payment worker process",
        "contributing_factors": [
            "Unhandled exception left the process in a bad state",
            "Missing catch/retry around a failing downstream call",
            "Exception silently swallowed, masking the real failure",
        ],
        "immediate_actions": [
            "Restart the crashed worker process",
            "Capture the stack trace and identify the failing call site",
            "Add a temporary guard/retry around the failing call path",
        ],
        "long_term_fixes": [
            "Add proper exception handling and structured error logging",
            "Add alerting on unhandled exception rate",
        ],
        "impact_assessment": "Payment worker crashes interrupting in-flight transaction processing",
        "estimated_resolution_time": "30-60 minutes",
    },
    "dependency_failure": {
        "probable_cause": "An upstream or third-party dependency required for payment processing is unavailable",
        "contributing_factors": [
            "Third-party provider outage or degraded status",
            "DNS resolution failure to the dependency",
            "Missing circuit breaker allowing cascading failure",
        ],
        "immediate_actions": [
            "Check the dependency's public status page",
            "Fail over to a backup provider if configured",
            "Queue affected requests for replay once the dependency recovers",
        ],
        "long_term_fixes": [
            "Add a circuit breaker and backup provider for this dependency",
            "Add synthetic monitoring for the dependency's health",
        ],
        "impact_assessment": "Payment requests blocked or degraded pending dependency recovery",
        "estimated_resolution_time": "Variable — dependent on third-party recovery",
    },
    "loss": {
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
    "performance_bottleneck": {
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
        category:   fault_class from data/taxonomy.yaml (e.g. "cpu", "logic_error").
        severity:   Incident severity (e.g. "SEV-1", "SEV-2").

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
