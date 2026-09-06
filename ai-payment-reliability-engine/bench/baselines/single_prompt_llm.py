"""
bench/baselines/single_prompt_llm.py — B4: one-shot LLM ranking baseline.

Sends a single prompt describing the case's services and their most
deviated metrics to the configured LLM provider (Groq/Ollama, reusing
pre.classifier.llm's provider selection) and asks for a ranked list of
candidate root-cause services. No agentic loop, no tool use, no
follow-up — this is the "just ask the model once" floor that agentic
approaches (B5, and this project's full pipeline) should beat.

Returns an empty ranking (never raises) when no LLM provider is
configured or the call fails, so a benchmark run without LLM credentials
degrades to "this baseline scored zero on every case" rather than
crashing the whole run.
"""

from __future__ import annotations

import json
import statistics

import httpx

from pre.classifier.llm import (
    _groq_api_key,
    _groq_configured,
    _groq_model,
    _groq_url,
    _ollama_configured,
    _ollama_model,
    _ollama_url,
)
from pre.signals.types import FailureCase

SYSTEM_PROMPT = """You are a root cause analysis expert for microservice systems.
Given a list of services and their most-deviated metrics since a fault was
detected, rank the services from most likely to least likely to be the root
cause.

Respond with ONLY a JSON array of service names, most likely first, e.g.:
["serviceA", "serviceB", "serviceC"]

Do not include any text outside the JSON array."""


def _service_of(metric_key: str) -> str:
    return metric_key.split(":", 1)[0]


def _build_case_summary(case: FailureCase, inject_time: int) -> tuple[str, list[str]]:
    """Return (prompt text, services in the case) — services list is the
    valid-answer set the model's ranking is filtered against.
    """
    services = sorted({_service_of(k) for k in case.metrics})
    lines = [f"System: {case.system}", "Services and largest post-injection deviation:"]

    for service in services:
        best_metric, best_dev = None, 0.0
        for key, series in case.metrics.items():
            if _service_of(key) != service:
                continue
            before = [v for t, v in zip(series.times, series.values) if t < inject_time]
            after = [v for t, v in zip(series.times, series.values) if t >= inject_time]
            if len(before) < 2 or not after:
                continue
            mean_before = statistics.mean(before)
            dev = max(abs(v - mean_before) for v in after)
            if dev > best_dev:
                best_dev = dev
                best_metric = key.split(":", 1)[1]
        if best_metric:
            lines.append(f"  - {service}: {best_metric} deviated by {best_dev:.2f}")
        else:
            lines.append(f"  - {service}: no significant deviation observed")

    return "\n".join(lines), services


def rank(case: FailureCase, inject_time: int | None = None) -> list[str]:
    if not case.metrics:
        return []

    all_times = sorted({t for series in case.metrics.values() for t in series.times})
    if inject_time is None:
        inject_time = all_times[len(all_times) // 2] if all_times else 0

    prompt, services = _build_case_summary(case, inject_time)

    if _groq_configured():
        url, headers, model = _groq_url(), {"Authorization": f"Bearer {_groq_api_key()}"}, _groq_model()
    elif _ollama_configured():
        url, headers, model = _ollama_url(), {}, _ollama_model()
    else:
        return []

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
    }

    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=30.0)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            lines = content.splitlines()
            content = "\n".join(l for l in lines[1:] if l.strip() not in ("```", "```json")).strip()
        parsed = json.loads(content)
    except Exception:
        return []

    if not isinstance(parsed, list):
        return []

    # Filter to services actually in the case, preserving model's order,
    # so a hallucinated service name can't corrupt AC@k scoring.
    valid = set(services)
    return [s for s in parsed if isinstance(s, str) and s in valid]
