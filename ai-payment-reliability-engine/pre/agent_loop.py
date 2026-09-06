"""
pre/agent_loop.py — Core 5-layer agent loop for the AI Payment
Reliability Engine, extracted from pre/main.py so the FastAPI layer
(pre/api/) stays thin.

5-layer agent loop (per incident):
  1. Classify   — ML + LLM ensemble
  2. RCA        — Ollama → template → default
  3. Remediate  — category-specific handler + Slack/PagerDuty
  4. Verify     — wait VERIFY_WAIT_SECONDS, re-poll metrics
  5. Log        — persist full incident record in agent_log
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

import pre.agent_log as agent_log
from pre.classifier.llm import classify_with_llm
from pre.classifier.model import ROUTE_TO, RUNBOOKS, get_classifier
from pre.database import save_incident
from pre.rca import generate_rca
from pre.remediation.dispatcher import dispatch
from pre.verification import verify

# ---------------------------------------------------------------------------
# In-memory incident store (most-recent-50, mirrors SQLite persistence)
# ---------------------------------------------------------------------------

_incidents: list[dict[str, Any]] = []


def incidents_processed_count() -> int:
    return len(_incidents)


# ---------------------------------------------------------------------------
# Seed scenarios (run once at startup to populate the demo UI)
# ---------------------------------------------------------------------------

SEED_SCENARIOS = [
    ("CPU utilization 98% sustained on payment service nodes",                     "Datadog"),
    ("Memory usage climbing steadily, OOM killed payment worker pods",             "CloudWatch"),
    ("Disk usage 96% critical on payment database volume",                        "Prometheus"),
    ("PostgreSQL connection pool exhausted: 500/500 connections in use",            "Datadog"),
    ("p99 latency on /api/payments degraded from 200ms to 3,100ms",                "Dynatrace"),
    ("Kafka consumer group payment-processor lag at 2.4M messages",                "Splunk"),
    ("Deadlock detected in payment order transaction processing",                  "PagerDuty"),
    ("Payment gateway API version mismatch causing request failures",              "Grafana"),
    ("Network packet loss 3.2% between us-east-1 and eu-west-1",                  "Grafana"),
    ("Unhandled exception crashing payment worker process repeatedly",             "Dynatrace"),
]


async def seed_incidents() -> None:
    """Process the demo seed scenarios once, spaced 2s apart, so the demo
    UI has data without blocking startup."""
    agent_log.append({"event": "seeding_started", "count": len(SEED_SCENARIOS)})
    for alert_text, source in SEED_SCENARIOS:
        try:
            await process_incident(alert_text, source)
        except Exception as exc:
            agent_log.append({"event": "seeding_error", "error": str(exc)})
        await asyncio.sleep(2)
    agent_log.append({"event": "seeding_complete", "count": len(SEED_SCENARIOS)})


# ---------------------------------------------------------------------------
# Core 5-layer agent loop
# ---------------------------------------------------------------------------

async def process_incident(alert_text: str, source: str) -> dict[str, Any]:
    incident_id = str(uuid.uuid4())[:8]
    started_at = datetime.now(timezone.utc).isoformat()

    agent_log.append({"event": "incident_started", "id": incident_id, "source": source})

    # ── Layer 1: Classify ────────────────────────────────────────────────────
    clf = get_classifier()
    ml_result = clf.classify(alert_text)
    agent_log.append({
        "event": "ml_classified",
        "id": incident_id,
        "category": ml_result.category,
        "severity": ml_result.severity,
        "confidence": round(ml_result.confidence, 3),
    })

    # LLM enrichment (optional)
    llm_result = classify_with_llm(alert_text, source)
    if llm_result is not None:
        agent_log.append({
            "event": "llm_classified",
            "id": incident_id,
            "category": llm_result.category,
            "severity": llm_result.severity,
            "confidence": round(llm_result.confidence, 3),
        })

    # Ensemble: LLM wins when confidence ≥ ML, otherwise keep ML
    if llm_result is not None and llm_result.confidence >= ml_result.confidence:
        final_category = llm_result.category
        final_severity = llm_result.severity
        classification_source = "llm"
        confidence = llm_result.confidence
        reasoning = llm_result.reasoning
    else:
        final_category = ml_result.category
        final_severity = ml_result.severity
        classification_source = "ml"
        confidence = ml_result.confidence
        reasoning = ml_result.reasoning

    agent_log.append({
        "event": "ensemble_result",
        "id": incident_id,
        "category": final_category,
        "severity": final_severity,
        "source": classification_source,
    })

    # ── Layer 2: RCA ─────────────────────────────────────────────────────────
    rca_dict, rca_source = generate_rca(alert_text, final_category, final_severity)
    agent_log.append({"event": "rca_generated", "id": incident_id, "rca_source": rca_source})

    # ── Layer 3: Remediate ───────────────────────────────────────────────────
    remediation = await dispatch(final_category, final_severity, alert_text)
    agent_log.append({
        "event": "remediation_complete",
        "id": incident_id,
        "action": remediation.action_taken,
        "escalated": remediation.escalate,
    })

    # ── Layer 4: Verify ──────────────────────────────────────────────────────
    verification = await verify(
        category=final_category,
        severity=final_severity,
        alert_text=alert_text,
        remediation_details={"action": remediation.action_taken},
    )
    agent_log.append({
        "event": "verification_complete",
        "id": incident_id,
        "status": verification["status"],
    })

    # ── Layer 5: Log ─────────────────────────────────────────────────────────
    incident = {
        "id": incident_id,
        "started_at": started_at,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "alert_text": alert_text,
        "classification": {
            "category": final_category,
            "severity": final_severity,
            "confidence": round(confidence, 3),
            "reasoning": reasoning,
            "source": classification_source,
        },
        "routing": {
            "team": ROUTE_TO.get(final_category, "payment-reliability"),
            "runbook": RUNBOOKS.get(final_category, ""),
        },
        "rca": {**rca_dict, "source": rca_source},
        "remediation": {
            "action_taken": remediation.action_taken,
            "simulated": remediation.simulated,
            "success": remediation.success,
            "details": remediation.details,
            "escalated": remediation.escalate,
            "escalation_reason": remediation.escalation_reason,
        },
        "verification": verification,
    }
    _incidents.append(incident)
    if len(_incidents) > 50:
        _incidents.pop(0)
    await save_incident(incident)
    agent_log.append({"event": "incident_complete", "id": incident_id, "verification": verification["status"]})

    return incident


async def handle_monitor_alert(alert: dict[str, Any]) -> None:
    """Callback invoked by the monitor when a threshold is breached."""
    await process_incident(
        alert_text=alert.get("alert_text", "Monitor threshold breached"),
        source=alert.get("source", "monitor"),
    )
