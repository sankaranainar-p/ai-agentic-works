"""
app/main.py — FastAPI application for the AI Payment Reliability Engine.

5-layer agent loop (per incident):
  1. Classify   — ML + LLM ensemble
  2. RCA        — Ollama → template → default
  3. Remediate  — category-specific handler + Slack/PagerDuty
  4. Verify     — wait VERIFY_WAIT_SECONDS, re-poll simulated metrics
  5. Log        — persist full incident record in agent_log

Endpoints:
  GET  /health
  POST /trigger
  GET  /incidents
  GET  /agent-log
  GET  /agent-log/stream   (SSE)
  GET  /stats
  GET  /scenarios
"""

from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

load_dotenv()

import app.agent_log as agent_log
import app.monitor as monitor
from app.auth import verify_api_key
from app.classifier.llm import classify_with_llm
from app.database import get_incidents, get_stats, init_db, save_incident
from app.classifier.model import ROUTE_TO, RUNBOOKS, SEVERITY_MAP, get_classifier
from app.rca import generate_rca
from app.remediation.dispatcher import dispatch
from app.verification import verify

# ---------------------------------------------------------------------------
# In-memory incident store
# ---------------------------------------------------------------------------

_incidents: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

_SEED_SCENARIOS = [
    ("HTTP 500 error rate at 9.2% on /api/v2/payments",                            "Datadog"),
    ("DDoS attack: 900,000 requests/min from 52 countries targeting /api/payment", "CloudWatch"),
    ("Service availability dropped to 96.8%, below 99.9% SLA threshold",           "Prometheus"),
    ("PostgreSQL connection pool exhausted: 500/500 connections in use",            "Datadog"),
    ("p99 latency on /api/payments degraded from 200ms to 3,100ms",                "Dynatrace"),
    ("Kafka consumer group payment-processor lag at 2.4M messages",                "Splunk"),
    ("Brute force attack: 1,200 failed login attempts from 45.33.22.11",           "PagerDuty"),
    ("Kubernetes node not-ready, 3 pods pending on infra cluster",                 "Grafana"),
    ("Network packet loss 3.2% between us-east-1 and eu-west-1",                  "Grafana"),
    ("p99 latency spike to 3,200ms on checkout service, SLO breach imminent",      "Dynatrace"),
]


async def _seed_incidents() -> None:
    agent_log.append({"event": "seeding_started", "count": len(_SEED_SCENARIOS)})
    for alert_text, source in _SEED_SCENARIOS:
        try:
            await _process_incident(alert_text, source)
        except Exception as exc:
            agent_log.append({"event": "seeding_error", "error": str(exc)})
        await asyncio.sleep(2)
    agent_log.append({"event": "seeding_complete", "count": len(_SEED_SCENARIOS)})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Initialise SQLite
    await init_db()
    agent_log.append({"event": "startup", "step": "db_ready"})

    # Pre-warm the ML classifier (fits on first call — do it at startup)
    agent_log.append({"event": "startup", "step": "pre_warming_classifier"})
    clf = get_classifier()
    agent_log.append({"event": "startup", "step": "classifier_ready"})

    # Start background monitor
    await monitor.start(_handle_monitor_alert)
    agent_log.append({"event": "startup", "step": "monitor_started"})

    # Seed demo incidents in the background so startup is non-blocking
    asyncio.create_task(_seed_incidents())
    agent_log.append({"event": "startup", "step": "seeding_scheduled"})

    yield

    await monitor.stop()
    agent_log.append({"event": "shutdown"})


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Payment Reliability Engine",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Core 5-layer agent loop
# ---------------------------------------------------------------------------

async def _process_incident(alert_text: str, source: str) -> dict[str, Any]:
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


async def _handle_monitor_alert(alert: dict[str, Any]) -> None:
    """Callback invoked by the monitor when a threshold is breached."""
    await _process_incident(
        alert_text=alert.get("alert_text", "Monitor threshold breached"),
        source=alert.get("source", "monitor"),
    )


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class TriggerRequest(BaseModel):
    alert_text: str
    source: str = "api"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "incidents_processed": len(_incidents),
        "log_entries": agent_log.count(),
    }


@app.post("/trigger", dependencies=[Depends(verify_api_key)])
async def trigger(req: TriggerRequest) -> dict[str, Any]:
    if not req.alert_text.strip():
        raise HTTPException(status_code=422, detail="alert_text must not be empty")
    incident = await _process_incident(req.alert_text, req.source)
    return incident


@app.get("/incidents", dependencies=[Depends(verify_api_key)])
async def list_incidents(limit: int = 50) -> list[dict[str, Any]]:
    return await get_incidents(limit)


@app.get("/agent-log", dependencies=[Depends(verify_api_key)])
async def get_agent_log(n: int = 100) -> list[dict[str, Any]]:
    return agent_log.get_recent(n)


@app.get("/agent-log/stream", dependencies=[Depends(verify_api_key)])
async def stream_agent_log() -> StreamingResponse:
    """Server-Sent Events stream of new log entries."""

    async def _generate() -> AsyncGenerator[str, None]:
        cursor = agent_log.count()
        while True:
            current = agent_log.count()
            if current > cursor:
                entries = agent_log.get_recent(current - cursor)
                for entry in entries:
                    yield f"data: {json.dumps(entry)}\n\n"
                cursor = current
            await asyncio.sleep(0.5)

    return StreamingResponse(_generate(), media_type="text/event-stream")


@app.get("/stats", dependencies=[Depends(verify_api_key)])
async def stats() -> dict[str, Any]:
    return await get_stats()


@app.get("/scenarios")
async def scenarios() -> list[dict[str, str]]:
    """Return sample alert texts for manual testing."""
    return [
        {"name": "HTTP 500 spike",          "alert_text": "Payment service 500 error rate 8% on /api/checkout"},
        {"name": "DDoS attack",             "alert_text": "WAF triggered: 500k requests/min flood from botnet IPs"},
        {"name": "Availability drop",       "alert_text": "Checkout service availability dropped to 98.1% — health checks failing"},
        {"name": "Performance degradation", "alert_text": "p99 latency 4500ms on payment processing API"},
        {"name": "Database issue",          "alert_text": "PostgreSQL connection pool exhausted, max_connections reached"},
        {"name": "Auth failure",            "alert_text": "SSL certificate expiring in 12 hours for payment-gateway.example.com"},
        {"name": "Network issue",           "alert_text": "Packet loss 15% between payment service and database host"},
        {"name": "Data pipeline",           "alert_text": "Kafka consumer lag 800k messages on payment-events topic"},
        {"name": "Infrastructure",          "alert_text": "Payment service pods crashlooping in production namespace"},
        {"name": "Security alert",          "alert_text": "SQL injection attempt detected on payment API endpoint"},
        {"name": "Unknown",                 "alert_text": "Unclassified anomaly detected in payment platform"},
    ]
