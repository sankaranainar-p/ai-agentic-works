"""
pre/api/routes.py — FastAPI route handlers for the AI Payment
Reliability Engine.

Every handler is a thin wrapper: validate/shape input, delegate to
pre.agent_loop / pre.database / pre.agent_log, shape the response. No
business logic lives here — see pre/agent_loop.py for the 5-layer loop.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import pre.agent_log as agent_log
from pre.agent_loop import incidents_processed_count, process_incident
from pre.auth import verify_api_key
from pre.database import get_incidents, get_stats

router = APIRouter()


class TriggerRequest(BaseModel):
    alert_text: str
    source: str = "api"


@router.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "incidents_processed": incidents_processed_count(),
        "log_entries": agent_log.count(),
    }


@router.post("/trigger", dependencies=[Depends(verify_api_key)])
async def trigger(req: TriggerRequest) -> dict[str, Any]:
    if not req.alert_text.strip():
        raise HTTPException(status_code=422, detail="alert_text must not be empty")
    return await process_incident(req.alert_text, req.source)


@router.get("/incidents", dependencies=[Depends(verify_api_key)])
async def list_incidents(limit: int = 50) -> list[dict[str, Any]]:
    return await get_incidents(limit)


@router.get("/agent-log", dependencies=[Depends(verify_api_key)])
async def get_agent_log(n: int = 100) -> list[dict[str, Any]]:
    return agent_log.get_recent(n)


@router.get("/agent-log/stream", dependencies=[Depends(verify_api_key)])
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


@router.get("/stats", dependencies=[Depends(verify_api_key)])
async def stats() -> dict[str, Any]:
    return await get_stats()


@router.get("/scenarios")
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
