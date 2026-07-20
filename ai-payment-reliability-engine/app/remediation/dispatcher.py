"""
app/remediation/dispatcher.py — Routes alerts to the correct handler.

Integrations:
  - Slack  (slack-sdk)    — real notification for SEV-1; requires SLACK_BOT_TOKEN + SLACK_CHANNEL
  - PagerDuty (httpx)    — real escalation webhook; requires PAGERDUTY_ROUTING_KEY
  Both integrations degrade gracefully when env vars are absent (log-only).
"""

from __future__ import annotations

import os
from typing import Any

import httpx

import app.agent_log as agent_log
from app.remediation import RemediationResult
from app.remediation.handlers import (
    handle_authentication,
    handle_availability_drop,
    handle_data_pipeline,
    handle_database,
    handle_ddos_attack,
    handle_http_500_spike,
    handle_infrastructure,
    handle_network,
    handle_performance_degradation,
    handle_security,
    handle_unknown,
)

_HANDLERS = {
    "http_500_spike":         handle_http_500_spike,
    "ddos_attack":            handle_ddos_attack,
    "availability_drop":      handle_availability_drop,
    "performance_degradation":handle_performance_degradation,
    "database":               handle_database,
    "authentication":         handle_authentication,
    "network":                handle_network,
    "data_pipeline":          handle_data_pipeline,
    "infrastructure":         handle_infrastructure,
    "security":               handle_security,
    "unknown":                handle_unknown,
}


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

async def _notify_slack(message: str, severity: str) -> None:
    token = os.getenv("SLACK_BOT_TOKEN")
    channel = os.getenv("SLACK_CHANNEL", "#incidents")

    if not token:
        agent_log.append({"event": "slack_skip", "reason": "SLACK_BOT_TOKEN not set", "message": message[:120]})
        return

    try:
        from slack_sdk.web.async_client import AsyncWebClient  # type: ignore

        client = AsyncWebClient(token=token)
        await client.chat_postMessage(
            channel=channel,
            text=f"*[{severity}]* {message}",
        )
        agent_log.append({"event": "slack_sent", "channel": channel, "severity": severity})
    except Exception as exc:
        agent_log.append({"event": "slack_error", "error": str(exc)})


# ---------------------------------------------------------------------------
# PagerDuty
# ---------------------------------------------------------------------------

async def _escalate_pagerduty(
    summary: str,
    severity: str,
    category: str,
    details: dict[str, Any],
) -> None:
    routing_key = os.getenv("PAGERDUTY_ROUTING_KEY")

    if not routing_key:
        agent_log.append({
            "event": "pagerduty_skip",
            "reason": "PAGERDUTY_ROUTING_KEY not set",
            "summary": summary[:120],
        })
        return

    pd_severity = {
        "SEV-1": "critical",
        "SEV-2": "error",
        "SEV-3": "warning",
        "SEV-4": "info",
    }.get(severity, "warning")

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "severity": pd_severity,
            "source": "ai-payment-reliability-engine",
            "custom_details": {
                "category": category,
                **details,
            },
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
            )
            resp.raise_for_status()
        agent_log.append({"event": "pagerduty_sent", "severity": severity, "category": category})
    except Exception as exc:
        agent_log.append({"event": "pagerduty_error", "error": str(exc)})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def dispatch(
    category: str,
    severity: str,
    alert_text: str,
) -> RemediationResult:
    """Route to the correct handler, then fire Slack/PagerDuty as needed."""
    handler = _HANDLERS.get(category, handle_unknown)
    result: RemediationResult = await handler(alert_text, severity)

    agent_log.append({
        "event": "remediation_dispatched",
        "category": category,
        "severity": severity,
        "action": result.action_taken,
        "success": result.success,
        "escalate": result.escalate,
    })

    # Slack notification for SEV-1
    if severity == "SEV-1":
        await _notify_slack(
            f"SEV-1 incident — {category}: {result.action_taken}",
            severity,
        )

    # PagerDuty escalation when handler requests it
    if result.escalate:
        await _escalate_pagerduty(
            summary=f"[{severity}] {category}: {result.escalation_reason or result.action_taken}",
            severity=severity,
            category=category,
            details={
                "action_taken": result.action_taken,
                "details": result.details,
                "alert_text": alert_text[:500],
            },
        )

    return result
