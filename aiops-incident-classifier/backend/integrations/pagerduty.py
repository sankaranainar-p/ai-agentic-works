"""
PagerDuty Events API v2 integration.
Triggers alerts for SEV-1 and SEV-2 incidents.
"""
import os
import httpx
from backend.models.schemas import EnsembleOutput, Severity

PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

SEV_TO_PRIO = {
    Severity.SEV1: "critical",
    Severity.SEV2: "error",
    Severity.SEV3: "warning",
    Severity.SEV4: "info",
}


def trigger(alert_text: str, result: EnsembleOutput) -> bool:
    """Send a PagerDuty alert for SEV-1 or SEV-2 incidents. Returns True on success."""
    routing_key = os.getenv("PAGERDUTY_ROUTING_KEY")
    if not routing_key:
        return False

    final = result.final_decision
    if final.severity not in (Severity.SEV1, Severity.SEV2):
        return False

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": alert_text[:1024],
            "severity": SEV_TO_PRIO[final.severity],
            "source": "aiops-incident-classifier",
            "custom_details": {
                "category": final.category.value,
                "confidence": round(final.confidence, 3),
                "route_to": final.route_to,
                "runbook": final.runbook,
                "recommended_action": final.recommended_action,
                "escalation_required": final.escalation_required,
                "auto_remediation": final.auto_remediation,
                "reasoning": final.reasoning,
                "incident_id": result.incident_id,
                "models_agreed": result.agreement,
            },
        },
    }

    try:
        resp = httpx.post(PD_EVENTS_URL, json=payload, timeout=10)
        return resp.status_code == 202
    except httpx.RequestError:
        return False
