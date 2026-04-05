"""
LLM-based incident classifier using Claude with tool_use for structured output.
Tool_use forces Claude to return a typed JSON schema — more reliable than parsing
free-form text or streaming JSON.
"""
import os
import anthropic
from backend.models.schemas import (
    Category, ClassificationOutput, IncidentInput, Severity
)
from backend.classifier.maps import ROUTING_MAP, RUNBOOK_MAP


class LLMUnavailableError(Exception):
    """Raised when the LLM cannot be reached due to auth, permission, or billing issues."""
    pass

SYSTEM_PROMPT = """\
You are an expert AIOps incident classification engine for a fintech/payments infrastructure.
Analyze the incident alert and call the classify_incident tool with accurate values.

Severity guide:
- SEV-1: Production outage, revenue impact, data breach, DDoS under attack
- SEV-2: Degraded service, significant user impact, partial availability loss
- SEV-3: Minor degradation, workaround available, low user impact
- SEV-4: Informational, no immediate user impact

Auto-remediation: true only for availability_drop, http_500_spike, or performance_degradation
Escalation required: true for SEV-1 or SEV-2, or any security/ddos_attack/availability incident
"""

CLASSIFY_TOOL = {
    "name": "classify_incident",
    "description": "Classify a fintech infrastructure incident with severity, category, and routing",
    "input_schema": {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "enum": [c.value for c in Category],
                "description": "Incident category",
            },
            "severity": {
                "type": "string",
                "enum": [s.value for s in Severity],
                "description": "Incident severity level",
            },
            "confidence": {
                "type": "number",
                "description": "Confidence score between 0.0 and 1.0",
            },
            "recommended_action": {
                "type": "string",
                "description": "Single most important immediate action to take",
            },
            "auto_remediation": {
                "type": "boolean",
                "description": "Whether an automated remediation script can handle this",
            },
            "escalation_required": {
                "type": "boolean",
                "description": "Whether this requires immediate human escalation",
            },
            "reasoning": {
                "type": "string",
                "description": "One-sentence explanation of the classification",
            },
        },
        "required": [
            "category", "severity", "confidence",
            "recommended_action", "auto_remediation", "escalation_required",
        ],
    },
}


def classify(incident: IncidentInput) -> ClassificationOutput:
    """Classify an incident using Claude tool_use for structured output.

    Raises:
        LLMUnavailableError: when auth/permission/billing prevents the API call.
    """
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

    user_message = f"Alert: {incident.alert_text}"
    if incident.source:
        user_message += f"\nSource: {incident.source}"
    if incident.timestamp:
        user_message += f"\nTimestamp: {incident.timestamp}"

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=[CLASSIFY_TOOL],
            tool_choice={"type": "tool", "name": "classify_incident"},
            messages=[{"role": "user", "content": user_message}],
        )
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
        raise LLMUnavailableError(str(exc)) from exc
    except Exception as exc:
        if "credit" in str(exc).lower():
            raise LLMUnavailableError(str(exc)) from exc
        raise

    # Extract the tool_use block — tool_choice forces exactly one
    tool_input = None
    for block in response.content:
        if block.type == "tool_use" and block.name == "classify_incident":
            tool_input = block.input
            break

    if tool_input is None:
        return _fallback()

    try:
        category = Category(tool_input["category"])
        severity = Severity(tool_input["severity"])
        confidence = float(tool_input.get("confidence", 0.8))
        confidence = min(max(confidence, 0.0), 1.0)
        recommended_action = tool_input.get("recommended_action", RUNBOOK_MAP[category][0])
        auto_remediation = bool(tool_input.get("auto_remediation", False))
        escalation_required = bool(tool_input.get("escalation_required", False))
        reasoning = tool_input.get("reasoning")
    except (KeyError, ValueError):
        return _fallback()

    # Enforce: DDoS is always SEV-1 + escalation
    if category == Category.DDOS_ATTACK:
        severity = Severity.SEV1
        escalation_required = True

    # HTTP 500 spike threshold: if confidence > 0.8, mark for escalation
    if category == Category.HTTP_500_SPIKE and confidence > 0.8:
        escalation_required = True

    return ClassificationOutput(
        category=category,
        severity=severity,
        confidence=confidence,
        recommended_action=recommended_action,
        runbook=RUNBOOK_MAP[category],
        route_to=ROUTING_MAP[category],
        auto_remediation=auto_remediation,
        escalation_required=escalation_required,
        reasoning=reasoning,
    )


def _fallback() -> ClassificationOutput:
    """Safe fallback classification when the model response is unusable."""
    cat = Category.APPLICATION
    return ClassificationOutput(
        category=cat,
        severity=Severity.SEV3,
        confidence=0.4,
        recommended_action=RUNBOOK_MAP[cat][0],
        runbook=RUNBOOK_MAP[cat],
        route_to=ROUTING_MAP[cat],
        auto_remediation=False,
        escalation_required=False,
        reasoning="LLM returned unexpected response; defaulting to application/SEV-3",
    )
