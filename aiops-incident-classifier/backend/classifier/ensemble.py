"""
Ensemble classifier: combines ML (40% weight) and LLM (60% weight).

Special rules (applied before severity override post-processing):
- ddos_attack: always forced to SEV-1 + escalation_required regardless of model output
- http_500_spike: escalation_required=True when final confidence > 0.8
- Agreement bonus: +0.05 confidence when both models agree on category
- Disagreement penalty: 0.9x confidence multiplier when models disagree

Post-processing severity overrides (run after both classifiers, both modes):
- availability_drop + alert contains availability % < 99.9  → SEV-1 + escalation
- http_500_spike   + alert contains error rate   % > 5.0   → SEV-1 + escalation
Sets ClassificationOutput.severity_override=True when triggered.
"""
import re
from typing import Optional

from backend.models.schemas import (
    Category, ClassificationOutput, EnsembleOutput, IncidentInput, Severity
)
from backend.classifier import llm_classifier, ml_classifier
from backend.classifier.llm_classifier import LLMUnavailableError

ML_WEIGHT = 0.4
LLM_WEIGHT = 0.6

HTTP_500_ESCALATION_THRESHOLD = 0.8

# Regex to extract all bare percentage values from alert text (e.g. "96.8%", "7%")
_PCT_RE = re.compile(r'\b(\d+(?:\.\d+)?)\s*%')

AVAILABILITY_DROP_THRESHOLD = 99.9   # availability below this → SEV-1
HTTP_500_ERROR_RATE_THRESHOLD = 5.0  # error rate above this  → SEV-1


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def classify(incident: IncidentInput, incident_id: Optional[str] = None) -> EnsembleOutput:
    ml_result = ml_classifier.classify(incident)

    try:
        llm_result = llm_classifier.classify(incident)
        llm_status = "ok"
    except LLMUnavailableError:
        return _ml_only_result(ml_result, incident, incident_id)

    agreement = ml_result.category == llm_result.category

    if agreement:
        blended_confidence = (
            ml_result.confidence * ML_WEIGHT + llm_result.confidence * LLM_WEIGHT
        )
        final_confidence = min(blended_confidence + 0.05, 1.0)
        base = llm_result  # LLM drives the final on agreement
    else:
        base = llm_result if llm_result.confidence >= ml_result.confidence else ml_result
        final_confidence = base.confidence * 0.9

    # Pre-override special rules
    final_category = base.category
    final_severity = base.severity
    final_escalation = base.escalation_required

    if final_category == Category.DDOS_ATTACK:
        final_severity = Severity.SEV1
        final_escalation = True

    if final_category == Category.HTTP_500_SPIKE and final_confidence > HTTP_500_ESCALATION_THRESHOLD:
        final_escalation = True

    if final_severity == Severity.SEV1:
        final_escalation = True

    final_decision = ClassificationOutput(
        category=final_category,
        severity=final_severity,
        confidence=min(max(final_confidence, 0.0), 1.0),
        recommended_action=base.recommended_action,
        runbook=base.runbook,
        route_to=base.route_to,
        auto_remediation=base.auto_remediation,
        escalation_required=final_escalation,
        reasoning=base.reasoning,
    )

    # Post-processing: text-based severity overrides (runs regardless of mode)
    final_decision = _apply_severity_overrides(final_decision, incident.alert_text)

    return EnsembleOutput(
        ml_result=ml_result,
        llm_result=llm_result,
        final_decision=final_decision,
        agreement=agreement,
        llm_status=llm_status,
        incident_id=incident_id,
    )


# ---------------------------------------------------------------------------
# ML-only fallback (LLM unavailable)
# ---------------------------------------------------------------------------

def _ml_only_result(
    ml_result: ClassificationOutput,
    incident: IncidentInput,
    incident_id: Optional[str],
) -> EnsembleOutput:
    """Build an EnsembleOutput using only the ML classifier when LLM is unavailable."""
    final_category = ml_result.category
    final_severity = ml_result.severity
    final_escalation = ml_result.escalation_required

    if final_category == Category.DDOS_ATTACK:
        final_severity = Severity.SEV1
        final_escalation = True

    if final_severity == Severity.SEV1:
        final_escalation = True

    final_decision = ClassificationOutput(
        category=final_category,
        severity=final_severity,
        confidence=ml_result.confidence,
        recommended_action=ml_result.recommended_action,
        runbook=ml_result.runbook,
        route_to=ml_result.route_to,
        auto_remediation=ml_result.auto_remediation,
        escalation_required=final_escalation,
        reasoning="ML-only classification — LLM unavailable",
    )

    # Post-processing still runs in fallback mode
    final_decision = _apply_severity_overrides(final_decision, incident.alert_text)

    return EnsembleOutput(
        ml_result=ml_result,
        llm_result=None,
        final_decision=final_decision,
        agreement=False,
        llm_status="unavailable",
        incident_id=incident_id,
    )


# ---------------------------------------------------------------------------
# Post-processing: text-based severity overrides
# ---------------------------------------------------------------------------

def _apply_severity_overrides(
    decision: ClassificationOutput,
    alert_text: str,
) -> ClassificationOutput:
    """Apply text-based severity override rules to a final_decision.

    Rules:
    1. availability_drop + any percentage in alert_text < 99.9  → SEV-1
    2. http_500_spike   + any percentage in alert_text > 5.0    → SEV-1
    3. ddos_attack      → already SEV-1, no change needed

    Sets severity_override=True on the returned object when a rule fires.
    Returns the original object unchanged when no rule fires.
    """
    category = decision.category

    if category not in (Category.AVAILABILITY_DROP, Category.HTTP_500_SPIKE):
        return decision

    percentages = [float(m) for m in _PCT_RE.findall(alert_text)]

    triggered = False
    if category == Category.AVAILABILITY_DROP:
        triggered = any(p < AVAILABILITY_DROP_THRESHOLD for p in percentages)
    elif category == Category.HTTP_500_SPIKE:
        triggered = any(p > HTTP_500_ERROR_RATE_THRESHOLD for p in percentages)

    if not triggered:
        return decision

    return ClassificationOutput(
        category=decision.category,
        severity=Severity.SEV1,
        confidence=decision.confidence,
        recommended_action=decision.recommended_action,
        runbook=decision.runbook,
        route_to=decision.route_to,
        auto_remediation=decision.auto_remediation,
        escalation_required=True,
        severity_override=True,
        reasoning=decision.reasoning,
    )
