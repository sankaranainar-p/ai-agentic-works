"""
Tests for ensemble classifier covering all 11 incident categories.
All external calls (ML model, Anthropic API) are mocked.
"""
import pytest
from unittest.mock import patch
from backend.models.schemas import Category, ClassificationOutput, IncidentInput, Severity
from backend.classifier import ensemble


def _output(category: Category, severity: Severity, confidence: float) -> ClassificationOutput:
    return ClassificationOutput(
        category=category,
        severity=severity,
        confidence=confidence,
        recommended_action="Take action",
        runbook=["Step 1", "Step 2"],
        route_to="SRE On-Call",
        auto_remediation=False,
        escalation_required=severity == Severity.SEV1,
    )


def _incident(text: str = "test alert") -> IncidentInput:
    return IncidentInput(alert_text=text)


def _classify(ml_out: ClassificationOutput, llm_out: ClassificationOutput, text: str = "t") -> ensemble.EnsembleOutput:
    with patch("backend.classifier.ensemble.ml_classifier.classify", return_value=ml_out), \
         patch("backend.classifier.ensemble.llm_classifier.classify", return_value=llm_out):
        return ensemble.classify(_incident(text))


# --- Category coverage tests ---

@pytest.mark.parametrize("category,severity", [
    (Category.INFRASTRUCTURE, Severity.SEV2),
    (Category.APPLICATION, Severity.SEV2),
    (Category.DATABASE, Severity.SEV1),
    (Category.NETWORK, Severity.SEV2),
    (Category.SECURITY, Severity.SEV1),
    (Category.DATA_PIPELINE, Severity.SEV3),
    (Category.PERFORMANCE_DEGRADATION, Severity.SEV3),
    (Category.AVAILABILITY, Severity.SEV1),
    (Category.DDOS_ATTACK, Severity.SEV1),
    (Category.AVAILABILITY_DROP, Severity.SEV2),
    (Category.HTTP_500_SPIKE, Severity.SEV2),
])
def test_all_categories_classified(category, severity):
    """Ensemble correctly classifies all 11 categories."""
    ml = _output(category, severity, 0.8)
    llm = _output(category, severity, 0.85)
    result = _classify(ml, llm)
    assert result.final_decision.category == category


def test_agreement_boosts_confidence():
    """When both models agree, final confidence exceeds both individual scores."""
    ml = _output(Category.APPLICATION, Severity.SEV2, 0.75)
    llm = _output(Category.APPLICATION, Severity.SEV2, 0.85)
    result = _classify(ml, llm)
    assert result.agreement is True
    assert result.final_decision.confidence > 0.85


def test_disagreement_picks_higher_confidence():
    """On disagreement, the higher-confidence model wins with a penalty."""
    ml = _output(Category.NETWORK, Severity.SEV3, 0.6)
    llm = _output(Category.SECURITY, Severity.SEV1, 0.92)
    result = _classify(ml, llm)
    assert result.agreement is False
    assert result.final_decision.category == Category.SECURITY
    assert result.final_decision.confidence < 0.92


def test_disagreement_penalty_applied():
    """Confidence penalty is applied when models disagree."""
    ml = _output(Category.NETWORK, Severity.SEV3, 0.55)
    llm = _output(Category.DATABASE, Severity.SEV1, 0.80)
    result = _classify(ml, llm)
    assert result.final_decision.confidence < 0.80


# --- Special rule tests ---

def test_ddos_always_sev1():
    """DDoS incidents are always forced to SEV-1 regardless of model output."""
    ml = _output(Category.DDOS_ATTACK, Severity.SEV3, 0.7)
    llm = _output(Category.DDOS_ATTACK, Severity.SEV3, 0.8)
    result = _classify(ml, llm)
    assert result.final_decision.severity == Severity.SEV1


def test_ddos_always_escalation_required():
    """DDoS incidents always require escalation."""
    ml = _output(Category.DDOS_ATTACK, Severity.SEV2, 0.75)
    llm = _output(Category.DDOS_ATTACK, Severity.SEV2, 0.88)
    result = _classify(ml, llm)
    assert result.final_decision.escalation_required is True


def test_http_500_high_confidence_requires_escalation():
    """HTTP 500 spike with confidence > 0.8 requires escalation."""
    ml = _output(Category.HTTP_500_SPIKE, Severity.SEV2, 0.85)
    llm = _output(Category.HTTP_500_SPIKE, Severity.SEV2, 0.90)
    result = _classify(ml, llm)
    # Agreement + bonus will push confidence above threshold
    assert result.final_decision.escalation_required is True


def test_sev1_always_escalation():
    """Any SEV-1 final decision requires escalation."""
    ml = _output(Category.DATABASE, Severity.SEV1, 0.9)
    llm = _output(Category.DATABASE, Severity.SEV1, 0.88)
    result = _classify(ml, llm)
    assert result.final_decision.severity == Severity.SEV1
    assert result.final_decision.escalation_required is True


# --- Structural tests ---

def test_ensemble_returns_both_results_and_id():
    """EnsembleOutput contains ml_result, llm_result, final_decision, and incident_id."""
    ml = _output(Category.DATABASE, Severity.SEV1, 0.8)
    llm = _output(Category.DATABASE, Severity.SEV1, 0.9)
    with patch("backend.classifier.ensemble.ml_classifier.classify", return_value=ml), \
         patch("backend.classifier.ensemble.llm_classifier.classify", return_value=llm):
        result = ensemble.classify(_incident(), incident_id="abc-123")

    assert result.ml_result.category == Category.DATABASE
    assert result.llm_result.category == Category.DATABASE
    assert result.incident_id == "abc-123"


def test_final_confidence_always_in_range():
    """Final confidence is always clamped to [0, 1]."""
    for ml_conf, llm_conf in [(0.5, 0.5), (0.9, 0.9), (0.3, 0.7), (0.95, 0.95)]:
        ml = _output(Category.INFRASTRUCTURE, Severity.SEV2, ml_conf)
        llm = _output(Category.INFRASTRUCTURE, Severity.SEV2, llm_conf)
        result = _classify(ml, llm)
        assert 0.0 <= result.final_decision.confidence <= 1.0
