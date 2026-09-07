"""
tests/test_rca_agent.py — Tests for RCA agent and schema validation.

Tests Pydantic schema enforcement, evidence ID validation, and claim filtering.
"""

import pytest

from pre.agents.rca import Claim, RCAResult, RCAAgent
from pre.agents.evidence import EvidenceItem, EvidencePack


def test_claim_requires_evidence():
    """Test that claims require at least one evidence ID."""
    with pytest.raises(ValueError):
        Claim(text="Claim", evidence_ids=[], confidence=0.8)


def test_claim_creation():
    """Test valid claim creation."""
    claim = Claim(
        text="Payment service CPU overload",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.85,
    )
    assert claim.text == "Payment service CPU overload"
    assert len(claim.evidence_ids) == 1
    assert claim.confidence == 0.85


def test_claim_multiple_evidence():
    """Test claim with multiple evidence IDs."""
    claim = Claim(
        text="Payment service degradation",
        evidence_ids=[
            "kpi:payment:cpu",
            "span:t1a2b",
            "logtpl:hash123",
        ],
        confidence=0.9,
    )
    assert len(claim.evidence_ids) == 3


def test_claim_confidence_bounds():
    """Test confidence score bounds."""
    # Valid bounds
    Claim(text="Test", evidence_ids=["kpi:svc:metric"], confidence=0.0)
    Claim(text="Test", evidence_ids=["kpi:svc:metric"], confidence=1.0)

    # Invalid bounds should raise
    with pytest.raises(ValueError):
        Claim(text="Test", evidence_ids=["kpi:svc:metric"], confidence=-0.1)

    with pytest.raises(ValueError):
        Claim(text="Test", evidence_ids=["kpi:svc:metric"], confidence=1.1)


def test_rca_result_creation():
    """Test RCAResult creation."""
    result = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="CPU overload",
        contributing_factors=["high traffic", "inefficient code"],
        claims=[],
        dropped_claims=0,
    )
    assert result.case_id == "TEST-001"
    assert result.root_cause_service == "payment"
    assert len(result.contributing_factors) == 2


def test_rca_agent_validation():
    """Test RCAAgent filters claims with invalid evidence IDs."""
    # Create evidence pack
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "CPU spiked", "payment"),
        EvidenceItem("span:t1a2b", "span", 0.8, "High error rate", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)

    # Create agent
    agent = RCAAgent(pack)

    # Valid claim (evidence exists)
    valid_claim = Claim(
        text="Payment service overload",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.85,
    )

    # Invalid claim (evidence doesn't exist)
    invalid_claim = Claim(
        text="Unknown problem",
        evidence_ids=["kpi:unknown:metric"],
        confidence=0.5,
    )

    # Validate
    valid, dropped = agent.validate_and_filter_claims([valid_claim, invalid_claim])

    assert len(valid) == 1
    assert dropped == 1
    assert valid[0].text == "Payment service overload"


def test_rca_agent_create_result():
    """Test RCAAgent creates result with dropped claims counted."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "CPU spiked", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    agent = RCAAgent(pack)

    valid_claim = Claim(
        text="CPU overload",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.85,
    )
    invalid_claim = Claim(
        text="Unknown",
        evidence_ids=["kpi:unknown:metric"],
        confidence=0.5,
    )

    result = agent.create_result(
        root_cause_service="payment",
        probable_cause="High CPU utilization",
        claims=[valid_claim, invalid_claim],
        contributing_factors=["Traffic spike"],
    )

    assert result.case_id == "TEST-001"
    assert result.root_cause_service == "payment"
    assert len(result.claims) == 1
    assert result.dropped_claims == 1
    assert result.claims[0].text == "CPU overload"


def test_rca_agent_mixed_evidence():
    """Test agent with claims having multiple evidence IDs."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "CPU spiked", "payment"),
        EvidenceItem("span:t1a2b", "span", 0.8, "Error rate up", "payment"),
        EvidenceItem("logtpl:hash123", "log", 0.7, "Novel errors", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=100)
    agent = RCAAgent(pack)

    # Claim with all valid evidence
    claim1 = Claim(
        text="Payment service failure",
        evidence_ids=["kpi:payment:cpu", "span:t1a2b", "logtpl:hash123"],
        confidence=0.9,
    )

    # Claim with partial valid evidence (should be dropped because one ID is invalid)
    claim2 = Claim(
        text="Unknown issue",
        evidence_ids=["kpi:payment:cpu", "kpi:unknown:metric"],
        confidence=0.5,
    )

    valid, dropped = agent.validate_and_filter_claims([claim1, claim2])

    assert len(valid) == 1
    assert dropped == 1
    assert valid[0].text == "Payment service failure"


def test_rca_result_schema_validation():
    """Test RCAResult Pydantic validation."""
    # Valid result
    result = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="CPU overload",
    )
    assert result.case_id == "TEST-001"

    # Missing required field should raise
    with pytest.raises(ValueError):
        RCAResult(
            # Missing case_id
            root_cause_service="payment",
            probable_cause="CPU overload",
        )
