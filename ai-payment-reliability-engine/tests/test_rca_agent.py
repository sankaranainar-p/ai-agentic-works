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


# ---------------------------------------------------------------------------
# Prompt-subset citation validation + evidence-service consistency
# ---------------------------------------------------------------------------

def _delay_pack():
    """The real RE1-OB_checkoutservice_delay_1 shape: checkoutservice latency
    ranks 1-2 (shown), currencyservice metrics rank lower (NOT shown at k=2)."""
    return EvidencePack(
        case_id="RE1-OB_checkoutservice_delay_1",
        items=[
            EvidenceItem("kpi:checkoutservice:latency-50", "kpi", 8.71,
                         "checkoutservice:latency-50 spiked to 2.7 (z=6055.2)", "checkoutservice"),
            EvidenceItem("kpi:checkoutservice:latency-90", "kpi", 7.94,
                         "checkoutservice:latency-90 spiked to 4.6 (z=2819.9)", "checkoutservice"),
            EvidenceItem("kpi:currencyservice:mem", "kpi", 1.5,
                         "currencyservice:mem spiked to 4.4e7 (z=3.8)", "currencyservice"),
            EvidenceItem("kpi:currencyservice:latency-90", "kpi", 1.6,
                         "currencyservice:latency-90 spiked (z=4.5)", "currencyservice"),
        ],
        token_estimate=80,
    )


def test_create_result_drops_id_outside_shown_prompt_subset():
    """A claim citing an id that IS in the full pack but was NOT rendered in
    the prompt (allowed_ids) must be dropped, not silently accepted."""
    agent = RCAAgent(_delay_pack())
    shown = {"kpi:checkoutservice:latency-50", "kpi:checkoutservice:latency-90"}  # top-2 rendered

    in_prompt = Claim(text="checkoutservice latency spiked hard",
                      evidence_ids=["kpi:checkoutservice:latency-50"], confidence=0.9)
    out_of_prompt = Claim(text="checkoutservice also had a memory blip",
                          evidence_ids=["kpi:currencyservice:mem"], confidence=0.6)  # real id, not shown

    res = agent.create_result("checkoutservice", "delay fault on checkoutservice",
                              [in_prompt, out_of_prompt], allowed_ids=shown)

    assert [c.text for c in res.claims] == ["checkoutservice latency spiked hard"]
    assert res.dropped_claims == 1
    assert "not shown in the prompt" in res.drop_reasons[0]
    assert "kpi:currencyservice:mem" in res.drop_reasons[0]


def test_create_result_flags_wrong_service_attribution():
    """The real checkoutservice_delay_1 failure: a claim naming 'currencyservice'
    while citing only checkoutservice evidence must be flagged/dropped."""
    agent = RCAAgent(_delay_pack())
    shown = {"kpi:checkoutservice:latency-50", "kpi:checkoutservice:latency-90"}

    misattributed = Claim(
        text="The currencyservice is experiencing high latency.",
        evidence_ids=["kpi:checkoutservice:latency-50", "kpi:checkoutservice:latency-90"],
        confidence=0.9,
    )
    correct = Claim(
        text="The checkoutservice is experiencing high latency.",
        evidence_ids=["kpi:checkoutservice:latency-50", "kpi:checkoutservice:latency-90"],
        confidence=0.9,
    )

    res = agent.create_result("checkoutservice", "delay on checkoutservice",
                              [misattributed, correct], allowed_ids=shown)

    assert [c.text for c in res.claims] == ["The checkoutservice is experiencing high latency."]
    assert res.dropped_claims == 1
    assert "currencyservice" in res.drop_reasons[0]
    assert "checkoutservice" in res.drop_reasons[0]


def test_short_pseudo_service_names_do_not_false_positive():
    """'main'/'redis' are pseudo-services in OB data — too short to scan for,
    so prose like 'the main issue' is not flagged."""
    pack = EvidencePack(
        case_id="c", token_estimate=10,
        items=[EvidenceItem("kpi:cartservice:cpu", "kpi", 5.0, "cartservice:cpu spiked", "cartservice"),
               EvidenceItem("kpi:main:mem", "kpi", 4.0, "main:mem spiked", "main"),
               EvidenceItem("kpi:redis:mem", "kpi", 4.0, "redis:mem spiked", "redis")],
    )
    agent = RCAAgent(pack)
    claim = Claim(text="The main issue is cartservice CPU saturation.",
                  evidence_ids=["kpi:cartservice:cpu"], confidence=0.9)
    res = agent.create_result("cartservice", "cpu", [claim],
                              allowed_ids={"kpi:cartservice:cpu"})
    assert len(res.claims) == 1 and res.dropped_claims == 0


# ---------------------------------------------------------------------------
# Headline root_cause_service verified against surviving claims
# ---------------------------------------------------------------------------

def test_headline_root_cause_needs_review_when_unbacked():
    """checkoutservice_delay_1 shape: model's summary says 'currencyservice'
    but the only claim that survives validation cites recommendationservice
    evidence -> the headline is not presented as a specific service."""
    agent = RCAAgent(_delay_pack())
    shown = {"kpi:checkoutservice:latency-50", "kpi:checkoutservice:latency-90"}
    surviving = Claim(
        text="recommendationservice load is elevated",
        evidence_ids=["kpi:checkoutservice:latency-50"], confidence=0.7,
    )  # names nothing >=6ch besides via cited svc; cites checkoutservice
    res = agent.create_result("currencyservice", "currencyservice mem saturation",
                              [surviving], allowed_ids=shown)
    # surviving claim's cited service is checkoutservice, not currencyservice
    assert res.root_cause_service == "needs_review"
    assert res.root_cause_verified is False
    assert res.proposed_root_cause_service == "currencyservice"
    assert "currencyservice" in res.review_reason and "checkoutservice" in res.review_reason


def test_headline_root_cause_kept_when_backed():
    agent = RCAAgent(_delay_pack())
    shown = {"kpi:checkoutservice:latency-50", "kpi:checkoutservice:latency-90"}
    claim = Claim(text="checkoutservice latency spiked far above baseline",
                  evidence_ids=["kpi:checkoutservice:latency-50", "kpi:checkoutservice:latency-90"],
                  confidence=0.95)
    res = agent.create_result("checkoutservice", "delay on checkoutservice",
                              [claim], allowed_ids=shown)
    assert res.root_cause_service == "checkoutservice"
    assert res.root_cause_verified is True
    assert res.review_reason == ""


def test_headline_unknown_when_model_abstains():
    agent = RCAAgent(_delay_pack())
    claim = Claim(text="checkoutservice latency spiked",
                  evidence_ids=["kpi:checkoutservice:latency-50"], confidence=0.9)
    res = agent.create_result("unknown", "cannot determine", [claim],
                              allowed_ids={"kpi:checkoutservice:latency-50"})
    assert res.root_cause_service == "unknown"
    assert res.root_cause_verified is False
    assert "did not identify" in res.review_reason


def test_headline_needs_review_when_all_claims_dropped():
    agent = RCAAgent(_delay_pack())
    bad = Claim(text="The currencyservice is experiencing high latency.",
                evidence_ids=["kpi:checkoutservice:latency-50"], confidence=0.9)  # misattribution -> dropped
    res = agent.create_result("checkoutservice", "x", [bad],
                              allowed_ids={"kpi:checkoutservice:latency-50"})
    assert res.claims == [] and res.dropped_claims == 1
    assert res.root_cause_service == "needs_review" and res.root_cause_verified is False
