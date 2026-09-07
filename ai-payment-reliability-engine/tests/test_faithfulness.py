"""
tests/test_faithfulness.py — Tests for two-stage faithfulness checking.

Tests stage 1 (existence and anomaly) and stage 2 (entailment judgment).
"""

import pytest

from bench.faithfulness import (
    FaithfulnessChecker,
    FaithfulnessScore,
    JudgeBackend,
    compute_faithfulness_metrics,
)
from pre.agents.evidence import EvidenceItem, EvidencePack
from pre.agents.rca import Claim, RCAResult


def test_faithfulness_checker_stage1_missing_id():
    """Test stage 1 fails when evidence ID is missing."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "CPU spiked", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service overload",
        evidence_ids=["kpi:unknown:metric"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert not score.stage1_pass
    assert "Missing evidence IDs" in score.stage1_reason
    assert not score.overall_faithful


def test_faithfulness_checker_stage1_weak_anomaly():
    """Test stage 1 fails when evidence has low anomaly score."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.2, "Weak signal", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service issue",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert not score.stage1_pass
    assert "Weak anomalies" in score.stage1_reason
    assert not score.overall_faithful


def test_faithfulness_checker_stage1_pass():
    """Test stage 1 passes with valid anomalous evidence."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.8, "CPU spiked", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service overload",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert score.stage1_pass
    assert score.stage1_reason == "All evidence IDs present and anomalous"


def test_faithfulness_checker_stage2_nli():
    """Test stage 2 with NLI cross-encoder backend."""
    items = [
        EvidenceItem(
            "kpi:payment:cpu",
            "kpi",
            0.9,
            "CPU utilization spiked to 95%",
            "payment",
        ),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack, judge_backend=JudgeBackend.NLI_CROSS_ENCODER)

    claim = Claim(
        text="Payment service overloaded due to high CPU",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert score.stage1_pass
    assert score.stage2_judge == "nli_cross_encoder"
    assert 0.0 <= score.stage2_score <= 1.0


def test_faithfulness_checker_stage2_chat():
    """Test stage 2 with chat model backend."""
    items = [
        EvidenceItem(
            "kpi:payment:cpu",
            "kpi",
            0.9,
            "CPU utilization spiked to 95%",
            "payment",
        ),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=50)
    checker = FaithfulnessChecker(pack, judge_backend=JudgeBackend.CHAT_MODEL)

    claim = Claim(
        text="Payment service overloaded due to high CPU",
        evidence_ids=["kpi:payment:cpu"],
        confidence=0.8,
    )

    score = checker.check_claim(claim)

    assert score.stage1_pass
    assert score.stage2_judge == "chat_model"
    assert 0.0 <= score.stage2_score <= 1.0


def test_faithfulness_score_multiple_evidence():
    """Test faithfulness score with multiple evidence IDs."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "CPU spiked", "payment"),
        EvidenceItem("span:t1a2b", "span", 0.8, "Error rate up", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=80)
    checker = FaithfulnessChecker(pack)

    claim = Claim(
        text="Payment service degradation",
        evidence_ids=["kpi:payment:cpu", "span:t1a2b"],
        confidence=0.85,
    )

    score = checker.check_claim(claim)

    assert score.stage1_pass
    assert len(score.evidence_ids) == 2
    assert "CPU spiked" in score.judge_output or "[NLI]" in score.judge_output


def test_faithfulness_checker_rca_result():
    """Test checking all claims in an RCA result."""
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.9, "CPU spiked", "payment"),
        EvidenceItem("span:t1a2b", "span", 0.8, "Errors increased", "payment"),
    ]
    pack = EvidencePack(case_id="TEST-001", items=items, token_estimate=80)
    checker = FaithfulnessChecker(pack)

    result = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="CPU overload",
        claims=[
            Claim(
                text="CPU saturation on payment nodes",
                evidence_ids=["kpi:payment:cpu"],
                confidence=0.9,
            ),
            Claim(
                text="Cascading errors due to throttling",
                evidence_ids=["span:t1a2b"],
                confidence=0.85,
            ),
            Claim(
                text="Misconfiguration issue",
                evidence_ids=["kpi:unknown:metric"],
                confidence=0.5,
            ),
        ],
    )

    scores = checker.check_rca_result(result)

    assert len(scores) == 3
    assert scores[0].overall_faithful  # CPU claim should pass
    assert not scores[2].overall_faithful  # Unknown evidence should fail


def test_compute_faithfulness_metrics_empty():
    """Test metrics with empty list."""
    metrics = compute_faithfulness_metrics([])

    assert metrics["stage1_pass_rate"] == 0.0
    assert metrics["stage2_pass_rate"] == 0.0
    assert metrics["overall_faithful_rate"] == 0.0
    assert metrics["avg_entailment_score"] == 0.0


def test_compute_faithfulness_metrics_all_pass():
    """Test metrics when all claims pass."""
    scores = [
        FaithfulnessScore(
            claim_text="Claim 1",
            evidence_ids=["id1"],
            stage1_pass=True,
            stage1_reason="Pass",
            stage2_score=0.9,
            stage2_judge="nli",
            judge_output="",
            overall_faithful=True,
        ),
        FaithfulnessScore(
            claim_text="Claim 2",
            evidence_ids=["id2"],
            stage1_pass=True,
            stage1_reason="Pass",
            stage2_score=0.85,
            stage2_judge="nli",
            judge_output="",
            overall_faithful=True,
        ),
    ]

    metrics = compute_faithfulness_metrics(scores)

    assert metrics["stage1_pass_rate"] == 1.0
    assert metrics["stage2_pass_rate"] == 1.0
    assert metrics["overall_faithful_rate"] == 1.0
    assert metrics["avg_entailment_score"] == pytest.approx(0.875)


def test_compute_faithfulness_metrics_partial_pass():
    """Test metrics with partial passes."""
    scores = [
        FaithfulnessScore(
            claim_text="Claim 1",
            evidence_ids=["id1"],
            stage1_pass=True,
            stage1_reason="Pass",
            stage2_score=0.9,
            stage2_judge="nli",
            judge_output="",
            overall_faithful=True,
        ),
        FaithfulnessScore(
            claim_text="Claim 2",
            evidence_ids=["id2"],
            stage1_pass=False,
            stage1_reason="Missing ID",
            stage2_score=0.0,
            stage2_judge="none",
            judge_output="",
            overall_faithful=False,
        ),
        FaithfulnessScore(
            claim_text="Claim 3",
            evidence_ids=["id3"],
            stage1_pass=True,
            stage1_reason="Pass",
            stage2_score=0.3,
            stage2_judge="nli",
            judge_output="",
            overall_faithful=False,
        ),
    ]

    metrics = compute_faithfulness_metrics(scores)

    assert metrics["stage1_pass_rate"] == pytest.approx(2.0 / 3.0)
    assert metrics["stage2_pass_rate"] == pytest.approx(0.5)  # 1 out of 2 stage1 passes
    assert metrics["overall_faithful_rate"] == pytest.approx(1.0 / 3.0)
    assert metrics["avg_entailment_score"] == pytest.approx(0.6)  # (0.9 + 0.3) / 2
