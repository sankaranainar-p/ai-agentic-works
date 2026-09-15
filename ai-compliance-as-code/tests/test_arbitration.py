"""
tests/test_arbitration.py — Unit tests for Phase 3 Cost-Sensitive Arbitration and CV Harness.

Verifies:
  1. Theoretical boundary transitions:
     - When c_H -> inf, abstention rate drops strictly to 0%.
     - When c_H -> 0, system defers 100% of ambiguous instances to human review.
  2. Oracle dominance:
     - L(pi_oracle) <= L(pi_cost_abstain) instance-wise and in expectation.
  3. W3C PROV-DM audit receipt builder:
     - SHA-256 cryptographic digest of source code snippet.
     - Complete W3C PROV-JSON structure (entities, activities, agents, relations).
  4. Routing policies:
     - Policy 3 (LearnedFeatureRouter) behavior on agreement vs disagreement.
     - Policy 4 (CostSensitiveRejectRouter) tri-choice action space.
  5. 5x3 Nested Cross-Validation, Wilson 95% CI, McNemar, and Wilcoxon testing.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pytest

from api.schemas import ComplianceFinding
from arbitration.cost_router import (
    CostSensitiveRejectRouter,
    LearnedFeatureRouter,
    RoutingDecision,
    extract_runtime_features,
)
from arbitration.fixed_confidence import FixedConfidenceMerge
from audit.prov_receipt import AuditReceiptBuilder
from harness.arbitration_bench import (
    calculate_instance_loss,
    compute_hypothesis_tests,
    compute_wilson_ci,
    generate_pareto_frontier,
    run_nested_cross_validation,
    simulate_oracle_instance,
)
from harness.complementarity import align_detector_runs
from tests.test_complementarity import generate_40_synthetic_records


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def sample_findings() -> Dict[str, List[ComplianceFinding]]:
    """Sample static and LLM findings for testing."""
    static_f = [
        ComplianceFinding(
            rule_id="GDPR-Art.32",
            title="Unencrypted HTTP outbound connection",
            severity="high",
            line_start=15,
            line_end=15,
            violation="Plaintext HTTP used for outbound data transfer.",
            remediation="Switch protocol from http:// to https://.",
            confidence=0.6,
        )
    ]
    llm_f = [
        ComplianceFinding(
            rule_id="GDPR-Art.5",
            title="PII data field logged without minimisation",
            severity="high",
            line_start=22,
            line_end=22,
            violation="Email address logged directly to logcat.",
            remediation="Mask or hash the email address prior to logging.",
            confidence=1.0,
        )
    ]
    return {"static": static_f, "llm": llm_f}


# ===========================================================================
# 1. Theoretical Boundary Transition Tests
# ===========================================================================

class TestTheoreticalBoundaryTransitions:
    def test_infinite_ch_drops_abstention_to_zero(
        self, sample_findings: Dict[str, List[ComplianceFinding]]
    ) -> None:
        """When c_H -> inf, cost of human review is prohibitive, so abstention drops to strictly 0%."""
        router = CostSensitiveRejectRouter(c_h=1e9)  # Near-infinite review cost
        static_f = sample_findings["static"]
        llm_f = sample_findings["llm"]

        # Evaluate across 20 varied snippets
        abstention_count = 0
        for i in range(20):
            code = f"public void method{i}() {{ String pass = 'secret'; }}"
            decision = router.decide(
                static_findings=static_f if i % 2 == 0 else [],
                llm_findings=llm_f if i % 3 == 0 else [],
                code=code,
                file_path=f"Service{i}.java",
            )
            if decision.action == "abstain":
                abstention_count += 1

        assert abstention_count == 0

    def test_zero_ch_defers_all_ambiguous_instances(
        self, sample_findings: Dict[str, List[ComplianceFinding]]
    ) -> None:
        """When c_H -> 0, human review is virtually free, so all ambiguous / disagreement instances defer to human."""
        router = CostSensitiveRejectRouter(c_h=0.0)  # Free human review
        static_f = sample_findings["static"]
        llm_f = sample_findings["llm"]

        # Exactly one detector fires -> ambiguous disagreement instance
        ambiguous_instances = [
            (static_f, []),  # S fires, L does not
            ([], llm_f),  # L fires, S does not
        ]

        for s_f, l_f in ambiguous_instances:
            code = "public void process() { HttpURLConnection conn = open(); }"
            decision = router.decide(
                static_findings=s_f,
                llm_findings=l_f,
                code=code,
                file_path="Process.java",
            )
            assert decision.action == "abstain"
            assert decision.status == "deferred_to_human"
            assert decision.estimated_risk == pytest.approx(decision.risk_h, rel=1e-4)


# ===========================================================================
# 2. Oracle Dominance Tests
# ===========================================================================

class TestOracleDominance:
    def test_oracle_dominance_instance_wise(self) -> None:
        """Verify that L(pi_oracle) <= L(pi_cost_abstain) holds instance-wise on synthetic data."""
        static_recs, llm_recs = generate_40_synthetic_records()
        c_fn = 1.0
        c_fp = 0.1
        c_h = 0.25
        c_l = 0.01
        c_s = 0.0
        eps_h = 0.02

        router = CostSensitiveRejectRouter(
            c_fn=c_fn, c_fp=c_fp, c_h=c_h, c_l=c_l, c_s=c_s, epsilon_h=eps_h
        )

        oracle_total_loss = 0.0
        p4_total_loss = 0.0

        for s_rec, l_rec in zip(static_recs, llm_recs):
            rec = {
                "ground_truth": s_rec.get("ground_truth", []),
                "static_record": s_rec,
                "llm_record": l_rec,
                "code_snippet": s_rec.get("code_snippet", ""),
                "code_snippet_path": s_rec.get("code_snippet_path", ""),
            }
            gt = rec["ground_truth"]

            # Oracle loss
            _, oracle_loss, _ = simulate_oracle_instance(
                rec, c_fn=c_fn, c_fp=c_fp, c_h=c_h, c_l=c_l, c_s=c_s, epsilon_h=eps_h
            )

            # Policy 4 loss
            s_preds = s_rec.get("predicted", [])
            l_preds = l_rec.get("predicted", [])
            features = extract_runtime_features(record=rec)
            rs, rl, rh, _ = router.compute_risks(
                static_findings=[{"rule_id": str(p)} for p in s_preds],  # type: ignore
                llm_findings=[{"rule_id": str(p)} for p in l_preds],  # type: ignore
                features=features,
            )

            if min(rs, rl) >= rh:
                p4_loss = rh
            elif rs < rl:
                p4_loss = c_s + calculate_instance_loss(s_preds, gt, c_fn, c_fp)
            else:
                p4_loss = c_l + calculate_instance_loss(l_preds, gt, c_fn, c_fp)

            oracle_total_loss += oracle_loss
            p4_total_loss += p4_loss

            # Oracle must never be worse than Policy 4 (within numerical float tolerance)
            assert oracle_loss <= p4_loss + 1e-6

        # Expected aggregate loss dominance
        assert oracle_total_loss <= p4_total_loss


# ===========================================================================
# 3. W3C PROV-DM Audit Receipt Tests
# ===========================================================================

class TestProvReceiptBuilder:
    def test_prov_json_structure_and_hashing(
        self, sample_findings: Dict[str, List[ComplianceFinding]]
    ) -> None:
        code = "public void sendData() { URL url = new URL('http://api.com'); }"
        expected_sha = hashlib.sha256(code.encode("utf-8")).hexdigest()

        builder = AuditReceiptBuilder(code=code, file_path="Payment.java", regulation="GDPR")
        builder.set_static_results(sample_findings["static"])
        builder.set_llm_results(sample_findings["llm"])
        builder.set_arbitration_decision(
            findings=sample_findings["static"],
            routing_action="symbolic",
            status="completed",
            estimated_risk=0.042,
            cost_parameters={"c_fn": 1.0, "c_fp": 0.1},
        )

        prov = builder.to_prov_json()

        # 1. Check prefixes
        assert "prefix" in prov
        assert "prov" in prov["prefix"]
        assert "cacc" in prov["prefix"]

        # 2. Check entities
        assert "entity" in prov
        entities = prov["entity"]
        snippet_key = f"cacc:InputSnippet_{expected_sha[:12]}"
        assert snippet_key in entities
        assert entities[snippet_key]["cacc:sha256"] == expected_sha
        assert entities[snippet_key]["cacc:filePath"] == "Payment.java"

        rule_pack_key = "cacc:RulePack_GDPR"
        assert rule_pack_key in entities

        # 3. Check activities
        assert "activity" in prov
        acts = prov["activity"]
        assert any(k.startswith("cacc:StaticScanActivity") for k in acts)
        assert any(k.startswith("cacc:LLMInferenceActivity") for k in acts)
        assert any(k.startswith("cacc:CostArbitrationActivity") for k in acts)

        # 4. Check agents
        assert "agent" in prov
        agents = prov["agent"]
        assert "cacc:StaticDetectorAgent" in agents
        assert "cacc:LLMDetectorAgent" in agents
        assert "cacc:ArbitratorAgent" in agents

        # 5. Check relations
        assert "wasGeneratedBy" in prov
        assert "used" in prov
        assert "wasAssociatedWith" in prov
        assert "wasDerivedFrom" in prov

        # Validate JSON serialization roundtrip
        json_str = builder.to_json()
        reloaded = json.loads(json_str)
        assert reloaded["entity"][snippet_key]["cacc:sha256"] == expected_sha


# ===========================================================================
# 4. Routing Strategy Execution Tests
# ===========================================================================

class TestRoutingStrategies:
    def test_learned_feature_router_agreement(
        self, sample_findings: Dict[str, List[ComplianceFinding]]
    ) -> None:
        """When detectors agree on rule IDs, LearnedFeatureRouter executes S at c_S ~ 0."""
        router = LearnedFeatureRouter()
        common_f = sample_findings["static"]

        decision = router.decide(
            static_findings=common_f,
            llm_findings=common_f,  # Identical findings
            code="public void foo() {}",
            file_path="Foo.java",
        )

        assert decision.action == "symbolic"
        assert decision.status == "completed"
        assert len(decision.findings) == len(common_f)

    def test_cost_sensitive_router_abstain_decision(
        self, sample_findings: Dict[str, List[ComplianceFinding]]
    ) -> None:
        """When uncertainty is high and c_H is low, router emits 'abstain' and 'deferred_to_human'."""
        router = CostSensitiveRejectRouter(c_h=0.01)  # Very low review cost
        decision = router.decide(
            static_findings=sample_findings["static"],
            llm_findings=[],  # High disagreement
            code="public void check() {}",
            file_path="Check.java",
        )

        assert decision.action == "abstain"
        assert decision.status == "deferred_to_human"
        assert decision.prov_receipt is not None


# ===========================================================================
# 5. Statistical Tools & Nested Cross-Validation Tests
# ===========================================================================

class TestCrossValidationAndStatistics:
    def test_wilson_ci_properties(self) -> None:
        # Extreme bounds
        l0, u0 = compute_wilson_ci(0, 100)
        assert l0 == 0.0
        assert u0 > 0.0

        ln, un = compute_wilson_ci(100, 100)
        assert ln < 1.0
        assert un == 1.0

        # Known standard 50/100 case
        l50, u50 = compute_wilson_ci(50, 100)
        assert l50 < 0.5 < u50
        assert 0.0 <= l50 <= u50 <= 1.0

    def test_mcnemar_and_wilcoxon_tests(self) -> None:
        p4_preds = [[5], [6], [25], [32]]
        p1_preds = [[99], [6], [99], [32]]
        p4_costs = [0.05, 0.10, 0.05, 0.08]
        p1_costs = [1.10, 0.10, 1.10, 0.08]
        gts = [[5], [6], [25], [32]]

        chi2, mcnemar_p, w_stat, w_p = compute_hypothesis_tests(
            p4_preds=p4_preds,
            p1_preds=p1_preds,
            p4_costs=p4_costs,
            p1_costs=p1_costs,
            ground_truths=gts,
        )

        assert chi2 >= 0.0
        assert 0.0 <= mcnemar_p <= 1.0
        assert 0.0 <= w_p <= 1.0

    def test_nested_cv_execution_on_synthetic_data(self) -> None:
        static_recs, llm_recs = generate_40_synthetic_records()
        aligned, _, _ = align_detector_runs(static_recs, llm_recs)

        results, best_tau = run_nested_cross_validation(
            aligned_records=aligned,
            outer_folds=3,
            inner_folds=2,
            tau_grid=[0.1, 0.25, 0.5],
        )

        assert "Policy 1 (Baseline)" in results
        assert "Policy 2 (Oracle)" in results
        assert "Policy 3 (Learned)" in results
        assert "Policy 4 (CostReject)" in results

        p2 = results["Policy 2 (Oracle)"]
        p4 = results["Policy 4 (CostReject)"]

        # Oracle cost must be lower than or equal to Policy 4 cost
        assert p2.mean_cost <= p4.mean_cost + 1e-4

        # Accuracy Wilson CIs must be well-formed
        for res in results.values():
            assert 0.0 <= res.accuracy_ci_95[0] <= res.accuracy_ci_95[1] <= 1.0
            assert 0.0 <= res.macro_f1 <= 1.0

    def test_pareto_frontier_monotonicity(self) -> None:
        static_recs, llm_recs = generate_40_synthetic_records()
        aligned, _, _ = align_detector_runs(static_recs, llm_recs)

        results, _ = run_nested_cross_validation(
            aligned_records=aligned,
            outer_folds=2,
            inner_folds=2,
            tau_grid=[0.2, 0.5],
        )

        pareto = generate_pareto_frontier(aligned, results)
        assert len(pareto) > 0

        # Verify sorted by cost
        costs = [pt["cost"] for pt in pareto]
        assert costs == sorted(costs)
