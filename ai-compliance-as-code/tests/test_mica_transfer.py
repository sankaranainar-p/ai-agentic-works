"""
tests/test_mica_transfer.py — Unit & Integration tests for MiCA Transfer Set Benchmark (Contribution C4).

Verifies:
  1. Rule-pack scoping audit: rules/mica.json strictly contains code-detectable
     articles (67, 68, 76, 82) and zero organizational governance articles (16, 30, 33, 34, 61, 72, 74).
  2. Inter-rater reliability (Cohen's Kappa κ):
     - Perfect agreement: κ = 1.0
     - Random agreement: κ ≈ 0.0
     - Realistic partial agreement: κ >= 0.70
  3. Zero-shot transfer evaluation:
     - Frozen Policy 4 (CostSensitiveRejectRouter) execution across synthetic 30-snippet fixture.
     - Emits results/mica_transfer/metrics.json and summary.md.
     - Bounded operational cost, out-of-distribution Macro-F1, and epistemic abstention.
  4. Scoping validation: organizational governance articles raise ValueError when loaded.
  5. Table 6 LaTeX artifact generation and booktabs validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pytest

from arbitration.cost_router import DEFAULT_ROUTER_WEIGHTS, CostSensitiveRejectRouter
from harness.mica_transfer_bench import (
    CODE_DETECTABLE_ARTICLES,
    MICA_ARTICLE_METADATA,
    ORGANIZATIONAL_GOVERNANCE_ARTICLES,
    compute_cohen_kappa,
    extract_annotator_verdict,
    generate_synthetic_mica_records,
    load_mica_snippets,
    parse_mica_article,
    run_mica_benchmark,
    run_zero_shot_transfer_evaluation,
    validate_mica_article,
    validate_mica_articles,
)
from harness.paper_artifacts import (
    DEFAULT_MICA_TRANSFER,
    SYNTHETIC_30_MICA_TRANSFER,
    generate_table6_latex,
)
from harness.validate_latex import validate_latex_content, validate_latex_file


# ===========================================================================
# 1. Scoping Audit & Organizational Governance Rejection (Test 3)
# ===========================================================================

class TestScopingAndOrganizationalGovernance:
    """Verifies strict scoping to code-detectable articles and rejection of governance."""

    def test_code_detectable_articles_allowed(self) -> None:
        """Articles 67, 68, 76, 82 must be accepted across int and string forms."""
        for art in [67, 68, 76, 82]:
            assert validate_mica_article(art) == art
            assert validate_mica_article(f"MiCA-Art.{art}") == art
            assert validate_mica_article(f"Art. {art}") == art

        assert validate_mica_articles([67, 68, 76, 82]) == [67, 68, 76, 82]

    def test_organizational_articles_raise_validation_error(self) -> None:
        """Organizational articles (16, 30, 33, 34, 61, 72, 74) must raise ValueError."""
        forbidden_articles = [16, 30, 33, 34, 61, 72, 74]
        for forbidden in forbidden_articles:
            with pytest.raises(ValueError) as exc_info:
                validate_mica_article(forbidden)
            assert "organizational governance requirement" in str(exc_info.value).lower()
            assert str(forbidden) in str(exc_info.value)

            # Test string forms as well
            with pytest.raises(ValueError):
                validate_mica_article(f"MiCA-Art.{forbidden}")

    def test_load_snippets_rejects_organizational_articles(self, tmp_path: Path) -> None:
        """load_mica_snippets must reject any JSONL file containing governance articles."""
        invalid_record = {
            "repo_name": "org/bad-service",
            "commit_id": "c1",
            "snippet": "public void manageGovernance() {}",
            "ground_truth_articles": [34],  # Organizational
            "annotator_1": 0,
            "annotator_2": 0,
        }
        jsonl_path = tmp_path / "invalid_mica.jsonl"
        jsonl_path.write_text(json.dumps(invalid_record) + "\n", encoding="utf-8")

        with pytest.raises(ValueError) as exc_info:
            load_mica_snippets(jsonl_path)
        assert "organizational governance requirement" in str(exc_info.value).lower()

    def test_rules_mica_json_strictly_scoped(self) -> None:
        """rules/mica.json must only define rules for Articles 67, 68, 76, and 82."""
        mica_rule_pack = Path("rules/mica.json")
        assert mica_rule_pack.exists(), "rules/mica.json must exist in repository root"

        data = json.loads(mica_rule_pack.read_text(encoding="utf-8"))
        rules = data.get("rules", [])
        rule_ids = {r["id"] for r in rules}

        expected_ids = {"MiCA-Art.67", "MiCA-Art.68", "MiCA-Art.76", "MiCA-Art.82"}
        assert rule_ids == expected_ids, f"rules/mica.json rule IDs {rule_ids} != {expected_ids}"

        # Assert no organizational articles anywhere in rules
        forbidden = {"16", "30", "33", "34", "61", "72", "74"}
        for r in rules:
            for f in forbidden:
                assert f"Art.{f}" not in r["id"]
                assert f"Art.{f}" not in r["title"]

        # Risk indicator severities mapping
        severities = data.get("risk_indicator_severities", {})
        for ind_name, ind_meta in severities.items():
            rule_ref = ind_meta.get("rule_ref", "")
            assert rule_ref in expected_ids, f"Indicator {ind_name} maps to unexpected rule {rule_ref}"


# ===========================================================================
# 2. Inter-Rater Reliability Engine (Test 1)
# ===========================================================================

class TestInterRaterReliability:
    """Verifies Cohen's Kappa (κ) computation across diverse agreement regimes."""

    def test_perfect_agreement(self) -> None:
        """Identical rater labels must yield κ = 1.0."""
        r1 = [1, 0, 1, 1, 0, 0, 1, 0]
        r2 = [1, 0, 1, 1, 0, 0, 1, 0]
        kappa = compute_cohen_kappa(r1, r2)
        assert kappa == 1.0

        # Uniform single-class edge case
        r_all_ones = [1, 1, 1, 1]
        assert compute_cohen_kappa(r_all_ones, r_all_ones) == 1.0

    def test_random_agreement(self) -> None:
        """Independent random raters must produce κ ≈ 0.0."""
        np.random.seed(42)
        r1 = np.random.choice([0, 1], size=1000, p=[0.5, 0.5])
        r2 = np.random.choice([0, 1], size=1000, p=[0.5, 0.5])
        kappa = compute_cohen_kappa(r1, r2)
        assert abs(kappa) < 0.10, f"Random raters should have κ near 0, got {kappa}"

    def test_realistic_partial_agreement(self) -> None:
        """Synthetic fixture raters must satisfy the paper's baseline threshold κ >= 0.70."""
        records = generate_synthetic_mica_records()
        r1 = [extract_annotator_verdict(r["annotator_1"]) for r in records]
        r2 = [extract_annotator_verdict(r["annotator_2"]) for r in records]

        kappa = compute_cohen_kappa(r1, r2)
        assert 0.70 <= kappa <= 1.0, f"Expected realistic agreement κ >= 0.70, got {kappa}"
        assert kappa == pytest.approx(0.8571, abs=1e-2)

    def test_kappa_symmetry_and_invariants(self) -> None:
        """κ(r1, r2) must equal κ(r2, r1) and be bounded within [-1.0, 1.0]."""
        r1 = [1, 0, 1, 0, 0, 1, 1, 0]
        r2 = [1, 1, 1, 0, 0, 0, 1, 0]
        k12 = compute_cohen_kappa(r1, r2)
        k21 = compute_cohen_kappa(r2, r1)
        assert k12 == k21
        assert -1.0 <= k12 <= 1.0


# ===========================================================================
# 3. Zero-Shot Policy Transfer Evaluation (Test 2)
# ===========================================================================

class TestZeroShotTransferEvaluation:
    """Verifies out-of-distribution execution of frozen GDPR router on MiCA."""

    def test_zero_shot_evaluation_synthetic_fixture(self, tmp_path: Path) -> None:
        """Execute transfer benchmark on 30-snippet fixture and verify metrics.json."""
        out_dir = tmp_path / "mica_transfer"
        res = run_mica_benchmark(output_dir=out_dir, use_synthetic=True)

        assert res.num_instances == 30
        assert res.inter_rater_kappa >= 0.70
        assert res.macro_f1 > 0.80

        # Policy 4 must achieve lower operational cost than Policy 1
        assert res.policy4_cost < res.policy1_cost
        assert res.cost_delta_pct < 0.0  # Cost reduction

        # Abstention must capture ambiguous edge cases
        assert res.abstention_rate > 0.0

        # Assert metrics.json persistence
        metrics_file = out_dir / "metrics.json"
        summary_file = out_dir / "summary.md"
        assert metrics_file.exists()
        assert summary_file.exists()

        data = json.loads(metrics_file.read_text(encoding="utf-8"))
        assert data["num_instances"] == 30
        assert data["inter_rater_kappa"] >= 0.70
        assert "by_article" in data

        # Per-article assertions for Articles 67, 68, 76, 82
        for art_id in ["67", "68", "76", "82"]:
            art_data = data["by_article"][art_id]
            assert art_data["count"] == 7
            assert art_data["kappa"] >= 0.70
            assert art_data["policy4_cost"] <= art_data["policy1_cost"]
            assert art_data["cost_delta_pct"] <= 0.0

    def test_frozen_router_invariance(self) -> None:
        """Confirm that Policy 4 uses exact GDPR weights without adaptation."""
        router = CostSensitiveRejectRouter(weights=DEFAULT_ROUTER_WEIGHTS, tau=None)
        assert router.tau is None  # Frozen threshold (no inner CV tuning on MiCA)
        assert router.weights["Intercept"] == DEFAULT_ROUTER_WEIGHTS["Intercept"]
        assert router.weights["granularity_file"] == DEFAULT_ROUTER_WEIGHTS["granularity_file"]


# ===========================================================================
# 4. Publication Table 6 LaTeX Generation (Contribution C4)
# ===========================================================================

class TestTable6PublicationArtifact:
    """Verifies Table 6 LaTeX booktabs adherence, column count, and syntax."""

    def test_table6_synthetic_generation_and_validation(self) -> None:
        """Table 6 generated from synthetic 30-instance fixture must pass LaTeX validator."""
        tex = generate_table6_latex(SYNTHETIC_30_MICA_TRANSFER, sample_count=30)

        # Environment balance
        assert r"\begin{table}[t]" in tex
        assert r"\end{table}" in tex
        assert r"\begin{tabular}{lccccc}" in tex
        assert r"\end{tabular}" in tex

        # Booktabs macros
        assert r"\toprule" in tex
        assert r"\midrule" in tex
        assert r"\bottomrule" in tex

        # Required columns from prompt
        assert r"\textbf{Article}" in tex
        assert r"\textbf{Sample Size ($N$)}" in tex
        assert r"\textbf{Inter-Rater $\kappa$}" in tex
        assert r"\textbf{Policy 1 Cost}" in tex
        assert r"\textbf{Policy 4 Cost}" in tex
        assert r"\textbf{Cost Delta ($\Delta\%$)}" in tex

        # Check required article names
        assert "MiCA-Art. 67 (Custody/Segregation)" in tex
        assert "MiCA-Art. 68 (Transaction Audit Trail)" in tex
        assert "MiCA-Art. 76 (Abuse Monitoring)" in tex
        assert r"MiCA-Art. 82 (Travel Rule \& KYC)" in tex

        # Preliminary caveat for N=30
        assert r"\textit{Note: Preliminary sample evaluation ($N=30$); final results await completion of full benchmark run.}" in tex

        # Pure-Python LaTeX syntax validation
        errors = validate_latex_content(tex, filename="table6_synthetic.tex")
        assert errors == [], f"Table 6 syntax validation failed: {errors}"

    def test_table6_full_sample_omits_caveat(self) -> None:
        """When N=250, Table 6 should omit the preliminary caveat."""
        tex = generate_table6_latex(DEFAULT_MICA_TRANSFER, sample_count=250)
        assert "N=250" in tex
        assert "Preliminary sample evaluation" not in tex
        errors = validate_latex_content(tex, filename="table6_default.tex")
        assert errors == [], f"Table 6 default validation failed: {errors}"
