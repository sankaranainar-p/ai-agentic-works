"""
tests/test_complementarity.py — Unit tests for Phase 2 Complementarity Analysis Engine.

Verifies:
  1. Ingestion and instance alignment using instance key (app_name::commit_id::code_snippet_path).
  2. Flagging of unmatched instances between static and LLM runs.
  3. Four-cell contingency counts and proportions:
       - Global benchmark
       - Partitioned by granularity (file, module, line)
       - Partitioned by article (Articles 5, 6, 25, 32, and other pooled)
  4. Statistical rigor of predictive logistic regression on disagreements (P(S=1 | S != L)):
       - Odds Ratio (OR) calculation: OR = exp(beta)
       - 95% Confidence Interval bounds: exp(beta +- 1.96 * SE)
       - Benjamini-Hochberg (FDR) adjusted p-values (q-values)
       - ROC-AUC and McFadden's pseudo-R²
  5. JSON serialization to metrics.json and Markdown summary table generation.
  6. Edge cases: zero disagreements, degenerate outcomes, small sample sizes.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pytest

from harness.complementarity import (
    ARTICLE_BUCKETS,
    GRANULARITIES,
    ComplementarityEngine,
    ContingencyCellCounts,
    align_detector_runs,
    benjamini_hochberg,
    compute_contingency_cells,
    fit_disagreement_model,
    make_instance_key,
    partition_contingency_analysis,
    run_complementarity_analysis,
)


# ===========================================================================
# Synthetic Dataset Generator (40 Paired Records)
# ===========================================================================

def generate_40_synthetic_records() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Generate 40 paired records with known contingency distributions and features.

    Distribution across the 4 cells:
      - Cell 1 (Both correct: S=1, L=1): 12 instances (idx 0..11)
      - Cell 2 (Both incorrect: S=0, L=0): 8 instances (idx 12..19)
      - Cell 3 (Static-only correct: S=1, L=0): 11 instances (idx 20..30)
      - Cell 4 (LLM-only correct: S=0, L=1): 9 instances (idx 31..39)
      Total = 40 instances.
      Disagreements (Cell 3 + Cell 4) = 20 instances (11 Static wins, 9 LLM wins).

    Granularity distribution (15 file, 15 module, 10 line):
      - File: 5 Cell 1, 3 Cell 2, 4 Cell 3, 3 Cell 4 = 15 total
      - Module: 4 Cell 1, 3 Cell 2, 5 Cell 3, 3 Cell 4 = 15 total
      - Line: 3 Cell 1, 2 Cell 2, 2 Cell 3, 3 Cell 4 = 10 total

    Article distribution (10 Art 5, 10 Art 6, 8 Art 25, 8 Art 32, 4 other):
      - Art 5: 10
      - Art 6: 10
      - Art 25: 8
      - Art 32: 8
      - Other (Art 15, 17): 4
      Total = 40.
    """
    # Pre-define cell assignment for all 40 instances
    # 1: both_c, 2: both_i, 3: static_o, 4: llm_o
    cell_assignments = [1] * 12 + [2] * 8 + [3] * 11 + [4] * 9

    # Granularity assignments matching target counts: 15 file, 15 module, 10 line
    # Cell 1 (12): 5 file, 4 module, 3 line
    # Cell 2 (8):  3 file, 3 module, 2 line
    # Cell 3 (11): 4 file, 5 module, 2 line
    # Cell 4 (9):  3 file, 3 module, 3 line
    granularities = (
        ["file"] * 5 + ["module"] * 4 + ["line"] * 3  # Cell 1 (12)
        + ["file"] * 3 + ["module"] * 3 + ["line"] * 2  # Cell 2 (8)
        + ["file"] * 4 + ["module"] * 5 + ["line"] * 2  # Cell 3 (11)
        + ["file"] * 3 + ["module"] * 3 + ["line"] * 3  # Cell 4 (9)
    )

    # Article assignments matching target counts: 10 Art 5, 10 Art 6, 8 Art 25, 8 Art 32, 4 other
    articles = [
        # Cell 1 (12)
        5, 5, 5, 6, 6, 6, 25, 25, 32, 32, 15, 17,
        # Cell 2 (8)
        5, 5, 6, 6, 25, 25, 32, 32,
        # Cell 3 (11)
        5, 5, 5, 6, 6, 6, 25, 25, 32, 32, 15,
        # Cell 4 (9)
        5, 5, 6, 6, 25, 25, 32, 32, 17,
    ]

    static_records: List[Dict[str, Any]] = []
    llm_records: List[Dict[str, Any]] = []

    for i in range(40):
        cell = cell_assignments[i]
        gran = granularities[i]
        art = articles[i]

        s_correct = cell in (1, 3)
        l_correct = cell in (1, 4)

        app_name = f"TestApp_{i % 4}"
        commit_id = f"commit_{i % 6:02d}abcdef"
        ext = ".kt" if i % 3 == 0 else ".java"
        line_info = f": lines {20 + i}-{25 + i}" if gran == "module" else (f": line {10 + i}" if gran == "line" else "")
        code_path = f"app/src/main/java/com/example/Service{i}{ext}{line_info}"

        # Distinct snippet length to provide variation for log10_char_length
        char_len = 80 + (i * 95)
        code_snippet = f"// Violation for GDPR Art.{art}\n" + ("x = 1;\n" * (char_len // 10))

        # Distinct hints fired
        hints_fired: List[str] = []
        if i % 2 == 0:
            hints_fired.append("unencrypted_http_outbound")
        if i % 3 == 0:
            hints_fired.append("personal_data_in_scope")
        if i % 5 == 0:
            hints_fired.append("password_field_present")

        gt = [art]
        s_pred = [art] if s_correct else ([99] if art != 99 else [98])
        l_pred = [art] if l_correct else ([99] if art != 99 else [98])

        s_rec = {
            "app_name": app_name,
            "commit_id": commit_id,
            "code_snippet_path": code_path,
            "granularity": gran,
            "target_article": art,
            "ground_truth": gt,
            "predicted": s_pred,
            "correct": s_correct,
            "char_length": len(code_snippet),
            "code_snippet": code_snippet,
            "hints_fired": list(hints_fired),
        }

        l_rec = {
            "app_name": app_name,
            "commit_id": commit_id,
            "code_snippet_path": code_path,
            "granularity": gran,
            "target_article": art,
            "ground_truth": gt,
            "predicted": l_pred,
            "correct": l_correct,
            "char_length": len(code_snippet),
            "code_snippet": code_snippet,
            "hints_fired": list(hints_fired),
        }

        static_records.append(s_rec)
        llm_records.append(l_rec)

    return static_records, llm_records


# ===========================================================================
# 1. Dataset Alignment & Instance Key Tests
# ===========================================================================

class TestDatasetAlignment:
    def test_instance_key_formation(self) -> None:
        rec = {
            "app_name": "SpyApp",
            "commit_id": "abc1234",
            "code_snippet_path": "src/Main.java: line 50",
        }
        key = make_instance_key(rec)
        assert key == "SpyApp::abc1234::src/Main.java: line 50"

    def test_alignment_with_synthetic_40(self) -> None:
        static_recs, llm_recs = generate_40_synthetic_records()
        aligned, unmatched_s, unmatched_l = align_detector_runs(static_recs, llm_recs)

        assert len(aligned) == 40
        assert len(unmatched_s) == 0
        assert len(unmatched_l) == 0

    def test_unmatched_instances_flagged(self) -> None:
        static_recs, llm_recs = generate_40_synthetic_records()
        # Add 2 extra static records and 3 extra LLM records
        extra_static = [
            {"app_name": "ExtraAppS", "commit_id": "c1", "code_snippet_path": f"src/Extra{i}.java"}
            for i in range(2)
        ]
        extra_llm = [
            {"app_name": "ExtraAppL", "commit_id": "c2", "code_snippet_path": f"src/Extra{i}.kt"}
            for i in range(3)
        ]

        aligned, unmatched_s, unmatched_l = align_detector_runs(
            static_recs + extra_static,
            llm_recs + extra_llm,
        )

        assert len(aligned) == 40
        assert len(unmatched_s) == 2
        assert len(unmatched_l) == 3
        assert "ExtraAppS::c1::src/Extra0.java" in unmatched_s
        assert "ExtraAppL::c2::src/Extra0.kt" in unmatched_l


# ===========================================================================
# 2. Four-Cell Contingency Table Tests
# ===========================================================================

class TestFourCellContingency:
    @pytest.fixture
    def aligned_40(self) -> List[Dict[str, Any]]:
        static_recs, llm_recs = generate_40_synthetic_records()
        aligned, _, _ = align_detector_runs(static_recs, llm_recs)
        return aligned

    def test_global_contingency_counts_and_proportions(self, aligned_40: List[Dict[str, Any]]) -> None:
        counts = compute_contingency_cells(aligned_40)

        # Expected counts
        assert counts.both_correct == 12
        assert counts.both_incorrect == 8
        assert counts.static_only == 11
        assert counts.llm_only == 9
        assert counts.total == 40
        assert counts.disagreement_count == 20

        # Expected proportions
        assert counts.both_correct_prop == pytest.approx(12 / 40)
        assert counts.both_incorrect_prop == pytest.approx(8 / 40)
        assert counts.static_only_prop == pytest.approx(11 / 40)
        assert counts.llm_only_prop == pytest.approx(9 / 40)
        assert counts.disagreement_prop == pytest.approx(20 / 40)

        # Sum of cell counts equals total
        assert counts.both_correct + counts.both_incorrect + counts.static_only + counts.llm_only == counts.total
        # Sum of cell proportions equals 1.0
        prop_sum = counts.both_correct_prop + counts.both_incorrect_prop + counts.static_only_prop + counts.llm_only_prop
        assert prop_sum == pytest.approx(1.0)

    def test_granularity_partitioned_counts(self, aligned_40: List[Dict[str, Any]]) -> None:
        global_c, by_gran, by_art = partition_contingency_analysis(aligned_40)

        assert set(by_gran.keys()) == set(GRANULARITIES)
        assert by_gran["file"].total == 15
        assert by_gran["module"].total == 15
        assert by_gran["line"].total == 10

        # Sum of totals equals global total
        assert sum(c.total for c in by_gran.values()) == 40

        # Exact expected cells per granularity
        assert by_gran["file"].both_correct == 5
        assert by_gran["file"].both_incorrect == 3
        assert by_gran["file"].static_only == 4
        assert by_gran["file"].llm_only == 3

        assert by_gran["module"].both_correct == 4
        assert by_gran["module"].both_incorrect == 3
        assert by_gran["module"].static_only == 5
        assert by_gran["module"].llm_only == 3

        assert by_gran["line"].both_correct == 3
        assert by_gran["line"].both_incorrect == 2
        assert by_gran["line"].static_only == 2
        assert by_gran["line"].llm_only == 3

        # Sum of each cell across granularities equals global cell count
        assert sum(c.both_correct for c in by_gran.values()) == global_c.both_correct
        assert sum(c.both_incorrect for c in by_gran.values()) == global_c.both_incorrect
        assert sum(c.static_only for c in by_gran.values()) == global_c.static_only
        assert sum(c.llm_only for c in by_gran.values()) == global_c.llm_only

    def test_article_partitioned_counts(self, aligned_40: List[Dict[str, Any]]) -> None:
        global_c, by_gran, by_art = partition_contingency_analysis(aligned_40)

        assert set(by_art.keys()) == set(ARTICLE_BUCKETS)
        assert by_art["5"].total == 10
        assert by_art["6"].total == 10
        assert by_art["25"].total == 8
        assert by_art["32"].total == 8
        assert by_art["other"].total == 4

        # Sum of totals across article buckets equals global total
        assert sum(c.total for c in by_art.values()) == 40

        # Sum of each cell across articles equals global cell count
        assert sum(c.both_correct for c in by_art.values()) == global_c.both_correct
        assert sum(c.both_incorrect for c in by_art.values()) == global_c.both_incorrect
        assert sum(c.static_only for c in by_art.values()) == global_c.static_only
        assert sum(c.llm_only for c in by_art.values()) == global_c.llm_only


# ===========================================================================
# 3. Benjamini-Hochberg (FDR) Multiple Comparison Tests
# ===========================================================================

class TestMultipleComparisonCorrection:
    def test_benjamini_hochberg_manual_benchmark(self) -> None:
        """Verify Benjamini-Hochberg FDR against known manual textbook calculation."""
        # Raw p-values:
        # p1 = 0.01, p2 = 0.04, p3 = 0.03, p4 = 0.001
        # m = 4 hypotheses
        # Sorted:
        # rank 1: 0.001 -> 0.001 * 4 / 1 = 0.004
        # rank 2: 0.010 -> 0.010 * 4 / 2 = 0.020
        # rank 3: 0.030 -> 0.030 * 4 / 3 = 0.040
        # rank 4: 0.040 -> 0.040 * 4 / 4 = 0.040
        # Monotonized backwards: [0.004, 0.020, 0.040, 0.040]
        # Restored to original indices: [0.020, 0.040, 0.040, 0.004]
        raw_p = [0.01, 0.04, 0.03, 0.001]
        expected_q = [0.02, 0.04, 0.04, 0.004]
        q_vals = benjamini_hochberg(raw_p)

        for actual, exp in zip(q_vals, expected_q):
            assert actual == pytest.approx(exp, rel=1e-5)

    def test_benjamini_hochberg_bounds_and_monotonicity(self) -> None:
        raw_p = [0.55, 0.02, 0.99, 0.005, 0.03, 0.12]
        q_vals = benjamini_hochberg(raw_p)

        assert len(q_vals) == len(raw_p)
        for p, q in zip(raw_p, q_vals):
            # q-value must be at least the p-value
            assert q >= p - 1e-9
            # q-value must be bounded in [0.0, 1.0]
            assert 0.0 <= q <= 1.0

    def test_benjamini_hochberg_edge_cases(self) -> None:
        assert benjamini_hochberg([]) == []
        assert benjamini_hochberg([0.05]) == [0.05]
        assert benjamini_hochberg([0.0, 1.0]) == [0.0, 1.0]


# ===========================================================================
# 4. Predictive Logistic Regression on Disagreement Tests
# ===========================================================================

class TestPredictiveDisagreementModel:
    @pytest.fixture
    def disagreement_instances(self) -> List[Dict[str, Any]]:
        static_recs, llm_recs = generate_40_synthetic_records()
        aligned, _, _ = align_detector_runs(static_recs, llm_recs)
        return [r for r in aligned if bool(r.get("static_correct")) != bool(r.get("llm_correct"))]

    def test_disagreement_instance_count(self, disagreement_instances: List[Dict[str, Any]]) -> None:
        assert len(disagreement_instances) == 20
        static_wins = sum(1 for r in disagreement_instances if r.get("static_correct"))
        llm_wins = sum(1 for r in disagreement_instances if r.get("llm_correct"))
        assert static_wins == 11
        assert llm_wins == 9

    def test_odds_ratio_and_confidence_interval_rigor(
        self, disagreement_instances: List[Dict[str, Any]]
    ) -> None:
        model = fit_disagreement_model(disagreement_instances)

        assert model.status in ("converged", "converged_approx")
        assert model.num_disagreements == 20
        assert model.num_static_wins == 11
        assert model.num_llm_wins == 9
        assert len(model.features) > 0

        # Check statistical properties for every feature in the model
        for feat in model.features:
            # Odds Ratio must equal exp(coef)
            expected_or = math.exp(feat.coef)
            assert feat.odds_ratio == pytest.approx(expected_or, rel=1e-4)

            # 95% CI lower bound must equal exp(coef - 1.95996 * SE)
            expected_ci_lower = math.exp(feat.coef - 1.95996398 * feat.std_err)
            assert feat.ci_95_lower == pytest.approx(expected_ci_lower, rel=1e-4)

            # 95% CI upper bound must equal exp(coef + 1.95996 * SE)
            expected_ci_upper = math.exp(feat.coef + 1.95996398 * feat.std_err)
            assert feat.ci_95_upper == pytest.approx(expected_ci_upper, rel=1e-4)

            # CI ordering check
            assert feat.ci_95_lower <= feat.odds_ratio <= feat.ci_95_upper

            # Positive quantities
            assert feat.odds_ratio > 0
            assert feat.std_err > 0

            # p-values within valid bounds
            assert 0.0 <= feat.p_value <= 1.0
            assert 0.0 <= feat.p_value_fdr <= 1.0

    def test_model_discriminative_power_metrics(
        self, disagreement_instances: List[Dict[str, Any]]
    ) -> None:
        model = fit_disagreement_model(disagreement_instances)

        # ROC-AUC must be a valid probability index [0.0, 1.0]
        assert model.roc_auc is not None
        assert 0.0 <= model.roc_auc <= 1.0

        # McFadden Pseudo-R² must be in [0.0, 1.0]
        assert model.pseudo_r2 is not None
        assert 0.0 <= model.pseudo_r2 <= 1.0

        # Log-likelihood check
        assert model.log_likelihood_full is not None
        assert model.log_likelihood_null is not None
        # Full model fits at least as well as null model
        assert model.log_likelihood_full >= model.log_likelihood_null - 1e-4

    def test_edge_case_degenerate_disagreement_outcome(self) -> None:
        # All instances where Static wins, no LLM wins
        static_recs, llm_recs = generate_40_synthetic_records()
        aligned, _, _ = align_detector_runs(static_recs, llm_recs)
        only_static_wins = [r for r in aligned if r.get("static_correct") and not r.get("llm_correct")]

        res = fit_disagreement_model(only_static_wins)
        assert res.status == "degenerate_outcome"
        assert res.num_static_wins == len(only_static_wins)
        assert res.num_llm_wins == 0


# ===========================================================================
# 5. End-to-End Execution and File Output Tests
# ===========================================================================

class TestEndToEndExecution:
    def test_end_to_end_engine_and_serialization(self, tmp_path: Path) -> None:
        static_recs, llm_recs = generate_40_synthetic_records()

        static_file = tmp_path / "static_results.jsonl"
        with static_file.open("w", encoding="utf-8") as f:
            for r in static_recs:
                f.write(json.dumps(r) + "\n")

        llm_file = tmp_path / "llm_results.jsonl"
        with llm_file.open("w", encoding="utf-8") as f:
            for r in llm_recs:
                f.write(json.dumps(r) + "\n")

        out_dir = tmp_path / "complementarity"
        metrics = run_complementarity_analysis(
            static_results=static_file,
            llm_results=llm_file,
            output_dir=out_dir,
        )

        assert (out_dir / "metrics.json").exists()
        assert (out_dir / "summary.md").exists()

        # Parse saved metrics.json
        saved_data = json.loads((out_dir / "metrics.json").read_text(encoding="utf-8"))
        assert "alignment" in saved_data
        assert "contingency_analysis" in saved_data
        assert "disagreement_model" in saved_data
        assert "summary_table_markdown" in saved_data

        assert saved_data["alignment"]["matched_instances"] == 40
        assert saved_data["contingency_analysis"]["global"]["counts"]["both_correct"] == 12
        assert saved_data["contingency_analysis"]["global"]["counts"]["disagreement"] == 20
        assert saved_data["disagreement_model"]["num_disagreements"] == 20

        # Verify markdown content
        summary_md = (out_dir / "summary.md").read_text(encoding="utf-8")
        assert "Four-Cell Contingency Table" in summary_md
        assert "Predictive Modeling on Disagreement" in summary_md
        assert "Odds Ratio" in summary_md
