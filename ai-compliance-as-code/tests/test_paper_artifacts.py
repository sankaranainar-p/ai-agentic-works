"""
tests/test_paper_artifacts.py — Verification suite for Phase 5 Publication Artifacts.

Validates:
  1. LaTeX Booktabs Table Generation:
     - Environment balance: \\begin{table[*]} / \\end{table[*]}, \\begin{tabular} / \\end{tabular}
     - Booktabs macros: \\toprule, \\midrule, \\bottomrule
     - Captions and cross-reference labels
     - Mathematical escaping and symbol formatting
     - Tables 1–4 and tables_preview.tex
  2. Publication Vector Figure Generation:
     - Figure 1: Reliability diagram + confidence distribution histogram
     - Figure 2: Risk-Coverage curve across rejection thresholds tau
     - Figure 3: Empirical Pareto frontier (Macro-F1 vs. Operational Cost)
     - Figure 4: W3C PROV-DM Receipt DAG (.dot, .pdf, .png)
     - Headless Matplotlib execution ('Agg' backend) without GUI requirement
     - Non-empty output files (> 1000 bytes)
  3. CLI Orchestration & Graceful Fallbacks:
     - export_all_paper_artifacts with and without existing results directories
     - CLI flags: --results-dir, --output-dir, --skip-figures
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Any

import pytest

from harness.paper_artifacts import (
    DEFAULT_CONTINGENCY,
    DEFAULT_DISAGREEMENT_FEATURES,
    DEFAULT_POLICY_COMPARISON,
    export_all_paper_artifacts,
    generate_table1_latex,
    generate_table2_latex,
    generate_table3_latex,
    generate_table4_latex,
    main as paper_artifacts_main,
)
from harness.plot_artifacts import (
    generate_all_figures,
    plot_figure1_reliability_diagram,
    plot_figure2_risk_coverage,
    plot_figure3_pareto_frontier,
    plot_figure4_prov_dag,
    main as plot_artifacts_main,
)


# ===========================================================================
# 1. LaTeX Table Syntax & Structure Tests
# ===========================================================================

class TestLaTeXTableGenerators:
    """Verify syntactic correctness and structural integrity of generated LaTeX tables."""

    @staticmethod
    def _assert_latex_balanced(tex: str, table_env: str = "table*") -> None:
        """Assert balanced environments and booktabs structure."""
        # Table environment balance
        begin_table = f"\\begin{{{table_env}}}"
        end_table = f"\\end{{{table_env}}}"
        begin_cnt = tex.count(begin_table)
        end_cnt = tex.count(end_table)
        assert begin_cnt == end_cnt == 1, (
            f"Mismatched {table_env} environments: {begin_cnt} begin vs {end_cnt} end"
        )

        # Tabular environment balance
        begin_tabular = r"\begin{tabular}"
        end_tabular = r"\end{tabular}"
        begin_tab_cnt = tex.count(begin_tabular)
        end_tab_cnt = tex.count(end_tabular)
        assert begin_tab_cnt == end_tab_cnt == 1, (
            f"Mismatched tabular environments: {begin_tab_cnt} begin vs {end_tab_cnt} end"
        )

        # Booktabs macros
        assert "\\toprule" in tex, "Missing \\toprule"
        assert "\\midrule" in tex, "Missing \\midrule"
        assert "\\bottomrule" in tex, "Missing \\bottomrule"

        # Caption and label
        assert "\\caption{" in tex, "Missing \\caption{...}"
        assert "\\label{" in tex, "Missing \\label{...}"

    def test_table1_complementarity_matrix(self):
        """Table 1: Verify 4-cell contingency matrix structure, columns, and percentages."""
        tex = generate_table1_latex(DEFAULT_CONTINGENCY)
        self._assert_latex_balanced(tex, table_env="table*")

        # Column headers
        assert "Total ($N$)" in tex
        assert "Both Correct" in tex
        assert "Both Incorrect" in tex
        assert "Static Only" in tex
        assert "LLM Only" in tex
        assert "Disagreement Rate" in tex

        # Partition scopes
        assert "Global Benchmark" in tex
        assert "Partitioned by Granularity Scope" in tex
        assert "File Scope" in tex
        assert "Module Scope" in tex
        assert "Line Scope" in tex
        assert "Partitioned by Key GDPR Articles" in tex
        assert "Article 5" in tex
        assert "Article 6" in tex
        assert "Article 25" in tex
        assert "Article 32" in tex

        # Verify percent signs are properly escaped as \%
        unsecaped_percents = re.findall(r"(?<!\\)%", tex)
        assert len(unsecaped_percents) == 0, f"Found unescaped '%' in Table 1: {unsecaped_percents}"

    def test_table2_disagreement_model(self):
        """Table 2: Verify feature regression weights, ORs, Wald z, and FDR q-values."""
        tex = generate_table2_latex(DEFAULT_DISAGREEMENT_FEATURES)
        self._assert_latex_balanced(tex, table_env="table")

        # Column headers
        assert "Odds Ratio (OR)" in tex
        assert "95\\% Confidence Interval" in tex
        assert "Wald $z$" in tex
        assert "$p$-value" in tex
        assert "FDR $q$-value" in tex

        # Essential features present
        assert "Granularity: File Scope" in tex
        assert "Plaintext HTTP Outbound" in tex
        assert "Plaintext Password Field" in tex
        assert "Kotlin" in tex

        # Significant features have bold / asterisk markers
        assert "\\textbf{" in tex
        assert "$^*$" in tex

    def test_table3_policy_comparison(self):
        """Table 3: Verify 4-Policy benchmark comparison metrics from 5x3 Nested CV."""
        tex = generate_table3_latex(DEFAULT_POLICY_COMPARISON)
        self._assert_latex_balanced(tex, table_env="table*")

        # Column headers
        assert "Arbitration Policy" in tex
        assert "Macro-F1" in tex
        assert "Precision" in tex
        assert "Recall" in tex
        assert "Operational Cost" in tex
        assert "Abstention Rate" in tex
        assert "McNemar $p$ vs P1" in tex

        # Four policies
        assert "Policy 1: FixedConfidenceMerge (Baseline)" in tex
        assert "Policy 2: Theoretical Oracle Bound" in tex
        assert "Policy 3: LearnedFeatureRouter" in tex
        assert "Policy 4: CostSensitiveRejectRouter (Proposed)" in tex

        # Cost uncertainty +/- present
        assert "\\pm" in tex

    def test_table4_calibration_decomposition(self):
        """Table 4: Verify M=5 quantile calibration table, Wilson MoE, and Murphy decomposition."""
        calib_data = {
            "num_samples": 887,
            "brier_score": 0.3092,
            "reliability": 0.2850,
            "resolution": 0.0458,
            "uncertainty": 0.0700,
            "ece": 0.5390,
            "mce": 0.6952,
            "bins": [
                {"bin": 1, "count": 178, "prop": 0.2007, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106, "calibration_error": 0.5000},
                {"bin": 2, "count": 177, "prop": 0.1995, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106, "calibration_error": 0.5000},
                {"bin": 3, "count": 178, "prop": 0.2007, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106, "calibration_error": 0.5000},
                {"bin": 4, "count": 177, "prop": 0.1995, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106, "calibration_error": 0.5000},
                {"bin": 5, "count": 177, "prop": 0.1995, "mean_confidence": 0.7630, "empirical_accuracy": 0.0678, "moe_95": 0.0378, "calibration_error": 0.6952},
            ],
        }

        tex = generate_table4_latex(calib_data)
        self._assert_latex_balanced(tex, table_env="table")

        # Column headers & summary rows
        assert "Bin ($m$)" in tex
        assert "Mean Conf. ($\\bar{p}_m$)" in tex
        assert "Emp. Acc. ($\\bar{y}_m$)" in tex
        assert "$\\pm 95\\%$ MoE" in tex
        assert "Murphy Decomposition" in tex
        assert "ECE" in tex
        assert "MCE" in tex
        assert "N=887" in tex


# ===========================================================================
# 2. Vector Figure Generation Tests
# ===========================================================================

class TestFigureGenerators:
    """Verify publication vector figure generation (PDF, PNG, DOT)."""

    def test_figure1_reliability_diagram(self, tmp_path: Path):
        """Figure 1: Reliability diagram and sample distribution histogram generation."""
        calib_data = {
            "brier_score": 0.3092,
            "ece": 0.5390,
            "mce": 0.6952,
            "bins": [
                {"bin": 1, "count": 178, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106},
                {"bin": 2, "count": 177, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106},
                {"bin": 3, "count": 178, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106},
                {"bin": 4, "count": 177, "mean_confidence": 0.5000, "empirical_accuracy": 0.0000, "moe_95": 0.0106},
                {"bin": 5, "count": 177, "mean_confidence": 0.7630, "empirical_accuracy": 0.0678, "moe_95": 0.0378},
            ],
        }
        fig_path = tmp_path / "figure1_reliability_diagram.pdf"
        res = plot_figure1_reliability_diagram(calib_data, fig_path)

        assert res.exists()
        assert res.stat().st_size > 1000
        png_path = fig_path.with_suffix(".png")
        assert png_path.exists()
        assert png_path.stat().st_size > 1000

    def test_figure2_risk_coverage(self, tmp_path: Path):
        """Figure 2: Risk-coverage trade-off curve across reject thresholds tau."""
        fig_path = tmp_path / "figure2_risk_coverage.pdf"
        res = plot_figure2_risk_coverage(fig_path, optimal_tau=0.10)

        assert res.exists()
        assert res.stat().st_size > 1000
        png_path = fig_path.with_suffix(".png")
        assert png_path.exists()
        assert png_path.stat().st_size > 1000

    def test_figure3_pareto_frontier(self, tmp_path: Path):
        """Figure 3: Empirical Pareto frontier (Macro-F1 vs. Operational Cost)."""
        fig_path = tmp_path / "figure3_pareto_frontier.pdf"
        res = plot_figure3_pareto_frontier(fig_path)

        assert res.exists()
        assert res.stat().st_size > 1000
        png_path = fig_path.with_suffix(".png")
        assert png_path.exists()
        assert png_path.stat().st_size > 1000

    def test_figure4_prov_dag(self, tmp_path: Path):
        """Figure 4: W3C PROV-DM receipt DAG (.dot, .pdf, .png)."""
        fig_path = tmp_path / "figure4_prov_dag.pdf"
        res = plot_figure4_prov_dag(fig_path)

        # PDF output
        assert res.exists()
        assert res.stat().st_size > 1000

        # PNG output
        png_path = fig_path.with_suffix(".png")
        assert png_path.exists()
        assert png_path.stat().st_size > 1000

        # DOT output
        dot_path = fig_path.with_suffix(".dot")
        assert dot_path.exists()
        dot_content = dot_path.read_text(encoding="utf-8")
        assert "digraph PROV_Receipt" in dot_content
        assert "Entity:" in dot_content
        assert "Activity:" in dot_content
        assert "Agent:" in dot_content
        assert "StaticScan" in dot_content
        assert "LLMInference" in dot_content
        assert "CostArbitration" in dot_content


# ===========================================================================
# 3. Master Export Pipeline & CLI Tests
# ===========================================================================

class TestPaperArtifactsExportPipeline:
    """Verify end-to-end export orchestrator and CLI entrypoint."""

    def test_export_all_paper_artifacts_with_figures(self, tmp_path: Path):
        """Export all tables and figures to temporary directory."""
        results_dir = tmp_path / "results"
        results_dir.mkdir(parents=True)
        output_dir = tmp_path / "paper_artifacts"

        exported = export_all_paper_artifacts(
            results_dir=results_dir,
            output_dir=output_dir,
            generate_figures=True,
        )

        expected_keys = {
            "table1", "table2", "table3", "table4", "tables_preview",
            "figure1", "figure2", "figure3", "figure4"
        }
        for key in expected_keys:
            assert key in exported, f"Missing key '{key}' in exported artifacts"
            assert exported[key].exists(), f"File {exported[key]} does not exist"
            assert exported[key].stat().st_size > 0

        # Check preview document structure
        preview_tex = (output_dir / "tables_preview.tex").read_text(encoding="utf-8")
        assert "\\documentclass" in preview_tex
        assert "\\usepackage{booktabs}" in preview_tex
        assert "\\input{table1_complementarity.tex}" in preview_tex
        assert "\\input{table2_disagreement_model.tex}" in preview_tex
        assert "\\input{table3_policy_comparison.tex}" in preview_tex
        assert "\\input{table4_calibration_decomposition.tex}" in preview_tex
        assert "\\end{document}" in preview_tex

    def test_export_all_paper_artifacts_skip_figures(self, tmp_path: Path):
        """Verify skip_figures flag omits figure generation."""
        output_dir = tmp_path / "tables_only"
        exported = export_all_paper_artifacts(
            results_dir=tmp_path,
            output_dir=output_dir,
            generate_figures=False,
        )

        assert "table1" in exported
        assert "table2" in exported
        assert "table3" in exported
        assert "table4" in exported
        assert "tables_preview" in exported
        assert "figure1" not in exported
        assert "figure2" not in exported

    def test_paper_artifacts_cli_success(self, tmp_path: Path):
        """CLI main function test."""
        out_dir = tmp_path / "cli_out"
        code = paper_artifacts_main(["--results-dir", str(tmp_path), "--output-dir", str(out_dir)])
        assert code == 0
        assert (out_dir / "table1_complementarity.tex").exists()
        assert (out_dir / "figures" / "figure1_reliability_diagram.pdf").exists()

    def test_plot_artifacts_cli_success(self, tmp_path: Path):
        """plot_artifacts CLI main function test."""
        out_dir = tmp_path / "fig_cli_out"
        code = plot_artifacts_main(["--results-dir", str(tmp_path), "--output-dir", str(out_dir)])
        assert code == 0
        assert (out_dir / "figure1_reliability_diagram.pdf").exists()
        assert (out_dir / "figure4_prov_dag.dot").exists()
