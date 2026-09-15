"""
tests/test_paper_artifacts.py — Verification suite for Phase 5 Publication Artifacts.

Validates:
  1. LaTeX Booktabs Table Generation & Data Provenance:
     - Environment balance: \\begin{table[*]} / \\end{table[*]}, \\begin{tabular} / \\end{tabular}
     - Booktabs macros: \\toprule, \\midrule, \\bottomrule
     - Captions and cross-reference labels
     - Mathematical escaping and symbol formatting
     - Dynamic sample count in captions ($N_{\\text{evaluated}}$)
     - Visual caveat marker in table notes when $N < 887$:
       "\\textit{Note: Preliminary sample evaluation ($N=...$); final results await completion of full benchmark run.}"
     - Verified 40-instance fixture distribution (--use-synthetic)
  2. Publication Vector Figure Generation:
     - Figure 1: Reliability diagram + confidence distribution histogram
     - Figure 2: Risk-Coverage curve across rejection thresholds tau
     - Figure 3: Empirical Pareto frontier (Macro-F1 vs. Operational Cost)
     - Figure 4: W3C PROV-DM Receipt DAG (.dot, .pdf, .png)
     - Headless Matplotlib execution ('Agg' backend) without GUI requirement
     - Non-empty output files (> 1000 bytes)
  3. Pure-Python LaTeX Syntax Validator (harness.validate_latex):
     - Validates generated paper artifacts with zero syntax errors.
     - Detects unbalanced environments, column mismatches, missing booktabs rules,
       and unescaped special characters.
  4. CLI Orchestration & Graceful Fallbacks:
     - export_all_paper_artifacts with and without existing results directories
     - CLI flags: --results-dir, --output-dir, --skip-figures, --use-synthetic
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
    DEFAULT_CALIBRATION,
    DEFAULT_ABLATION,
    SYNTHETIC_40_CONTINGENCY,
    SYNTHETIC_40_POLICY_COMPARISON,
    SYNTHETIC_40_CALIBRATION,
    SYNTHETIC_40_ABLATION,
    export_all_paper_artifacts,
    generate_table1_latex,
    generate_table2_latex,
    generate_table3_latex,
    generate_table4_latex,
    generate_table5_latex,
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
from harness.validate_latex import (
    LaTeXValidator,
    parse_tabular_column_count,
    split_cells_by_ampersand,
    validate_latex_content,
    validate_latex_dir,
    validate_latex_file,
    main as validate_latex_main,
)


# ===========================================================================
# 1. LaTeX Table Syntax & Structure Tests
# ===========================================================================

class TestLaTeXTableGenerators:
    """Verify syntactic correctness and structural integrity of generated LaTeX tables."""

    @staticmethod
    def _assert_latex_balanced(tex: str, table_env: str = "table*") -> None:
        """Assert balanced environments and booktabs structure."""
        begin_table = f"\\begin{{{table_env}}}"
        end_table = f"\\end{{{table_env}}}"
        begin_cnt = tex.count(begin_table)
        end_cnt = tex.count(end_table)
        assert begin_cnt == end_cnt == 1, (
            f"Mismatched {table_env} environments: {begin_cnt} begin vs {end_cnt} end"
        )

        begin_tabular = r"\begin{tabular}"
        end_tabular = r"\end{tabular}"
        begin_tab_cnt = tex.count(begin_tabular)
        end_tab_cnt = tex.count(end_tabular)
        assert begin_tab_cnt == end_tab_cnt == 1, (
            f"Mismatched tabular environments: {begin_tab_cnt} begin vs {end_tab_cnt} end"
        )

        assert "\\toprule" in tex, "Missing \\toprule"
        assert "\\midrule" in tex, "Missing \\midrule"
        assert "\\bottomrule" in tex, "Missing \\bottomrule"

        assert "\\caption{" in tex, "Missing \\caption{...}"
        assert "\\label{" in tex, "Missing \\label{...}"

    def test_table1_full_benchmark_provenance(self):
        """Table 1: Verify 4-cell contingency matrix structure, columns, and percentages for N=887."""
        tex = generate_table1_latex(DEFAULT_CONTINGENCY, sample_count=887)
        self._assert_latex_balanced(tex, table_env="table*")

        assert "Total ($N$)" in tex
        assert "Both Correct" in tex
        assert "Both Incorrect" in tex
        assert "Static Only" in tex
        assert "LLM Only" in tex
        assert "Disagreement Rate" in tex
        assert "N=887" in tex
        # Full run should NOT contain preliminary evaluation caveat note
        assert "Preliminary sample evaluation" not in tex

        unsecaped_percents = re.findall(r"(?<!\\)%", tex)
        assert len(unsecaped_percents) == 0, f"Found unescaped '%' in Table 1: {unsecaped_percents}"

    def test_table1_partial_sample_caveat(self):
        """Table 1: Verify dynamic caption and visual caveat note for N=50 partial sample."""
        tex = generate_table1_latex(DEFAULT_CONTINGENCY, sample_count=50)
        self._assert_latex_balanced(tex, table_env="table*")

        assert "N=50" in tex
        assert "\\textit{Note: Preliminary sample evaluation ($N=50$); final results await completion of full benchmark run.}" in tex

    def test_table2_disagreement_model(self):
        """Table 2: Verify feature regression weights, ORs, Wald z, and FDR q-values."""
        tex = generate_table2_latex(DEFAULT_DISAGREEMENT_FEATURES, sample_count=887)
        self._assert_latex_balanced(tex, table_env="table")

        assert "Odds Ratio (OR)" in tex
        assert "95\\% Confidence Interval" in tex
        assert "Wald $z$" in tex
        assert "$p$-value" in tex
        assert "FDR $q$-value" in tex

        assert "Granularity: File Scope" in tex
        assert "Plaintext HTTP Outbound" in tex
        assert "Plaintext Password Field" in tex
        assert "Kotlin" in tex

        assert "\\textbf{" in tex
        assert "$^*$" in tex

    def test_table2_partial_sample_caveat(self):
        """Table 2: Verify caveat note when evaluated on partial sample (e.g., N=50)."""
        tex = generate_table2_latex(DEFAULT_DISAGREEMENT_FEATURES, sample_count=50)
        self._assert_latex_balanced(tex, table_env="table")
        assert "N=50" in tex
        assert "\\textit{Note: Preliminary sample evaluation ($N=50$); final results await completion of full benchmark run.}" in tex

    def test_table3_policy_comparison(self):
        """Table 3: Verify 4-Policy benchmark comparison metrics from 5x3 Nested CV."""
        tex = generate_table3_latex(DEFAULT_POLICY_COMPARISON, sample_count=887)
        self._assert_latex_balanced(tex, table_env="table*")

        assert "Arbitration Policy" in tex
        assert "Macro-F1" in tex
        assert "Precision" in tex
        assert "Recall" in tex
        assert "Operational Cost" in tex
        assert "Abstention Rate" in tex
        assert "McNemar $p$ vs P1" in tex

        assert "Policy 1: FixedConfidenceMerge (Baseline)" in tex
        assert "Policy 2: Theoretical Oracle Bound" in tex
        assert "Policy 3: LearnedFeatureRouter" in tex
        assert "Policy 4: CostSensitiveRejectRouter (Proposed)" in tex
        assert "\\pm" in tex

    def test_table3_partial_sample_caveat(self):
        """Table 3: Verify caveat note when evaluated on partial sample (e.g., N=40)."""
        tex = generate_table3_latex(DEFAULT_POLICY_COMPARISON, sample_count=40)
        self._assert_latex_balanced(tex, table_env="table*")
        assert "N=40" in tex
        assert "\\textit{Note: Preliminary sample evaluation ($N=40$); final results await completion of full benchmark run.}" in tex

    def test_table4_calibration_decomposition(self):
        """Table 4: Verify M=5 quantile calibration table, Wilson MoE, and Murphy decomposition."""
        tex = generate_table4_latex(DEFAULT_CALIBRATION, sample_count=887)
        self._assert_latex_balanced(tex, table_env="table")

        assert "Bin ($m$)" in tex
        assert "Mean Conf. ($\\bar{p}_m$)" in tex
        assert "Emp. Acc. ($\\bar{y}_m$)" in tex
        assert "$\\pm 95\\%$ MoE" in tex
        assert "Murphy Decomposition" in tex
        assert "ECE" in tex
        assert "MCE" in tex
        assert "N=887" in tex
        assert "Preliminary sample evaluation" not in tex

    def test_table4_partial_sample_caveat(self):
        """Table 4: Verify dynamic caption and caveat note on partial sample (N=40)."""
        tex = generate_table4_latex(SYNTHETIC_40_CALIBRATION, sample_count=40)
        self._assert_latex_balanced(tex, table_env="table")
        assert "N=40" in tex
        assert "\\textit{Note: Preliminary sample evaluation ($N=40$); final results await completion of full benchmark run.}" in tex

    def test_table5_reconstructability_ablation(self):
        """Table 5: Verify backward minimality ablation table, R* checkmarks, and permutation baseline."""
        tex = generate_table5_latex(DEFAULT_ABLATION, sample_count=887)
        self._assert_latex_balanced(tex, table_env="table")

        assert "Configuration" in tex
        assert "Retained Fields" in tex
        assert "Accuracy" in tex
        assert "Retention \\%" in tex
        assert "R^*" in tex
        assert "Permutation baseline:" in tex
        assert "Fallback/timeout reconstructability:" in tex
        assert "Preliminary sample evaluation" not in tex

    def test_table5_partial_sample_caveat(self):
        """Table 5: Verify dynamic caption and caveat note on partial sample (N=40)."""
        tex = generate_table5_latex(SYNTHETIC_40_ABLATION, sample_count=40)
        self._assert_latex_balanced(tex, table_env="table")
        assert "N=40" in tex
        assert "\\textit{Note: Preliminary sample evaluation ($N=40$); final results await completion of full benchmark run.}" in tex


# ===========================================================================
# 2. Pure-Python LaTeX Validator Tests (harness.validate_latex)
# ===========================================================================

class TestLaTeXValidator:
    """Verify syntax validator accuracy on valid tables and synthetic negative cases."""

    def test_validator_passes_on_valid_table(self):
        tex = generate_table1_latex(DEFAULT_CONTINGENCY, sample_count=887)
        errors = validate_latex_content(tex, filename="test_table1.tex")
        assert len(errors) == 0, f"Unexpected validation errors: {errors}"

    def test_validator_detects_unmatched_environment(self):
        tex = "\\begin{table}\n\\begin{tabular}{lc}\n\\end{table}\n\\end{tabular}"
        errors = validate_latex_content(tex, filename="bad_env.tex")
        assert any("Mismatched environment" in e for e in errors)

    def test_validator_detects_unclosed_environment(self):
        tex = "\\begin{table*}\n\\centering\nText\n"
        errors = validate_latex_content(tex, filename="unclosed.tex")
        assert any("Unclosed environment" in e for e in errors)

    def test_validator_detects_column_mismatch(self):
        # 3 columns expected, 2 provided
        tex = (
            "\\begin{tabular}{lcc}\n"
            "\\toprule\n"
            "Col1 & Col2 \\\\\n"
            "\\bottomrule\n"
            "\\end{tabular}"
        )
        errors = validate_latex_content(tex, filename="bad_cols.tex")
        assert any("Column count mismatch in tabular" in e for e in errors)

    def test_validator_accepts_multicolumn_spanning_full_table(self):
        # 3 columns expected, multicolumn spans 3
        tex = (
            "\\begin{tabular}{lcc}\n"
            "\\toprule\n"
            "A & B & C \\\\\n"
            "\\midrule\n"
            "\\multicolumn{3}{l}{Note text} \\\\\n"
            "\\bottomrule\n"
            "\\end{tabular}"
        )
        errors = validate_latex_content(tex, filename="good_multi.tex")
        assert len(errors) == 0

    def test_validator_detects_missing_booktabs_rules(self):
        tex = (
            "\\begin{tabular}{lc}\n"
            "A & B \\\\\n"
            "\\midrule\n"
            "C & D \\\\\n"
            "\\end{tabular}"
        )
        errors = validate_latex_content(tex, filename="missing_rules.tex")
        assert any("missing \\toprule" in e.lower() or "missing \\bottomrule" in e.lower() for e in errors)

    def test_validator_detects_unescaped_underscore(self):
        tex = "\\begin{table}\nHere is some_variable that should be escaped\n\\end{table}"
        errors = validate_latex_content(tex, filename="bad_underscore.tex")
        assert any("Unescaped underscore" in e for e in errors)

    def test_validator_permits_underscore_in_math_and_label(self):
        tex = (
            "\\begin{table}\n"
            "\\label{tab:my_label_here}\n"
            "Formula: $x_{1} + y_{2} = z$\n"
            "\\input{sub_file.tex}\n"
            "\\end{table}"
        )
        errors = validate_latex_content(tex, filename="good_underscore.tex")
        assert len(errors) == 0

    def test_validator_detects_unescaped_percent(self):
        tex = "\\begin{table}\nPerformance reached 50% accuracy\n\\end{table}"
        errors = validate_latex_content(tex, filename="bad_pct.tex")
        assert any("Unescaped percent sign" in e for e in errors)

    def test_validator_detects_unescaped_ampersand_outside_tabular(self):
        tex = "\\begin{table}\nWe used Method A & Method B\n\\end{table}"
        errors = validate_latex_content(tex, filename="bad_amp.tex")
        assert any("Unescaped '&' outside tabular" in e for e in errors)


# ===========================================================================
# 3. Vector Figure Generation Tests
# ===========================================================================

class TestFigureGenerators:
    """Verify publication vector figure generation (PDF, PNG, DOT)."""

    def test_figure1_reliability_diagram(self, tmp_path: Path):
        """Figure 1: Reliability diagram and sample distribution histogram generation."""
        fig_path = tmp_path / "figure1_reliability_diagram.pdf"
        res = plot_figure1_reliability_diagram(DEFAULT_CALIBRATION, fig_path)

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

        assert res.exists()
        assert res.stat().st_size > 1000

        png_path = fig_path.with_suffix(".png")
        assert png_path.exists()
        assert png_path.stat().st_size > 1000

        dot_path = fig_path.with_suffix(".dot")
        assert dot_path.exists()
        dot_content = dot_path.read_text(encoding="utf-8")
        assert "digraph PROV_Receipt" in dot_content
        assert "Entity:" in dot_content
        assert "Activity:" in dot_content
        assert "Agent:" in dot_content


# ===========================================================================
# 4. Master Export Pipeline & CLI Tests
# ===========================================================================

class TestPaperArtifactsExportPipeline:
    """Verify end-to-end export orchestrator, synthetic flag, and CLI entrypoints."""

    def test_export_all_with_synthetic_flag(self, tmp_path: Path):
        """Verify export_all_paper_artifacts with use_synthetic=True."""
        output_dir = tmp_path / "synthetic_artifacts"

        exported = export_all_paper_artifacts(
            results_dir=tmp_path,
            output_dir=output_dir,
            generate_figures=True,
            use_synthetic=True,
        )

        # Assert all tables exist and have N=40 in caption
        for t_name in [
            "table1_complementarity.tex",
            "table2_disagreement_model.tex",
            "table3_policy_comparison.tex",
            "table4_calibration_decomposition.tex",
            "table5_reconstructability_ablation.tex",
        ]:
            content = (output_dir / t_name).read_text(encoding="utf-8")
            assert "N=40" in content
            assert "\\textit{Note: Preliminary sample evaluation ($N=40$); final results await completion of full benchmark run.}" in content

        # Run python LaTeX validator on generated output
        val_results = validate_latex_dir(output_dir)
        for p, errs in val_results.items():
            assert len(errs) == 0, f"Validator failed on {p}: {errs}"

        # Assert all 4 figures exist as both PDF and PNG with size > 1000
        fig_dir = output_dir / "figures"
        for f_num in range(1, 5):
            pdf_matches = list(fig_dir.glob(f"figure{f_num}_*.pdf"))
            png_matches = list(fig_dir.glob(f"figure{f_num}_*.png"))
            assert len(pdf_matches) == 1
            assert len(png_matches) == 1
            assert pdf_matches[0].stat().st_size > 1000
            assert png_matches[0].stat().st_size > 1000

    def test_export_all_from_test_fixtures_dir(self, tmp_path: Path):
        """Verify on-the-fly ingestion from results/test_fixtures (40 instances)."""
        fixtures_dir = Path("results/test_fixtures")
        if not fixtures_dir.exists():
            pytest.skip("results/test_fixtures not found in workspace")

        output_dir = tmp_path / "fixture_artifacts"
        exported = export_all_paper_artifacts(
            results_dir=fixtures_dir,
            output_dir=output_dir,
            generate_figures=False,
            use_synthetic=False,
        )

        assert "table1" in exported
        t1_content = (output_dir / "table1_complementarity.tex").read_text(encoding="utf-8")
        assert "N=40" in t1_content
        assert "\\textit{Note: Preliminary sample evaluation ($N=40$); final results await completion of full benchmark run.}" in t1_content

    def test_paper_artifacts_cli_with_synthetic(self, tmp_path: Path):
        """Test paper_artifacts CLI with --use-synthetic flag."""
        out_dir = tmp_path / "cli_synth"
        code = paper_artifacts_main(["--output-dir", str(out_dir), "--use-synthetic"])
        assert code == 0
        assert (out_dir / "table1_complementarity.tex").exists()
        assert (out_dir / "figures" / "figure1_reliability_diagram.pdf").exists()

    def test_validate_latex_cli(self, tmp_path: Path):
        """Test validate_latex CLI entrypoint."""
        out_dir = tmp_path / "val_cli"
        paper_artifacts_main(["--output-dir", str(out_dir), "--use-synthetic", "--skip-figures"])
        code = validate_latex_main([str(out_dir)])
        assert code == 0
