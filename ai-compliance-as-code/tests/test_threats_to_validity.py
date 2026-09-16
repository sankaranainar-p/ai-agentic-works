"""
tests/test_threats_to_validity.py — Unit tests for Section 6 (Threats to Validity) & Reconciler.

Verifies:
  1. Pure-Python LaTeX validation of paper/sections/06_threats_to_validity.tex:
     - Zero syntax errors, balanced environments, proper booktabs usage.
  2. Structural adherence:
     - Contains all four required subsections: Construct, Internal, External, Conclusion.
     - Summary table formatted with \\begin{table*}[t] and booktabs rules.
  3. Empirical reconciliation:
     - All numerical claims (AhMyth 52.31%, Acc drops 90.0% -> 57.5%, McNemar p=0.000122,
       Fisher p=0.000924, MiCA kappa=0.8571, costs c_FN=1.0, c_FP=0.1, c_H=0.25) match disk artifacts.
  4. Bibliography audit:
     - paper/references.bib contains the canonical citation @book{wohlin2012experimentation, ...}.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from harness.reconcile_threats import reconcile_section6
from harness.validate_latex import validate_latex_file


class TestThreatsToValiditySection:
    """Verifies syntax, structure, and empirical reconciliation of Section 6."""

    def test_section6_latex_syntax_validation(self) -> None:
        """Section 6 LaTeX file must pass pure-Python LaTeX validator with 0 errors."""
        tex_path = Path("paper/sections/06_threats_to_validity.tex")
        assert tex_path.exists(), "paper/sections/06_threats_to_validity.tex must exist"

        errors = validate_latex_file(tex_path)
        assert errors == [], f"LaTeX syntax validation failed: {errors}"

    def test_section6_structural_subsections_and_table(self) -> None:
        """Section 6 must contain the 4 standard subsections and summary table."""
        tex_path = Path("paper/sections/06_threats_to_validity.tex")
        content = tex_path.read_text(encoding="utf-8")

        # Subsections
        assert r"\subsection{Construct Validity}" in content
        assert r"\subsection{Internal Validity}" in content
        assert r"\subsection{External Validity}" in content
        assert r"\subsection{Conclusion Validity}" in content

        # Summary Table
        assert r"\begin{table*}[t]" in content
        assert r"\end{table*}" in content
        assert r"\begin{tabular}" in content
        assert r"\end{tabular}" in content
        assert r"\toprule" in content
        assert r"\midrule" in content
        assert r"\bottomrule" in content
        assert r"\label{tab:threats_summary}" in content

        # Check that no raw code citations appear (e.g., cost_router.py or gdpr.json)
        assert "cost_router.py" not in content
        assert "gdpr.json" not in content
        assert "static_scanner.py" not in content
        assert "mica_transfer_bench.py" not in content

    def test_section6_empirical_reconciliation(self) -> None:
        """All empirical numerical assertions in Section 6 must reconcile with disk."""
        tex_path = Path("paper/sections/06_threats_to_validity.tex")
        checks = reconcile_section6(tex_path=tex_path, results_dir=Path("results"))

        assert len(checks) >= 10
        failed = [c for c in checks if c["status"] != "PASS"]
        assert failed == [], f"Empirical reconciliation failed on: {failed}"

    def test_references_bib_contains_wohlin_citation(self) -> None:
        """paper/references.bib must exist and contain the canonical Wohlin citation."""
        bib_path = Path("paper/references.bib")
        assert bib_path.exists(), "paper/references.bib must exist"

        bib_content = bib_path.read_text(encoding="utf-8")
        assert "wohlin2012experimentation" in bib_content
        assert "Experimentation in Software Engineering" in bib_content
        assert "Wohlin, Claes" in bib_content
