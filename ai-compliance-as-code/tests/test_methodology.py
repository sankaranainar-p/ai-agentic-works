"""
tests/test_methodology.py — Validation of Section 3 (Methodology) LaTeX Document.
"""

from pathlib import Path
import pytest
from harness.validate_latex import validate_latex_file

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_METHODOLOGY_TEX = _PROJECT_ROOT / "paper" / "sections" / "03_methodology.tex"
_REFERENCES_BIB = _PROJECT_ROOT / "paper" / "references.bib"


def test_methodology_file_exists():
    """Ensure paper/sections/03_methodology.tex is generated."""
    assert _METHODOLOGY_TEX.is_file(), f"Missing {_METHODOLOGY_TEX}"


def test_methodology_latex_validation():
    """Verify Section 3 passes LaTeX syntax and booktabs validation with zero errors."""
    errors = validate_latex_file(_METHODOLOGY_TEX)
    assert errors == [], f"LaTeX validation errors in {_METHODOLOGY_TEX.name}: {errors}"


def test_methodology_structural_coverage():
    """Assert all formal subsections, policies, and key equations are present."""
    content = _METHODOLOGY_TEX.read_text(encoding="utf-8")

    # Subsections
    assert "\\subsection{Problem Formulation and Asymmetric Regulatory Loss}" in content
    assert "\\subsection{Contrast with Unidirectional SAST Alert Triage}" in content
    assert "\\subsection{Granularity-Conditioned Feature Representation}" in content
    assert "\\subsection{Arbitration Policies and Selective Prediction}" in content
    assert "\\subsection{Confidence Calibration and Continuous Risk Conditioning}" in content
    assert "\\subsection{Cryptographic Provenance and Audit Sufficiency}" in content

    # Key Policies
    assert "Policy 1: Fixed Confidence Merge" in content
    assert "Policy 2: Clairvoyant Oracle" in content
    assert "Policy 3: Learned Feature Router" in content
    assert "Policy 4: Cost-Sensitive Reject Router" in content

    # Key mathematical symbols
    assert "R(S \\mid x)" in content
    assert "R(L \\mid x)" in content
    assert "R(H \\mid x)" in content
    assert "c_{FN}" in content
    assert "c_{FP}" in content
    assert "c_H" in content
    assert "\\Delta_{\\text{rec}}" in content


def test_references_bib_citations():
    """Assert all required external baselines and author prior work are present in references.bib."""
    bib_content = _REFERENCES_BIB.read_text(encoding="utf-8")

    required_keys = [
        "ran2025gdprbenchandroid",
        "wen2024automatically",
        "chen2024llm4fpm",
        "iranmanesh2025zerofalse",
        "agrawal2025sastgenius",
        "lin2025adataint",
        "paramasivan2025ai",
        "paramasivan2024acs",
        "chow1970optimum",
        "madras2018predict",
        "mozannar2020consistent",
        "murphy1973new",
        "moreau2013prov",
    ]

    for key in required_keys:
        assert f"{{{key}," in bib_content or f"@misc{{{key}," in bib_content or f"@article{{{key}," in bib_content or f"@incollection{{{key}," in bib_content, (
            f"Missing required bibtex entry: {key}"
        )
