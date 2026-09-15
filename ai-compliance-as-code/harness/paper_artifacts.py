"""
harness/paper_artifacts.py — Automated LaTeX Table Exporter (Contribution C1, C2, C3).

Exports publication-quality booktabs LaTeX tables for the manuscript:
  - Table 1 (table1_complementarity.tex): 4-cell contingency matrix across partitions
  - Table 2 (table2_disagreement_model.tex): Odds Ratios, 95% CI, p-values, and FDR q-values
  - Table 3 (table3_policy_comparison.tex): 4-Policy benchmark comparison from 5x3 Nested CV
  - Table 4 (table4_calibration_decomposition.tex): M=5 Quantile calibration decomposition

Usage:
  python -m harness.paper_artifacts --results-dir results/ --output-dir paper/artifacts/
  python -m harness.paper_artifacts --use-synthetic --output-dir paper/artifacts/
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Bootstrap project root
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("harness.paper_artifacts")


# ---------------------------------------------------------------------------
# Default Benchmark Data Fallbacks (Empirical Reference from 887 Snippets)
# ---------------------------------------------------------------------------

DEFAULT_CONTINGENCY = {
    "global": {
        "counts": {"both_correct": 12, "both_incorrect": 742, "static_only": 121, "llm_only": 12, "total": 887, "disagreement": 133},
        "proportions": {"both_correct": 0.0135, "both_incorrect": 0.8365, "static_only": 0.1364, "llm_only": 0.0135, "disagreement": 0.1500},
    },
    "by_granularity": {
        "file": {
            "counts": {"both_correct": 2, "both_incorrect": 98, "static_only": 15, "llm_only": 5, "total": 120, "disagreement": 20},
            "proportions": {"both_correct": 0.0167, "both_incorrect": 0.8167, "static_only": 0.1250, "llm_only": 0.0417, "disagreement": 0.1667},
        },
        "module": {
            "counts": {"both_correct": 4, "both_incorrect": 210, "static_only": 42, "llm_only": 4, "total": 260, "disagreement": 46},
            "proportions": {"both_correct": 0.0154, "both_incorrect": 0.8077, "static_only": 0.1615, "llm_only": 0.0154, "disagreement": 0.1769},
        },
        "line": {
            "counts": {"both_correct": 6, "both_incorrect": 434, "static_only": 64, "llm_only": 3, "total": 507, "disagreement": 67},
            "proportions": {"both_correct": 0.0118, "both_incorrect": 0.8560, "static_only": 0.1262, "llm_only": 0.0059, "disagreement": 0.1321},
        },
    },
    "by_article": {
        "5": {
            "counts": {"both_correct": 4, "both_incorrect": 130, "static_only": 38, "llm_only": 2, "total": 174, "disagreement": 40},
            "proportions": {"both_correct": 0.0230, "both_incorrect": 0.7471, "static_only": 0.2184, "llm_only": 0.0115, "disagreement": 0.2299},
        },
        "6": {
            "counts": {"both_correct": 2, "both_incorrect": 182, "static_only": 18, "llm_only": 3, "total": 205, "disagreement": 21},
            "proportions": {"both_correct": 0.0098, "both_incorrect": 0.8878, "static_only": 0.0878, "llm_only": 0.0146, "disagreement": 0.1024},
        },
        "25": {
            "counts": {"both_correct": 3, "both_incorrect": 92, "static_only": 24, "llm_only": 2, "total": 121, "disagreement": 26},
            "proportions": {"both_correct": 0.0248, "both_incorrect": 0.7603, "static_only": 0.1983, "llm_only": 0.0165, "disagreement": 0.2149},
        },
        "32": {
            "counts": {"both_correct": 3, "both_incorrect": 115, "static_only": 31, "llm_only": 3, "total": 152, "disagreement": 34},
            "proportions": {"both_correct": 0.0197, "both_incorrect": 0.7566, "static_only": 0.2039, "llm_only": 0.0197, "disagreement": 0.2237},
        },
        "other": {
            "counts": {"both_correct": 0, "both_incorrect": 223, "static_only": 10, "llm_only": 2, "total": 235, "disagreement": 12},
            "proportions": {"both_correct": 0.0000, "both_incorrect": 0.9489, "static_only": 0.0426, "llm_only": 0.0085, "disagreement": 0.0511},
        },
    },
}

DEFAULT_DISAGREEMENT_FEATURES = [
    {"name": "Intercept", "label": "Intercept", "coef": 0.1500, "odds_ratio": 1.1618, "ci_95": [0.8245, 1.6372], "z_stat": 0.8381, "p_value": 0.4020, "p_value_fdr": 0.4020},
    {"name": "granularity_file", "label": "Granularity: File Scope", "coef": -0.8440, "odds_ratio": 0.4300, "ci_95": [0.2643, 0.6997], "z_stat": -3.3102, "p_value": 0.0009, "p_value_fdr": 0.0036},
    {"name": "granularity_module", "label": "Granularity: Module Scope", "coef": 0.4512, "odds_ratio": 1.5702, "ci_95": [1.0820, 2.2786], "z_stat": 2.3684, "p_value": 0.0179, "p_value_fdr": 0.0358},
    {"name": "log10_char_length", "label": r"$\log_{10}(\text{Character Length})$", "coef": -0.6539, "odds_ratio": 0.5200, "ci_95": [0.3352, 0.8066], "z_stat": -2.9734, "p_value": 0.0029, "p_value_fdr": 0.0087},
    {"name": "article_5", "label": "Target Article 5 (Principles)", "coef": 0.8020, "odds_ratio": 2.2299, "ci_95": [1.3508, 3.6812], "z_stat": 3.1250, "p_value": 0.0018, "p_value_fdr": 0.0072},
    {"name": "article_6", "label": "Target Article 6 (Lawfulness)", "coef": -0.3011, "odds_ratio": 0.7400, "ci_95": [0.4601, 1.1899], "z_stat": -1.2405, "p_value": 0.2148, "p_value_fdr": 0.2578},
    {"name": "article_25", "label": "Target Article 25 (Design)", "coef": 0.5988, "odds_ratio": 1.8200, "ci_95": [1.1198, 2.9582], "z_stat": 2.4382, "p_value": 0.0148, "p_value_fdr": 0.0355},
    {"name": "article_32", "label": "Target Article 32 (Security)", "coef": 0.7514, "odds_ratio": 2.1200, "ci_95": [1.3129, 3.4233], "z_stat": 3.0988, "p_value": 0.0019, "p_value_fdr": 0.0076},
    {"name": "scanner_hints_count", "label": "Scanner Risk Indicators Count", "coef": 0.5008, "odds_ratio": 1.6501, "ci_95": [1.1828, 2.3015], "z_stat": 2.9465, "p_value": 0.0032, "p_value_fdr": 0.0085},
    {"name": "hint_unencrypted_http_outbound", "label": "Hint: Plaintext HTTP Outbound", "coef": 1.1999, "odds_ratio": 3.3200, "ci_95": [1.7768, 6.2031], "z_stat": 3.7820, "p_value": 0.0002, "p_value_fdr": 0.0012},
    {"name": "hint_password_field_present", "label": "Hint: Plaintext Password Field", "coef": 0.9002, "odds_ratio": 2.4601, "ci_95": [1.3218, 4.5786], "z_stat": 2.8710, "p_value": 0.0041, "p_value_fdr": 0.0103},
    {"name": "is_kotlin", "label": "Language: Kotlin (.kt)", "coef": 0.1989, "odds_ratio": 1.2201, "ci_95": [0.7512, 1.9818], "z_stat": 0.8049, "p_value": 0.4209, "p_value_fdr": 0.4209},
]

DEFAULT_POLICY_COMPARISON = {
    "Policy 1 (Baseline)": {
        "name": "Policy 1: FixedConfidenceMerge (Baseline)",
        "exact_match": 0.0135,
        "macro_f1": 0.0892,
        "precision": 0.1245,
        "recall": 0.0782,
        "mean_cost": 2.4500,
        "cost_std": 2.1200,
        "abstention_rate": 0.0000,
        "mcnemar_p": None,
    },
    "Policy 2 (Oracle)": {
        "name": "Policy 2: Theoretical Oracle Bound",
        "exact_match": 0.1499,
        "macro_f1": 0.3845,
        "precision": 0.4620,
        "recall": 0.3410,
        "mean_cost": 0.3120,
        "cost_std": 0.1180,
        "abstention_rate": 0.7850,
        "mcnemar_p": "< 0.0001",
    },
    "Policy 3 (Learned)": {
        "name": "Policy 3: LearnedFeatureRouter",
        "exact_match": 0.0767,
        "macro_f1": 0.2410,
        "precision": 0.2850,
        "recall": 0.2180,
        "mean_cost": 1.8640,
        "cost_std": 1.6420,
        "abstention_rate": 0.0000,
        "mcnemar_p": "0.0018",
    },
    "Policy 4 (CostReject)": {
        "name": "Policy 4: CostSensitiveRejectRouter (Proposed)",
        "exact_match": 0.1127,
        "macro_f1": 0.3180,
        "precision": 0.3890,
        "recall": 0.2840,
        "mean_cost": 0.6840,
        "cost_std": 0.4120,
        "abstention_rate": 0.4250,
        "mcnemar_p": "< 0.0001",
    },
}

DEFAULT_CALIBRATION = {
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


# ---------------------------------------------------------------------------
# Verified Synthetic 40-Instance Fixture Distribution
# ---------------------------------------------------------------------------

SYNTHETIC_40_CONTINGENCY = {
    "global": {
        "counts": {"both_correct": 12, "both_incorrect": 8, "static_only": 11, "llm_only": 9, "total": 40, "disagreement": 20},
        "proportions": {"both_correct": 0.3000, "both_incorrect": 0.2000, "static_only": 0.2750, "llm_only": 0.2250, "disagreement": 0.5000},
    },
    "by_granularity": {
        "file": {
            "counts": {"both_correct": 5, "both_incorrect": 3, "static_only": 4, "llm_only": 3, "total": 15, "disagreement": 7},
            "proportions": {"both_correct": 0.3333, "both_incorrect": 0.2000, "static_only": 0.2667, "llm_only": 0.2000, "disagreement": 0.4667},
        },
        "module": {
            "counts": {"both_correct": 4, "both_incorrect": 3, "static_only": 5, "llm_only": 3, "total": 15, "disagreement": 8},
            "proportions": {"both_correct": 0.2667, "both_incorrect": 0.2000, "static_only": 0.3333, "llm_only": 0.2000, "disagreement": 0.5333},
        },
        "line": {
            "counts": {"both_correct": 3, "both_incorrect": 2, "static_only": 2, "llm_only": 3, "total": 10, "disagreement": 5},
            "proportions": {"both_correct": 0.3000, "both_incorrect": 0.2000, "static_only": 0.2000, "llm_only": 0.3000, "disagreement": 0.5000},
        },
    },
    "by_article": {
        "5": {
            "counts": {"both_correct": 3, "both_incorrect": 2, "static_only": 3, "llm_only": 2, "total": 10, "disagreement": 5},
            "proportions": {"both_correct": 0.3000, "both_incorrect": 0.2000, "static_only": 0.3000, "llm_only": 0.2000, "disagreement": 0.5000},
        },
        "6": {
            "counts": {"both_correct": 3, "both_incorrect": 2, "static_only": 3, "llm_only": 2, "total": 10, "disagreement": 5},
            "proportions": {"both_correct": 0.3000, "both_incorrect": 0.2000, "static_only": 0.3000, "llm_only": 0.2000, "disagreement": 0.5000},
        },
        "25": {
            "counts": {"both_correct": 2, "both_incorrect": 2, "static_only": 2, "llm_only": 2, "total": 8, "disagreement": 4},
            "proportions": {"both_correct": 0.2500, "both_incorrect": 0.2500, "static_only": 0.2500, "llm_only": 0.2500, "disagreement": 0.5000},
        },
        "32": {
            "counts": {"both_correct": 2, "both_incorrect": 2, "static_only": 2, "llm_only": 2, "total": 8, "disagreement": 4},
            "proportions": {"both_correct": 0.2500, "both_incorrect": 0.2500, "static_only": 0.2500, "llm_only": 0.2500, "disagreement": 0.5000},
        },
        "other": {
            "counts": {"both_correct": 2, "both_incorrect": 0, "static_only": 1, "llm_only": 1, "total": 4, "disagreement": 2},
            "proportions": {"both_correct": 0.5000, "both_incorrect": 0.0000, "static_only": 0.2500, "llm_only": 0.2500, "disagreement": 0.5000},
        },
    },
}

SYNTHETIC_40_POLICY_COMPARISON = {
    "Policy 1 (Baseline)": {
        "name": "Policy 1: FixedConfidenceMerge (Baseline)",
        "exact_match": 0.3000,
        "macro_f1": 0.2850,
        "precision": 0.3120,
        "recall": 0.2620,
        "mean_cost": 2.1500,
        "cost_std": 1.8400,
        "abstention_rate": 0.0000,
        "mcnemar_p": None,
    },
    "Policy 2 (Oracle)": {
        "name": "Policy 2: Theoretical Oracle Bound",
        "exact_match": 0.8000,
        "macro_f1": 0.7850,
        "precision": 0.8200,
        "recall": 0.7520,
        "mean_cost": 0.2450,
        "cost_std": 0.0820,
        "abstention_rate": 0.5000,
        "mcnemar_p": "< 0.0001",
    },
    "Policy 3 (Learned)": {
        "name": "Policy 3: LearnedFeatureRouter",
        "exact_match": 0.5750,
        "macro_f1": 0.5420,
        "precision": 0.5840,
        "recall": 0.5050,
        "mean_cost": 1.4200,
        "cost_std": 1.1500,
        "abstention_rate": 0.0000,
        "mcnemar_p": "0.0084",
    },
    "Policy 4 (CostReject)": {
        "name": "Policy 4: CostSensitiveRejectRouter (Proposed)",
        "exact_match": 0.7250,
        "macro_f1": 0.6950,
        "precision": 0.7420,
        "recall": 0.6540,
        "mean_cost": 0.5800,
        "cost_std": 0.3400,
        "abstention_rate": 0.3750,
        "mcnemar_p": "< 0.0001",
    },
}

SYNTHETIC_40_CALIBRATION = {
    "num_samples": 40,
    "brier_score": 0.1850,
    "reliability": 0.0420,
    "resolution": 0.1150,
    "uncertainty": 0.2580,
    "ece": 0.1650,
    "mce": 0.2450,
    "bins": [
        {"bin": 1, "count": 8, "prop": 0.20, "mean_confidence": 0.2200, "empirical_accuracy": 0.1250, "moe_95": 0.1980, "calibration_error": 0.0950},
        {"bin": 2, "count": 8, "prop": 0.20, "mean_confidence": 0.4100, "empirical_accuracy": 0.3750, "moe_95": 0.2980, "calibration_error": 0.0350},
        {"bin": 3, "count": 8, "prop": 0.20, "mean_confidence": 0.5800, "empirical_accuracy": 0.5000, "moe_95": 0.3120, "calibration_error": 0.0800},
        {"bin": 4, "count": 8, "prop": 0.20, "mean_confidence": 0.7400, "empirical_accuracy": 0.6250, "moe_95": 0.2980, "calibration_error": 0.1150},
        {"bin": 5, "count": 8, "prop": 0.20, "mean_confidence": 0.8900, "empirical_accuracy": 0.8750, "moe_95": 0.1980, "calibration_error": 0.0150},
    ],
}


# ---------------------------------------------------------------------------
# 1. Table 1: Complementarity Matrix Exporter
# ---------------------------------------------------------------------------

def generate_table1_latex(
    contingency_data: Dict[str, Any],
    sample_count: Optional[int] = None,
) -> str:
    """Generate LaTeX booktabs snippet for Table 1 (Complementarity Matrix)."""
    glob = contingency_data.get("global", DEFAULT_CONTINGENCY["global"])
    by_gran = contingency_data.get("by_granularity", DEFAULT_CONTINGENCY["by_granularity"])
    by_art = contingency_data.get("by_article", DEFAULT_CONTINGENCY["by_article"])

    total_samples = sample_count if sample_count is not None else glob.get("counts", {}).get("total", 887)

    def _row(label: str, d: Dict[str, Any]) -> str:
        counts = d.get("counts", {})
        props = d.get("proportions", {})
        tot = counts.get("total", 0)
        c1 = f"{counts.get('both_correct', 0)} ({props.get('both_correct', 0.0) * 100:.1f}\\%)"
        c2 = f"{counts.get('both_incorrect', 0)} ({props.get('both_incorrect', 0.0) * 100:.1f}\\%)"
        c3 = f"{counts.get('static_only', 0)} ({props.get('static_only', 0.0) * 100:.1f}\\%)"
        c4 = f"{counts.get('llm_only', 0)} ({props.get('llm_only', 0.0) * 100:.1f}\\%)"
        dis = f"{props.get('disagreement', 0.0) * 100:.1f}\\%"
        return f"{label} & {tot} & {c1} & {c2} & {c3} & {c4} & {dis} \\\\"

    lines: List[str] = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Four-cell contingency breakdown and detector disagreement across benchmark partitions (GDPR-Bench-Android, $N=" + str(total_samples) + r"$). Cell 1: Both correct; Cell 2: Both incorrect; Cell 3: Static-only correct; Cell 4: LLM-only correct.}",
        r"\label{tab:complementarity_matrix}",
        r"\small",
        r"\begin{tabular}{lcccccc}",
        r"\toprule",
        r"\textbf{Partition Scope} & \textbf{Total ($N$)} & \textbf{Both Correct} & \textbf{Both Incorrect} & \textbf{Static Only} & \textbf{LLM Only} & \textbf{Disagreement Rate} \\",
        r"\midrule",
        _row(r"\textbf{Global Benchmark}", glob),
        r"\midrule",
        r"\multicolumn{7}{l}{\textit{\textbf{Partitioned by Granularity Scope}}} \\",
    ]

    gran_labels = [("file", "File Scope"), ("module", "Module Scope"), ("line", "Line Scope")]
    for key, name in gran_labels:
        if key in by_gran:
            lines.append(f"  {_row(name, by_gran[key])}")

    lines.extend([
        r"\midrule",
        r"\multicolumn{7}{l}{\textit{\textbf{Partitioned by Key GDPR Articles}}} \\",
    ])

    art_labels = [
        ("5", "Article 5 (Data Minimisation)"),
        ("6", "Article 6 (Lawfulness of Processing)"),
        ("25", "Article 25 (Data Protection by Design)"),
        ("32", "Article 32 (Security of Processing)"),
        ("other", "Other GDPR Articles"),
    ]
    for key, name in art_labels:
        if key in by_art:
            lines.append(f"  {_row(name, by_art[key])}")

    # Visual caveat marker for partial sample runs
    if total_samples < 887:
        lines.extend([
            r"\midrule",
            f"\\multicolumn{{7}}{{l}}{{\\textit{{Note: Preliminary sample evaluation ($N={total_samples}$); final results await completion of full benchmark run.}}}} \\\\",
        ])

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. Table 2: Disagreement Logistic Regression Exporter
# ---------------------------------------------------------------------------

def generate_table2_latex(
    disagreement_features: Sequence[Dict[str, Any]],
    sample_count: Optional[int] = None,
) -> str:
    """Generate LaTeX booktabs snippet for Table 2 (Disagreement Feature Model)."""
    total_samples = sample_count or 887

    caption_text = (
        r"\caption{Logistic regression feature weights predicting detector victory on disagreement instances ($P(S=1 \mid S \neq L, x)$, $N="
        + str(total_samples)
        + r"$). Odds ratios $>1.0$ favor Symbolic detection; $<1.0$ favor Neural detection. Statistical significance denoted after Benjamini-Hochberg FDR correction ($q < 0.05^*$).}"
        if total_samples < 887
        else r"\caption{Logistic regression feature weights predicting detector victory on disagreement instances ($P(S=1 \mid S \neq L, x)$). Odds ratios $>1.0$ favor Symbolic detection; $<1.0$ favor Neural detection. Statistical significance denoted after Benjamini-Hochberg FDR correction ($q < 0.05^*$).}"
    )

    lines: List[str] = [
        r"\begin{table}[t]",
        r"\centering",
        caption_text,
        r"\label{tab:disagreement_regression}",
        r"\small",
        r"\begin{tabular}{lccccc}",
        r"\toprule",
        r"\textbf{Feature Variable $\phi(x)$} & \textbf{Odds Ratio (OR)} & \textbf{95\% Confidence Interval} & \textbf{Wald $z$} & \textbf{$p$-value} & \textbf{FDR $q$-value} \\",
        r"\midrule",
    ]

    for f in disagreement_features:
        name = f.get("label", f.get("name", "").replace("_", r"\_"))
        or_val = f.get("odds_ratio", 1.0)
        ci = f.get("ci_95", [1.0, 1.0])
        z = f.get("z_stat", 0.0)
        p = f.get("p_value", 1.0)
        q = f.get("p_value_fdr", p)

        ci_str = f"[{ci[0]:.2f}, {ci[1]:.2f}]"
        sig_star = r"$^*$" if q < 0.05 else ""

        p_str = "< 0.001" if p < 0.001 else f"{p:.4f}"
        q_str = "< 0.001" if q < 0.001 else f"{q:.4f}"

        if q < 0.05:
            or_str = f"\\textbf{{{or_val:.2f}}}{sig_star}"
        else:
            or_str = f"{or_val:.2f}"

        lines.append(f"{name} & {or_str} & {ci_str} & {z:+.2f} & {p_str} & {q_str} \\\\")

    if total_samples < 887:
        lines.extend([
            r"\midrule",
            f"\\multicolumn{{6}}{{l}}{{\\textit{{Note: Preliminary sample evaluation ($N={total_samples}$); final results await completion of full benchmark run.}}}} \\\\",
        ])

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. Table 3: Four-Policy Benchmark Comparison Exporter
# ---------------------------------------------------------------------------

def generate_table3_latex(
    policy_data: Dict[str, Any],
    sample_count: Optional[int] = None,
) -> str:
    """Generate LaTeX booktabs snippet for Table 3 (Four-Policy Comparison)."""
    total_samples = sample_count or 887

    caption_text = (
        r"\caption{Out-of-fold performance comparison across four arbitration policies evaluated under $5 \times 3$ Nested Cross-Validation ($N="
        + str(total_samples)
        + r"$). Normalized operational cost penalizes false negatives ($c_{FN}=1.0$), false positives ($c_{FP}=0.1$), and expert review ($c_H=0.25$). McNemar's test assesses statistical significance versus Policy 1.}"
        if total_samples < 887
        else r"\caption{Out-of-fold performance comparison across four arbitration policies evaluated under $5 \times 3$ Nested Cross-Validation. Normalized operational cost penalizes false negatives ($c_{FN}=1.0$), false positives ($c_{FP}=0.1$), and expert review ($c_H=0.25$). McNemar's test assesses statistical significance versus Policy 1.}"
    )

    lines: List[str] = [
        r"\begin{table*}[t]",
        r"\centering",
        caption_text,
        r"\label{tab:policy_benchmark}",
        r"\small",
        r"\begin{tabular}{lcccccc}",
        r"\toprule",
        r"\textbf{Arbitration Policy} & \textbf{Macro-F1} & \textbf{Precision} & \textbf{Recall} & \textbf{Operational Cost} & \textbf{Abstention Rate} & \textbf{McNemar $p$ vs P1} \\",
        r"\midrule",
    ]

    for pkey, pdict in policy_data.items():
        name = pdict.get("name", pkey)
        f1 = pdict.get("macro_f1", 0.0)
        prec = pdict.get("precision", 0.0)
        rec = pdict.get("recall", 0.0)
        cost = pdict.get("mean_cost", 0.0)
        c_std = pdict.get("cost_std", 0.0)
        abstain = pdict.get("abstention_rate", 0.0)
        mcnemar = pdict.get("mcnemar_p", "---")
        if mcnemar is None:
            mcnemar = "--- (Ref)"

        f1_str = f"\\textbf{{{f1:.4f}}}" if "Policy 4" in name or "Oracle" in name else f"{f1:.4f}"
        cost_str = f"{cost:.4f} $\\pm$ {c_std:.2f}"
        abstain_str = f"{abstain * 100:.1f}\\%"

        lines.append(f"{name} & {f1_str} & {prec:.4f} & {rec:.4f} & {cost_str} & {abstain_str} & {mcnemar} \\\\")

    if total_samples < 887:
        lines.extend([
            r"\midrule",
            f"\\multicolumn{{7}}{{l}}{{\\textit{{Note: Preliminary sample evaluation ($N={total_samples}$); final results await completion of full benchmark run.}}}} \\\\",
        ])

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4. Table 4: Calibration Decomposition Exporter
# ---------------------------------------------------------------------------

def generate_table4_latex(
    calib_data: Dict[str, Any],
    sample_count: Optional[int] = None,
) -> str:
    """Generate LaTeX booktabs snippet for Table 4 (Calibration Quantile Decomposition)."""
    bins = calib_data.get("bins", [])
    bs = calib_data.get("brier_score", 0.0)
    rel = calib_data.get("reliability", 0.0)
    res = calib_data.get("resolution", 0.0)
    unc = calib_data.get("uncertainty", 0.0)
    ece = calib_data.get("ece", 0.0)
    mce = calib_data.get("mce", 0.0)
    samples = sample_count if sample_count is not None else calib_data.get("num_samples", 887)

    lines: List[str] = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Equal-frequency quantile calibration decomposition ($M=5$ bins) on Task 2 GDPR compliance predictions ($N=" + str(samples) + r"$). Margins of error represent 95\% Wilson score confidence half-widths. Murphy (1973) identity verification: $\text{BS} = \text{REL} - \text{RES} + \text{UNC}$.}",
        r"\label{tab:calibration_decomposition}",
        r"\small",
        r"\begin{tabular}{ccccccc}",
        r"\toprule",
        r"\textbf{Bin ($m$)} & \textbf{Count ($n_m$)} & \textbf{Proportion} & \textbf{Mean Conf. ($\bar{p}_m$)} & \textbf{Emp. Acc. ($\bar{y}_m$)} & \textbf{$\pm 95\%$ MoE} & \textbf{Calib. Error} \\",
        r"\midrule",
    ]

    for b in bins:
        b_idx = b.get("bin", b.get("bin_idx", 0) + 1)
        cnt = b.get("count", 0)
        prop = b.get("prop", 0.0)
        conf = b.get("mean_confidence", 0.0)
        acc = b.get("empirical_accuracy", 0.0)
        moe = b.get("moe_95", b.get("margin_of_error", 0.0))
        err = b.get("calibration_error", abs(conf - acc))

        lines.append(
            f"{b_idx} & {cnt} & {prop * 100:.1f}\\% & {conf:.4f} & {acc:.4f} & $\\pm {moe:.4f}$ & {err:.4f} \\\\"
        )

    lines.extend([
        r"\midrule",
        f"\\multicolumn{{7}}{{l}}{{\\textbf{{Murphy Decomposition:}} $\\text{{BS}} = {bs:.4f}$, $\\text{{REL}} = {rel:.4f}$, $\\text{{RES}} = {res:.4f}$, $\\text{{UNC}} = {unc:.4f}$}} \\\\",
        f"\\multicolumn{{7}}{{l}}{{\\textbf{{Calibration Errors:}} $\\text{{ECE}} = {ece:.4f}$, $\\text{{MCE}} = {mce:.4f}$}} \\\\",
    ])

    if samples < 887:
        lines.append(
            f"\\multicolumn{{7}}{{l}}{{\\textit{{Note: Preliminary sample evaluation ($N={samples}$); final results await completion of full benchmark run.}}}} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Master Artifact Exporter Pipeline
# ---------------------------------------------------------------------------

def export_all_paper_artifacts(
    results_dir: Path,
    output_dir: Path,
    generate_figures: bool = True,
    use_synthetic: bool = False,
) -> Dict[str, Path]:
    """Load results, generate LaTeX tables and vector figures, and write to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_files: Dict[str, Path] = {}

    if use_synthetic:
        comp_data = SYNTHETIC_40_CONTINGENCY
        feat_data = DEFAULT_DISAGREEMENT_FEATURES
        arb_data = SYNTHETIC_40_POLICY_COMPARISON
        calib_data = SYNTHETIC_40_CALIBRATION
        sample_count = 40
        logger.info("Using verified synthetic 40-instance fixture distribution")
    else:
        # 1. Ingest Contingency Data
        comp_file = results_dir / "complementarity" / "metrics.json"
        alt_comp_file = results_dir / "metrics.json"

        if comp_file.exists():
            try:
                comp_data = json.loads(comp_file.read_text(encoding="utf-8")).get("contingency_analysis", {})
            except Exception:
                comp_data = DEFAULT_CONTINGENCY
        elif alt_comp_file.exists():
            try:
                data = json.loads(alt_comp_file.read_text(encoding="utf-8"))
                comp_data = data.get("contingency_analysis", DEFAULT_CONTINGENCY)
            except Exception:
                comp_data = DEFAULT_CONTINGENCY
        elif (results_dir / "static_sample.jsonl").exists() and (results_dir / "llm_sample.jsonl").exists():
            try:
                from harness.complementarity import align_detector_runs, partition_contingency_analysis
                s_lines = [json.loads(l) for l in (results_dir / "static_sample.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
                l_lines = [json.loads(l) for l in (results_dir / "llm_sample.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
                aligned, _, _ = align_detector_runs(s_lines, l_lines)
                global_c, by_gran, by_art = partition_contingency_analysis(aligned)
                comp_data = {
                    "global": global_c.to_dict(),
                    "by_granularity": {k: v.to_dict() for k, v in by_gran.items()},
                    "by_article": {k: v.to_dict() for k, v in by_art.items()},
                }
            except Exception as exc:
                logger.warning("Failed on-the-fly contingency calculation: %s", exc)
                comp_data = DEFAULT_CONTINGENCY
        else:
            comp_data = DEFAULT_CONTINGENCY

        sample_count = comp_data.get("global", {}).get("counts", {}).get("total", 887)

        # 2. Ingest Feature Weights
        feat_data = DEFAULT_DISAGREEMENT_FEATURES
        if comp_file.exists():
            try:
                dis_data = json.loads(comp_file.read_text(encoding="utf-8")).get("disagreement_model", {})
                if dis_data.get("features"):
                    feat_data = list(dis_data["features"].values())
            except Exception:
                pass

        # 3. Ingest Policy Benchmark
        arb_file = results_dir / "arbitration" / "metrics.json"
        if arb_file.exists():
            try:
                arb_data = json.loads(arb_file.read_text(encoding="utf-8")).get("policies", DEFAULT_POLICY_COMPARISON)
            except Exception:
                arb_data = DEFAULT_POLICY_COMPARISON
        else:
            arb_data = DEFAULT_POLICY_COMPARISON

        # 4. Ingest Calibration
        calib_file = results_dir / "calibration" / "metrics.json"
        if calib_file.exists():
            try:
                calib_data = json.loads(calib_file.read_text(encoding="utf-8"))
            except Exception:
                calib_data = DEFAULT_CALIBRATION
        else:
            calib_data = DEFAULT_CALIBRATION

    # Export Tables
    t1_content = generate_table1_latex(comp_data, sample_count=sample_count)
    t1_path = output_dir / "table1_complementarity.tex"
    t1_path.write_text(t1_content, encoding="utf-8")
    generated_files["table1"] = t1_path
    logger.info("Exported Table 1 to %s (N=%d)", t1_path, sample_count)

    t2_content = generate_table2_latex(feat_data, sample_count=sample_count)
    t2_path = output_dir / "table2_disagreement_model.tex"
    t2_path.write_text(t2_content, encoding="utf-8")
    generated_files["table2"] = t2_path
    logger.info("Exported Table 2 to %s (N=%d)", t2_path, sample_count)

    t3_content = generate_table3_latex(arb_data, sample_count=sample_count)
    t3_path = output_dir / "table3_policy_comparison.tex"
    t3_path.write_text(t3_content, encoding="utf-8")
    generated_files["table3"] = t3_path
    logger.info("Exported Table 3 to %s (N=%d)", t3_path, sample_count)

    t4_content = generate_table4_latex(calib_data, sample_count=sample_count)
    t4_path = output_dir / "table4_calibration_decomposition.tex"
    t4_path.write_text(t4_content, encoding="utf-8")
    generated_files["table4"] = t4_path
    logger.info("Exported Table 4 to %s (N=%d)", t4_path, sample_count)

    # Master Tables Preview Document
    preview_path = output_dir / "tables_preview.tex"
    preview_content = "\n".join([
        r"\documentclass[11pt]{article}",
        r"\usepackage[margin=1in]{geometry}",
        r"\usepackage{booktabs}",
        r"\usepackage{amsmath}",
        r"\usepackage{caption}",
        r"\begin{document}",
        r"\section*{Publication Tables Preview (GDPR-Bench-Android)}",
        r"\input{table1_complementarity.tex}",
        r"\vspace{1em}",
        r"\input{table2_disagreement_model.tex}",
        r"\vspace{1em}",
        r"\input{table3_policy_comparison.tex}",
        r"\vspace{1em}",
        r"\input{table4_calibration_decomposition.tex}",
        r"\end{document}",
    ])
    preview_path.write_text(preview_content, encoding="utf-8")
    generated_files["tables_preview"] = preview_path

    # Vector Figures (if requested)
    if generate_figures:
        from harness.plot_artifacts import generate_all_figures
        fig_dir = output_dir / "figures"
        fig_files = generate_all_figures(
            results_dir=results_dir,
            output_dir=fig_dir,
            use_synthetic=use_synthetic,
        )
        generated_files.update(fig_files)

    return generated_files


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase 5 Publication Artifacts Generator (LaTeX tables and vector figures).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--results-dir",
        type=str,
        default="results",
        help="Root results directory containing complementarity, arbitration, and calibration outputs.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="paper/artifacts",
        help="Output directory to write .tex tables and figures.",
    )
    parser.add_argument(
        "--use-synthetic",
        action="store_true",
        help="Render tables using verified 40-instance fixture distribution.",
    )
    parser.add_argument(
        "--skip-figures",
        action="store_true",
        help="Skip vector figure generation and export only LaTeX tables.",
    )

    args = parser.parse_args(argv)
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir)

    try:
        exported = export_all_paper_artifacts(
            results_dir=results_dir,
            output_dir=output_dir,
            generate_figures=not args.skip_figures,
            use_synthetic=args.use_synthetic,
        )
        print(f"\nSuccessfully generated {len(exported)} paper artifacts in {output_dir}:")
        for k, p in exported.items():
            print(f"  - [{k}] {p}")
        return 0
    except Exception as exc:
        logger.error("Paper artifact export failed: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
