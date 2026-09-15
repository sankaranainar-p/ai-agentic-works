"""
harness/metrics.py — Evaluation metrics for GDPR-Bench-Android (Section 6.1.4).

Task 1: Multi-granularity localization scored by Accuracy@k (k in 1..5) at file, module, and line level.
Task 2: Snippet-level multi-label classification scored by exact-match accuracy and macro P/R/F1.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Collection, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

import numpy as np


# ---------------------------------------------------------------------------
# Task 1: Multi-granularity Violation Localization Metrics
# ---------------------------------------------------------------------------

def compute_accuracy_at_k(ranks: Sequence[Optional[int]], k: int) -> float:
    """Compute Accuracy@k given a sequence of 1-based prediction ranks.

    Accuracy@k = (1 / N) * sum_{i=1}^N 1{r_i <= k and r_i >= 1}
    where r_i is the rank of the first correct GDPR article in the method's predictions.

    Args:
        ranks: Sequence of 1-based ranks (None represents no correct prediction / rank infinity).
        k: The rank threshold (e.g. 1..5).

    Returns:
        Accuracy score between 0.0 and 1.0. Returns 0.0 if ranks sequence is empty.
    """
    if not ranks or k < 1:
        return 0.0

    hits = sum(1 for r in ranks if r is not None and 1 <= r <= k)
    return hits / len(ranks)


def compute_accuracy_at_k_range(
    ranks: Sequence[Optional[int]],
    ks: Sequence[int] = (1, 2, 3, 4, 5),
) -> Dict[int, float]:
    """Compute Accuracy@k for all specified k values (default: 1..5)."""
    return {k: compute_accuracy_at_k(ranks, k) for k in ks}


@dataclass
class Task1Metrics:
    """Multi-granularity localization results across file, module, and line levels."""

    file_level: Dict[int, float]
    module_level: Dict[int, float]
    line_level: Dict[int, float]
    num_instances: int

    def to_dict(self) -> Dict[str, Union[Dict[int, float], int]]:
        return {
            "num_instances": self.num_instances,
            "file_level": self.file_level,
            "module_level": self.module_level,
            "line_level": self.line_level,
        }


def compute_task1_metrics(
    file_ranks: Sequence[Optional[int]],
    module_ranks: Sequence[Optional[int]],
    line_ranks: Sequence[Optional[int]],
    ks: Sequence[int] = (1, 2, 3, 4, 5),
) -> Task1Metrics:
    """Compute Task 1 multi-granularity Accuracy@k across all three scopes."""
    num_instances = max(len(file_ranks), len(module_ranks), len(line_ranks))
    return Task1Metrics(
        file_level=compute_accuracy_at_k_range(file_ranks, ks),
        module_level=compute_accuracy_at_k_range(module_ranks, ks),
        line_level=compute_accuracy_at_k_range(line_ranks, ks),
        num_instances=num_instances,
    )


# ---------------------------------------------------------------------------
# Task 2: Snippet-level Multi-label Classification Metrics
# ---------------------------------------------------------------------------

GDPR_BENCHMARK_ARTICLES: List[int] = sorted([
    5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 25, 28, 30, 32, 33, 34, 44, 49
])


@dataclass
class MultiLabelMetrics:
    """Task 2 metrics: Exact-match accuracy, Macro-Precision, Macro-Recall, and Partitioned Macro-F1."""

    exact_match_accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    num_instances: int
    num_classes: int
    macro_f1_global: float = 0.0
    macro_f1_in_scope: float = 0.0
    macro_precision_global: float = 0.0
    macro_precision_in_scope: float = 0.0
    macro_recall_global: float = 0.0
    macro_recall_in_scope: float = 0.0
    classes: List[int] = field(default_factory=list)
    in_scope_classes: List[int] = field(default_factory=list)
    per_class: Dict[int, Dict[str, float]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "num_instances": self.num_instances,
            "num_classes": self.num_classes,
            "exact_match_accuracy": round(self.exact_match_accuracy, 4),
            "macro_precision": round(self.macro_precision, 4),
            "macro_recall": round(self.macro_recall, 4),
            "macro_f1": round(self.macro_f1, 4),
            "macro_f1_global": round(self.macro_f1_global, 4),
            "macro_f1_in_scope": round(self.macro_f1_in_scope, 4),
            "macro_precision_global": round(self.macro_precision_global, 4),
            "macro_precision_in_scope": round(self.macro_precision_in_scope, 4),
            "macro_recall_global": round(self.macro_recall_global, 4),
            "macro_recall_in_scope": round(self.macro_recall_in_scope, 4),
            "classes": self.classes,
            "in_scope_classes": self.in_scope_classes,
            "per_class": self.per_class,
        }


def compute_multilabel_metrics(
    predictions: Sequence[Collection[int]],
    ground_truths: Sequence[Collection[int]],
    classes: Optional[Iterable[int]] = None,
) -> MultiLabelMetrics:
    """Compute exact-match accuracy, macro-precision, macro-recall, and macro-f1.

    Reports partitioned metrics:
      - macro_f1_global: Macro-average across all 23 GDPR benchmark articles.
      - macro_f1_in_scope: Macro-average only across articles present in ground truth.

    Args:
        predictions: Sequence of predicted article collections per instance.
        ground_truths: Sequence of ground-truth article collections per instance.
        classes: Optional fixed universe of class integer labels (C). If None, defaults
                 to all 23 GDPR-Bench-Android articles.

    Returns:
        MultiLabelMetrics instance.
    """
    n = len(ground_truths)
    if n == 0:
        return MultiLabelMetrics(
            exact_match_accuracy=0.0,
            macro_precision=0.0,
            macro_recall=0.0,
            macro_f1=0.0,
            num_instances=0,
            num_classes=0,
        )

    # Normalize sets
    pred_sets = [set(p) for p in predictions]
    gt_sets = [set(g) for g in ground_truths]

    # Exact-match accuracy: 1/N * sum( 1{pred == gt} )
    exact_matches = sum(1 for p, g in zip(pred_sets, gt_sets) if p == g)
    exact_match_acc = exact_matches / n

    # Partition classes: in-scope vs global
    in_scope_classes = sorted({c for g in gt_sets for c in g})
    if classes is not None:
        global_classes = sorted(set(classes))
    else:
        global_classes = list(GDPR_BENCHMARK_ARTICLES)

    c_set = sorted(set(global_classes) | set(in_scope_classes) | {c for p in pred_sets for c in p})

    if not c_set:
        return MultiLabelMetrics(
            exact_match_accuracy=exact_match_acc,
            macro_precision=0.0,
            macro_recall=0.0,
            macro_f1=0.0,
            num_instances=n,
            num_classes=0,
        )

    per_class_dict: Dict[int, Dict[str, float]] = {}
    raw_p: Dict[int, float] = {}
    raw_r: Dict[int, float] = {}
    raw_f1: Dict[int, float] = {}

    for c in c_set:
        tp = sum(1 for p, g in zip(pred_sets, gt_sets) if c in p and c in g)
        fp = sum(1 for p, g in zip(pred_sets, gt_sets) if c in p and c not in g)
        fn = sum(1 for p, g in zip(pred_sets, gt_sets) if c not in p and c in g)

        p_c = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r_c = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_c = (2 * p_c * r_c / (p_c + r_c)) if (p_c + r_c) > 0 else 0.0

        raw_p[c] = p_c
        raw_r[c] = r_c
        raw_f1[c] = f1_c

        per_class_dict[c] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(p_c, 4),
            "recall": round(r_c, 4),
            "f1": round(f1_c, 4),
        }

    # Partitioned macro averages
    if in_scope_classes:
        macro_f1_in_scope = sum(raw_f1[c] for c in in_scope_classes) / len(in_scope_classes)
        macro_precision_in_scope = sum(raw_p[c] for c in in_scope_classes) / len(in_scope_classes)
        macro_recall_in_scope = sum(raw_r[c] for c in in_scope_classes) / len(in_scope_classes)
    else:
        macro_f1_in_scope = 0.0
        macro_precision_in_scope = 0.0
        macro_recall_in_scope = 0.0

    if global_classes:
        macro_f1_global = sum(raw_f1[c] for c in global_classes) / len(global_classes)
        macro_precision_global = sum(raw_p[c] for c in global_classes) / len(global_classes)
        macro_recall_global = sum(raw_r[c] for c in global_classes) / len(global_classes)
    else:
        macro_f1_global = 0.0
        macro_precision_global = 0.0
        macro_recall_global = 0.0

    macro_f1 = macro_f1_global if classes is None else (sum(raw_f1[c] for c in c_set) / len(c_set))
    macro_precision = macro_precision_global if classes is None else (sum(raw_p[c] for c in c_set) / len(c_set))
    macro_recall = macro_recall_global if classes is None else (sum(raw_r[c] for c in c_set) / len(c_set))

    return MultiLabelMetrics(
        exact_match_accuracy=exact_match_acc,
        macro_precision=macro_precision,
        macro_recall=macro_recall,
        macro_f1=macro_f1,
        macro_f1_global=macro_f1_global,
        macro_f1_in_scope=macro_f1_in_scope,
        macro_precision_global=macro_precision_global,
        macro_precision_in_scope=macro_precision_in_scope,
        macro_recall_global=macro_recall_global,
        macro_recall_in_scope=macro_recall_in_scope,
        num_instances=n,
        num_classes=len(global_classes),
        classes=global_classes,
        in_scope_classes=in_scope_classes,
        per_class=per_class_dict,
    )


# ---------------------------------------------------------------------------
# Section 3: Confidence Calibration & Reliability Analysis (Murphy 1973)
# ---------------------------------------------------------------------------

@dataclass
class CalibrationBin:
    """Evaluation statistics for a single confidence bin."""

    bin_idx: int
    count: int
    prop: float
    mean_confidence: float
    empirical_accuracy: float
    calibration_error: float
    confidence_lower: float = 0.0
    confidence_upper: float = 1.0
    margin_of_error: float = 0.0
    moe_95: float = 0.0
    wald_moe: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bin": self.bin_idx + 1,
            "bin_idx": self.bin_idx,
            "count": self.count,
            "prop": round(self.prop, 4),
            "mean_confidence": round(self.mean_confidence, 4),
            "empirical_accuracy": round(self.empirical_accuracy, 4),
            "calibration_error": round(self.calibration_error, 4),
            "margin_of_error": round(self.margin_of_error, 4),
            "moe_95": round(self.moe_95 if self.moe_95 > 0 else self.margin_of_error, 4),
            "wald_moe": round(self.wald_moe, 4),
            "confidence_lower": round(self.confidence_lower, 4),
            "confidence_upper": round(self.confidence_upper, 4),
        }


@dataclass
class CalibrationReport:
    """Comprehensive confidence calibration and Murphy (1973) decomposition results."""

    strategy: str
    num_bins: int
    num_samples: int
    ece: float
    mce: float
    brier_score: float
    reliability: float
    resolution: float
    uncertainty: float
    base_rate: float
    brier_score_raw: float = 0.0
    bins: List[CalibrationBin] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy,
            "num_bins": self.num_bins,
            "num_samples": self.num_samples,
            "ece": round(self.ece, 8),
            "mce": round(self.mce, 8),
            "brier_score": round(self.brier_score, 10),
            "brier_score_raw": round(self.brier_score_raw, 10),
            "reliability": round(self.reliability, 10),
            "resolution": round(self.resolution, 10),
            "uncertainty": round(self.uncertainty, 10),
            "base_rate": round(self.base_rate, 8),
            "murphy_identity_error": round(
                abs(self.brier_score - (self.reliability - self.resolution + self.uncertainty)), 12
            ),
            "bins": [b.to_dict() for b in self.bins],
        }

    def format_ascii_table(self) -> str:
        """Format an ASCII reliability table displaying Bin, Count, Mean Conf, Empirical Acc, and ±95% MoE."""
        header = "+-----+-------+-----------+---------------+----------+"
        title  = "| Bin | Count | Mean Conf | Empirical Acc | ±95% MoE |"
        lines = [header, title, header]
        for b in self.bins:
            b_num = b.bin_idx + 1
            moe_str = f"±{b.margin_of_error:.4f}"
            lines.append(
                f"| {b_num:3d} | {b.count:5d} | {b.mean_confidence:9.4f} | {b.empirical_accuracy:13.4f} | {moe_str:>8s} |"
            )
        lines.append(header)
        return "\n".join(lines)


def compute_calibration_analysis(
    confidences: Sequence[float],
    labels: Sequence[Union[int, bool, float]],
    num_bins: int = 5,
    strategy: str = "quantile",
) -> CalibrationReport:
    """Compute calibration metrics, ECE, MCE, Wilson margins of error, and Murphy decomposition.

    Supports:
      - strategy='quantile': Equal-frequency binning with ordinal rank-based tie handling
      - strategy='uniform': Equal-width binning across [0.0, 1.0]

    Murphy's Decomposition (1973):
      BS = REL - RES + UNC
      where:
        REL = sum_{m=1}^M (n_m / N) * (bar{p}_m - bar{y}_m)^2
        RES = sum_{m=1}^M (n_m / N) * (bar{y}_m - bar{y})^2
        UNC = bar{y} * (1 - bar{y})

    Args:
        confidences: Sequence of confidence values in [0.0, 1.0].
        labels: Sequence of binary ground truth outcomes in {0, 1}.
        num_bins: Number of calibration bins (default: 5).
        strategy: 'quantile' (default) or 'uniform'.

    Returns:
        CalibrationReport instance.

    Raises:
        ValueError: If inputs are empty, length mismatch, or num_bins < 1.
    """
    if len(confidences) == 0 or len(labels) == 0:
        raise ValueError("confidences and labels must not be empty")
    if len(confidences) != len(labels):
        raise ValueError(
            f"confidences length ({len(confidences)}) must match labels length ({len(labels)})"
        )
    if num_bins < 1:
        raise ValueError(f"num_bins must be a positive integer >= 1, got {num_bins}")
    if strategy not in ("quantile", "uniform"):
        raise ValueError(
            f"strategy must be 'quantile' or 'uniform', got {strategy!r}"
        )

    confs = np.asarray(confidences, dtype=float)
    labs = np.asarray(labels, dtype=float)
    N = len(confs)

    # Sanitize bounds
    confs = np.clip(confs, 0.0, 1.0)
    labs = (labs > 0.5).astype(float)

    # Base rate & uncertainty
    y_bar = float(np.mean(labs))
    unc = float(y_bar * (1.0 - y_bar))

    # Bin assignment
    bin_bounds: List[Tuple[float, float]] = []

    if strategy == "uniform":
        bin_width = 1.0 / num_bins
        bin_idx = np.minimum((confs * num_bins).astype(int), num_bins - 1)
        bin_idx = np.maximum(bin_idx, 0)
        for m in range(num_bins):
            bin_bounds.append((m * bin_width, (m + 1) * bin_width))

    elif strategy == "quantile":
        # Handle edge case where all confidences are identical
        if np.isclose(float(np.max(confs)), float(np.min(confs))):
            bin_idx = np.zeros(N, dtype=int)
            val = float(confs[0])
            for m in range(num_bins):
                bin_bounds.append((val, val))
        else:
            order = np.argsort(confs, kind="stable")
            bin_idx = np.empty(N, dtype=int)
            bin_idx[order] = np.clip((np.arange(N) * num_bins) // N, 0, num_bins - 1)
            for m in range(num_bins):
                m_mask = (bin_idx == m)
                if np.any(m_mask):
                    bin_bounds.append((float(np.min(confs[m_mask])), float(np.max(confs[m_mask]))))
                else:
                    bin_bounds.append((0.0, 1.0))

    # Compute per-bin metrics
    bins: List[CalibrationBin] = []
    rel = 0.0
    res = 0.0
    ece = 0.0
    abs_errors: List[float] = []
    z_95 = 1.959963984540054

    for m in range(num_bins):
        mask = (bin_idx == m)
        nm = int(np.sum(mask))
        prop = nm / N
        b_lower, b_upper = bin_bounds[m]

        if nm > 0:
            pm = float(np.mean(confs[mask]))
            ym = float(np.mean(labs[mask]))
            cal_err = abs(pm - ym)
            abs_errors.append(cal_err)

            # Murphy terms
            rel += prop * ((pm - ym) ** 2)
            res += prop * ((ym - y_bar) ** 2)
            ece += prop * cal_err

            # Wilson 95% margin of error
            denom = 1.0 + (z_95 * z_95) / nm
            term = (ym * (1.0 - ym)) / nm + (z_95 * z_95) / (4.0 * nm * nm)
            wilson_moe = float((z_95 / denom) * math.sqrt(term))

            # Wald margin of error
            wald_moe = float(z_95 * math.sqrt(max(ym * (1.0 - ym), 0.0) / nm))
        else:
            pm = 0.0
            ym = 0.0
            cal_err = 0.0
            wilson_moe = 0.0
            wald_moe = 0.0

        bins.append(
            CalibrationBin(
                bin_idx=m,
                count=nm,
                prop=prop,
                mean_confidence=pm,
                empirical_accuracy=ym,
                calibration_error=cal_err,
                margin_of_error=wilson_moe,
                moe_95=wilson_moe,
                confidence_lower=b_lower,
                confidence_upper=b_upper,
                wald_moe=wald_moe,
            )
        )

    mce = max(abs_errors) if abs_errors else 0.0
    # Murphy decomposition identity: BS = REL - RES + UNC
    brier_score = float(rel - res + unc)
    raw_brier = float(np.mean((confs - labs) ** 2))

    return CalibrationReport(
        strategy=strategy,
        num_bins=num_bins,
        num_samples=N,
        ece=float(ece),
        mce=float(mce),
        brier_score=brier_score,
        reliability=float(rel),
        resolution=float(res),
        uncertainty=float(unc),
        base_rate=float(y_bar),
        brier_score_raw=raw_brier,
        bins=bins,
    )
