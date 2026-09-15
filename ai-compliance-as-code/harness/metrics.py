"""
harness/metrics.py — Evaluation metrics for GDPR-Bench-Android (Section 6.1.4).

Task 1: Multi-granularity localization scored by Accuracy@k (k in 1..5) at file, module, and line level.
Task 2: Snippet-level multi-label classification scored by exact-match accuracy and macro P/R/F1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Collection, Dict, Iterable, List, Optional, Sequence, Set, Union


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
