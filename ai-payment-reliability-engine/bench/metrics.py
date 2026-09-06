"""
bench/metrics.py — Evaluation metrics for the AI Payment Reliability
Engine benchmark harness (see PROTOCOL.md for the research questions
these serve, and AC@k / Avg@5 definitions matched to RCAEval's own
Evaluator for B2 baseline parity).

Implemented metrics:
    macro_f1                — unweighted mean of per-class F1 (classification)
    expected_calibration_error (ECE)  — confidence calibration
    brier_score              — proper scoring rule for probabilistic predictions
    accuracy_at_k (AC@k)     — RCAEval-compatible: fraction of cases where the
                               ground-truth answer is within the top-k ranks
    average_at_k (Avg@5)     — mean of AC@1..AC@k, matching RCAEval's
                               Evaluator.average(k) exactly
    faithfulness             — fraction of an explanation's cited evidence
                               keys that are actually present in the case's
                               observed signals (a simple groundedness check,
                               not a claim of causal correctness)
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Sequence


# ---------------------------------------------------------------------------
# Classification metrics
# ---------------------------------------------------------------------------

def macro_f1(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    """Unweighted mean of per-class F1 score.

    Classes are the union of labels seen in y_true and y_pred. A class with
    zero true positives, false positives, and false negatives (never
    predicted, never true) is excluded from the mean, matching sklearn's
    `f1_score(average="macro")` behaviour of only averaging over classes
    that appear in y_true (labels with no support are skipped by default).
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"length mismatch: {len(y_true)} vs {len(y_pred)}")
    if not y_true:
        raise ValueError("y_true must not be empty")

    classes = sorted(set(y_true))
    f1_scores = []
    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        f1_scores.append(f1)

    return sum(f1_scores) / len(f1_scores)


def expected_calibration_error(
    confidences: Sequence[float],
    correct: Sequence[bool],
    n_bins: int = 10,
) -> float:
    """ECE: weighted average gap between confidence and accuracy across bins.

    Bins confidences into `n_bins` equal-width buckets over [0, 1]. For each
    non-empty bin, computes |mean_confidence - accuracy| and weights it by
    the bin's share of all predictions, per Guo et al. 2017.
    """
    if len(confidences) != len(correct):
        raise ValueError(f"length mismatch: {len(confidences)} vs {len(correct)}")
    if not confidences:
        raise ValueError("confidences must not be empty")

    bins: list[list[tuple[float, bool]]] = [[] for _ in range(n_bins)]
    for conf, is_correct in zip(confidences, correct):
        conf = min(max(conf, 0.0), 1.0)
        idx = min(int(conf * n_bins), n_bins - 1)
        bins[idx].append((conf, is_correct))

    total = len(confidences)
    ece = 0.0
    for bucket in bins:
        if not bucket:
            continue
        bucket_confidences = [c for c, _ in bucket]
        bucket_correct = [c for _, c in bucket]
        avg_confidence = sum(bucket_confidences) / len(bucket_confidences)
        accuracy = sum(bucket_correct) / len(bucket_correct)
        ece += (len(bucket) / total) * abs(avg_confidence - accuracy)

    return ece


def brier_score(confidences: Sequence[float], correct: Sequence[bool]) -> float:
    """Mean squared error between predicted confidence and outcome (0/1).

    Standard binary Brier score: mean((confidence - outcome)^2), lower is
    better, 0 is perfect, 1 is worst possible (fully confident and always wrong).
    """
    if len(confidences) != len(correct):
        raise ValueError(f"length mismatch: {len(confidences)} vs {len(correct)}")
    if not confidences:
        raise ValueError("confidences must not be empty")

    return sum(
        (conf - (1.0 if is_correct else 0.0)) ** 2
        for conf, is_correct in zip(confidences, correct)
    ) / len(confidences)


# ---------------------------------------------------------------------------
# Ranking metrics — RCAEval-compatible (for B2 parity, see PROTOCOL.md)
# ---------------------------------------------------------------------------

def accuracy_at_k(ranked_answers: Sequence[Sequence[Any]], k: int) -> float:
    """AC@k = mean over cases of 1[answer in ranks[:k]].

    `ranked_answers` is a sequence of (ranks, answer) pairs, where `ranks`
    is the method's ranked candidate list for that case (already sorted
    best-first) and `answer` is the ground-truth value to look for.
    Matches RCAEval's Evaluator.accuracy(k) exactly (see
    RCAEval/benchmark/evaluation.py): each case contributes 1 if the
    answer appears anywhere in the first k ranks, else 0; the metric is
    the mean of these 0/1 values.
    """
    if k < 1:
        raise ValueError("k must be >= 1")
    if not ranked_answers:
        raise ValueError("ranked_answers must not be empty")

    hits = 0
    for ranks, answer in ranked_answers:
        if answer in ranks[:k]:
            hits += 1
    return hits / len(ranked_answers)


def average_at_k(ranked_answers: Sequence[Sequence[Any]], k: int) -> float:
    """Avg@k = mean of AC@1 .. AC@k. Matches RCAEval's Evaluator.average(k)."""
    if k < 1:
        raise ValueError("k must be >= 1")
    return sum(accuracy_at_k(ranked_answers, i) for i in range(1, k + 1)) / k


# ---------------------------------------------------------------------------
# Faithfulness — groundedness of an explanation against observed evidence
# ---------------------------------------------------------------------------

def faithfulness(cited_evidence_keys: Sequence[str], available_evidence_keys: Sequence[str]) -> float:
    """Fraction of an explanation's cited evidence keys that are present in
    the case's actually-observed signal keys (e.g. metric/log/span
    identifiers).

    This is a groundedness proxy, not a causal-correctness check: a
    faithfulness of 1.0 means every citation refers to something the
    pipeline actually saw, not that the citations are the true root cause.
    Duplicate citations count once (checked against a set).
    """
    if not cited_evidence_keys:
        raise ValueError("cited_evidence_keys must not be empty")

    available = set(available_evidence_keys)
    cited = set(cited_evidence_keys)
    grounded = cited & available
    return len(grounded) / len(cited)
