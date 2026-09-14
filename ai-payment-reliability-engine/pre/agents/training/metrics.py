"""pre/agents/training/metrics.py — Calibration and classification metrics.

Shared by the triage training pipelines. Pure functions over numpy arrays;
no model or dataset coupling.

Confidence-based metrics (ECE, reliability curve, precision/recall vs tau)
take:
    confidences: predicted probability assigned to the predicted class, (N,)
    correct:     1.0 if that top-1 prediction matched the label, else 0.0, (N,)

multiclass_brier takes the full (N, K) probability matrix and the true labels.
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import f1_score


def macro_f1(y_true, y_pred) -> float:
    """Unweighted mean of per-class F1 (classes with no support score 0)."""
    return float(f1_score(y_true, y_pred, average="macro", zero_division=0))


def _bin_edges(n_bins: int) -> np.ndarray:
    return np.linspace(0.0, 1.0, n_bins + 1)


def _bin_mask(confidences: np.ndarray, lo: float, hi: float, is_last: bool) -> np.ndarray:
    # (lo, hi] bins; the final bin also includes exactly 1.0
    if is_last:
        return (confidences > lo) & (confidences <= hi + 1e-12)
    return (confidences > lo) & (confidences <= hi)


def expected_calibration_error(confidences, correct, n_bins: int = 10) -> float:
    """ECE = sum_b (n_b / N) * |acc_b - conf_b| over equal-width confidence bins."""
    confidences = np.asarray(confidences, dtype=float)
    correct = np.asarray(correct, dtype=float)
    n = len(confidences)
    if n == 0:
        return 0.0

    edges = _bin_edges(n_bins)
    ece = 0.0
    for i, (lo, hi) in enumerate(zip(edges[:-1], edges[1:])):
        mask = _bin_mask(confidences, lo, hi, is_last=(i == n_bins - 1))
        if not mask.any():
            continue
        ece += mask.sum() / n * abs(correct[mask].mean() - confidences[mask].mean())
    return float(ece)


def reliability_curve(confidences, correct, n_bins: int = 10):
    """Return (bin_confidence, bin_accuracy, bin_count) for non-empty bins."""
    confidences = np.asarray(confidences, dtype=float)
    correct = np.asarray(correct, dtype=float)

    edges = _bin_edges(n_bins)
    conf, acc, cnt = [], [], []
    for i, (lo, hi) in enumerate(zip(edges[:-1], edges[1:])):
        mask = _bin_mask(confidences, lo, hi, is_last=(i == n_bins - 1))
        if not mask.any():
            continue
        conf.append(float(confidences[mask].mean()))
        acc.append(float(correct[mask].mean()))
        cnt.append(int(mask.sum()))
    return np.array(conf), np.array(acc), np.array(cnt)


def multiclass_brier(probs, y_true, classes) -> float:
    """Mean over samples of sum_k (p_k - onehot_k)^2. Range [0, 2]; 0 is perfect.

    `probs` columns must align to `classes`. Labels not in `classes` contribute
    an all-zero one-hot row (counts fully against the model).
    """
    probs = np.asarray(probs, dtype=float)
    classes = list(classes)
    col = {c: i for i, c in enumerate(classes)}

    onehot = np.zeros_like(probs)
    for r, label in enumerate(y_true):
        if label in col:
            onehot[r, col[label]] = 1.0
    return float(np.mean(np.sum((probs - onehot) ** 2, axis=1)))


def precision_recall_vs_tau(confidences, correct, taus):
    """For each tau return (tau, precision, recall, abstain_rate).

    precision = accuracy among predictions kept (confidence >= tau)
    recall    = kept-and-correct / N   (credit only for confident hits)
    abstain   = fraction of N dropped
    """
    confidences = np.asarray(confidences, dtype=float)
    correct = np.asarray(correct, dtype=float)
    n = len(confidences)

    rows = []
    for tau in taus:
        keep = confidences >= tau
        k = int(keep.sum())
        if k == 0:
            rows.append((float(tau), 0.0, 0.0, 1.0))
            continue
        rows.append((
            float(tau),
            float(correct[keep].mean()),
            float(correct[keep].sum() / n),
            float(1.0 - k / n),
        ))
    return rows
