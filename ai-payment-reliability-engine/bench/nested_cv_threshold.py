#!/usr/bin/env python3
"""bench/nested_cv_threshold.py — Task 1.2: out-of-sample threshold selection
via nested cross-validation, replacing the in-sample-calibrated tau that
tools/train_triage_model.py selects on the validation split it was itself
calibrated on (same-data leak: the isotonic calibrator and the tau sweep
both see the validation set).

Reuses tools/train_triage_model.py's load_rcaeval / protocol_split / FEATURE_NAMES
/ precision_recall_vs_tau / pick_tau directly, so this script's dev/test/frozen
case membership is byte-identical to the deployed model's (same RANDOM_SEED=42
split), without re-implementing any of that logic.

Steps (see PLAN v3.2 section 1.2):
  1. Pool train+val (204+68=272) into a dev pool; reserve test (51) and frozen (17).
  2. Outer 5-fold stratified CV over the dev pool. Print per-fold class counts
     before fitting anything; confirm every fold has >=2 socket cases.
  3. Per outer fold: fit on inner folds, predict the held-out fold. Aggregate
     into one out-of-fold (OOF) prediction set spanning all 272 dev cases.
  4. Fit the deployment isotonic calibrator once on the aggregated OOF pairs.
  5. Sweep tau for 0.95 target precision on CALIBRATED OOF probabilities
     (not raw scores — isotonic is monotone, not affine, so the two scales
     select different tau values).
  6. Diagnostic only: refit an inner calibrator per outer fold, sweep tau
     per fold, report dispersion. Not the operating point.
  7. Fit the final classifier on the full 272-case dev pool, apply the OOF
     calibrator (step 4) and OOF-selected tau (step 5) ONCE to the untouched
     51-case test split. Report precision/recall/coverage with raw counts.
  8. Wilson 95% CI on any rate computed from n < 10, since a binomial rate
     from a handful of trials is not a meaningful point estimate.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.train_triage_model import (  # noqa: E402
    FEATURE_NAMES,
    RANDOM_SEED,
    load_rcaeval,
    pick_tau,
    protocol_split,
)
from pre.agents.training.metrics import precision_recall_vs_tau  # noqa: E402

TARGET_PRECISION = 0.95
OUTER_K = 5
SOCKET_MIN_PER_FOLD = 2
SMALL_N_THRESHOLD = 10


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial rate k/n."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return max(0.0, center - margin), min(1.0, center + margin)


def fit_lr(X: np.ndarray, y: np.ndarray):
    scaler = StandardScaler().fit(X)
    lr = LogisticRegression(
        max_iter=2000, random_state=RANDOM_SEED, solver="lbfgs", class_weight="balanced"
    )
    lr.fit(scaler.transform(X), y)
    return scaler, lr


def raw_conf_correct(scaler, lr, X: np.ndarray, y: np.ndarray):
    probs = lr.predict_proba(scaler.transform(X))
    preds = lr.classes_[probs.argmax(axis=1)]
    raw_conf = probs.max(axis=1)
    correct = (preds == y).astype(float)
    return raw_conf, correct


def class_counts(labels: np.ndarray) -> dict:
    vals, counts = np.unique(labels, return_counts=True)
    return dict(zip(vals.tolist(), counts.tolist()))


def bar(title: str) -> None:
    print("=" * 90)
    print(title)
    print("=" * 90)


def main() -> None:
    bar("LOAD DATA + REPRODUCE ORIGINAL SPLIT (unchanged from tools/train_triage_model.py)")
    df = load_rcaeval("data/rcaeval", Path(".feature_cache"))
    train_i, val_i, test_i, frozen_i = protocol_split(df)
    lab = df["label"].values
    X_all = df[FEATURE_NAMES].values
    print(f"original split: train={len(train_i)} val={len(val_i)} "
          f"test={len(test_i)} frozen={len(frozen_i)}")

    bar("STEP 1: PARTITION BUDGETING")
    dev_i = np.concatenate([train_i, val_i])
    print(f"development pool (train+val, pooled): {len(dev_i)}  (= {len(train_i)} + {len(val_i)})")
    print(f"reserved test split (untouched until Step 7): {len(test_i)}")
    print(f"reserved frozen cases (never touched, this script or any prior one): {len(frozen_i)}")
    all_sets = [set(dev_i.tolist()), set(test_i.tolist()), set(frozen_i.tolist())]
    disjoint = all(len(a & b) == 0 for i, a in enumerate(all_sets) for b in all_sets[i + 1:])
    print(f"PARTITION DISJOINTNESS: {'verified' if disjoint else 'FAILED'} "
          f"(no case appears in more than one of dev/test/frozen)")
    if not disjoint:
        raise RuntimeError("partition overlap detected — aborting")
    print(f"dev pool class counts: {class_counts(lab[dev_i])}")

    bar(f"STEP 2: PRE-FLIGHT CHECK — per-outer-fold class counts (k={OUTER_K}), before any metric is computed")
    y_dev = lab[dev_i]

    def try_kfold(k: int):
        skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=RANDOM_SEED)
        folds = list(skf.split(dev_i, y_dev))
        classes = sorted(set(y_dev.tolist()))
        rows = []
        min_socket = None
        for fold_id, (_, held_local) in enumerate(folds):
            held_labels = y_dev[held_local]
            counts = class_counts(held_labels)
            rows.append((fold_id, len(held_local), counts))
            if "socket" in counts:
                sc = counts["socket"]
            else:
                sc = 0
            min_socket = sc if min_socket is None else min(min_socket, sc)
        return folds, classes, rows, min_socket

    folds, classes, rows, min_socket = try_kfold(OUTER_K)
    header = "fold n_held_out " + " ".join(f"{c:>9s}" for c in classes)
    print(header)
    for fold_id, n_held, counts in rows:
        line = f"{fold_id:>4d} {n_held:>10d} " + " ".join(f"{counts.get(c, 0):>9d}" for c in classes)
        print(line)
    print(f"\nminimum socket count in any held-out fold at k={OUTER_K}: {min_socket}")

    final_k = OUTER_K
    if min_socket < SOCKET_MIN_PER_FOLD:
        print(f"DECISION: k={OUTER_K} rejected — a held-out fold has < {SOCKET_MIN_PER_FOLD} socket cases. "
              f"Falling back to k=3.")
        final_k = 3
        folds, classes, rows, min_socket = try_kfold(final_k)
        header = "fold n_held_out " + " ".join(f"{c:>9s}" for c in classes)
        print(header)
        for fold_id, n_held, counts in rows:
            line = f"{fold_id:>4d} {n_held:>10d} " + " ".join(f"{counts.get(c, 0):>9d}" for c in classes)
            print(line)
        print(f"minimum socket count in any held-out fold at k={final_k}: {min_socket}")
    else:
        print(f"DECISION: k={OUTER_K} retained — every outer fold has >= {SOCKET_MIN_PER_FOLD} socket cases.")
    print(f"\nFINAL K = {final_k}")

    bar(f"STEP 3: OUT-OF-FOLD PREDICTION (outer CV, k={final_k})")
    oof_raw_conf = np.zeros(len(dev_i))
    oof_correct = np.zeros(len(dev_i))
    fold_of_case = np.full(len(dev_i), -1, dtype=int)
    for fold_id, (inner_local, held_local) in enumerate(folds):
        Xtr, ytr = X_all[dev_i[inner_local]], y_dev[inner_local]
        Xheld, yheld = X_all[dev_i[held_local]], y_dev[held_local]
        scaler, lr = fit_lr(Xtr, ytr)
        raw_conf, correct = raw_conf_correct(scaler, lr, Xheld, yheld)
        oof_raw_conf[held_local] = raw_conf
        oof_correct[held_local] = correct
        fold_of_case[held_local] = fold_id
        print(f"fold {fold_id}: n_train={len(inner_local)} n_held_out={len(held_local):>3d}  "
              f"accuracy={correct.mean():.4f}")
    assert (fold_of_case >= 0).all(), "every dev case must get exactly one OOF prediction"
    print(f"\nOOF coverage: {len(dev_i)}/{len(dev_i)} dev cases have exactly one out-of-fold prediction "
          f"(each from a model that never saw that case during training)")

    bar("STEP 4: DEPLOYMENT ISOTONIC CALIBRATOR — fit once on all aggregated OOF points")
    isotonic_oof = IsotonicRegression(out_of_bounds="clip")
    isotonic_oof.fit(oof_raw_conf, oof_correct)
    print(f"isotonic calibrator fit on {len(dev_i)} aggregated OOF (raw_confidence, correct) pairs")
    print(f"raw OOF confidence range: [{oof_raw_conf.min():.4f}, {oof_raw_conf.max():.4f}]")

    bar("STEP 5: THRESHOLD SWEEP ON CALIBRATED OOF PROBABILITIES (not raw scores)")
    oof_calibrated = isotonic_oof.predict(oof_raw_conf)
    print(f"calibrated OOF confidence range: [{oof_calibrated.min():.4f}, {oof_calibrated.max():.4f}]")
    print("(isotonic is monotone, not affine — the tau selected on the calibrated scale is "
          "not the same threshold value a raw-scale sweep would select)")
    taus = np.linspace(0.1, 0.99, 90)
    pr_rows = precision_recall_vs_tau(oof_calibrated, oof_correct, taus)
    tau_star, oof_precision, oof_recall, oof_abstain = pick_tau(pr_rows, TARGET_PRECISION)
    print(f"\nFINAL OPERATING POINT (selected on OOF calibrated scale, target precision {TARGET_PRECISION}):")
    print(f"  tau*      = {tau_star:.4f}")
    print(f"  precision = {oof_precision:.4f}  (OOF, out-of-sample estimate)")
    print(f"  recall    = {oof_recall:.4f}")
    print(f"  abstain   = {oof_abstain:.4f}  (coverage = {1 - oof_abstain:.4f})")

    bar("STEP 6: STABILITY REPORTING — per-fold INNER calibrator + tau sweep (diagnostic only)")
    fold_taus = []
    for fold_id, (_, held_local) in enumerate(folds):
        mask = fold_of_case == fold_id
        fconf, fcorrect = oof_raw_conf[mask], oof_correct[mask]
        inner_iso = IsotonicRegression(out_of_bounds="clip")
        inner_iso.fit(fconf, fcorrect)
        fcal = inner_iso.predict(fconf)
        fpr_rows = precision_recall_vs_tau(fcal, fcorrect, taus)
        ftau, fprec, frec, fabst = pick_tau(fpr_rows, TARGET_PRECISION)
        fold_taus.append(ftau)
        print(f"fold {fold_id}: n={mask.sum():>3d}  inner-calibrator tau={ftau:.4f}  "
              f"precision={fprec:.4f}  recall={frec:.4f}  abstain={fabst:.4f}")
    fold_taus = np.array(fold_taus)
    print(f"\nTHRESHOLD DISPERSION ACROSS {final_k} FOLDS (diagnostic; this is NOT the operating point):")
    print(f"  values : {fold_taus.tolist()}")
    print(f"  min={fold_taus.min():.4f}  max={fold_taus.max():.4f}  range={fold_taus.max() - fold_taus.min():.4f}  "
          f"mean={fold_taus.mean():.4f}  std={fold_taus.std():.4f}")
    print(f"  OPERATING POINT (Step 5) tau*={tau_star:.4f} for comparison")

    bar("STEP 7: TEST EVALUATION (test split touched for the first and only time below)")
    final_scaler, final_lr = fit_lr(X_all[dev_i], y_dev)
    print("final deployed classifier fit on the FULL 272-case dev pool (not any single outer-fold model)")
    test_raw_conf, test_correct = raw_conf_correct(final_scaler, final_lr, X_all[test_i], lab[test_i])
    test_calibrated = isotonic_oof.predict(test_raw_conf)
    n_test = len(test_i)
    print(f"test set: n={n_test}, accuracy={test_correct.mean():.4f}")
    print(f"applying tau*={tau_star:.4f} (from Step 5, OOF-selected) to isotonic_oof-calibrated test "
          f"confidences (isotonic_oof from Step 4, fit only on dev-pool OOF data):")
    keep = test_calibrated >= tau_star
    n_kept = int(keep.sum())
    n_correct_kept = int(test_correct[keep].sum())
    test_precision = n_correct_kept / n_kept if n_kept else 0.0
    test_recall = n_correct_kept / n_test
    test_coverage = n_kept / n_test
    print(f"  kept (confidence >= tau*): numerator={n_correct_kept} denominator={n_kept}  "
          f"(of {n_test} total test cases)")
    print(f"  OUT-OF-SAMPLE precision = {n_correct_kept}/{n_kept if n_kept else 1} = {test_precision:.4f}")
    print(f"  OUT-OF-SAMPLE recall    = {n_correct_kept}/{n_test} = {test_recall:.4f}")
    print(f"  OUT-OF-SAMPLE coverage  = {n_kept}/{n_test} = {test_coverage:.4f}  (abstain={1 - test_coverage:.4f})")

    bar("STEP 8: WILSON 95% CI FOR SMALL-n RATES")
    if n_kept == 0:
        print(f"  n_kept = 0 — no predictions cleared tau*={tau_star:.4f} on the test split; "
              f"precision is undefined at this operating point (0/0).")
    elif n_kept < SMALL_N_THRESHOLD:
        lo, hi = wilson_ci(n_correct_kept, n_kept)
        print(f"  test-split kept count (denominator) = {n_kept} < {SMALL_N_THRESHOLD} -- "
              f"the precision point estimate is not statistically meaningful at this n.")
        print(f"  Wilson 95% CI for precision = {n_correct_kept}/{n_kept} = {test_precision:.4f}: "
              f"[{lo:.4f}, {hi:.4f}]")
        span = hi - lo
        print(f"  CI width = {span:.4f} ({span * 100:.1f}% of the full [0,1] range) -- "
              f"treat the point estimate as uninformative at this sample size, not as a stable rate.")
    else:
        print(f"  n_kept = {n_kept} >= {SMALL_N_THRESHOLD} — precision estimate treated as meaningful "
              f"at this sample size; Wilson CI not required by Step 8's threshold.")

    bar("DONE")


if __name__ == "__main__":
    main()
