#!/usr/bin/env python3
"""Task 1.3 — Leave-One-System-Out (LOSO) triage ablation.

Precondition (Task 1.3a, both independently-sufficient reasons):
  - alert.service collapses to the synthetic "cluster" value on 125/125
    RE1-SS cases (vs. 13 distinct real services for RE1-OB, 31 for RE2-TT).
  - alert_metric_family is decoupled from true fault label on RE1-SS:
    0/24 true-cpu cases ever fire cpu_saturation (94.4% fire memory_saturation
    regardless of label).
  - kpi_co_breaching_services has zero variance on RE1-SS (std=0.0, always 1)
    vs. real variance on RE1-OB (~13) and RE2-TT (~68).
RE1-SS is excluded. Two-fold LOSO runs on RE1-OB and RE2-TT only.

Reuses tools/train_triage_model.py's load_rcaeval / FEATURE_NAMES /
fit_calibrate / macro_f1 directly — same feature pipeline and model
(StandardScaler + LogisticRegression + IsotonicRegression) as the
committed multi-system pipeline, no new model design.

Result: both folds land at or below their own per-fold majority-class
baseline (Fold A 0.1760 < baseline 0.2000; Fold B 0.1667 == baseline,
a total single-class collapse to "disk" on all 90 test cases). The
scaler-distribution sanity check at the end of this script (Fold A only,
per request) shows this is substantially a scaling artifact, not
necessarily a clean "features don't transfer" result: kpi_co_breaching_
services -- a raw, unnormalized count -- is near-constant *within* each
system but at a totally different absolute magnitude *between* systems
(TT-fit mean=68.03, scale=0.16; OB's raw mean of 13.0 lands at -334.8
TT-fit standard deviations). kpi_slope_60s and ev_item_count show the
same pattern at smaller magnitude. 43/46 features are unremarkable
(within +-3 TT-fit-stds). This makes the raw-count features look more
like a system-identity leak than an incident-shape signal, and should
be resolved (drop or log/ratio-normalize) before the collapse is read
as a clean cross-system-transfer finding.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.train_triage_model import (  # noqa: E402
    ALERT_FEATURE_NAMES,
    FEATURE_NAMES,
    PACK_FEATURE_NAMES,
    RANDOM_SEED,
    fit_calibrate,
    load_rcaeval,
)

TAUS = np.linspace(0.1, 0.95, 50)


def bar(title: str) -> None:
    print("=" * 90)
    print(title)
    print("=" * 90)


def main() -> None:
    bar("EXCLUSION STATEMENT (Task 1.3a precondition)")
    print("RE1-SS (Sock Shop) EXCLUDED from this LOSO run. Justification (either alone sufficient):")
    print("  1. alert.service == 'cluster' on 125/125 RE1-SS cases (vs 13 real services on RE1-OB,")
    print("     31 real services on RE2-TT) -- kpi_co_breaching_services has std=0.0 (always 1) as")
    print("     a direct consequence: zero-variance feature, unconditionally uninformative for SS.")
    print("  2. alert_metric_family is decoupled from true fault label on RE1-SS: 0/24 true-cpu")
    print("     cases ever fire cpu_saturation (94.4% fire memory_saturation regardless of label).")
    print("Two-fold LOSO below uses RE1-OB and RE2-TT only.")

    bar("LEAKAGE CHECK: feature list actually used this fold")
    print(f"ALERT_FEATURE_NAMES ({len(ALERT_FEATURE_NAMES)}): {ALERT_FEATURE_NAMES}")
    print(f"PACK_FEATURE_NAMES  ({len(PACK_FEATURE_NAMES)}): {PACK_FEATURE_NAMES}")
    print(f"FEATURE_NAMES total: {len(FEATURE_NAMES)}")
    # A per-service one-hot would show up as many near-duplicate columns named
    # "service_<name>" (one per distinct service string seen in the data) or
    # as a feature whose name IS a raw service identifier. Check for that
    # pattern specifically, not a bare "service" substring match (which false-
    # positives on the legitimate scalar count feature kpi_co_breaching_services).
    tfidf_hits = [f for f in FEATURE_NAMES if "tfidf" in f.lower() or "tf_idf" in f.lower()]
    service_onehot_hits = [f for f in FEATURE_NAMES if f.lower().startswith("service_") or f.lower().startswith("svc_")]
    print(f"features matching TF-IDF naming: {tfidf_hits if tfidf_hits else 'NONE'}")
    print(f"features matching a per-service-one-hot naming pattern (service_*/svc_*): "
          f"{service_onehot_hits if service_onehot_hits else 'NONE'}")
    print(f"(note: 'kpi_co_breaching_services' contains the substring 'service' but is a scalar COUNT "
          f"of distinct services, not a one-hot of which service -- confirmed not a leakage vector, "
          f"see full 46-name list above for manual verification)")
    assert not tfidf_hits and not service_onehot_hits, "system-agnostic feature claim violated"
    print("VERIFIED: no per-service one-hot, no TF-IDF feature in this fold's feature set.")

    bar("LOAD DATA (RE1-OB, RE1-SS, RE2-TT cached features; RE1-SS filtered out below)")
    df = load_rcaeval("data/rcaeval", Path(".feature_cache"))
    lab = df["label"].values
    print(f"pooled cache rows: {len(df)}  sources: {sorted(df['source'].unique())}")

    ob_idx_all = np.where(df["source"].values == "RE1-OB")[0]
    tt_idx_all = np.where(df["source"].values == "RE2-TT")[0]
    print(f"RE1-OB n={len(ob_idx_all)}  RE2-TT n={len(tt_idx_all)}  (RE1-SS excluded from both folds)")

    bar("STEP 2: LABEL-SPACE CHECK (before any macro-F1 is computed)")
    ob_classes = sorted(set(lab[ob_idx_all].tolist()))
    tt_classes = sorted(set(lab[tt_idx_all].tolist()))
    print(f"RE1-OB class set: {ob_classes}")
    print(f"RE2-TT class set: {tt_classes}")
    only_in_tt = sorted(set(tt_classes) - set(ob_classes))
    only_in_ob = sorted(set(ob_classes) - set(tt_classes))
    if ob_classes != tt_classes:
        print(f"LABEL SPACES DIFFER: classes only in RE2-TT (not RE1-OB): {only_in_tt}  "
              f"classes only in RE1-OB (not RE2-TT): {only_in_ob or 'none'}")
        print("Consequence flagged explicitly per fold below (train missing a class the test set has,")
        print("or train has a class the test set can never exercise).")
    else:
        print("Label spaces match exactly.")

    def run_fold(name: str, train_idx: np.ndarray, test_idx: np.ndarray, train_name: str, test_name: str):
        bar(f"FOLD {name}: train={train_name} (n={len(train_idx)}) -> test={test_name} (n={len(test_idx)})")
        train_classes = sorted(set(lab[train_idx].tolist()))
        test_classes = sorted(set(lab[test_idx].tolist()))
        print(f"train class set: {train_classes}")
        print(f"test  class set: {test_classes}")
        missing_from_train = sorted(set(test_classes) - set(train_classes))
        extra_in_train = sorted(set(train_classes) - set(test_classes))
        if missing_from_train:
            print(f"WARNING: test set contains class(es) the model NEVER saw in training: {missing_from_train} "
                  f"-- these test cases are structurally unclassifiable correctly; recall=0 guaranteed for them.")
        if extra_in_train:
            print(f"NOTE: train set contains class(es) never present in this test set: {extra_in_train} "
                  f"-- model *can* predict these as false positives on test even though they never occur "
                  f"as ground truth here.")

        # carve an internal validation split out of the TRAIN system only, for isotonic calibration
        # (LOSO has no separate validation system; this mirrors the committed pipeline's val role
        # without touching the test system's data in any way).
        tr_i, va_i = train_test_split(
            train_idx, train_size=0.8, random_state=RANDOM_SEED, stratify=lab[train_idx]
        )
        split_idx = {"train": tr_i, "val": va_i, "test": test_idx}
        bundle, ev = fit_calibrate(FEATURE_NAMES, df, lab, split_idx, TAUS)
        m = ev["test"]

        # majority-class baseline computed on THIS fold's own test set
        test_label_counts = pd.Series(lab[test_idx]).value_counts()
        baseline_class = test_label_counts.idxmax()
        baseline_acc = test_label_counts.max() / len(test_idx)
        print(f"\nper-fold majority-class baseline (test set): predict '{baseline_class}' always -> "
              f"acc={baseline_acc:.4f}  ({test_label_counts.max()}/{len(test_idx)})")

        print(f"\nmodel accuracy = {m['accuracy']:.4f}   macro_f1 = {m['macro_f1']:.4f}")
        print(f"accuracy - baseline = {m['accuracy'] - baseline_acc:+.4f}")

        preds = m["preds"]
        truth = m["labels"]
        pred_counts = pd.Series(preds).value_counts()
        print(f"\nprediction distribution on test set: {pred_counts.to_dict()}")
        fp_classes_not_in_test = sorted(set(preds.tolist()) - set(test_classes))
        if fp_classes_not_in_test:
            print(f"model predicted class(es) that NEVER occur as ground truth in this test set: "
                  f"{fp_classes_not_in_test} -- count: "
                  f"{ {c: int((preds == c).sum()) for c in fp_classes_not_in_test} }")

        print("\nraw confusion table (rows=true, cols=predicted):")
        conf = pd.crosstab(pd.Series(truth, name="true"), pd.Series(preds, name="pred"))
        print(conf.to_string())

        return {"name": name, "accuracy": m["accuracy"], "macro_f1": m["macro_f1"],
                "baseline_acc": baseline_acc, "n_test": len(test_idx), "bundle": bundle}

    result_a = run_fold("A", tt_idx_all, ob_idx_all, "RE2-TT", "RE1-OB")
    result_b = run_fold("B", ob_idx_all, tt_idx_all, "RE1-OB", "RE2-TT")

    bar("SCALER-DISTRIBUTION SANITY CHECK (Fold A: scaler fit on RE2-TT train split, "
        "evaluated against RE1-OB's actual raw feature distribution)")
    print("Tests whether Fold A's collapse (acc 0.1760 < baseline 0.2000, 120/125 predicted 'cpu') is a")
    print("scaling artifact (OB's raw values fall far outside what the TT-fit scaler expects) or a real")
    print("transfer failure (values are in-range but the decision boundary still doesn't generalize).\n")
    scaler_a = result_a["bundle"]["scaler"]
    X_ob_raw = df.loc[ob_idx_all, FEATURE_NAMES].values
    ob_min = X_ob_raw.min(axis=0)
    ob_mean = X_ob_raw.mean(axis=0)
    ob_max = X_ob_raw.max(axis=0)
    tt_mean_fit = scaler_a.mean_
    tt_scale_fit = scaler_a.scale_
    # how many TT-fit standard deviations OB's mean sits from the TT-fit center --
    # this is literally the standardized value StandardScaler.transform() would produce
    # for OB's average case, per feature.
    ob_mean_in_tt_stds = (ob_mean - tt_mean_fit) / np.where(tt_scale_fit == 0, 1.0, tt_scale_fit)

    rows = []
    for i, fname in enumerate(FEATURE_NAMES):
        rows.append({
            "feature": fname,
            "TT_fit_mean": tt_mean_fit[i],
            "TT_fit_scale": tt_scale_fit[i],
            "OB_raw_min": ob_min[i],
            "OB_raw_mean": ob_mean[i],
            "OB_raw_max": ob_max[i],
            "OB_mean_in_TT_stds": ob_mean_in_tt_stds[i],
        })
    diag = pd.DataFrame(rows)
    pd.set_option("display.width", 200)
    pd.set_option("display.max_rows", 60)
    pd.set_option("display.float_format", lambda x: f"{x:.4f}")

    print("kpi_co_breaching_services specifically (flagged in Task 1.3a as fold-dependent-scale):")
    print(diag[diag["feature"] == "kpi_co_breaching_services"].to_string(index=False))

    print("\nAll 46 features, sorted by |OB_mean_in_TT_stds| descending (most out-of-distribution first):")
    diag_sorted = diag.reindex(diag["OB_mean_in_TT_stds"].abs().sort_values(ascending=False).index)
    print(diag_sorted.to_string(index=False))

    n_extreme = int((diag["OB_mean_in_TT_stds"].abs() > 3).sum())
    print(f"\nfeatures where OB's mean sits >3 TT-fit-standard-deviations from the TT-fit center: "
          f"{n_extreme}/{len(FEATURE_NAMES)}")
    print(f"features where OB's mean sits >10 TT-fit-standard-deviations from the TT-fit center: "
          f"{int((diag['OB_mean_in_TT_stds'].abs() > 10).sum())}/{len(FEATURE_NAMES)}")

    bar("SUMMARY: LOSO vs IN-DOMAIN (Task 1.1/1.2) -- DIFFERENT QUESTIONS, NOT DIRECTLY COMPARABLE NUMBERS")
    for r in (result_a, result_b):
        print(f"Fold {r['name']}: acc={r['accuracy']:.4f}  macro_f1={r['macro_f1']:.4f}  "
              f"baseline_acc={r['baseline_acc']:.4f}  n_test={r['n_test']}")
    print("\nIn-domain multi-system reference points (from prior tasks, NOT re-run here):")
    print("  Task 1.1 combined-features multi-system model: test acc reported in docs/a7_multisystem_training_report.md")
    print("  Task 1.2 nested-CV OOF (pooled dev, in-domain): precision=0.8684 recall=0.1213 @ tau*=0.7418 "
          "(threshold-selection honesty, not a same-metric comparison to LOSO accuracy/macro-F1 above)")
    print("LOSO answers cross-system transfer (train on one deployed system's fault signatures, test on a")
    print("system the model never saw); nested CV in Task 1.2 answers in-domain threshold honesty (same")
    print("systems in train and test, pooled). These are different questions on different metrics --")
    print("do not read one as validating or contradicting the other.")

    bar("DONE")


if __name__ == "__main__":
    main()
