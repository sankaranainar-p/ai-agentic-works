#!/usr/bin/env python3
"""Task 1.3 corrected re-run — LOSO with the 3 raw-count features normalized.

Companion to bench/loso_task1.3.py (kept unmodified — that file is the
pre-fix, provisional run; this file is the corrected re-run, per instruction
to keep both in the trail). Same two folds (RE1-OB <-> RE2-TT, RE1-SS
excluded per Task 1.3a), same model (StandardScaler + LogisticRegression +
IsotonicRegression via tools/train_triage_model.fit_calibrate, no new model
design) — the only change is how 3 of the 46 features are computed:

  - kpi_co_breaching_services -> kpi_co_breaching_ratio: divided by the
    total distinct services observed in that case's raw metrics (not
    topology size -- RE1-OB and RE1-SS both have 0 topology nodes in this
    adapter, per Task 1.3's scaler check, so "services seen in this case's
    metrics" is the only denominator available for both folds). Bounded
    (0, 1], a genuine relative-breadth signal instead of an absolute count
    whose scale tracks each system's total service count (OB ~13, TT ~68).
  - kpi_slope_60s -> signed-log: sign(x) * log1p(abs(x)). This one *is* a
    units/magnitude problem (OB's raw range spans -69905 to +4,090,470,
    genuinely heavy-tailed, not a near-zero-variance-in-one-system issue),
    so log compression is the right tool here.
  - ev_item_count -> log1p(x). Included for completeness per instruction,
    but flagged going in: this feature's problem is that RE2-TT's evidence
    pack saturates its hard 40-item cap on nearly every case (near-zero
    within-system variance at the cap), which no monotonic transform can
    fix -- a monotonic function of a near-constant is still near-constant.
    Reported honestly below rather than assumed fixed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.train_triage_model import (  # noqa: E402
    FEATURE_NAMES,
    RANDOM_SEED,
    fit_calibrate,
    load_rcaeval,
)
from pre.signals.rcaeval import RCAEvalAdapter  # noqa: E402

TAUS = np.linspace(0.1, 0.95, 50)

# pre-fix numbers from bench/loso_task1.3_output.txt, for the explicit
# before/after comparison this script is required to print.
PREFIX = {
    "A": {"accuracy": 0.1760, "macro_f1": 0.0607, "baseline_acc": 0.2000},
    "B": {"accuracy": 0.1667, "macro_f1": 0.0476, "baseline_acc": 0.1667},
}


def bar(title: str) -> None:
    print("=" * 90)
    print(title)
    print("=" * 90)


def total_distinct_services_per_case(dataset: str) -> dict[str, int]:
    """Distinct {service} prefixes across a case's raw metric keys.

    Same denominator basis available for every RCAEval case regardless of
    whether topology data exists (RE1-OB and RE1-SS both have 0 topology
    nodes in this adapter -- confirmed in bench/loso_task1.3.py's scaler
    check -- so topology size cannot be used as the ratio denominator).
    """
    adapter = RCAEvalAdapter("data/rcaeval", dataset)
    out = {}
    for case, _gt in adapter:
        svcs = {k.split(":")[0] for k in case.metrics.keys()}
        out[case.case_id] = max(len(svcs), 1)
    return out


def main() -> None:
    bar("LOAD DATA + APPLY FEATURE NORMALIZATION")
    df = load_rcaeval("data/rcaeval", Path(".feature_cache"))
    lab = df["label"].values
    ob_idx_all = np.where(df["source"].values == "RE1-OB")[0]
    tt_idx_all = np.where(df["source"].values == "RE2-TT")[0]
    print(f"RE1-OB n={len(ob_idx_all)}  RE2-TT n={len(tt_idx_all)}  (RE1-SS excluded, same as pre-fix run)")

    print("\ncomputing total-distinct-services-per-case denominator (RE1-OB, RE2-TT only)...")
    denom = {}
    denom.update(total_distinct_services_per_case("RE1-OB"))
    denom.update(total_distinct_services_per_case("RE2-TT"))
    denom_series = df["case_id"].map(denom)
    missing = int(denom_series.isna().sum() - len(df) + len(ob_idx_all) + len(tt_idx_all))
    print(f"denominator resolved for {denom_series.notna().sum()} of {len(ob_idx_all) + len(tt_idx_all)} "
          f"OB+TT rows (RE1-SS rows intentionally unresolved -- excluded from LOSO either way)")

    df_fixed = df.copy()
    raw_co_breach = df_fixed["kpi_co_breaching_services"].copy()
    df_fixed["kpi_co_breaching_services"] = raw_co_breach / denom_series.fillna(1)
    raw_slope = df_fixed["kpi_slope_60s"].copy()
    df_fixed["kpi_slope_60s"] = np.sign(raw_slope) * np.log1p(np.abs(raw_slope))
    raw_item_count = df_fixed["ev_item_count"].copy()
    df_fixed["ev_item_count"] = np.log1p(raw_item_count)

    print("\nbefore -> after, OB+TT rows only (min / mean / max):")
    for name, raw, fixed in (
        ("kpi_co_breaching_services -> kpi_co_breaching_ratio", raw_co_breach, df_fixed["kpi_co_breaching_services"]),
        ("kpi_slope_60s -> signed-log", raw_slope, df_fixed["kpi_slope_60s"]),
        ("ev_item_count -> log1p", raw_item_count, df_fixed["ev_item_count"]),
    ):
        idx = np.concatenate([ob_idx_all, tt_idx_all])
        r, f = raw.values[idx], fixed.values[idx]
        print(f"  {name}")
        print(f"    OB: raw min/mean/max = {r[:len(ob_idx_all)].min():.2f}/{r[:len(ob_idx_all)].mean():.2f}/{r[:len(ob_idx_all)].max():.2f}"
              f"   fixed = {f[:len(ob_idx_all)].min():.4f}/{f[:len(ob_idx_all)].mean():.4f}/{f[:len(ob_idx_all)].max():.4f}")
        print(f"    TT: raw min/mean/max = {r[len(ob_idx_all):].min():.2f}/{r[len(ob_idx_all):].mean():.2f}/{r[len(ob_idx_all):].max():.2f}"
              f"   fixed = {f[len(ob_idx_all):].min():.4f}/{f[len(ob_idx_all):].mean():.4f}/{f[len(ob_idx_all):].max():.4f}")

    def run_fold(name: str, train_idx: np.ndarray, test_idx: np.ndarray, train_name: str, test_name: str):
        bar(f"FOLD {name} (FIXED FEATURES): train={train_name} (n={len(train_idx)}) -> test={test_name} (n={len(test_idx)})")
        tr_i, va_i = train_test_split(
            train_idx, train_size=0.8, random_state=RANDOM_SEED, stratify=lab[train_idx]
        )
        split_idx = {"train": tr_i, "val": va_i, "test": test_idx}
        bundle, ev = fit_calibrate(FEATURE_NAMES, df_fixed, lab, split_idx, TAUS)
        m = ev["test"]

        test_label_counts = pd.Series(lab[test_idx]).value_counts()
        baseline_class = test_label_counts.idxmax()
        baseline_acc = test_label_counts.max() / len(test_idx)
        print(f"per-fold majority-class baseline (test set): predict '{baseline_class}' always -> "
              f"acc={baseline_acc:.4f}  ({test_label_counts.max()}/{len(test_idx)})")
        print(f"model accuracy = {m['accuracy']:.4f}   macro_f1 = {m['macro_f1']:.4f}")
        print(f"accuracy - baseline = {m['accuracy'] - baseline_acc:+.4f}")

        pre = PREFIX[name]
        print(f"\nBEFORE (pre-fix, bench/loso_task1.3_output.txt): "
              f"acc={pre['accuracy']:.4f}  macro_f1={pre['macro_f1']:.4f}  baseline={pre['baseline_acc']:.4f}")
        print(f"AFTER  (this run, fixed features):               "
              f"acc={m['accuracy']:.4f}  macro_f1={m['macro_f1']:.4f}  baseline={baseline_acc:.4f}")
        print(f"delta accuracy: {m['accuracy'] - pre['accuracy']:+.4f}   "
              f"delta macro_f1: {m['macro_f1'] - pre['macro_f1']:+.4f}")

        preds = m["preds"]
        truth = m["labels"]
        pred_counts = pd.Series(preds).value_counts()
        n_predicted_classes = len(pred_counts)
        print(f"\nprediction distribution on test set: {pred_counts.to_dict()}")
        print(f"distinct classes predicted: {n_predicted_classes} "
              f"({'CONSTANT-CLASSIFIER COLLAPSE PERSISTS' if n_predicted_classes == 1 else 'collapse resolved -- multiple classes predicted'})")

        print("\nraw confusion table (rows=true, cols=predicted):")
        conf = pd.crosstab(pd.Series(truth, name="true"), pd.Series(preds, name="pred"))
        print(conf.to_string())

        return {"name": name, "accuracy": m["accuracy"], "macro_f1": m["macro_f1"],
                "baseline_acc": baseline_acc, "n_test": len(test_idx),
                "n_predicted_classes": n_predicted_classes, "bundle": bundle}

    result_a = run_fold("A", tt_idx_all, ob_idx_all, "RE2-TT", "RE1-OB")
    result_b = run_fold("B", ob_idx_all, tt_idx_all, "RE1-OB", "RE2-TT")

    bar("POST-FIX SCALER CHECK (Fold A): did the 3 fixed features actually move closer to the TT-fit center?")
    scaler_a = result_a["bundle"]["scaler"]
    X_ob_fixed = df_fixed.loc[ob_idx_all, FEATURE_NAMES].values
    fixed_names = ["kpi_co_breaching_services", "kpi_slope_60s", "ev_item_count"]
    for fname in fixed_names:
        i = FEATURE_NAMES.index(fname)
        ob_mean = X_ob_fixed[:, i].mean()
        tt_mean_fit = scaler_a.mean_[i]
        tt_scale_fit = scaler_a.scale_[i]
        stds = (ob_mean - tt_mean_fit) / (tt_scale_fit if tt_scale_fit else 1.0)
        print(f"  {fname:28s} TT-fit mean={tt_mean_fit:9.4f}  TT-fit scale={tt_scale_fit:9.4f}  "
              f"OB mean={ob_mean:9.4f}  OB mean in TT-fit stds = {stds:9.2f}")

    bar("SUMMARY")
    for r in (result_a, result_b):
        pre = PREFIX[r["name"]]
        print(f"Fold {r['name']}: BEFORE acc={pre['accuracy']:.4f} macro_f1={pre['macro_f1']:.4f} baseline={pre['baseline_acc']:.4f}  "
              f"|  AFTER acc={r['accuracy']:.4f} macro_f1={r['macro_f1']:.4f} baseline={r['baseline_acc']:.4f}  "
              f"|  predicted-classes={r['n_predicted_classes']}")
    print("\nBoth pre-fix and post-fix results are kept in the paper's trail: bench/loso_task1.3.py /")
    print("_output.txt (original, provisional) and bench/loso_task1.3_normalized.py / _output.txt (this")
    print("run, corrected features). The scaler-artifact mechanism identified in the original run's sanity")
    print("check is what explains the difference between the two, not a change in model or methodology.")

    bar("DONE")


if __name__ == "__main__":
    main()
