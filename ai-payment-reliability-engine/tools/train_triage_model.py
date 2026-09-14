#!/usr/bin/env python3
"""
tools/train_triage_model.py — Multi-system fault_class triage model.

Per PROTOCOL.md's split:
  - Train / validation / (within-system) test: RCAEval RE1-OB + RE1-SS + RE2-TT,
    pooled and stratified by fault_class, RANDOM_SEED=42,
    60% train / 20% val / 15% test / 5% frozen (frozen never touched here).
  - Cross-system held-out test: OpenRCA Bank (--openrca-root), evaluated once.

Features (pre/agents/training/featurize.py), system-agnostic:
  - A5 alert: rule_id + payment_sli one-hot + KPI shape
  - A8 evidence pack: per metric-family strongest |z|, best rank, top-k count,
    and the family of the #1 ranked candidate
The report includes an alert-only / pack-only / combined ablation.
No service one-hot, no TF-IDF.

Model: StandardScaler -> multinomial LogisticRegression (class_weight=balanced)
-> IsotonicRegression recalibrating the top-1 confidence for abstention.

Outputs:
  models/triage_multisystem.joblib
  docs/a7_multisystem_training_report.md
  docs/a7_multisystem_precision_vs_tau.csv
  docs/a7_multisystem_reliability.png            (if matplotlib present)
  docs/a7_multisystem_precision_vs_tau.png       (if matplotlib present)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from pre.agents.evidence import EvidenceRanker
from pre.agents.training.featurize import (
    ALERT_FEATURE_NAMES,
    FEATURE_NAMES,
    PACK_FEATURE_NAMES,
    featurize,
    metric_family,
)
from pre.agents.training.metrics import (
    expected_calibration_error,
    macro_f1,
    multiclass_brier,
    precision_recall_vs_tau,
    reliability_curve,
)
from pre.classifier.taxonomy import all_categories
from pre.signals.alert_synth import synthesize_alert
from pre.signals.rcaeval import RCAEvalAdapter

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

RANDOM_SEED = 42
RCAEVAL_DATASETS = ["RE1-OB", "RE1-SS", "RE2-TT"]
_VALID = set(all_categories())


# --------------------------------------------------------------------------- #
# Feature extraction (cached per source, keyed by FEATURE_NAMES schema)
# --------------------------------------------------------------------------- #
def _featurize_iter(adapter, source: str) -> pd.DataFrame:
    rows = []
    for case, gt in adapter:
        alert = synthesize_alert(case)
        pack = EvidenceRanker(case, alert).rank()
        vec = featurize(case, alert, pack)
        top1 = metric_family(pack.items[0].id) if pack.items else "none"
        rows.append(
            {
                **{name: v for name, v in zip(FEATURE_NAMES, vec)},
                "label": gt.fault_type,
                "case_id": case.case_id,
                "source": source,
                # metadata for the report diagnostic (not model inputs):
                "alert_rule_id": "SILENT" if alert.silent else (alert.rule_id or "SILENT"),
                "alert_metric_family": "SILENT" if alert.silent else metric_family(alert.metric_key),
                "pack_top1_family": top1,
            }
        )
    return pd.DataFrame(rows)


def _cached_features(cache_dir: Path, source: str, builder) -> pd.DataFrame:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"features_{source}.parquet"
    if path.exists():
        df = pd.read_parquet(path)
        if list(df.columns[: len(FEATURE_NAMES)]) == FEATURE_NAMES:
            print(f"  [{source}] {len(df)} cases (cached)")
            return df
        print(f"  [{source}] cache schema stale, rebuilding")
    else:
        print(f"  [{source}] extracting features...")
    df = builder()
    df.to_parquet(path)
    print(f"  [{source}] {len(df)} cases -> {path}")
    return df


def load_rcaeval(rcaeval_root: str, cache_dir: Path) -> pd.DataFrame:
    frames = [
        _cached_features(
            cache_dir, ds, lambda ds=ds: _featurize_iter(RCAEvalAdapter(rcaeval_root, ds), ds)
        )
        for ds in RCAEVAL_DATASETS
    ]
    df = pd.concat(frames, ignore_index=True)
    unknown = sorted(set(df["label"]) - _VALID)
    if unknown:
        print(f"  dropping {(~df['label'].isin(_VALID)).sum()} cases with non-taxonomy labels: {unknown}")
        df = df[df["label"].isin(_VALID)].reset_index(drop=True)
    return df


# --------------------------------------------------------------------------- #
# Split — stratified 60/20/15/5, seed 42
# --------------------------------------------------------------------------- #
def protocol_split(df: pd.DataFrame):
    y = df["label"].values
    idx = np.arange(len(df))

    train_i, rest_i = train_test_split(
        idx, train_size=0.60, random_state=RANDOM_SEED, stratify=y
    )
    # rest is 40%: split into val 20 / test 15 / frozen 5  -> 0.5 / 0.375 / 0.125 of rest
    val_i, tmp_i = train_test_split(
        rest_i, train_size=0.50, random_state=RANDOM_SEED, stratify=y[rest_i]
    )
    test_i, frozen_i = train_test_split(
        tmp_i, train_size=0.75, random_state=RANDOM_SEED, stratify=y[tmp_i]
    )
    return train_i, val_i, test_i, frozen_i


# --------------------------------------------------------------------------- #
# Evaluation helpers
# --------------------------------------------------------------------------- #
def evaluate(lr, scaler, isotonic, classes, X, y, taus):
    """Return a metrics dict for one split."""
    Xs = scaler.transform(X)
    probs = lr.predict_proba(Xs)
    preds = lr.classes_[probs.argmax(axis=1)]
    conf = isotonic.predict(probs.max(axis=1))
    correct = (preds == y).astype(float)

    bconf, bacc, bcnt = reliability_curve(conf, correct, n_bins=10)
    return {
        "n": int(len(y)),
        "accuracy": float(correct.mean()),
        "macro_f1": macro_f1(y, preds),
        "ece": expected_calibration_error(conf, correct, n_bins=10),
        "brier": multiclass_brier(probs, y, list(lr.classes_)),
        "reliability": (bconf.tolist(), bacc.tolist(), bcnt.tolist()),
        "pr_vs_tau": precision_recall_vs_tau(conf, correct, taus),
        "preds": preds,
        "labels": np.asarray(y),
        "conf": conf,
    }


def fit_calibrate(cols, df, lab, split_idx, taus):
    """Fit scaler+LR on `cols`, isotonic-calibrate on val, eval val+test.

    Returns (bundle, {"validation": m, "test": m}).
    """
    X = df[cols].values
    tr, va, te = split_idx["train"], split_idx["val"], split_idx["test"]

    scaler = StandardScaler().fit(X[tr])
    lr = LogisticRegression(
        max_iter=2000, random_state=RANDOM_SEED, solver="lbfgs", class_weight="balanced"
    )
    lr.fit(scaler.transform(X[tr]), lab[tr])

    vp = lr.predict_proba(scaler.transform(X[va]))
    isotonic = IsotonicRegression(out_of_bounds="clip")
    isotonic.fit(vp.max(axis=1), (lr.classes_[vp.argmax(axis=1)] == lab[va]).astype(int))

    bundle = {"cols": list(cols), "scaler": scaler, "lr": lr, "isotonic": isotonic}
    ev = {
        "validation": evaluate(lr, scaler, isotonic, lr.classes_, X[va], lab[va], taus),
        "test": evaluate(lr, scaler, isotonic, lr.classes_, X[te], lab[te], taus),
    }
    return bundle, ev


def pick_tau(pr_rows, target_precision=0.95):
    """Lowest tau whose precision >= target; else the tau with precision closest to it."""
    feasible = [r for r in pr_rows if r[1] >= target_precision and r[3] < 1.0]
    if feasible:
        best = min(feasible, key=lambda r: r[0])
        return best[0], best[1], best[2], best[3]
    scored = [r for r in pr_rows if r[3] < 1.0]
    if not scored:
        return 0.5, 0.0, 0.0, 1.0
    best = min(scored, key=lambda r: abs(r[1] - target_precision))
    return best[0], best[1], best[2], best[3]


# --------------------------------------------------------------------------- #
# Plots
# --------------------------------------------------------------------------- #
def plot_reliability(splits: dict, path: Path):
    if plt is None:
        return
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.plot([0, 1], [0, 1], "k--", alpha=0.5, label="perfect")
    for name, m in splits.items():
        bconf, bacc, _ = m["reliability"]
        if bconf:
            ax.plot(bconf, bacc, "o-", label=f"{name} (ECE={m['ece']:.3f})")
    ax.set_xlabel("mean predicted confidence")
    ax.set_ylabel("empirical accuracy")
    ax.set_title("Reliability diagram — calibrated top-1 confidence")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=100)
    plt.close(fig)


def plot_precision_tau(curve_df: pd.DataFrame, tau: float, path: Path):
    if plt is None:
        return
    fig, ax = plt.subplots(figsize=(10.2, 7.65))  # 1020x765 at dpi=100
    ax.plot(curve_df["tau"], curve_df["precision"], "b-", lw=2, label="precision")
    ax.plot(curve_df["tau"], curve_df["recall"], "g-", lw=2, label="recall")
    ax.plot(curve_df["tau"], 1 - curve_df["abstain_rate"], "orange", lw=2, label="answer rate")
    ax.axhline(0.95, color="r", ls="--", alpha=0.6, label="95% target")
    ax.axvline(tau, color="k", ls=":", alpha=0.6, label=f"tau={tau:.3f}")
    ax.set_xlabel("tau (confidence threshold)")
    ax.set_ylabel("rate")
    ax.set_title("Precision / recall / answer-rate vs tau (validation)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=100)
    plt.close(fig)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _split_block(name: str, m: dict) -> str:
    bconf, bacc, bcnt = m["reliability"]
    rel_rows = "\n".join(
        f"| {c:.2f} | {a:.2f} | {n} |" for c, a, n in zip(bconf, bacc, bcnt)
    ) or "| _(no populated bins)_ | | |"
    return (
        f"### {name}\n"
        f"- n: {m['n']}\n"
        f"- accuracy: {m['accuracy']:.3f}\n"
        f"- macro F1: {m['macro_f1']:.3f}\n"
        f"- ECE (10-bin): {m['ece']:.3f}\n"
        f"- Brier (multiclass, LR probs): {m['brier']:.3f}\n\n"
        f"reliability (calibrated confidence):\n\n"
        f"| mean conf | empirical acc | n |\n|---|---|---|\n{rel_rows}\n"
    )


def _tau_digest(pr_rows) -> str:
    picks = [min(pr_rows, key=lambda r: abs(r[0] - t)) for t in (0.1, 0.3, 0.5, 0.7, 0.9)]
    body = "\n".join(
        f"| {t:.2f} | {p:.3f} | {rc:.3f} | {ab:.3f} |" for t, p, rc, ab in picks
    )
    return f"| tau | precision | recall | abstain |\n|---|---|---|---|\n{body}\n"


def _confusion_lines(m: dict, classes: list[str]) -> str:
    labels = np.asarray(m["labels"])
    preds = np.asarray(m["preds"])
    seen = [c for c in classes if c in set(labels) or c in set(preds)]
    header = "actual \\ pred | " + " | ".join(seen)
    sep = "|".join(["---"] * (len(seen) + 1))
    rows = [header, sep]
    for a in seen:
        cells = [a] + [str(int(np.sum((labels == a) & (preds == p)))) for p in seen]
        rows.append(" | ".join(cells))
    return "\n".join(rows)


def _crosstab_md(df: pd.DataFrame, row: str, col: str) -> str:
    ct = pd.crosstab(df[row], df[col])
    head = f"{row} \\ {col} | " + " | ".join(map(str, ct.columns))
    sep = "|".join(["---"] * (len(ct.columns) + 1))
    body = "\n".join(
        f"{idx} | " + " | ".join(str(int(v)) for v in ct.loc[idx]) for idx in ct.index
    )
    return f"{head}\n{sep}\n{body}"


def _diagnostic_section(df: pd.DataFrame) -> list[str]:
    return [
        "## Diagnostic — A5 alert vs A8 evidence pack as a fault_class signal",
        "",
        "The A5 alert collapses fault classes together: it fires ~the same rule on "
        "~the same metric family regardless of the injected fault (wide-metric-count "
        "multiple-comparisons race — see `pre/signals/alert_synth.py`).",
        "",
        "true fault_class vs the A5 alert's `rule_id`:",
        "",
        _crosstab_md(df, "label", "alert_rule_id"),
        "",
        "true fault_class vs the A5 alert's breached metric family:",
        "",
        _crosstab_md(df, "label", "alert_metric_family"),
        "",
        "true fault_class vs the **A8 pack's #1 ranked metric family** "
        "(the signal the pack features use):",
        "",
        _crosstab_md(df, "label", "pack_top1_family"),
    ]


def _ablation_table(ablation: dict) -> str:
    head = "| feature source | split | acc | macro F1 | ECE | Brier |\n|---|---|---|---|---|---|"
    rows = []
    for name, ev in ablation.items():
        for split in ("validation", "test"):
            m = ev[split]
            rows.append(
                f"| {name} | {split} | {m['accuracy']:.3f} | {m['macro_f1']:.3f} | "
                f"{m['ece']:.3f} | {m['brier']:.3f} |"
            )
    return head + "\n" + "\n".join(rows)


def write_report(
    path: Path,
    df: pd.DataFrame,
    split_idx: dict,
    splits: dict,
    ablation: dict,
    tau_info,
    curve_path: Path,
    classes: list[str],
    bank: dict | None,
):
    tau, tau_p, tau_r, tau_ab = tau_info
    train_i = split_idx["train"]
    train_dist = pd.Series(df.iloc[train_i]["label"]).value_counts().sort_index().to_dict()

    lines = [
        "# A7 Multi-System Triage Model — fault_class",
        "",
        "Target: **fault_class** (data/taxonomy.yaml). Extends the RE1-OB "
        "`root_cause_service` baseline (`a7_triage_training_report.md`) to all "
        "RCAEval systems with a cross-system held-out test, per PROTOCOL.md.",
        "",
        f"> **Feature source matters.** Test accuracy: A5 alert-only "
        f"{ablation['A5 alert-only']['test']['accuracy']:.3f} (prior baseline 0.137), "
        f"A8 pack-only {ablation['A8 pack-only']['test']['accuracy']:.3f}, "
        f"combined {ablation['combined']['test']['accuracy']:.3f} "
        f"(chance ~{1 / df['label'].nunique():.3f}). Full metrics table below is for the "
        f"combined model; the feature-source ablation and the tau curve follow.",
        "",
        "## Data",
        f"- Train/val/test pool: RCAEval {', '.join(RCAEVAL_DATASETS)} — "
        f"{len(df)} cases, {df['label'].nunique()} fault_class labels",
        f"- Split (stratified by fault_class, seed {RANDOM_SEED}): "
        f"train {len(split_idx['train'])} / val {len(split_idx['val'])} / "
        f"test {len(split_idx['test'])} / frozen {len(split_idx['frozen'])} (untouched)",
        f"- Train label distribution: {train_dist}",
        "",
        "## Features",
        f"- **A5 alert** ({len(ALERT_FEATURE_NAMES)} cols): rule_id one-hot + payment_sli "
        "one-hot + KPI shape (breach magnitude, slope-60s, co-breaching services) + silent flag",
        f"- **A8 evidence pack** ({len(PACK_FEATURE_NAMES)} cols): per metric-family "
        "(cpu/memory/disk/socket/latency/network/other) — strongest log1p|z|, best-rank "
        "reciprocal, top-10 count — plus a one-hot of the #1 ranked candidate's family "
        "and the pack size",
        f"- combined = {len(FEATURE_NAMES)} cols. System-agnostic (no service one-hot, no "
        "TF-IDF); same schema applies to OpenRCA Bank",
        "",
        "## Model",
        "- StandardScaler -> LogisticRegression(multinomial lbfgs, class_weight=balanced, "
        f"random_state={RANDOM_SEED})",
        "- IsotonicRegression on validation top-1 confidence -> P(correct), used for abstention",
        "",
        "## Feature-source ablation (LogReg refit per source, same split)",
        "",
        _ablation_table(ablation),
        "",
        "## In-distribution results — combined model (RCAEval)",
        "",
        _split_block("Validation", splits["validation"]),
        "confusion (validation):\n\n" + _confusion_lines(splits["validation"], classes),
        "",
        _split_block("Test (15% held-out, same systems)", splits["test"]),
        "confusion (test):\n\n" + _confusion_lines(splits["test"], classes),
        "",
        *_diagnostic_section(df),
        "",
        "## Tau selection (95% precision target, on validation)",
        f"- selected tau: {tau:.3f}",
        f"- precision at tau: {tau_p:.3f}",
        f"- recall at tau: {tau_r:.3f}",
        f"- abstain rate at tau: {tau_ab:.3f}",
        f"- full curve: `{curve_path.name}`"
        + (f", plot `{curve_path.stem}.png`" if plt is not None else ""),
        "",
        _tau_digest(splits["validation"]["pr_vs_tau"]),
        "## Reliability diagram",
        "- `a7_multisystem_reliability.png` (validation + test)"
        + ("" if plt is not None else " — SKIPPED (matplotlib not installed)"),
        "",
        "## Cross-system generalization — OpenRCA Bank (held-out)",
        "",
    ]

    if bank is None:
        lines += [
            "**DEFERRED** — OpenRCA Bank telemetry not present. Only "
            "`tests/fixtures/openrca_bank/` (3 rows) exists. Download with "
            "`data/scripts/download_openrca.py` then rerun with `--openrca-root data/openrca`.",
            "",
            "Known ceiling once run: OpenRCA Bank's `record.csv` includes root-cause "
            "`reason`s that map to `dependency_failure` / `configuration_error` — classes "
            "absent from RCAEval training, so the model structurally cannot predict them "
            "(counted as errors, reported separately).",
        ]
    else:
        lines += [
            _split_block("OpenRCA Bank", bank),
            f"- precision/recall at val-selected tau={tau:.3f}: "
            f"{bank['tau_precision']:.3f} / {bank['tau_recall']:.3f} "
            f"(abstain {bank['tau_abstain']:.3f})",
            "",
            f"- unseen-class cases (no RCAEval training signal): {bank['unseen_n']} "
            f"of {bank['n']} ({bank['unseen_frac']:.1%}) — labels {bank['unseen_labels']}",
            "",
            "Confusion (Bank):",
            "",
            _confusion_lines(bank, classes),
        ]

    path.write_text("\n".join(lines) + "\n")
    print(f"  report -> {path}")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rcaeval-root", default="data/rcaeval")
    ap.add_argument("--openrca-root", default=None, help="dir containing Bank/ (omit to defer)")
    ap.add_argument("--output-dir", default="models")
    ap.add_argument("--report-dir", default="docs")
    ap.add_argument("--cache-dir", default=".feature_cache")
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    report_dir = Path(args.report_dir)
    cache_dir = Path(args.cache_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    print("[1/6] Loading + featurizing RCAEval (RE1-OB, RE1-SS, RE2-TT)...")
    df = load_rcaeval(args.rcaeval_root, cache_dir)

    print("[2/6] Splitting 60/20/15/5 stratified by fault_class...")
    train_i, val_i, test_i, frozen_i = protocol_split(df)
    split_idx = {"train": train_i, "val": val_i, "test": test_i, "frozen": frozen_i}
    lab = df["label"].values
    print(f"  train {len(train_i)} | val {len(val_i)} | test {len(test_i)} | frozen {len(frozen_i)}")

    taus = np.linspace(0.1, 0.95, 50)

    print("[3/6] Fitting 3 models: A5-alert-only / A8-pack-only / combined...")
    ablation = {}
    bundles = {}
    for name, cols in (
        ("A5 alert-only", ALERT_FEATURE_NAMES),
        ("A8 pack-only", PACK_FEATURE_NAMES),
        ("combined", FEATURE_NAMES),
    ):
        bundles[name], ablation[name] = fit_calibrate(cols, df, lab, split_idx, taus)
        v, t = ablation[name]["validation"], ablation[name]["test"]
        print(f"  {name:16s} val acc {v['accuracy']:.3f} F1 {v['macro_f1']:.3f} | "
              f"test acc {t['accuracy']:.3f} F1 {t['macro_f1']:.3f}")

    # Primary model = combined
    primary = bundles["combined"]
    scaler, lr, isotonic = primary["scaler"], primary["lr"], primary["isotonic"]
    splits = ablation["combined"]

    print("[4/6] Selecting tau for 95% precision (combined, on validation)...")
    tau_info = pick_tau(splits["validation"]["pr_vs_tau"], 0.95)
    tau = tau_info[0]
    print(f"  tau for 95% precision: {tau:.3f} (precision {tau_info[1]:.3f}, recall {tau_info[2]:.3f})")

    curve_df = pd.DataFrame(
        splits["validation"]["pr_vs_tau"], columns=["tau", "precision", "recall", "abstain_rate"]
    )
    curve_path = report_dir / "a7_multisystem_precision_vs_tau.csv"
    curve_df.to_csv(curve_path, index=False)

    plot_reliability(
        {"validation": splits["validation"], "test": splits["test"]},
        report_dir / "a7_multisystem_reliability.png",
    )
    plot_precision_tau(curve_df, tau, report_dir / "a7_multisystem_precision_vs_tau.png")

    print("[5/6] Cross-system held-out: OpenRCA Bank...")
    bank = None
    if args.openrca_root:
        try:
            from pre.signals.openrca import OpenRCABankAdapter

            bdf = _cached_features(
                cache_dir, "openrca_bank",
                lambda: _featurize_iter(OpenRCABankAdapter(args.openrca_root), "openrca_bank"),
            )
            m = evaluate(lr, scaler, isotonic, lr.classes_, bdf[FEATURE_NAMES].values, bdf["label"].values, taus)
            keep = m["conf"] >= tau
            k = int(keep.sum())
            m["tau_precision"] = float((m["preds"][keep] == m["labels"][keep]).mean()) if k else 0.0
            m["tau_recall"] = float((m["preds"][keep] == m["labels"][keep]).sum() / m["n"]) if k else 0.0
            m["tau_abstain"] = float(1 - k / m["n"])
            unseen = ~np.isin(m["labels"], list(lr.classes_))
            m["unseen_n"] = int(unseen.sum())
            m["unseen_frac"] = float(unseen.mean())
            m["unseen_labels"] = sorted(set(m["labels"][unseen]))
            bank = m
            print(f"  Bank: acc {m['accuracy']:.3f} macroF1 {m['macro_f1']:.3f} "
                  f"ECE {m['ece']:.3f} Brier {m['brier']:.3f} (unseen classes: {m['unseen_n']}/{m['n']})")
        except FileNotFoundError as e:
            print(f"  --openrca-root given but data not resolvable: {e}\n  -> deferring")

    print("[6/6] Saving model + report...")
    joblib.dump(
        {
            "scaler": scaler, "lr": lr, "isotonic": isotonic, "tau": float(tau),
            "classes": list(lr.classes_), "feature_names": FEATURE_NAMES, "seed": RANDOM_SEED,
        },
        out_dir / "triage_multisystem.joblib",
    )
    print(f"  model -> {out_dir / 'triage_multisystem.joblib'}")

    write_report(
        report_dir / "a7_multisystem_training_report.md",
        df, split_idx, splits, ablation, tau_info, curve_path, list(lr.classes_), bank,
    )
    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        print(f"\nFAILED: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)
