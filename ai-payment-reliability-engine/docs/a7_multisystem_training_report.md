# A7 Multi-System Triage Model — fault_class

Target: **fault_class** (data/taxonomy.yaml). Extends the RE1-OB `root_cause_service` baseline (`a7_triage_training_report.md`) to all RCAEval systems with a cross-system held-out test, per PROTOCOL.md.

> **Feature source matters.** Test accuracy: A5 alert-only 0.137 (prior baseline 0.137), A8 pack-only 0.510, combined 0.529 (chance ~0.167). Full metrics table below is for the combined model; the feature-source ablation and the tau curve follow.

## Data
- Train/val/test pool: RCAEval RE1-OB, RE1-SS, RE2-TT — 340 cases, 6 fault_class labels
- Split (stratified by fault_class, seed 42): train 204 / val 68 / test 51 / frozen 17 (untouched)
- Train label distribution: {'cpu': 39, 'delay': 39, 'disk': 39, 'loss': 39, 'memory': 39, 'socket': 9}

## Features
- **A5 alert** (17 cols): rule_id one-hot + payment_sli one-hot + KPI shape (breach magnitude, slope-60s, co-breaching services) + silent flag
- **A8 evidence pack** (29 cols): per metric-family (cpu/memory/disk/socket/latency/network/other) — strongest log1p|z|, best-rank reciprocal, top-10 count — plus a one-hot of the #1 ranked candidate's family and the pack size
- combined = 46 cols. System-agnostic (no service one-hot, no TF-IDF); same schema applies to OpenRCA Bank

## Model
- StandardScaler -> LogisticRegression(multinomial lbfgs, class_weight=balanced, random_state=42)
- IsotonicRegression on validation top-1 confidence -> P(correct), used for abstention

## Feature-source ablation (LogReg refit per source, same split)

| feature source | split | acc | macro F1 | ECE | Brier |
|---|---|---|---|---|---|
| A5 alert-only | validation | 0.221 | 0.209 | 0.000 | 0.847 |
| A5 alert-only | test | 0.137 | 0.137 | 0.125 | 0.856 |
| A8 pack-only | validation | 0.471 | 0.458 | 0.000 | 0.638 |
| A8 pack-only | test | 0.510 | 0.498 | 0.101 | 0.573 |
| combined | validation | 0.471 | 0.457 | 0.000 | 0.646 |
| combined | test | 0.529 | 0.559 | 0.142 | 0.600 |

## In-distribution results — combined model (RCAEval)

### Validation
- n: 68
- accuracy: 0.471
- macro F1: 0.457
- ECE (10-bin): 0.000
- Brier (multiclass, LR probs): 0.646

reliability (calibrated confidence):

| mean conf | empirical acc | n |
|---|---|---|
| 0.18 | 0.18 | 22 |
| 0.44 | 0.44 | 25 |
| 0.67 | 0.67 | 6 |
| 0.87 | 0.87 | 15 |

confusion (validation):

actual \ pred | cpu | delay | disk | loss | memory | socket
---|---|---|---|---|---|---
cpu | 5 | 1 | 4 | 0 | 1 | 2
delay | 0 | 6 | 3 | 1 | 0 | 3
disk | 1 | 1 | 7 | 1 | 0 | 3
loss | 3 | 0 | 4 | 3 | 1 | 2
memory | 2 | 0 | 1 | 0 | 9 | 1
socket | 1 | 0 | 0 | 0 | 0 | 2

### Test (15% held-out, same systems)
- n: 51
- accuracy: 0.529
- macro F1: 0.559
- ECE (10-bin): 0.142
- Brier (multiclass, LR probs): 0.600

reliability (calibrated confidence):

| mean conf | empirical acc | n |
|---|---|---|
| 0.18 | 0.27 | 22 |
| 0.28 | 1.00 | 1 |
| 0.44 | 0.54 | 13 |
| 0.67 | 1.00 | 7 |
| 0.87 | 0.75 | 8 |

confusion (test):

actual \ pred | cpu | delay | disk | loss | memory | socket
---|---|---|---|---|---|---
cpu | 6 | 0 | 3 | 1 | 0 | 0
delay | 0 | 4 | 5 | 1 | 0 | 0
disk | 0 | 1 | 6 | 1 | 0 | 2
loss | 1 | 2 | 3 | 3 | 0 | 0
memory | 1 | 0 | 3 | 0 | 6 | 0
socket | 0 | 0 | 0 | 0 | 0 | 2

## Diagnostic — A5 alert vs A8 evidence pack as a fault_class signal

The A5 alert collapses fault classes together: it fires ~the same rule on ~the same metric family regardless of the injected fault (wide-metric-count multiple-comparisons race — see `pre/signals/alert_synth.py`).

true fault_class vs the A5 alert's `rule_id`:

label \ alert_rule_id | cpu_saturation | generic_anomaly | latency_degradation | memory_saturation
---|---|---|---|---
cpu | 20 | 5 | 3 | 37
delay | 22 | 0 | 2 | 41
disk | 24 | 0 | 4 | 37
loss | 18 | 3 | 3 | 41
memory | 15 | 3 | 2 | 45
socket | 13 | 0 | 0 | 2

true fault_class vs the A5 alert's breached metric family:

label \ alert_metric_family | cpu | disk | latency | memory | network | other
---|---|---|---|---|---|---
cpu | 20 | 0 | 3 | 37 | 1 | 4
delay | 22 | 0 | 2 | 41 | 0 | 0
disk | 24 | 0 | 4 | 37 | 0 | 0
loss | 19 | 0 | 3 | 41 | 0 | 2
memory | 15 | 1 | 2 | 45 | 1 | 1
socket | 13 | 0 | 0 | 2 | 0 | 0

true fault_class vs the **A8 pack's #1 ranked metric family** (the signal the pack features use):

label \ pack_top1_family | cpu | disk | latency | memory | none | other | socket
---|---|---|---|---|---|---|---
cpu | 14 | 1 | 3 | 12 | 13 | 22 | 0
delay | 0 | 6 | 17 | 6 | 21 | 14 | 1
disk | 4 | 10 | 5 | 5 | 30 | 11 | 0
loss | 1 | 4 | 22 | 4 | 17 | 17 | 0
memory | 0 | 1 | 9 | 28 | 11 | 16 | 0
socket | 0 | 0 | 7 | 0 | 0 | 8 | 0

## Tau selection (95% precision target, on validation)
- selected tau: 0.672
- precision at tau: 0.867
- recall at tau: 0.191
- abstain rate at tau: 0.779
- full curve: `a7_multisystem_precision_vs_tau.csv`, plot `a7_multisystem_precision_vs_tau.png`

| tau | precision | recall | abstain |
|---|---|---|---|
| 0.10 | 0.471 | 0.471 | 0.000 |
| 0.31 | 0.609 | 0.412 | 0.324 |
| 0.50 | 0.810 | 0.250 | 0.691 |
| 0.71 | 0.867 | 0.191 | 0.779 |
| 0.90 | 0.000 | 0.000 | 1.000 |

## Reliability diagram
- `a7_multisystem_reliability.png` (validation + test)

## Cross-system generalization — OpenRCA Bank (held-out)

**DEFERRED** — OpenRCA Bank telemetry not present. Only `tests/fixtures/openrca_bank/` (3 rows) exists. Download with `data/scripts/download_openrca.py` then rerun with `--openrca-root data/openrca`.

Known ceiling once run: OpenRCA Bank's `record.csv` includes root-cause `reason`s that map to `dependency_failure` / `configuration_error` — classes absent from RCAEval training, so the model structurally cannot predict them (counted as errors, reported separately).
