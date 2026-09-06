# PROTOCOL.md — Evaluation Protocol for the AI Payment Reliability Engine

This document freezes the research questions, metrics, data splits, and
statistical procedure used to evaluate the classifier + RCA + remediation
pipeline against RCAEval and OpenRCA-derived incident data. It is the
contract between experiment code and the taxonomy in `data/taxonomy.yaml`:
any change to fault_class/payment_sli/sli_map that would invalidate a
metric definition below requires a new version of this document.

## Research Questions

| ID  | Question | Mode |
|-----|----------|------|
| RQ1 | How accurately does the ML-only classifier assign the correct `fault_class` label compared to RCAEval/OpenRCA ground truth? | Offline |
| RQ2 | Does adding the LLM classifier (Groq/Ollama) to the ensemble improve fault_class accuracy and/or severity calibration over ML-only, and by how much? | Offline |
| RQ3 | How well does the mapped `payment_sli` (via `sli_map`) track the actual injected fault's impact on payment-domain metrics, across the five target systems? | Offline |
| RQ4 | Does automated remediation dispatch reduce mean time-to-resolution (MTTR) versus a no-remediation baseline, when run against live/replayed telemetry? | Online |
| RQ5 | Is the end-to-end 5-layer agent loop (classify → RCA → remediate → verify → log) stable and safe (no duplicate escalations, no crash loops) under a sustained incident stream? | Online |

- **Offline**: evaluated against static, pre-labelled RCAEval/OpenRCA cases; no live system under test.
- **Online**: evaluated against a running instance of the target system (Online Boutique, Sock Shop, Train Ticket, OpenRCA Bank, or the OTel Demo) with faults injected live.

## Metric Definitions

- **fault_class accuracy** — exact-match rate between the predicted `fault_class` (from `data/taxonomy.yaml`) and the RCAEval/OpenRCA ground-truth label for the case, over all cases in the evaluated split.
- **Top-3 accuracy** — fraction of cases where the ground-truth `fault_class` appears in the classifier's top-3 ranked predictions (by calibrated probability for ML, by stated confidence for LLM).
- **Severity calibration error (SCE)** — mean absolute difference between predicted severity rank (SEV-1=4 … SEV-4=1) and a held-out human-labelled severity rank for the same case, over all cases where a human label exists.
- **SLI mapping precision** — fraction of predicted `payment_sli` values (via `sli_map`) that match the SLI a human reviewer independently identifies as the one materially degraded by the injected fault.
- **MTTR (mean time-to-resolution)** — wall-clock time from `incident_started` to `verification_complete` with `status == "resolved"`, averaged over all incidents in an online run; incidents that never resolve within the run window are excluded and reported separately as the unresolved rate.
- **Escalation correctness** — fraction of incidents where `remediation.escalated` matches the ground-truth "should have escalated" label (SEV-1/SEV-2 by definition, or human override).
- **Availability** — fraction of the online run duration during which `GET /health` returns HTTP 200.

## Train / Validation / Test Splits

- Cases are split **by fault-injection run**, not by individual telemetry sample, to avoid leakage between splits on the same injected fault.
- RCAEval RE1/RE2/RE3 cases: 60% train / 20% validation / 15% test, with the remaining 5% held out as a frozen "final report" set touched at most once.
- OpenRCA cases: used only for validation and test (40% validation / 60% test) since RCAEval provides the primary training signal for the ML classifier's `_TRAINING_DATA`.
- Splits are stratified by `fault_class` so each split contains a proportional representation of all thirteen classes plus `unknown`.
- The ML classifier's fixed `RANDOM_SEED = 42` (see `pre/classifier/model.py`) governs both the train/test split shuffle and `LinearSVC`'s internal randomness, so splits are reproducible run-to-run.
- Train split is used only to fit/retrain the ML pipeline (`MLClassifier._train`). LLM configurations are never fine-tuned; only prompt and provider selection are evaluated against validation, with test reserved for the final comparison in the paper/report.

## Statistical Procedure

- Significance threshold: **alpha = 0.05**.
- All pairwise comparisons across LLM configurations (e.g. Groq vs. Ollama vs. ML-only, or prompt variant A vs. B) use **Holm–Bonferroni correction** across the full family of comparisons made for a given RQ, controlling family-wise error rate.
- Each LLM configuration is run **five times** (five repeats) per test case to average out sampling variance in the LLM's `temperature`-driven output; the ML classifier is deterministic given `RANDOM_SEED` and is run once per case.
- Reported effect sizes accompany every significance test (Cohen's d for continuous metrics such as MTTR/SCE, Cohen's h for proportions such as accuracy).
- Paired tests (Wilcoxon signed-rank) are used when comparing two classifiers on the same case set; unpaired tests (Mann-Whitney U) are used only when case sets differ (e.g. RCAEval vs. OpenRCA).

## Stopping Rules

- **Offline evaluation** stops once all cases in the frozen test split have been scored for the configuration under test; no early stopping is applied to offline runs since they are not adaptive.
- **Online evaluation (RQ4/RQ5)** stops for a given run when *either*:
  1. 200 incidents have completed the full 5-layer loop (classify → RCA → remediate → verify → log), or
  2. 2 hours of wall-clock time have elapsed since the first incident in the run,
  whichever comes first.
- An online run is **aborted early** (and excluded from the final report, logged as a failed run) if:
  - `GET /health` fails to return HTTP 200 for more than 60 consecutive seconds, or
  - more than 3 duplicate PagerDuty escalations for the same `incident_id` are observed (indicates a dispatch bug, not a real reliability signal).
- Repeats for a given LLM configuration stop at exactly 5 regardless of variance observed; if variance across the 5 repeats exceeds a coefficient of variation of 0.5 for the primary metric, this is reported as a limitation rather than triggering additional repeats (pre-registered to avoid p-hacking via repeat inflation).
