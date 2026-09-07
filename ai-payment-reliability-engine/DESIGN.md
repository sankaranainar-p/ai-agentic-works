# AI Payment Reliability Engine — Design

## Overview

Real-time payment incident classifier and root cause analysis engine.
Combines a scikit-learn ML classifier with an LLM (Groq in production,
Ollama locally) for structured incident triage and RCA generation.

## Architecture

```
Alert ingested
      │
      ▼
┌─────────────────┐
│  ML Classifier  │  scikit-learn TF-IDF + LinearSVC
│  (always runs)  │  → category, severity, confidence
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LLM Classifier │  Groq (cloud) or Ollama (local) — optional enrichment
│  (if available) │  → structured JSON classification
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Ensemble       │  Merges ML + LLM results; LLM wins on confidence ties
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  RCA Generator  │  LLM → template → default fallback chain
└────────┬────────┘
         │
         ▼
    API Response
```

## LLM Provider Priority

Both the classifier (`pre/classifier/llm.py`) and RCA generator (`pre/rca.py`)
follow the same provider selection order:

1. **Groq** (cloud) — when `GROQ_API_KEY` is set  
   Model: `llama3-8b-8192` via `https://api.groq.com/openai/v1`  
   Use for: Render deployment and any environment without a local GPU

2. **Ollama** (local) — when `OLLAMA_BASE_URL` is set  
   Model: `llama3.1` via `http://localhost:11434`  
   Use for: local development

3. **ML-only / template fallback** — when neither is configured  
   Classifier returns ML result only; RCA falls back to template or default

## Environment Variables

| Variable           | Default                   | Description                                       |
|--------------------|---------------------------|---------------------------------------------------|
| `GROQ_API_KEY`     | *(unset)*                 | Groq API key — activates Groq provider            |
| `GROQ_MODEL`       | `llama3-8b-8192`          | Groq model tag                                    |
| `OLLAMA_BASE_URL`  | `http://localhost:11434`  | Base URL of the local Ollama server               |
| `OLLAMA_MODEL`     | `llama3.1`                | Ollama model tag                                  |

## Graceful Fallbacks

- **No `GROQ_API_KEY` and no `OLLAMA_BASE_URL`** → ML-only classification, RCA returns template fallback
- **Groq or Ollama unreachable** → same fallback as above
- **No `SLACK_BOT_TOKEN`** → notifications logged only
- **No `PAGERDUTY_ROUTING_KEY`** → escalations logged only

## Known Limitations

- **Verification and monitor breach detection are stubs.** `pre/verification.py`
  and `pre/monitor.py` previously simulated outcomes with `random.random()`;
  they now raise `NotImplementedError` instead, so the pipeline never
  silently fabricates a "resolved" result. Concretely:
  - Background paths (startup seeding, the monitor's probabilistic breach
    check) catch this exception per-incident and log a `seeding_error` /
    `monitor_poll_error` event, so the app keeps running.
  - The direct `POST /trigger` path does **not** catch it: calling
    `/trigger` today returns HTTP 500 once it reaches the verify layer.
  - To restore end-to-end incident processing, implement a real metrics
    client (suggested module: `pre.telemetry.metrics_client`) that re-polls
    the SLI named in `data/taxonomy.yaml` `sli_map` for the affected
    service and compares it against a threshold, then call it from
    `pre/verification.py::_check_resolution` and
    `pre/monitor.py::_probabilistic_breach`.

## Deployment

- **Local dev**: set `OLLAMA_BASE_URL=http://localhost:11434` in `.env`
- **Render**: set `GROQ_API_KEY` in the Render dashboard (sync: false); `GROQ_MODEL` is set in `render.yaml`

## Module Layout

```
pre/
├── __init__.py
├── main.py                 Thin FastAPI app: wiring, lifespan, CORS, router mount
├── agent_loop.py           5-layer agent loop (classify → RCA → remediate → verify → log)
├── api/
│   ├── __init__.py
│   └── routes.py           All HTTP route handlers (thin; delegate to agent_loop)
├── rca.py                  Root cause analysis generator
├── database.py             Async SQLite persistence (aiosqlite)
├── agent_log.py            Thread-safe in-memory event log
├── monitor.py              Background asyncio monitor loop
├── verification.py         Post-remediation verification
├── classifier/
│   ├── __init__.py
│   ├── taxonomy.py         Shared fault taxonomy loader (data/taxonomy.yaml)
│   ├── llm.py              Groq/Ollama LLM classifier
│   └── model.py            scikit-learn ML classifier (TF-IDF + LinearSVC),
│                            persisted to models/ with a fixed random seed
└── remediation/
    ├── __init__.py          RemediationResult dataclass
    ├── dispatcher.py        Routes to handler, fires Slack/PagerDuty
    └── handlers/
        └── __init__.py      One async handler per fault_class category

pre/signals/                 Adapters normalising external benchmark
├── __init__.py               datasets into a shared FailureCase /
├── types.py                  GroundTruth / LogEvent / Span model (see
├── log_template.py            module docstrings for the isolation
├── rcaeval.py                  invariant: GroundTruth is never reachable
├── openrca.py                   from a FailureCase handed to an agent).
└── alert_synth.py               openrca.py additionally resamples OpenRCA
                                Bank's mixed-granularity telemetry (60s
                                metrics, 1s logs, 1ms traces) onto a
                                shared 1s grid with explicit
                                MetricSeries.is_forward_filled flags —
                                see its module docstring and
                                CONVERSION.md's OpenRCA section for the
                                schema decisions and their verification.
                                alert_synth.py (A5) turns a FailureCase's
                                metrics into one synthetic monitoring
                                Alert via robust (median/MAD) z-scoring
                                against an ordered, versioned rule set
                                in data/alert_rules.yaml — deterministic
                                per case_id (same case always renders
                                the same alert text, byte-for-byte; see
                                tests/test_alert_synth.py's Hypothesis
                                property test), with a documented,
                                verified-against-real-data limitation
                                around multiple-comparisons false
                                positives on wide-metric-count cases
                                (see CONVERSION.md's alert_synth section).

bench/                       Benchmark harness (A14, PROTOCOL.md RQ1-5)
├── __init__.py
├── run_benchmark.py          YAML-config-driven harness: selects adapter,
│                             system_variant (full/A1-A6 ablations),
│                             baselines, repeats; writes
│                             results/<run_id>/{manifest.json,metrics.csv}
├── metrics.py                macro_f1, ECE, Brier, AC@k, Avg@5
│                             (RCAEval-compatible), faithfulness
├── configs/                  YAML configs (see re1_ob_smoke.yaml for
│                             the minimal harness-smoke-test shape)
└── baselines/
    ├── __init__.py            BASELINE_IDS = B1..B5
    ├── rules.py               B1: n-sigma deviation ranking, no learning
    ├── rcaeval_baseline.py    B2: wraps RCAEval's own BARO baseline;
    │                          verified to reproduce the published
    │                          RCAEval README Avg@5 table on RE2-TT
    │                          exactly (see tests/test_b2_rcaeval_parity.py)
    ├── ml_triage.py           B3: repurposes pre.classifier.model for
    │                          service-level ranking
    ├── single_prompt_llm.py   B4: one-shot LLM ranking prompt
    └── openrca_agent.py       B5: OpenRCA's own scoring algorithm,
                               ported and verified against OpenRCA's
                               archived Bank predictions

data/
├── taxonomy.yaml            Shared fault_class / payment_sli / sli_map taxonomy
├── alert_rules.yaml         Ordered, versioned alert rules for
│                             pre/signals/alert_synth.py (A5) — metric
│                             suffix pattern -> z-threshold -> template
├── scripts/
│   ├── download_rcaeval.py  Downloads + checksum-verifies RCAEval RE1/RE2
│   │                         zips from Zenodo record 14590730 into data/rcaeval/
│   └── download_openrca.py  Downloads OpenRCA Bank's record.csv/query.csv
│                             plus only the telemetry date-folders they
│                             reference (not the full ~26GB tree) from the
│                             public Hugging Face mirror into data/openrca/
├── rcaeval/                 (gitignored) full downloaded RCAEval datasets
└── openrca/                 (gitignored) full downloaded OpenRCA Bank data

scripts/
├── generate_b2_parity_report.py  Regenerates docs/b2_rcaeval_parity_report.*
└── alert_detection_delay_report.py  A5's required verification report:
                              detection-delay distribution + silent rate
                              per dataset, run against real fixture data
                              (see CONVERSION.md's alert_synth section)

models/
└── ml_classifier_v1.joblib  Persisted trained ML pipeline (fixed seed)

tests/
├── test_health.py           Smoke test: app starts, GET /health succeeds
├── test_taxonomy.py         Validates data/taxonomy.yaml sli_map integrity
├── test_verification_stub.py  Locks in NotImplementedError stub behaviour:
│                             background paths log-and-continue, POST
│                             /trigger surfaces it as a 500
├── test_rcaeval_adapter.py  Tests pre/signals/rcaeval.py against the
│                             trimmed fixture in tests/fixtures/rcaeval/
├── test_rcaeval_downloader.py  Tests download_rcaeval.py's checksum
│                             verification without network access
├── test_rcaeval_metrics_file_resolution.py  Regression test: RE2 uses
│                             simple_metrics.csv, not data.csv
├── test_openrca_adapter.py  Tests pre/signals/openrca.py against the
│                             trimmed real-data fixture in
│                             tests/fixtures/openrca_bank/ (evidence
│                             window reproduction, forward-fill flag
│                             mechanics, ground truth field mapping)
├── test_bench_metrics.py    Unit tests for bench/metrics.py
├── test_alert_synth.py      Tests pre/signals/alert_synth.py (A5): one
│                             unit test per rule in data/alert_rules.yaml,
│                             a Hypothesis property test that the same
│                             FailureCase always renders a byte-identical
│                             Alert, and regression tests for the two
│                             real MAD-floor bugs found against real
│                             OpenRCA telemetry (see CONVERSION.md)
├── test_b2_rcaeval_parity.py  THE gate: B2 must match RCAEval's published
│                             RE2-TT table. Requires a separate Python
│                             3.12 venv with RCAEval installed and the
│                             real 2.8GB RE2-TT dataset; skipped by
│                             default (see its module docstring)
├── test_b5_openrca_agent.py  B5 exact-parity check against OpenRCA's own
│                             archived Bank predictions/scores
├── test_run_benchmark.py    Tests bench/run_benchmark.py's harness
├── contract/
│   └── test_adapter_contract.py  Cross-adapter contract test: every
│                             adapter's fixture output (RCAEval, OpenRCA
│                             Bank) must satisfy the same FailureCase/
│                             GroundTruth structural contract (see A4)
└── fixtures/
    ├── rcaeval/              Trimmed RE1-OB + RE2-OB cases (~420KB total)
    ├── openrca/              OpenRCA's full archived agent-Bank.csv (88KB,
    │                         used by test_b5_openrca_agent.py only)
    └── openrca_bank/         Trimmed real OpenRCA Bank telemetry, 3 cases
                              narrowed to +-15s/+-60s windows (~4.4MB,
                              used by test_openrca_adapter.py and the
                              contract test; see CONVERSION.md for how
                              this was built from the real download)
```

