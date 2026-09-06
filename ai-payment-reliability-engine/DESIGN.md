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

data/
└── taxonomy.yaml            Shared fault_class / payment_sli / sli_map taxonomy

models/
└── ml_classifier_v1.joblib  Persisted trained ML pipeline (fixed seed)

tests/
├── test_health.py           Smoke test: app starts, GET /health succeeds
└── test_taxonomy.py         Validates data/taxonomy.yaml sli_map integrity
```
