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

Both the classifier (`app/classifier/llm.py`) and RCA generator (`app/rca.py`)
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
app/
├── __init__.py
├── main.py                 FastAPI app, 5-layer agent loop, all endpoints
├── rca.py                  Root cause analysis generator
├── database.py             Async SQLite persistence (aiosqlite)
├── agent_log.py            Thread-safe in-memory event log
├── monitor.py              Background asyncio monitor loop
├── verification.py         Post-remediation verification
├── classifier/
│   ├── __init__.py
│   ├── llm.py              Groq/Ollama LLM classifier
│   └── model.py            scikit-learn ML classifier (TF-IDF + LinearSVC)
└── remediation/
    ├── __init__.py          RemediationResult dataclass
    ├── dispatcher.py        Routes to handler, fires Slack/PagerDuty
    └── handlers/
        └── __init__.py      11 category-specific async handlers
```
