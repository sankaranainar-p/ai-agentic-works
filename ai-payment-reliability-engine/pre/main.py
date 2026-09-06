"""
pre/main.py — FastAPI application entrypoint for the AI Payment
Reliability Engine.

This module is intentionally thin: it wires up the FastAPI app, CORS,
lifespan (startup/shutdown), and mounts the routes defined in
pre/api/routes.py. The 5-layer agent loop lives in pre/agent_loop.py.

5-layer agent loop (per incident):
  1. Classify   — ML + LLM ensemble
  2. RCA        — Ollama → template → default
  3. Remediate  — category-specific handler + Slack/PagerDuty
  4. Verify     — wait VERIFY_WAIT_SECONDS, re-poll metrics
  5. Log        — persist full incident record in agent_log

Endpoints (see pre/api/routes.py):
  GET  /health
  POST /trigger
  GET  /incidents
  GET  /agent-log
  GET  /agent-log/stream   (SSE)
  GET  /stats
  GET  /scenarios
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

import pre.agent_log as agent_log
import pre.monitor as monitor
from pre.agent_loop import handle_monitor_alert, seed_incidents
from pre.api.routes import router
from pre.classifier.model import get_classifier
from pre.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Initialise SQLite
    await init_db()
    agent_log.append({"event": "startup", "step": "db_ready"})

    # Load (or train + persist) the ML classifier
    agent_log.append({"event": "startup", "step": "loading_classifier"})
    get_classifier()
    agent_log.append({"event": "startup", "step": "classifier_ready"})

    # Start background monitor
    await monitor.start(handle_monitor_alert)
    agent_log.append({"event": "startup", "step": "monitor_started"})

    # Seed demo incidents in the background so startup is non-blocking
    asyncio.create_task(seed_incidents())
    agent_log.append({"event": "startup", "step": "seeding_scheduled"})

    yield

    await monitor.stop()
    agent_log.append({"event": "shutdown"})


app = FastAPI(
    title="AI Payment Reliability Engine",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
