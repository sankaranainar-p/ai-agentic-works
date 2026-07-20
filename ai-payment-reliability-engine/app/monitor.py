"""
app/monitor.py — Background asyncio monitor loop.

Reads monitor-config.json from the project root, polls each configured
metric source on its interval, and calls *incident_callback* whenever a
threshold is breached.

monitor-config.json schema example:
{
  "checks": [
    {
      "name": "checkout_error_rate",
      "source": "prometheus",
      "alert_text": "HTTP 500 error rate above threshold on checkout service",
      "threshold": 0.05,
      "interval_seconds": 30
    }
  ]
}

The monitor does NOT make real metric queries — it simulates a threshold
breach by comparing a configurable simulated_value field (default 0) against
the threshold.  Replace _poll_check() with real metric fetching as needed.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Awaitable, Callable

import random

import app.agent_log as agent_log

# Path to the config file — relative to repo root
_CONFIG_PATH = Path(__file__).parent.parent / "monitor-config.json"

# Tunable via env for local dev
_DEFAULT_INTERVAL = float(os.getenv("MONITOR_INTERVAL_SECONDS", "30"))
BREACH_PROBABILITY = float(os.getenv("BREACH_PROBABILITY", "0.15"))

IncidentCallback = Callable[[dict[str, Any]], Awaitable[None]]

_monitor_task: asyncio.Task | None = None


def _load_config() -> dict[str, Any]:
    if not _CONFIG_PATH.exists():
        return {"checks": []}
    with _CONFIG_PATH.open() as fh:
        return json.load(fh)


async def _poll_check(check: dict[str, Any], callback: IncidentCallback) -> None:
    """Evaluate a single check and invoke *callback* if the threshold is breached.

    A check fires when either:
      - simulated_value >= threshold  (explicit config-driven breach), or
      - random.random() < BREACH_PROBABILITY  (probabilistic — for local dev)
    """
    threshold = float(check.get("threshold", 1.0))
    simulated_value = float(check.get("simulated_value", 0.0))

    breached = simulated_value >= threshold or random.random() < BREACH_PROBABILITY
    if breached:
        alert = {
            "name": check.get("name", "unknown"),
            "source": check.get("source", "monitor"),
            "alert_text": check.get("alert_text", f"Threshold breached for {check.get('name')}"),
            "simulated_value": simulated_value,
            "threshold": threshold,
        }
        agent_log.append({"event": "monitor_threshold_breached", "check": alert["name"]})
        await callback(alert)


async def _monitor_loop(config: dict[str, Any], callback: IncidentCallback) -> None:
    """Run all checks on their configured intervals indefinitely."""
    checks = config.get("checks", [])
    if not checks:
        agent_log.append({"event": "monitor_started", "checks": 0, "note": "no checks configured"})
        return

    agent_log.append({"event": "monitor_started", "checks": len(checks)})

    # Track per-check next-run timestamps using a simple counter approach
    counters: dict[str, float] = {c.get("name", str(i)): 0.0 for i, c in enumerate(checks)}

    while True:
        for check in checks:
            name = check.get("name", "unknown")
            interval = float(check.get("interval_seconds", _DEFAULT_INTERVAL))
            if counters[name] <= 0:
                try:
                    await _poll_check(check, callback)
                except Exception as exc:
                    agent_log.append({"event": "monitor_poll_error", "check": name, "error": str(exc)})
                counters[name] = interval

        await asyncio.sleep(1)
        for name in counters:
            counters[name] = max(0.0, counters[name] - 1)


async def start(callback: IncidentCallback) -> None:
    """Start the background monitor loop.  Safe to call multiple times."""
    global _monitor_task
    if _monitor_task is not None and not _monitor_task.done():
        return
    config = _load_config()
    _monitor_task = asyncio.create_task(_monitor_loop(config, callback))


async def stop() -> None:
    """Cancel the background monitor loop if running."""
    global _monitor_task
    if _monitor_task is not None and not _monitor_task.done():
        _monitor_task.cancel()
        try:
            await _monitor_task
        except asyncio.CancelledError:
            pass
    _monitor_task = None
