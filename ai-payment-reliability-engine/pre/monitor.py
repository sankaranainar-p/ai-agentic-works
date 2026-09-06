"""
pre/monitor.py — Background asyncio monitor loop.

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

Explicit breaches (simulated_value >= threshold) are always detected.
Probabilistic breach detection (for local dev, when no simulated_value is
configured) is a stub — see _probabilistic_breach() below.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Awaitable, Callable

import pre.agent_log as agent_log

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


def _probabilistic_breach(check: dict[str, Any]) -> bool:
    """Probabilistic breach detection used when a check has no real
    simulated_value signal, for local dev without a live metric source.

    TODO(pre.telemetry.metrics_client): replace this stub with a real
    metric fetch against the check's configured source (e.g. Prometheus
    query for the service+metric named in data/taxonomy.yaml `sli_map`)
    and compare the live value against `threshold`.
    """
    raise NotImplementedError(
        "Probabilistic breach detection is a stub. Implement "
        "pre.telemetry.metrics_client to fetch the real metric for this "
        "check and compare it against `threshold`, then call it from here."
    )


async def _poll_check(check: dict[str, Any], callback: IncidentCallback) -> None:
    """Evaluate a single check and invoke *callback* if the threshold is breached.

    Explicit config-driven breach (simulated_value >= threshold) is checked
    first and always works. Only when that doesn't fire do we fall back to
    probabilistic detection, which is currently a stub (see
    _probabilistic_breach) pending a real metrics client.
    """
    threshold = float(check.get("threshold", 1.0))
    simulated_value = float(check.get("simulated_value", 0.0))

    breached = simulated_value >= threshold
    if not breached:
        breached = _probabilistic_breach(check)

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
