"""
app/verification.py — Post-remediation incident verification.

Waits VERIFY_WAIT_SECONDS (env, default 10) then simulates a metric
re-poll to determine whether the incident has resolved.
"""

from __future__ import annotations

import asyncio
import os
import random
from typing import Any


def _wait_seconds() -> float:
    return float(os.getenv("VERIFY_WAIT_SECONDS", "10"))


async def verify(
    category: str,
    severity: str,
    alert_text: str,
    remediation_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wait, then simulate a metric re-poll for the given incident.

    Returns a dict with keys:
        status          "resolved" | "unresolved"
        category        echoed back
        severity        echoed back
        wait_seconds    how long we waited
        simulated       always True — replace body with real metric fetch
        details         human-readable outcome description
    """
    wait = _wait_seconds()
    await asyncio.sleep(wait)

    # Simulated resolution probability — higher confidence for less severe incidents
    resolution_chance = {
        "SEV-1": 0.55,
        "SEV-2": 0.70,
        "SEV-3": 0.85,
        "SEV-4": 0.95,
    }.get(severity, 0.70)

    resolved = random.random() < resolution_chance
    status = "resolved" if resolved else "unresolved"

    details_map = {
        True:  f"Metrics returned to normal after remediation for {category}.",
        False: f"Metrics still anomalous after remediation for {category}. Manual review required.",
    }

    return {
        "status": status,
        "category": category,
        "severity": severity,
        "wait_seconds": wait,
        "simulated": True,
        "details": details_map[resolved],
    }
