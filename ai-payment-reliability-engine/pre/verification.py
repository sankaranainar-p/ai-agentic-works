"""
pre/verification.py — Post-remediation incident verification.

Waits VERIFY_WAIT_SECONDS (env, default 10) then re-polls metrics to
determine whether the incident has resolved.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any


def _wait_seconds() -> float:
    return float(os.getenv("VERIFY_WAIT_SECONDS", "10"))


def _check_resolution(category: str, severity: str, alert_text: str) -> bool:
    """Re-poll the real metric source to determine whether the incident
    has resolved.

    TODO(pre.telemetry.metrics_client): replace this stub with a real
    metric re-poll against the payment_sli mapped for the affected
    service (see data/taxonomy.yaml `sli_map`), e.g. querying Prometheus
    for the SLI's current value and comparing it against its threshold.
    """
    raise NotImplementedError(
        "Resolution check is a stub. Implement pre.telemetry.metrics_client "
        "to re-poll the real SLI (see data/taxonomy.yaml sli_map) and "
        "compare against its threshold, then call it from here."
    )


async def verify(
    category: str,
    severity: str,
    alert_text: str,
    remediation_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wait, then re-poll metrics for the given incident.

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

    resolved = _check_resolution(category, severity, alert_text)
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
