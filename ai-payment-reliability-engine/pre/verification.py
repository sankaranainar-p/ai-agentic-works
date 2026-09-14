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
    """Re-poll the real SLI to determine whether the incident has resolved.

    Live-testbed path (A13): set A13_VERIFY_SLI to a payment_sli name (see
    data/taxonomy.yaml) and PROM_URL to a reachable Prometheus; resolution is
    then decided by pre.verify.kpi_verifier.wait_for_recovery — the SLI must
    hold inside its objective for the sustained interval (PROTOCOL.md).

    Without A13_VERIFY_SLI there is no real metric source wired, so this stays
    a stub rather than guessing.
    """
    sli = os.getenv("A13_VERIFY_SLI")
    if sli:
        from pre.verify.kpi_verifier import wait_for_recovery

        return wait_for_recovery(sli).recovered

    raise NotImplementedError(
        "Resolution check is a stub. Set A13_VERIFY_SLI (+ PROM_URL) to verify "
        "against the live testbed via pre.verify.kpi_verifier, or implement a "
        "metric re-poll against the SLI mapped in data/taxonomy.yaml sli_map."
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
