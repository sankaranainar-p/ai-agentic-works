"""
app/remediation — Automated remediation package.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RemediationResult:
    """Outcome of a remediation handler."""

    action_taken: str
    simulated: bool
    success: bool
    details: str
    escalate: bool = False
    escalation_reason: str = ""
