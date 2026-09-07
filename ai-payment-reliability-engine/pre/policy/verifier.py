"""
pre/policy/verifier.py — Policy verifier implementing remediation invariants.

Invariants (I1–I5):
  I1: No action targets a node currently in degraded state (failing health checks)
  I2: No two actions on the same target within 120 seconds
  I3: SEV-1 incidents always escalate (never suppress with cheaper actions)
  I4: Escalation only on SEV-1/SEV-2 (never escalate for SEV-3/SEV-4)
  I5: Scaling actions capped at 50% of original (prevent runaway scale-up)

Pure function: no side effects, deterministic, fully testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pre.policy.action_catalog import Action, ActionType


@dataclass(frozen=True)
class VerificationResult:
    """Result of policy verification."""

    approved: bool  # Action passes all invariants
    blocked_invariants: list[str]  # Which invariants failed (e.g., ["I1", "I3"])
    reason: str  # Human-readable explanation


class PolicyVerifier:
    """Pure function verifier implementing invariants I1-I5."""

    # Degraded services (would come from health check system in production)
    DEGRADED_SERVICES: set[str] = set()

    # Action history: (service, timestamp) -> action
    ACTION_HISTORY: dict[tuple[str, int], Action] = {}

    def __init__(
        self,
        degraded_services: Optional[set[str]] = None,
        action_history: Optional[dict[tuple[str, int], Action]] = None,
    ):
        """Initialize verifier with context.

        Args:
            degraded_services: Set of services currently failing health checks
            action_history: Dict of (service, timestamp) -> Action for recent actions
        """
        self.degraded_services = degraded_services or set()
        self.action_history = action_history or {}

    def verify(self, action: Action) -> VerificationResult:
        """Verify an action against all invariants.

        Returns:
            VerificationResult with approval status and blocked invariants
        """
        blocked = []

        # I1: No action targets degraded node
        if not self._check_i1(action):
            blocked.append("I1")

        # I2: No two actions on same target within 120s
        if not self._check_i2(action):
            blocked.append("I2")

        # I3: SEV-1 always escalates
        if not self._check_i3(action):
            blocked.append("I3")

        # I4: Escalation only on SEV-1/SEV-2
        if not self._check_i4(action):
            blocked.append("I4")

        # I5: Scaling capped at 50% of original
        if not self._check_i5(action):
            blocked.append("I5")

        approved = len(blocked) == 0
        reason = self._reason_for_blocked(action, blocked, approved)

        return VerificationResult(
            approved=approved,
            blocked_invariants=blocked,
            reason=reason,
        )

    def _check_i1(self, action: Action) -> bool:
        """I1: No action targets a degraded node.

        Exception: Escalate actions are always allowed (reporting issue, not executing).
        """
        if action.action_type == ActionType.ESCALATE:
            return True  # Escalate can target degraded nodes

        return action.target_service not in self.degraded_services

    def _check_i2(self, action: Action) -> bool:
        """I2: No two actions on same target within 120 seconds."""
        # Find recent actions on the same service
        recent_threshold = action.timestamp - 120

        for (service, ts), prev_action in self.action_history.items():
            if service == action.target_service and ts >= recent_threshold:
                return False  # Found a recent action on same target

        return True

    def _check_i3(self, action: Action) -> bool:
        """I3: SEV-1 always escalates (never suppress with cheaper actions).

        If severity is SEV-1, the action must be ESCALATE.
        """
        if action.severity == "SEV-1":
            return action.action_type == ActionType.ESCALATE

        return True  # Non-SEV-1 actions are unconstrained

    def _check_i4(self, action: Action) -> bool:
        """I4: Escalation only on SEV-1/SEV-2 (never escalate low severity).

        If action is ESCALATE, severity must be SEV-1 or SEV-2.
        """
        if action.action_type == ActionType.ESCALATE:
            return action.severity in ("SEV-1", "SEV-2")

        return True  # Non-escalation actions are unconstrained

    def _check_i5(self, action: Action) -> bool:
        """I5: Scaling capped at 50% of original replica count.

        Scale-up actions fail if replicas > 50% of baseline (we'll use 10 as default baseline).
        Scale-down is always allowed.
        """
        if action.action_type != ActionType.SCALE:
            return True  # Only scaling actions are subject to this limit

        direction = action.parameters.get("direction", "")
        if direction == "down":
            return True  # Scale-down is always allowed

        # Scale-up: check replicas don't exceed 50% of baseline
        replicas = action.parameters.get("replicas", 0)
        baseline_replicas = 10  # Default baseline in production would come from cluster state

        # Approve if scaling to at most 150% of baseline (50% increase)
        max_allowed = int(baseline_replicas * 1.5)
        return replicas <= max_allowed

    def _reason_for_blocked(
        self,
        action: Action,
        blocked: list[str],
        approved: bool,
    ) -> str:
        """Generate human-readable reason for approval/rejection."""
        if approved:
            return f"Action approved: {action.description}"

        reasons = []
        for inv in blocked:
            if inv == "I1":
                reasons.append(
                    f"I1 violation: {action.target_service} is degraded (failing health checks)"
                )
            elif inv == "I2":
                reasons.append(
                    f"I2 violation: Recent action on {action.target_service} within 120s"
                )
            elif inv == "I3":
                reasons.append("I3 violation: SEV-1 must escalate, not perform cheaper action")
            elif inv == "I4":
                reasons.append("I4 violation: Escalation only allowed for SEV-1/SEV-2")
            elif inv == "I5":
                replicas = action.parameters.get("replicas", 0)
                reasons.append(
                    f"I5 violation: Scale-up to {replicas} exceeds 50% increase limit"
                )

        return f"Action blocked: {'; '.join(reasons)}"


def verify_action(
    action: Action,
    degraded_services: Optional[set[str]] = None,
    action_history: Optional[dict[tuple[str, int], Action]] = None,
) -> VerificationResult:
    """Pure function: verify action against invariants.

    Args:
        action: Action to verify
        degraded_services: Services currently degraded
        action_history: Recent action history

    Returns:
        VerificationResult with approval status
    """
    verifier = PolicyVerifier(degraded_services, action_history)
    return verifier.verify(action)
