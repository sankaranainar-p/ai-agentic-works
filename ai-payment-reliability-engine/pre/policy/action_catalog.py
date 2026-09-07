"""
pre/policy/action_catalog.py — Typed remediation actions.

Actions are the set of operations available to the remediation agent.
Each action is immutable and fully typed. Actions flow through the policy
verifier for invariant checking before execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ActionType(Enum):
    """Remediation action types."""

    RESTART = "restart"  # Restart a service
    SCALE = "scale"  # Horizontal or vertical scaling
    SHED_LOAD = "shed_load"  # Gracefully reduce load (rate limiting, circuit break)
    REROUTE = "reroute"  # Route traffic away from degraded service
    TOGGLE_FLAG = "toggle_flag"  # Enable/disable feature flag
    ROLL_BACK = "roll_back"  # Rollback deployment or config
    ESCALATE = "escalate"  # Escalate to on-call via PagerDuty/Slack


@dataclass(frozen=True)
class Action:
    """A single remediation action with typed parameters."""

    action_type: ActionType
    target_service: str  # Service to remediate
    severity: str  # SEV-1, SEV-2, SEV-3, SEV-4
    case_id: str  # Incident case ID
    timestamp: int  # Unix seconds when action was proposed
    description: str  # Human-readable description
    parameters: dict = None  # Type-specific parameters

    def __post_init__(self):
        if self.parameters is None:
            object.__setattr__(self, "parameters", {})

    @staticmethod
    def restart(
        target_service: str,
        severity: str,
        case_id: str,
        timestamp: int,
    ) -> Action:
        """Create a restart action."""
        return Action(
            action_type=ActionType.RESTART,
            target_service=target_service,
            severity=severity,
            case_id=case_id,
            timestamp=timestamp,
            description=f"Restart {target_service}",
            parameters={},
        )

    @staticmethod
    def scale(
        target_service: str,
        severity: str,
        case_id: str,
        timestamp: int,
        direction: str,  # "up" or "down"
        replicas: int,
    ) -> Action:
        """Create a scaling action."""
        return Action(
            action_type=ActionType.SCALE,
            target_service=target_service,
            severity=severity,
            case_id=case_id,
            timestamp=timestamp,
            description=f"Scale {target_service} {direction} to {replicas} replicas",
            parameters={"direction": direction, "replicas": replicas},
        )

    @staticmethod
    def shed_load(
        target_service: str,
        severity: str,
        case_id: str,
        timestamp: int,
        rate_limit_percent: int,  # 0-100
    ) -> Action:
        """Create a load-shedding action."""
        return Action(
            action_type=ActionType.SHED_LOAD,
            target_service=target_service,
            severity=severity,
            case_id=case_id,
            timestamp=timestamp,
            description=f"Shed {100-rate_limit_percent}% load from {target_service}",
            parameters={"rate_limit_percent": rate_limit_percent},
        )

    @staticmethod
    def reroute(
        target_service: str,
        severity: str,
        case_id: str,
        timestamp: int,
        destination: str,
    ) -> Action:
        """Create a traffic reroute action."""
        return Action(
            action_type=ActionType.REROUTE,
            target_service=target_service,
            severity=severity,
            case_id=case_id,
            timestamp=timestamp,
            description=f"Reroute traffic from {target_service} to {destination}",
            parameters={"destination": destination},
        )

    @staticmethod
    def toggle_flag(
        target_service: str,
        severity: str,
        case_id: str,
        timestamp: int,
        flag_name: str,
        enable: bool,
    ) -> Action:
        """Create a feature flag toggle action."""
        return Action(
            action_type=ActionType.TOGGLE_FLAG,
            target_service=target_service,
            severity=severity,
            case_id=case_id,
            timestamp=timestamp,
            description=f"{'Enable' if enable else 'Disable'} flag {flag_name} on {target_service}",
            parameters={"flag_name": flag_name, "enable": enable},
        )

    @staticmethod
    def roll_back(
        target_service: str,
        severity: str,
        case_id: str,
        timestamp: int,
        version: str,
    ) -> Action:
        """Create a rollback action."""
        return Action(
            action_type=ActionType.ROLL_BACK,
            target_service=target_service,
            severity=severity,
            case_id=case_id,
            timestamp=timestamp,
            description=f"Rollback {target_service} to {version}",
            parameters={"version": version},
        )

    @staticmethod
    def escalate(
        target_service: str,
        severity: str,
        case_id: str,
        timestamp: int,
        escalation_level: str,  # "oncall", "team_lead", "vp"
    ) -> Action:
        """Create an escalation action."""
        return Action(
            action_type=ActionType.ESCALATE,
            target_service=target_service,
            severity=severity,
            case_id=case_id,
            timestamp=timestamp,
            description=f"Escalate {target_service} incident to {escalation_level}",
            parameters={"escalation_level": escalation_level},
        )
