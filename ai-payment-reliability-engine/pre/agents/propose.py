"""
pre/agents/propose.py — Action proposal agent that selects remediation actions.

Given an RCA result, propose one or more actions from the catalogue.
Actions flow through the policy verifier before execution.
"""

from __future__ import annotations

import time
from typing import Optional

from pre.agents.rca import RCAResult
from pre.policy.action_catalog import Action, ActionType


class ActionProposalAgent:
    """Proposes remediation actions given RCA results."""

    # Map fault classes to primary action types
    FAULT_CLASS_TO_ACTION = {
        "cpu": ActionType.SCALE,
        "memory": ActionType.RESTART,
        "disk": ActionType.SCALE,
        "socket": ActionType.SCALE,
        "delay": ActionType.REROUTE,
        "loss": ActionType.REROUTE,
        "logic_error": ActionType.ROLL_BACK,
        "concurrency_issue": ActionType.SHED_LOAD,
        "api_compatibility_issue": ActionType.ROLL_BACK,
        "performance_bottleneck": ActionType.SCALE,
        "exception_handling_error": ActionType.ROLL_BACK,
        "configuration_error": ActionType.ROLL_BACK,
        "dependency_failure": ActionType.REROUTE,
    }

    def __init__(self, rca_result: RCAResult, case_id: Optional[str] = None):
        """Initialize proposal agent with RCA result.

        Args:
            rca_result: RCA result with root cause and severity
            case_id: Case ID (defaults to rca_result.case_id)
        """
        self.rca_result = rca_result
        self.case_id = case_id or rca_result.case_id
        self.timestamp = int(time.time())

    def propose(self) -> list[Action]:
        """Propose actions for the incident.

        Returns:
            List of actions selected from the catalogue, ordered by severity/urgency
        """
        actions = []

        # Always escalate SEV-1
        if self._is_sev_1():
            actions.append(self._propose_escalate())
            # Don't propose additional actions for SEV-1; escalation handles it
            return actions

        # Propose primary action based on root cause
        primary_action = self._propose_primary_action()
        if primary_action:
            actions.append(primary_action)

        # Optionally propose secondary actions (load shedding as fallback)
        if not self._is_sev_4():
            secondary = self._propose_secondary_action()
            if secondary:
                actions.append(secondary)

        return actions

    def _is_sev_1(self) -> bool:
        """Check if this is a SEV-1 incident."""
        return self.rca_result.probable_cause and "SEV-1" in self._infer_severity()

    def _is_sev_4(self) -> bool:
        """Check if this is a SEV-4 incident."""
        return "SEV-4" in self._infer_severity()

    def _infer_severity(self) -> str:
        """Infer severity level from context (would come from triage result in production)."""
        # This is a simplified inference; in production, severity comes from triage agent
        if "critical" in self.rca_result.probable_cause.lower():
            return "SEV-1"
        if "error" in self.rca_result.probable_cause.lower():
            return "SEV-2"
        if "degraded" in self.rca_result.probable_cause.lower():
            return "SEV-3"
        return "SEV-4"

    def _propose_primary_action(self) -> Optional[Action]:
        """Propose primary action based on root cause service and fault class."""
        # Get action type from fault class
        action_type = self.FAULT_CLASS_TO_ACTION.get(
            self._fault_class(),
            ActionType.SHED_LOAD,  # Default to load shedding
        )

        service = self.rca_result.root_cause_service or "unknown"
        severity = self._infer_severity()

        # Factory method calls
        if action_type == ActionType.RESTART:
            return Action.restart(service, severity, self.case_id, self.timestamp)

        elif action_type == ActionType.SCALE:
            return Action.scale(
                service, severity, self.case_id, self.timestamp, "up", 5  # Default scale to 5 replicas
            )

        elif action_type == ActionType.SHED_LOAD:
            return Action.shed_load(
                service, severity, self.case_id, self.timestamp, 70  # Keep 70% of load
            )

        elif action_type == ActionType.REROUTE:
            backup_service = self._find_backup_service(service)
            return Action.reroute(service, severity, self.case_id, self.timestamp, backup_service)

        elif action_type == ActionType.ROLL_BACK:
            return Action.roll_back(
                service, severity, self.case_id, self.timestamp, "latest-stable"
            )

        return None

    def _propose_secondary_action(self) -> Optional[Action]:
        """Propose secondary action (fallback to load shedding if possible)."""
        service = self.rca_result.root_cause_service or "unknown"
        severity = self._infer_severity()

        # Secondary action is always load shedding (if not already the primary)
        primary_action = self._propose_primary_action()
        if primary_action and primary_action.action_type != ActionType.SHED_LOAD:
            return Action.shed_load(
                service, severity, self.case_id, self.timestamp, 80  # Shed 20% load
            )

        return None

    def _propose_escalate(self) -> Action:
        """Propose escalation action for SEV-1."""
        service = self.rca_result.root_cause_service or "payment"
        return Action.escalate(
            service,
            "SEV-1",
            self.case_id,
            self.timestamp,
            escalation_level="oncall",
        )

    def _fault_class(self) -> str:
        """Extract fault class from probable cause."""
        # Simplified; in production this would be from the triage/RCA result
        probable_cause = self.rca_result.probable_cause.lower()

        fault_classes = [
            "cpu", "memory", "disk", "socket", "delay", "loss",
            "logic_error", "concurrency_issue", "api_compatibility_issue",
            "performance_bottleneck", "exception_handling_error",
            "configuration_error", "dependency_failure",
        ]

        for fc in fault_classes:
            if fc.replace("_", " ") in probable_cause:
                return fc

        return "unknown"

    def _find_backup_service(self, service: str) -> str:
        """Find a backup service for rerouting (placeholder)."""
        # In production, would query service topology
        backup_map = {
            "payment": "payment-backup",
            "checkout": "checkout-backup",
            "bank": "bank-backup",
        }
        return backup_map.get(service, f"{service}-backup")
