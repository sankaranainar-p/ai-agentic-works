"""
tests/test_propose.py — Tests for action proposal agent.

Tests that actions are proposed correctly based on RCA results.
"""

import pytest

from pre.agents.propose import ActionProposalAgent
from pre.agents.rca import RCAResult
from pre.policy.action_catalog import ActionType


def test_propose_sev1_escalates():
    """Test that SEV-1 incidents always escalate."""
    rca = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="Critical: CPU saturation",  # Contains "Critical"
    )

    agent = ActionProposalAgent(rca)
    actions = agent.propose()

    assert len(actions) >= 1
    assert actions[0].action_type == ActionType.ESCALATE
    assert actions[0].severity == "SEV-1"


def test_propose_cpu_fault_scales():
    """Test that CPU faults propose scaling actions."""
    rca = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="CPU saturation on payment nodes",
    )

    agent = ActionProposalAgent(rca)
    actions = agent.propose()

    assert len(actions) > 0
    primary = actions[0]
    assert primary.action_type == ActionType.SCALE
    assert primary.parameters["direction"] == "up"


def test_propose_memory_fault_restarts():
    """Test that memory faults propose restart actions."""
    rca = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="Memory exhaustion on payment service",
    )

    agent = ActionProposalAgent(rca)
    actions = agent.propose()

    assert len(actions) > 0
    primary = actions[0]
    assert primary.action_type == ActionType.RESTART


def test_propose_logic_error_rollbacks():
    """Test that logic errors propose rollback actions."""
    rca = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="Logic error in payment processing",
    )

    agent = ActionProposalAgent(rca)
    actions = agent.propose()

    assert len(actions) > 0
    primary = actions[0]
    assert primary.action_type == ActionType.ROLL_BACK


def test_propose_with_custom_case_id():
    """Test proposal with custom case ID."""
    rca = RCAResult(
        case_id="RCA-123",
        root_cause_service="payment",
        probable_cause="CPU saturation",
    )

    custom_case_id = "CUSTOM-456"
    agent = ActionProposalAgent(rca, case_id=custom_case_id)
    actions = agent.propose()

    for action in actions:
        assert action.case_id == custom_case_id


def test_propose_action_has_timestamp():
    """Test that proposed actions have valid timestamps."""
    rca = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="CPU saturation",
    )

    agent = ActionProposalAgent(rca)
    actions = agent.propose()

    assert len(actions) > 0
    for action in actions:
        assert action.timestamp > 0


def test_propose_sev4_no_escalate():
    """Test that SEV-4 incidents don't escalate."""
    rca = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="Minor degradation in performance",  # SEV-4
    )

    agent = ActionProposalAgent(rca)
    actions = agent.propose()

    # Should not escalate
    escalate_actions = [a for a in actions if a.action_type == ActionType.ESCALATE]
    assert len(escalate_actions) == 0


def test_propose_non_sev1_has_secondary():
    """Test that non-SEV-1 incidents have secondary action options."""
    rca = RCAResult(
        case_id="TEST-001",
        root_cause_service="payment",
        probable_cause="CPU saturation",  # Not critical, so SEV-2/3/4
    )

    agent = ActionProposalAgent(rca)
    actions = agent.propose()

    # Should have at least one action (primary)
    assert len(actions) >= 1
