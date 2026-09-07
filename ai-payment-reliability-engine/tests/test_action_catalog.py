"""
tests/test_action_catalog.py — Tests for action catalogue.

Verifies typed action creation and parameter handling.
"""

import pytest

from pre.policy.action_catalog import Action, ActionType


def test_action_restart():
    """Test restart action creation."""
    action = Action.restart("payment", "SEV-2", "TEST-001", 1000)
    assert action.action_type == ActionType.RESTART
    assert action.target_service == "payment"
    assert action.severity == "SEV-2"
    assert action.case_id == "TEST-001"
    assert action.timestamp == 1000


def test_action_scale():
    """Test scale action with parameters."""
    action = Action.scale(
        "payment", "SEV-2", "TEST-001", 1000, direction="up", replicas=5
    )
    assert action.action_type == ActionType.SCALE
    assert action.parameters["direction"] == "up"
    assert action.parameters["replicas"] == 5


def test_action_shed_load():
    """Test load shedding action."""
    action = Action.shed_load("payment", "SEV-3", "TEST-001", 1000, rate_limit_percent=70)
    assert action.action_type == ActionType.SHED_LOAD
    assert action.parameters["rate_limit_percent"] == 70


def test_action_reroute():
    """Test traffic reroute action."""
    action = Action.reroute("payment", "SEV-2", "TEST-001", 1000, destination="payment-backup")
    assert action.action_type == ActionType.REROUTE
    assert action.parameters["destination"] == "payment-backup"


def test_action_toggle_flag():
    """Test feature flag toggle action."""
    action = Action.toggle_flag(
        "payment", "SEV-3", "TEST-001", 1000, flag_name="new_checkout", enable=False
    )
    assert action.action_type == ActionType.TOGGLE_FLAG
    assert action.parameters["flag_name"] == "new_checkout"
    assert action.parameters["enable"] is False


def test_action_roll_back():
    """Test rollback action."""
    action = Action.roll_back("payment", "SEV-2", "TEST-001", 1000, version="v1.2.0")
    assert action.action_type == ActionType.ROLL_BACK
    assert action.parameters["version"] == "v1.2.0"


def test_action_escalate():
    """Test escalation action."""
    action = Action.escalate(
        "payment", "SEV-1", "TEST-001", 1000, escalation_level="oncall"
    )
    assert action.action_type == ActionType.ESCALATE
    assert action.parameters["escalation_level"] == "oncall"


def test_action_immutable():
    """Test that actions are immutable (frozen)."""
    action = Action.restart("payment", "SEV-2", "TEST-001", 1000)

    with pytest.raises(Exception):  # FrozenInstanceError from dataclass
        action.severity = "SEV-1"


def test_action_description():
    """Test action description generation."""
    action = Action.scale(
        "payment", "SEV-2", "TEST-001", 1000, direction="up", replicas=5
    )
    assert "payment" in action.description
    assert "5" in action.description
