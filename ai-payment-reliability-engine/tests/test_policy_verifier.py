"""
tests/test_policy_verifier.py — Tests for policy verifier and invariants.

Tests I1-I5 invariants and includes property tests using Hypothesis.
"""

import pytest
from hypothesis import given, strategies as st

from pre.policy.action_catalog import Action, ActionType
from pre.policy.verifier import PolicyVerifier, verify_action


def test_invariant_i1_degraded_node():
    """I1: No action targets degraded node."""
    degraded = {"payment"}
    verifier = PolicyVerifier(degraded_services=degraded)

    # Restart on degraded node should be blocked
    action = Action.restart("payment", "SEV-2", "TEST-001", 1000)
    result = verifier.verify(action)

    assert not result.approved
    assert "I1" in result.blocked_invariants


def test_invariant_i1_escalate_allowed():
    """I1: Escalate is allowed even on degraded nodes."""
    degraded = {"payment"}
    verifier = PolicyVerifier(degraded_services=degraded)

    action = Action.escalate("payment", "SEV-1", "TEST-001", 1000, "oncall")
    result = verifier.verify(action)

    assert "I1" not in result.blocked_invariants


def test_invariant_i1_healthy_node():
    """I1: Actions on healthy nodes pass."""
    degraded = {"payment"}
    verifier = PolicyVerifier(degraded_services=degraded)

    action = Action.restart("checkout", "SEV-2", "TEST-001", 1000)
    result = verifier.verify(action)

    assert "I1" not in result.blocked_invariants


def test_invariant_i2_recent_action_blocked():
    """I2: No two actions on same target within 120s."""
    action_history = {
        ("payment", 900): Action.restart("payment", "SEV-2", "TEST-001", 900)
    }
    verifier = PolicyVerifier(action_history=action_history)

    # Action within 120s should be blocked
    new_action = Action.restart("payment", "SEV-2", "TEST-002", 950)
    result = verifier.verify(new_action)

    assert not result.approved
    assert "I2" in result.blocked_invariants


def test_invariant_i2_old_action_allowed():
    """I2: Actions on same target after 120s are allowed."""
    action_history = {
        ("payment", 800): Action.restart("payment", "SEV-2", "TEST-001", 800)
    }
    verifier = PolicyVerifier(action_history=action_history)

    # Action after 120s should be allowed
    new_action = Action.restart("payment", "SEV-2", "TEST-002", 950)
    result = verifier.verify(new_action)

    assert "I2" not in result.blocked_invariants


def test_invariant_i3_sev1_must_escalate():
    """I3: SEV-1 always escalates (never cheaper actions)."""
    verifier = PolicyVerifier()

    # SEV-1 with non-escalation action should be blocked
    action = Action.restart("payment", "SEV-1", "TEST-001", 1000)
    result = verifier.verify(action)

    assert not result.approved
    assert "I3" in result.blocked_invariants


def test_invariant_i3_sev1_escalate_ok():
    """I3: SEV-1 escalation is allowed."""
    verifier = PolicyVerifier()

    action = Action.escalate("payment", "SEV-1", "TEST-001", 1000, "oncall")
    result = verifier.verify(action)

    assert "I3" not in result.blocked_invariants


def test_invariant_i3_lower_severity_ok():
    """I3: SEV-2/3/4 can use any action."""
    verifier = PolicyVerifier()

    for severity in ["SEV-2", "SEV-3", "SEV-4"]:
        action = Action.restart("payment", severity, "TEST-001", 1000)
        result = verifier.verify(action)
        assert "I3" not in result.blocked_invariants


def test_invariant_i4_escalate_sev1_sev2_ok():
    """I4: Escalation allowed for SEV-1 and SEV-2."""
    verifier = PolicyVerifier()

    for severity in ["SEV-1", "SEV-2"]:
        action = Action.escalate("payment", severity, "TEST-001", 1000, "oncall")
        result = verifier.verify(action)
        assert "I4" not in result.blocked_invariants


def test_invariant_i4_escalate_low_severity_blocked():
    """I4: Escalation blocked for SEV-3 and SEV-4."""
    verifier = PolicyVerifier()

    for severity in ["SEV-3", "SEV-4"]:
        action = Action.escalate("payment", severity, "TEST-001", 1000, "oncall")
        result = verifier.verify(action)
        assert not result.approved
        assert "I4" in result.blocked_invariants


def test_invariant_i5_scale_up_within_limit():
    """I5: Scale-up within 50% increase is allowed."""
    verifier = PolicyVerifier()

    # Baseline 10, scaling to 15 is 50% increase
    action = Action.scale("payment", "SEV-2", "TEST-001", 1000, "up", 15)
    result = verifier.verify(action)

    assert "I5" not in result.blocked_invariants


def test_invariant_i5_scale_up_exceeds_limit():
    """I5: Scale-up exceeding 50% is blocked."""
    verifier = PolicyVerifier()

    # Baseline 10, scaling to 20 is 100% increase (exceeds limit)
    action = Action.scale("payment", "SEV-2", "TEST-001", 1000, "up", 20)
    result = verifier.verify(action)

    assert not result.approved
    assert "I5" in result.blocked_invariants


def test_invariant_i5_scale_down_always_ok():
    """I5: Scale-down is always allowed."""
    verifier = PolicyVerifier()

    action = Action.scale("payment", "SEV-3", "TEST-001", 1000, "down", 1)
    result = verifier.verify(action)

    assert "I5" not in result.blocked_invariants


# Property tests with Hypothesis

@given(
    service=st.sampled_from(["payment", "checkout", "bank"]),
    severity=st.sampled_from(["SEV-1", "SEV-2", "SEV-3", "SEV-4"]),
)
def test_property_sev1_always_escalates(service, severity):
    """Property: No approved SEV-1 action is non-escalation."""
    verifier = PolicyVerifier()

    action = Action.restart(service, severity, "TEST-001", 1000)
    result = verifier.verify(action)

    if severity == "SEV-1":
        assert not result.approved, f"SEV-1 {action.action_type} should not be approved"


@given(
    service=st.sampled_from(["payment", "checkout", "bank"]),
    ts1=st.integers(min_value=1000, max_value=2000),
)
def test_property_no_duplicate_approvals_within_120s(service, ts1):
    """Property: No two approved actions on same target within 120s."""
    action_history = {
        (service, ts1): Action.restart(service, "SEV-2", "TEST-001", ts1)
    }
    verifier = PolicyVerifier(action_history=action_history)

    # Try to execute another action on same service within 120s
    ts2 = ts1 + 60  # 60s later (within 120s window)
    new_action = Action.restart(service, "SEV-2", "TEST-002", ts2)
    result = verifier.verify(new_action)

    # Same service within 120s: should fail I2
    assert not result.approved, f"Duplicate action on {service} within 120s should fail"
    assert "I2" in result.blocked_invariants


@given(
    direction=st.sampled_from(["up", "down"]),
    replicas=st.integers(min_value=1, max_value=30),
)
def test_property_scaling_bounds(direction, replicas):
    """Property: Scale-up bounded, scale-down unbounded."""
    verifier = PolicyVerifier()
    action = Action.scale("payment", "SEV-2", "TEST-001", 1000, direction, replicas)
    result = verifier.verify(action)

    baseline = 10
    max_allowed = int(baseline * 1.5)

    if direction == "down":
        assert "I5" not in result.blocked_invariants, "Scale-down should always pass I5"
    elif replicas <= max_allowed:
        assert "I5" not in result.blocked_invariants, f"Scale-up to {replicas} within limit"
    else:
        assert "I5" in result.blocked_invariants, f"Scale-up to {replicas} exceeds limit"
