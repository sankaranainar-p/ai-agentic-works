"""
tests/test_orchestrator.py — Tests for pipeline orchestrator and audit ledger.

Verifies step execution, timeout detection, and ledger recording.
"""

import tempfile
import time
from pathlib import Path

import pytest

from pre.agents.orchestrator import Orchestrator, StepTimeout
from pre.audit.ledger import Ledger, StepOutcome


def test_orchestrator_simple_pipeline():
    """Test running a simple pipeline."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = Ledger(Path(tmpdir) / "audit.jsonl")
        orchestrator = Orchestrator(ledger)

        # Add simple steps
        orchestrator.add_step(
            "step1",
            lambda ctx: ("result1", 10),
            wall_budget=5.0,
            token_budget=100,
        )
        orchestrator.add_step(
            "step2",
            lambda ctx: ("result2", 20),
            wall_budget=5.0,
            token_budget=100,
        )

        # Run pipeline
        results = orchestrator.run()

        assert "step1" in results
        assert "step2" in results
        assert results["step1"] == "result1"
        assert results["step2"] == "result2"


def test_orchestrator_timeout_detection():
    """Test timeout detection and StepTimeout exception."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = Ledger(Path(tmpdir) / "audit.jsonl")
        orchestrator = Orchestrator(ledger)

        # Add step that exceeds time budget
        def slow_step(ctx):
            time.sleep(0.2)
            return ("result", 10)

        orchestrator.add_step(
            "slow_step",
            slow_step,
            wall_budget=0.05,  # 50ms budget, will timeout
            token_budget=0,
        )

        # Should raise StepTimeout
        with pytest.raises(StepTimeout):
            orchestrator.run()


def test_orchestrator_error_handling():
    """Test error handling and ledger recording."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = Ledger(Path(tmpdir) / "audit.jsonl")
        orchestrator = Orchestrator(ledger)

        # Add step that raises an error
        def error_step(ctx):
            raise ValueError("Test error")

        orchestrator.add_step("error_step", error_step)

        # Should raise the error
        with pytest.raises(ValueError):
            orchestrator.run()

        # Ledger should record the error
        outcomes = ledger.read()
        assert len(outcomes) == 1
        assert outcomes[0].success is False
        assert "Test error" in outcomes[0].error


def test_orchestrator_token_tracking():
    """Test token budget tracking."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = Ledger(Path(tmpdir) / "audit.jsonl")
        orchestrator = Orchestrator(ledger)

        orchestrator.add_step("step1", lambda ctx: ("r1", 100), token_budget=200)
        orchestrator.add_step("step2", lambda ctx: ("r2", 50), token_budget=200)

        orchestrator.run()

        assert orchestrator.total_tokens == 150


def test_ledger_record_and_read():
    """Test ledger recording and reading."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = Ledger(Path(tmpdir) / "audit.jsonl")

        # Record outcomes
        outcome1 = StepOutcome("step1", True, 1.5, tokens_used=100)
        outcome2 = StepOutcome("step2", False, 2.0, error="failed")

        ledger.record(outcome1)
        ledger.record(outcome2)

        # Read back
        outcomes = ledger.read()
        assert len(outcomes) == 2
        assert outcomes[0].step_name == "step1"
        assert outcomes[0].success is True
        assert outcomes[1].step_name == "step2"
        assert outcomes[1].success is False


def test_ledger_validation():
    """Test ledger validation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = Ledger(Path(tmpdir) / "audit.jsonl")

        # Empty ledger should be invalid
        is_valid, msg = ledger.validate()
        assert not is_valid

        # Record outcome
        outcome = StepOutcome("step1", True, 1.0)
        ledger.record(outcome)

        # Now should be valid
        is_valid, msg = ledger.validate()
        assert is_valid


def test_ledger_summary():
    """Test ledger summary statistics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = Ledger(Path(tmpdir) / "audit.jsonl")

        ledger.record(StepOutcome("step1", True, 1.0, tokens_used=100))
        ledger.record(StepOutcome("step2", True, 0.5, tokens_used=50))
        ledger.record(StepOutcome("step3", False, 0.1, error="failed"))
        ledger.record(StepOutcome("step4", False, 2.0, timed_out=True))

        summary = ledger.summary()

        assert summary["total_steps"] == 4
        assert summary["successful_steps"] == 2
        assert summary["failed_steps"] == 2
        assert summary["timeout_count"] == 1
        assert summary["total_tokens"] == 150
        assert summary["total_wall_seconds"] == pytest.approx(3.6, abs=0.1)
