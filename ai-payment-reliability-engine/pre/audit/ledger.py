"""
pre/audit/ledger.py — Append-only JSONL ledger for audit trail.

Each step in the pipeline records a JSON object with:
- Step name and outcome
- Wall-clock time (seconds and microseconds)
- Token usage
- Errors/timeouts
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class StepOutcome:
    """Outcome of a pipeline step."""

    step_name: str
    success: bool
    wall_seconds: float
    tokens_used: int = 0
    error: Optional[str] = None
    timed_out: bool = False
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", time.time())


class Ledger:
    """Append-only JSONL ledger for audit trail."""

    def __init__(self, path: str | Path = "audit.jsonl"):
        """Initialize ledger.

        Args:
            path: Path to JSONL ledger file
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, outcome: StepOutcome) -> None:
        """Record a step outcome to the ledger.

        Args:
            outcome: StepOutcome to record
        """
        record = asdict(outcome)
        line = json.dumps(record)
        with open(self.path, "a") as f:
            f.write(line + "\n")

    def read(self) -> list[StepOutcome]:
        """Read all records from ledger.

        Returns:
            List of StepOutcome objects in order
        """
        outcomes = []
        if not self.path.exists():
            return outcomes

        with open(self.path) as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    outcome = StepOutcome(**data)
                    outcomes.append(outcome)

        return outcomes

    def validate(self) -> tuple[bool, str]:
        """Validate ledger against schema.

        Returns:
            (is_valid: bool, message: str)
        """
        if not self.path.exists():
            return False, "Ledger file does not exist"

        try:
            outcomes = self.read()
            if not outcomes:
                return False, "Ledger is empty"

            for outcome in outcomes:
                if not isinstance(outcome.step_name, str):
                    return False, f"Invalid step_name: {outcome.step_name}"
                if not isinstance(outcome.success, bool):
                    return False, f"Invalid success: {outcome.success}"
                if not isinstance(outcome.wall_seconds, (int, float)):
                    return False, f"Invalid wall_seconds: {outcome.wall_seconds}"
                if outcome.error and not isinstance(outcome.error, str):
                    return False, f"Invalid error: {outcome.error}"

            return True, "Ledger is valid"
        except Exception as e:
            return False, f"Validation error: {e}"

    def summary(self) -> dict:
        """Summarize ledger statistics.

        Returns:
            Dict with counts, total time, total tokens
        """
        outcomes = self.read()
        total_time = sum(o.wall_seconds for o in outcomes)
        total_tokens = sum(o.tokens_used for o in outcomes)
        success_count = sum(1 for o in outcomes if o.success)
        timeout_count = sum(1 for o in outcomes if o.timed_out)
        error_count = sum(1 for o in outcomes if o.error)

        return {
            "total_steps": len(outcomes),
            "successful_steps": success_count,
            "failed_steps": len(outcomes) - success_count,
            "timeout_count": timeout_count,
            "error_count": error_count,
            "total_wall_seconds": total_time,
            "total_tokens": total_tokens,
        }
