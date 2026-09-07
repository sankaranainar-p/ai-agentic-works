"""
pre/agents/orchestrator.py — Pipeline orchestrator with explicit steps and budgets.

Executes the incident response pipeline as an ordered list of steps, each with:
- Wall-clock time budget (seconds)
- Token budget
- Timeout handling with StepTimeout outcome
- Ledger recording of each step
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from pre.audit.ledger import Ledger, StepOutcome


class StepStatus(Enum):
    """Step execution status."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    TIMEOUT = "timeout"
    FAILED = "failed"


@dataclass(frozen=True)
class StepTimeout(Exception):
    """Raised when a step exceeds its time or token budget."""

    step_name: str
    wall_seconds: float
    tokens_used: int
    budget_seconds: float
    budget_tokens: int


class PipelineStep:
    """A single step in the incident response pipeline."""

    def __init__(
        self,
        name: str,
        func: Callable,
        wall_budget: float,
        token_budget: int,
    ):
        """Initialize a pipeline step.

        Args:
            name: Step name
            func: Callable that executes the step
            wall_budget: Time budget in seconds
            token_budget: Token budget (0 for unlimited)
        """
        self.name = name
        self.func = func
        self.wall_budget = wall_budget
        self.token_budget = token_budget


class Orchestrator:
    """Pipeline orchestrator with step budgets and timeout handling."""

    def __init__(self, ledger: Optional[Ledger] = None):
        """Initialize orchestrator.

        Args:
            ledger: Optional Ledger for recording steps
        """
        self.ledger = ledger or Ledger()
        self.steps: list[PipelineStep] = []
        self.results: dict[str, any] = {}
        self.total_tokens = 0

    def add_step(
        self,
        name: str,
        func: Callable,
        wall_budget: float = 60.0,
        token_budget: int = 0,
    ) -> None:
        """Add a step to the pipeline.

        Args:
            name: Step name
            func: Callable(context: dict) -> (result: any, tokens_used: int)
            wall_budget: Time budget in seconds
            token_budget: Token budget (0 = unlimited)
        """
        step = PipelineStep(name, func, wall_budget, token_budget)
        self.steps.append(step)

    def run(self) -> dict[str, any]:
        """Execute the pipeline.

        Returns:
            Dict of results from all steps

        Raises:
            StepTimeout: If any step exceeds its budget
        """
        context = {}

        for step in self.steps:
            start_time = time.time()

            try:
                # Execute step
                result, tokens_used = step.func(context)

                # Record success
                elapsed = time.time() - start_time
                self.results[step.name] = result
                self.total_tokens += tokens_used

                outcome = StepOutcome(
                    step_name=step.name,
                    success=True,
                    wall_seconds=elapsed,
                    tokens_used=tokens_used,
                )
                self.ledger.record(outcome)

                # Check for timeout
                if elapsed > step.wall_budget:
                    raise StepTimeout(
                        step_name=step.name,
                        wall_seconds=elapsed,
                        tokens_used=tokens_used,
                        budget_seconds=step.wall_budget,
                        budget_tokens=step.token_budget,
                    )

                if step.token_budget > 0 and tokens_used > step.token_budget:
                    raise StepTimeout(
                        step_name=step.name,
                        wall_seconds=elapsed,
                        tokens_used=tokens_used,
                        budget_seconds=step.wall_budget,
                        budget_tokens=step.token_budget,
                    )

                context[step.name] = result

            except StepTimeout as e:
                # Record timeout
                elapsed = time.time() - start_time
                outcome = StepOutcome(
                    step_name=step.name,
                    success=False,
                    wall_seconds=elapsed,
                    tokens_used=e.tokens_used,
                    timed_out=True,
                    error=f"Budget exceeded: {e.wall_seconds:.1f}s / {e.budget_seconds}s",
                )
                self.ledger.record(outcome)
                raise

            except Exception as e:
                # Record error
                elapsed = time.time() - start_time
                outcome = StepOutcome(
                    step_name=step.name,
                    success=False,
                    wall_seconds=elapsed,
                    error=str(e),
                )
                self.ledger.record(outcome)
                raise

        return self.results

    def summary(self) -> dict:
        """Get pipeline execution summary.

        Returns:
            Dict with step counts and token usage
        """
        ledger_summary = self.ledger.summary()
        return {
            **ledger_summary,
            "total_tokens": self.total_tokens,
        }
