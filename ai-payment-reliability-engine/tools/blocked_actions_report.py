#!/usr/bin/env python3
"""
tools/blocked_actions_report.py — Generate report of blocked actions and their violations.

Produces a table suitable for the paper showing which invariants caused each action to be blocked.

Usage:
    python3 tools/blocked_actions_report.py [--output blocked_actions.txt]
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from pre.agents.propose import ActionProposalAgent
from pre.agents.rca import RCAResult
from pre.policy.action_catalog import Action, ActionType
from pre.policy.verifier import PolicyVerifier


def generate_blocked_actions_report(
    output_path: str | Path = "results/blocked_actions.txt",
) -> None:
    """Generate a table of blocked actions and their invariant violations.

    This creates a comprehensive report showing examples of actions that failed
    verification and which invariants caused the rejection.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    test_cases = _generate_test_cases()
    blocked_actions = []

    for case_name, action, degraded, history in test_cases:
        verifier = PolicyVerifier(degraded_services=degraded, action_history=history)
        result = verifier.verify(action)

        if not result.approved:
            blocked_actions.append(
                {
                    "case": case_name,
                    "action": f"{action.action_type.value} on {action.target_service}",
                    "severity": action.severity,
                    "blocked_by": ", ".join(result.blocked_invariants) or "None",
                    "reason": result.reason,
                }
            )

    # Write report
    with open(output_path, "w") as f:
        f.write("=" * 120 + "\n")
        f.write("BLOCKED REMEDIATION ACTIONS — POLICY INVARIANT VIOLATIONS\n")
        f.write("=" * 120 + "\n\n")

        f.write("Summary:\n")
        f.write(f"Total blocked actions analyzed: {len(blocked_actions)}\n")
        f.write("\n")

        # Invariant summary
        invariant_counts = {}
        for action in blocked_actions:
            for inv in action["blocked_by"].split(", "):
                inv = inv.strip()
                if inv and inv != "None":
                    invariant_counts[inv] = invariant_counts.get(inv, 0) + 1

        f.write("Invariants triggered:\n")
        for inv in sorted(invariant_counts.keys()):
            f.write(f"  {inv}: {invariant_counts[inv]} violation(s)\n")
        f.write("\n")

        # Detailed table
        f.write("-" * 120 + "\n")
        f.write(
            f"{'Case':<25} | {'Action':<30} | {'Severity':<8} | {'Blocked By':<15} | {'Reason':<40}\n"
        )
        f.write("-" * 120 + "\n")

        for action in sorted(blocked_actions, key=lambda x: x["blocked_by"]):
            f.write(
                f"{action['case']:<25} | {action['action']:<30} | {action['severity']:<8} | "
                f"{action['blocked_by']:<15} | {action['reason'][:40]:<40}\n"
            )

        f.write("-" * 120 + "\n")

        # Invariant descriptions
        f.write("\n\nINVARIANT DEFINITIONS:\n")
        f.write("-" * 80 + "\n")
        f.write("I1: No action targets a node currently in degraded state (failing health checks)\n")
        f.write("I2: No two actions on the same target within 120 seconds\n")
        f.write("I3: SEV-1 incidents always escalate (never suppress with cheaper actions)\n")
        f.write("I4: Escalation only on SEV-1/SEV-2 (never escalate for SEV-3/SEV-4)\n")
        f.write("I5: Scaling actions capped at 50% of original (prevent runaway scale-up)\n")

    print(f"Report written to {output_path}")
    print(f"Total blocked actions: {len(blocked_actions)}")


def _generate_test_cases() -> list[tuple[str, Action, set[str], dict]]:
    """Generate test cases that violate invariants."""
    cases = []

    # I1: Action on degraded node
    cases.append(
        (
            "I1: Degraded node",
            Action.restart("payment", "SEV-2", "TEST-001", 1000),
            {"payment"},
            {},
        )
    )

    # I2: Duplicate action within 120s
    cases.append(
        (
            "I2: Duplicate action",
            Action.restart("payment", "SEV-2", "TEST-002", 1050),
            set(),
            {("payment", 1000): Action.restart("payment", "SEV-2", "TEST-001", 1000)},
        )
    )

    # I3: SEV-1 non-escalation
    cases.append(
        (
            "I3: SEV-1 non-escalate",
            Action.restart("payment", "SEV-1", "TEST-003", 1000),
            set(),
            {},
        )
    )

    # I4: Low severity escalation
    cases.append(
        (
            "I4: Low severity escalate",
            Action.escalate("payment", "SEV-3", "TEST-004", 1000, "oncall"),
            set(),
            {},
        )
    )

    # I5: Scale-up exceeds limit
    cases.append(
        (
            "I5: Scale-up limit",
            Action.scale("payment", "SEV-2", "TEST-005", 1000, "up", 20),
            set(),
            {},
        )
    )

    # Multiple violations
    cases.append(
        (
            "I1 + I3: Degraded + SEV-1",
            Action.restart("payment", "SEV-1", "TEST-006", 1000),
            {"payment"},
            {},
        )
    )

    return cases


def main():
    parser = argparse.ArgumentParser(
        description="Generate report of blocked remediation actions"
    )
    parser.add_argument(
        "--output",
        default="results/blocked_actions.txt",
        help="Output file for report",
    )
    args = parser.parse_args()

    generate_blocked_actions_report(args.output)


if __name__ == "__main__":
    main()
