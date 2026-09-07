#!/usr/bin/env python3
"""
tools/evaluate_triage.py — Evaluate triage model on validation/test splits.

Usage:
    python3 tools/evaluate_triage.py [--split validation|test]

Computes metrics for the triage model:
- Macro F1: unweighted mean F1 across all classes
- ECE: expected calibration error (confidence calibration)
- Brier score: proper scoring rule for probabilistic predictions
- Coverage: fraction of predictions not abstained at tau
- Precision: accuracy on non-abstained predictions (tuned for 95%)

Generates reliability diagram showing confidence vs accuracy and saves
to results/reliability_diagram.png.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bench.metrics import macro_f1, expected_calibration_error, brier_score
from bench.metrics import coverage_at_tau, precision_at_tau


def evaluate_triage_model(split: str = "validation"):
    """Evaluate the triage model.

    This is a placeholder for the full evaluation pipeline that would:
    1. Load the specified split (validation or test)
    2. Run triage model on all cases
    3. Collect predictions and posteriors
    4. Compute macro F1, ECE, Brier, coverage, precision
    5. Generate reliability diagram
    6. Save results to results/

    In a full implementation, this would integrate with bench/run_benchmark.py
    and pre.agents.triage.
    """
    print(f"Evaluating triage model on {split} split")
    print("(Placeholder: full evaluation requires integration with benchmark harness)")
    print()
    print("Metrics to report at tau=0.65:")
    print("- Macro F1 score")
    print("- Expected calibration error (ECE)")
    print("- Brier score")
    print("- Coverage (% non-abstained)")
    print("- Precision (accuracy on non-abstained)")
    print()
    print("Output: results/reliability_diagram.png (calibration plot)")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate the triage model"
    )
    parser.add_argument(
        "--split",
        choices=["validation", "test"],
        default="validation",
        help="Evaluation split",
    )
    args = parser.parse_args()

    evaluate_triage_model(args.split)


if __name__ == "__main__":
    main()
