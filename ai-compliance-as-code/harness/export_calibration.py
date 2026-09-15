"""
harness/export_calibration.py — CLI utility for confidence calibration analysis.

Loads detector results (checkpoint.jsonl or predictions.json), runs calibration
analysis with Murphy's decomposition and Wilson margins of error, and exports:
  - results/calibration/metrics.json
  - ASCII reliability table to stdout

Usage:
  python -m harness.export_calibration --results results/task2_static_23/checkpoint.jsonl --output-dir results/calibration
  python -m harness.export_calibration --results results/task2_llm_sample/checkpoint.jsonl --bins 5 --strategy quantile
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Bootstrap project root
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from harness.metrics import CalibrationReport, compute_calibration_analysis

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("harness.export_calibration")


def load_records(path: Path) -> List[Dict[str, Any]]:
    """Load benchmark or detector result records from JSONL or JSON file."""
    if not path.exists():
        raise FileNotFoundError(f"Results file does not exist: {path}")

    records: List[Dict[str, Any]] = []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return records

    # Attempt JSON array first
    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
        except json.JSONDecodeError:
            pass

    # Parse JSONL
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
        except json.JSONDecodeError:
            continue

    return records


def extract_confidences_and_labels(
    records: Sequence[Dict[str, Any]],
    default_confidence: float = 0.85,
    eval_level: str = "exact_match",
) -> Tuple[List[float], List[int]]:
    """Extract (confidence, binary_label) pairs from ingested records.

    Handles:
      1. Explicit 'confidence' and 'label'/'correct' fields.
      2. Finding lists carrying 'confidence'.
      3. Task 2 snippet predictions with 'ground_truth' and 'predicted'.
    """
    confidences: List[float] = []
    labels: List[int] = []

    for r in records:
        # Case 1: Direct confidence & label
        if "confidence" in r and ("label" in r or "correct" in r or "y" in r):
            conf = float(r["confidence"])
            label_raw = r.get("label", r.get("correct", r.get("y", 0)))
            label = 1 if label_raw in (1, True, "1") else 0
            confidences.append(conf)
            labels.append(label)
            continue

        # Case 2: Findings list with confidences
        findings = r.get("findings")
        if isinstance(findings, list) and len(findings) > 0:
            for f in findings:
                if isinstance(f, dict):
                    conf = float(f.get("confidence", default_confidence))
                    is_hit = 1 if f.get("hit", f.get("correct", True)) else 0
                    confidences.append(conf)
                    labels.append(is_hit)
            continue

        # Case 3: Ground truth vs Predicted
        gt = r.get("ground_truth", [])
        pred = r.get("predicted", [])
        gt_set = set(gt) if isinstance(gt, (list, set, tuple)) else {gt}
        pred_set = set(pred) if isinstance(pred, (list, set, tuple)) else {pred}

        if eval_level == "exact_match":
            label = 1 if gt_set == pred_set else 0
        else:
            # Overlap / hit level
            label = 1 if (gt_set & pred_set) or (not gt_set and not pred_set) else 0

        # Elicit confidence
        if "confidence" in r:
            conf = float(r["confidence"])
        elif pred:
            # Non-empty prediction: default confidence
            conf = default_confidence
        else:
            # Abstention or no violation predicted
            conf = 0.50

        confidences.append(conf)
        labels.append(label)

    return confidences, labels


def export_calibration(
    results_path: Path,
    output_dir: Path,
    num_bins: int = 5,
    strategy: str = "quantile",
    default_confidence: float = 0.85,
    eval_level: str = "exact_match",
) -> CalibrationReport:
    """Run calibration evaluation and export results to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    records = load_records(results_path)
    if not records:
        raise ValueError(f"No valid records found in {results_path}")

    confidences, labels = extract_confidences_and_labels(
        records,
        default_confidence=default_confidence,
        eval_level=eval_level,
    )

    report = compute_calibration_analysis(
        confidences=confidences,
        labels=labels,
        num_bins=num_bins,
        strategy=strategy,
    )

    # Save metrics.json
    metrics_file = output_dir / "metrics.json"
    metrics_file.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    logger.info("Saved calibration metrics to %s", metrics_file)

    # Print ASCII table and summary
    print("\n" + "=" * 54)
    print(f"  Confidence Calibration Analysis ({strategy.upper()}, M={num_bins})")
    print("=" * 54)
    print(report.format_ascii_table())
    print("-" * 54)
    print(f"  Samples:                {report.num_samples}")
    print(f"  Base Rate (y_bar):      {report.base_rate:.4f}")
    print(f"  Expected Calib Error:   {report.ece:.4f}")
    print(f"  Maximum Calib Error:    {report.mce:.4f}")
    print(f"  Brier Score (BS):       {report.brier_score:.6f}")
    print(f"  Reliability (REL):      {report.reliability:.6f}")
    print(f"  Resolution (RES):       {report.resolution:.6f}")
    print(f"  Uncertainty (UNC):      {report.uncertainty:.6f}")
    diff = abs(report.brier_score - (report.reliability - report.resolution + report.uncertainty))
    print(f"  Murphy Identity Check:  |BS - (REL - RES + UNC)| = {diff:.2e}")
    print("=" * 54 + "\n")

    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Confidence Calibration and Murphy Decomposition CLI utility.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--results",
        type=str,
        default="results/task2_llm_sample/checkpoint.jsonl",
        help="Path to checkpoint.jsonl or predictions.json results file.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results/calibration",
        help="Output directory to write metrics.json and calibration artifacts.",
    )
    parser.add_argument(
        "--bins",
        "--num-bins",
        dest="num_bins",
        type=int,
        default=5,
        help="Number of calibration bins (default: 5).",
    )
    parser.add_argument(
        "--strategy",
        type=str,
        choices=["quantile", "uniform"],
        default="quantile",
        help="Binning strategy: 'quantile' (equal-frequency) or 'uniform' (equal-width).",
    )
    parser.add_argument(
        "--default-confidence",
        type=float,
        default=0.85,
        help="Fallback confidence score when not explicitly provided in records.",
    )
    parser.add_argument(
        "--eval-level",
        type=str,
        choices=["exact_match", "overlap"],
        default="exact_match",
        help="Ground truth evaluation criterion: 'exact_match' or 'overlap'.",
    )

    args = parser.parse_args(argv)
    results_path = Path(args.results)
    output_dir = Path(args.output_dir)

    try:
        export_calibration(
            results_path=results_path,
            output_dir=output_dir,
            num_bins=args.num_bins,
            strategy=args.strategy,
            default_confidence=args.default_confidence,
            eval_level=args.eval_level,
        )
        return 0
    except Exception as exc:
        logger.error("Calibration export failed: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
