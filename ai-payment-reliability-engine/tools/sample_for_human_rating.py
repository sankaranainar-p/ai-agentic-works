#!/usr/bin/env python3
"""
tools/sample_for_human_rating.py — Sample 50 RCA cases for human faithfulness rating.

Usage:
    python3 tools/sample_for_human_rating.py [--output rating_study.csv]

Generates a CSV file with 50 sampled cases for human-rating study. Each row
contains a case_id, RCA claim, evidence description, and space for human ratings
(0-2 scale: 0=not faithful, 1=partially faithful, 2=faithful).

The human ratings are collected to compute Cohen's kappa agreement between
the automated faithfulness checker and human raters. This feeds the journal
version evaluation.

Output format:
    case_id, claim_text, evidence_summary, evidence_pack_size, human_rating, rater_id
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path


def sample_for_rating(
    output_path: str | Path = "results/rating_study.csv",
    sample_size: int = 50,
    random_seed: int = 42,
) -> None:
    """Generate CSV for human-rating study.

    This is a placeholder that creates the template for human rating.
    In a full implementation, this would:
    1. Load validation split cases
    2. Run RCA agent on each
    3. Generate faithfulness scores
    4. Sample 50 cases stratified by:
       - Ground-truth fault class
       - Evidence pack size (small, medium, large)
       - Predicted faithfulness (to capture both high-confidence and uncertain cases)
    5. Write CSV with:
       - case_id
       - RCA claim text
       - Evidence summary (top 3 evidence items)
       - Evidence pack size (token count)
       - Empty "human_rating" column for collection
       - Empty "rater_id" column for tracking
       - Empty "notes" column for rater comments
    """
    random.seed(random_seed)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate sample data for demonstration
    sample_cases = []
    for i in range(sample_size):
        case_id = f"RATING-{i+1:03d}"
        fault_class = random.choice(["cpu", "memory", "latency", "error_rate"])
        pack_size = random.randint(500, 5000)

        claim_templates = {
            "cpu": "High CPU utilization on payment service nodes causing request throttling",
            "memory": "Memory leak or heap exhaustion leading to OOM kills",
            "latency": "Database latency spike degrading payment processing",
            "error_rate": "Cascading service failures due to upstream timeout",
        }
        claim = claim_templates.get(fault_class, "Unknown root cause")

        evidence_templates = {
            "cpu": "CPU spike | Error rate increase | Timeout messages",
            "memory": "Memory usage surge | Garbage collection pause | Pod restarts",
            "latency": "Database query latency up | Connection pool exhaustion | Lock contention",
            "error_rate": "Timeout errors | Circuit breaker trips | Cascading failures",
        }
        evidence = evidence_templates.get(fault_class, "Various metrics spiked")

        sample_cases.append(
            {
                "case_id": case_id,
                "fault_class": fault_class,
                "claim_text": claim,
                "evidence_summary": evidence,
                "pack_size": pack_size,
                "human_rating": "",  # To be filled by rater
                "rater_id": "",  # To be filled by rater
                "notes": "",  # Optional rater comments
            }
        )

    # Write CSV
    fieldnames = [
        "case_id",
        "fault_class",
        "claim_text",
        "evidence_summary",
        "pack_size",
        "human_rating",
        "rater_id",
        "notes",
    ]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sample_cases)

    print(f"Wrote {sample_size} cases to {output_path}")
    print("Human ratings scale: 0=not faithful, 1=partially faithful, 2=fully faithful")
    print(f"Remember to fill in rater_id (e.g., 'rater_1', 'rater_2') for agreement analysis")


def main():
    parser = argparse.ArgumentParser(
        description="Generate cases for human faithfulness-rating study"
    )
    parser.add_argument(
        "--output",
        default="results/rating_study.csv",
        help="Path to write rating CSV",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=50,
        help="Number of cases to sample",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    sample_for_rating(
        output_path=args.output,
        sample_size=args.sample_size,
        random_seed=args.seed,
    )


if __name__ == "__main__":
    main()
