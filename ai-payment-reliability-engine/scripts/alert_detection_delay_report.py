"""
scripts/alert_detection_delay_report.py — A5's required verification
report: prints (and optionally writes) the detection-delay distribution
and silent-alert rate produced by pre.signals.alert_synth, per dataset,
against real (not synthetic) fixture data.

This is the durable, re-runnable artifact backing the A5 claim "alerts
are synthesised with a sane detection-delay distribution, and silent
cases are counted, not dropped" — run it, don't just trust the module's
unit tests, which use small synthetic cases by design (see
tests/test_alert_synth.py's own docstring for why).

Usage:
    python scripts/alert_detection_delay_report.py
    python scripts/alert_detection_delay_report.py --openrca-dir /path/to/downloaded/Bank/parent
"""

from __future__ import annotations

import argparse
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pre.signals.alert_synth import synthesize_alerts_summary  # noqa: E402
from pre.signals.openrca import OpenRCABankAdapter  # noqa: E402
from pre.signals.rcaeval import RCAEvalAdapter  # noqa: E402


def _percentile(sorted_values: list[int], pct: float) -> float:
    if not sorted_values:
        return float("nan")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    k = (len(sorted_values) - 1) * pct
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return float(sorted_values[f])
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def _report_for(label: str, cases) -> dict:
    cases = list(cases)
    alerts, summary = synthesize_alerts_summary(cases)
    delays = sorted(summary.detection_delays_seconds)

    rule_counts: dict[str, int] = {}
    for a in alerts:
        if not a.silent:
            rule_counts[a.rule_id] = rule_counts.get(a.rule_id, 0) + 1

    print(f"\n=== {label} ===")
    print(f"cases: {summary.total_cases}")
    print(f"detected: {summary.detected_count}  silent: {summary.silent_count}  silent_rate: {summary.silent_rate:.2%}")
    if delays:
        print(
            f"detection_delay_seconds: min={min(delays)} "
            f"p50={_percentile(delays, 0.50):.0f} "
            f"p90={_percentile(delays, 0.90):.0f} "
            f"max={max(delays)} "
            f"mean={statistics.mean(delays):.1f}"
        )
    else:
        print("detection_delay_seconds: (no detected cases)")
    if rule_counts:
        print("breaches by rule:", dict(sorted(rule_counts.items(), key=lambda kv: -kv[1])))

    return {
        "label": label,
        "total_cases": summary.total_cases,
        "detected": summary.detected_count,
        "silent": summary.silent_count,
        "silent_rate": summary.silent_rate,
        "delays": delays,
        "rule_counts": rule_counts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rcaeval-fixture-dir",
        type=Path,
        default=REPO_ROOT / "tests" / "fixtures" / "rcaeval",
        help="RCAEval fixture root (default: the committed trimmed fixture)",
    )
    parser.add_argument(
        "--openrca-fixture-dir",
        type=Path,
        default=REPO_ROOT / "tests" / "fixtures" / "openrca_bank",
        help="OpenRCA Bank fixture root (default: the committed trimmed fixture)",
    )
    args = parser.parse_args(argv)

    results = []
    for dataset in ["RE1-OB", "RE2-OB"]:
        cases = [fc for fc, gt in RCAEvalAdapter(args.rcaeval_fixture_dir, dataset)]
        results.append(_report_for(f"RCAEval {dataset}", cases))

    openrca_cases = [fc for fc, gt in OpenRCABankAdapter(args.openrca_fixture_dir)]
    results.append(_report_for("OpenRCA Bank", openrca_cases))

    print(
        "\nNOTE: OpenRCA Bank cases score ~1700 metric series each versus "
        "RCAEval's ~49-75; at z_threshold=3.0 this makes a same-timestamp "
        "false-positive breach on OpenRCA cases likely by chance alone "
        "(~99% per case, vs ~12% for RCAEval, by the binomial union bound "
        "-- see pre/signals/alert_synth.py's module docstring and "
        "CONVERSION.md for the exact numbers). Detection-delay uniformity "
        "on OpenRCA cases in this report reflects that multiple-comparisons "
        "effect, not necessarily faster true detection."
    )

    print("\n=== Overall ===")
    total_cases = sum(r["total_cases"] for r in results)
    total_detected = sum(r["detected"] for r in results)
    total_silent = sum(r["silent"] for r in results)
    print(f"total cases across all datasets: {total_cases}")
    print(f"total detected: {total_detected}  total silent: {total_silent}  "
          f"overall silent_rate: {(total_silent / total_cases if total_cases else 0):.2%}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
