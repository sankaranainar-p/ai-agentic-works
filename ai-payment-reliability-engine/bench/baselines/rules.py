"""
bench/baselines/rules.py — B1: rule-based root cause ranking.

Reuses the simple threshold-detection idea from the legacy
pre/monitor.py handlers (a metric "fires" when it deviates from its own
pre-injection baseline by more than a fixed number of standard
deviations — an n-sigma rule) rather than any learned model. Services
are ranked by the largest such deviation across their metrics in the
post-injection window.

This is intentionally the simplest possible baseline: no calibration, no
learning, just "which service's numbers moved the most, in units of its
own pre-injection variance". It exists to give every other baseline (and
the full pipeline) a floor to beat.
"""

from __future__ import annotations

import statistics
from collections import defaultdict

from pre.signals.types import FailureCase

N_SIGMA_FLOOR = 1e-6  # avoid divide-by-zero for a perfectly flat metric


def _service_of(metric_key: str) -> str:
    return metric_key.split(":", 1)[0]


def rank(case: FailureCase, inject_time: int | None = None) -> list[str]:
    """Rank services by max n-sigma deviation of any of their metrics in
    the post-injection window versus that metric's pre-injection mean/std.

    `inject_time` defaults to the midpoint of the case's time range when
    not supplied (callers scoring against a benchmark should pass the
    real GroundTruth.inject_time; this baseline must not be handed the
    GroundTruth object itself, only the timestamp it needs — see the
    calling convention in bench/run_benchmark.py).
    """
    if not case.metrics:
        return []

    all_times = sorted({t for series in case.metrics.values() for t in series.times})
    if inject_time is None:
        inject_time = all_times[len(all_times) // 2] if all_times else 0

    service_scores: dict[str, float] = defaultdict(float)

    for key, series in case.metrics.items():
        service = _service_of(key)
        before = [v for t, v in zip(series.times, series.values) if t < inject_time]
        after = [v for t, v in zip(series.times, series.values) if t >= inject_time]
        if len(before) < 2 or not after:
            continue

        mean_before = statistics.mean(before)
        std_before = statistics.pstdev(before) or N_SIGMA_FLOOR
        max_after = max(abs(v - mean_before) for v in after)
        n_sigma = max_after / std_before

        service_scores[service] = max(service_scores[service], n_sigma)

    ranked = sorted(service_scores.items(), key=lambda item: item[1], reverse=True)
    return [service for service, _score in ranked]
