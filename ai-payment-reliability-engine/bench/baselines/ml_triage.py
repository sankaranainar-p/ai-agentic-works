"""
bench/baselines/ml_triage.py — B3: this project's ML classifier repurposed
for service-level root cause ranking.

pre.classifier.model.MLClassifier classifies free-text alerts into a
fault_class, not a service. To use it as a service-ranking baseline, this
module builds a short synthetic alert per service (naming the service and
summarising its most-deviated metric) and ranks services by the
classifier's confidence that the resulting text describes a real fault
(rather than "unknown"). This is a repurposing, not the classifier's
intended use — see PROTOCOL.md RQ1 for the classifier's actual evaluation
mode (fault_class accuracy on RCAEval/OpenRCA labels).
"""

from __future__ import annotations

import statistics

from pre.classifier.model import get_classifier
from pre.signals.types import FailureCase


def _service_of(metric_key: str) -> str:
    return metric_key.split(":", 1)[0]


def _summarise_deviation(case: FailureCase, service: str, inject_time: int) -> str:
    """Build a short alert-style sentence for *service* naming its most
    deviated metric, for the ML classifier to score.
    """
    best_metric, best_dev = None, 0.0
    for key, series in case.metrics.items():
        if _service_of(key) != service:
            continue
        before = [v for t, v in zip(series.times, series.values) if t < inject_time]
        after = [v for t, v in zip(series.times, series.values) if t >= inject_time]
        if len(before) < 2 or not after:
            continue
        mean_before = statistics.mean(before)
        dev = max(abs(v - mean_before) for v in after)
        if dev > best_dev:
            best_dev = dev
            best_metric = key.split(":", 1)[1]

    metric_desc = best_metric or "metric"
    return f"{service} {metric_desc} elevated above baseline in payment service"


def rank(case: FailureCase, inject_time: int | None = None) -> list[str]:
    """Rank services by the ML classifier's confidence on a synthetic
    per-service alert sentence.
    """
    if not case.metrics:
        return []

    all_times = sorted({t for series in case.metrics.values() for t in series.times})
    if inject_time is None:
        inject_time = all_times[len(all_times) // 2] if all_times else 0

    services = sorted({_service_of(k) for k in case.metrics})
    clf = get_classifier()

    scored: list[tuple[str, float]] = []
    for service in services:
        text = _summarise_deviation(case, service, inject_time)
        result = clf.classify(text)
        scored.append((service, result.confidence))

    scored.sort(key=lambda item: item[1], reverse=True)
    return [service for service, _confidence in scored]
