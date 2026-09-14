"""
pre/agents/evidence.py — Evidence ranking and selection for incident RCA.

Ranks anomalous KPIs, error spans, and log templates by signal strength,
walks the service dependency graph to boost candidates on the critical
path, and returns a ranked evidence pack with stable IDs and descriptions.

Each evidence item carries a stable ID (kpi:svc:metric, span:traceid,
logtpl:hash) and a one-line description. The pack is capped at 40 items
and records its approximate token size.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from typing import Optional

import networkx as nx
import numpy as np

from pre.signals.alert_synth import Alert
from pre.signals.types import FailureCase, LogEvent, Span


@dataclass(frozen=True)
class EvidenceItem:
    """A single piece of evidence with stable ID and description."""

    id: str  # Format: kpi:svc:metric | span:traceid | logtpl:hash
    type: str  # "kpi", "span", "log"
    score: float  # Signal strength; unbounded for KPIs (log1p of |z|), [0,1] for spans/logs
    description: str  # One-line description for humans
    service: Optional[str] = None  # Service this evidence implicates
    z_score: Optional[float] = None  # Raw robust z-score (KPIs only); secondary sort key
    graph_distance: Optional[int] = None  # Hops from the alert's service (None = unknown/unreachable)


def _sort_key(item: EvidenceItem) -> tuple[float, float, float]:
    """Deterministic ranking key: score desc, then |z| desc, then graph distance asc.

    Never falls back to list/insertion order for items that carry any
    distinguishing signal — a KPI's score is a strictly monotone function
    of |z|, so two KPIs with different z can never tie on the first key.
    """
    z_mag = abs(item.z_score) if item.z_score is not None else 0.0
    dist = float(item.graph_distance) if item.graph_distance is not None else math.inf
    return (-item.score, -z_mag, dist)


@dataclass(frozen=True)
class EvidencePack:
    """Ranked evidence for root cause analysis."""

    case_id: str
    items: list[EvidenceItem]  # Sorted by score descending, capped at 40
    token_estimate: int  # Approximate token count for LLM consumption


_MAD_TO_STD = 1.4826  # scales MAD to a consistent estimator of stddev for normal data
_MAD_ABSOLUTE_FLOOR = 1e-9  # final fallback when the pre-window is genuinely all-zero
_MAD_RELATIVE_FLOOR = 0.01  # minimum scaled-MAD as a fraction of the pre-window's value scale


class RobustScaler:
    """Robust z-score using median and MAD (median absolute deviation)."""

    @staticmethod
    def robust_z_score(values: list[float], target: float) -> float:
        """Compute robust z-score: (target - median) / scaled_MAD.

        The MAD floor is relative to the pre-window's own value SCALE
        (``_MAD_RELATIVE_FLOOR * max(|median|, max|v|)``), not a fixed
        absolute epsilon — ported from ``pre/signals/alert_synth.py``'s
        ``_robust_z_scores``. A near-constant-but-not-flat pre-window (MAD
        rounds to 0.0 in float while the metric still moves a little) would
        otherwise divide a tiny fluctuation by ~1e-9 and report a z-score
        in the millions.
        """
        if len(values) < 2:
            return 0.0

        values_arr = np.array(values, dtype=np.float64)
        median = np.median(values_arr)
        mad = np.median(np.abs(values_arr - median))

        scale_reference = max(abs(median), float(np.max(np.abs(values_arr))))
        scaled_mad = max(
            mad * _MAD_TO_STD,
            _MAD_RELATIVE_FLOOR * scale_reference,
            _MAD_ABSOLUTE_FLOOR,
        )
        return (target - median) / scaled_mad


class EvidenceRanker:
    """Rank evidence items from a failure case."""

    def __init__(self, case: FailureCase, alert: Alert):
        self.case = case
        self.alert = alert
        self.items: list[EvidenceItem] = []

        # Split metrics by baseline boundary
        self.baseline_boundary = self._compute_baseline_boundary()
        self.pre_times, self.post_times = self._split_times()

    def _compute_baseline_boundary(self) -> int:
        """Find the temporal midpoint (split between pre and post baseline)."""
        all_times = []
        for series in self.case.metrics.values():
            all_times.extend(series.times)

        if not all_times:
            return 0
        return all_times[len(all_times) // 2]

    def _split_times(self) -> tuple[list[int], list[int]]:
        """Split times into pre-baseline and post-baseline."""
        all_times = []
        for series in self.case.metrics.values():
            all_times.extend(series.times)

        if not all_times:
            return [], []

        boundary = self.baseline_boundary
        pre = sorted(set(t for t in all_times if t < boundary))
        post = sorted(set(t for t in all_times if t >= boundary))
        return pre, post

    def rank_kpis(self) -> list[EvidenceItem]:
        """Rank KPIs by robust z-score anomaly."""
        items = []

        for key, series in self.case.metrics.items():
            if not series.values or len(series.values) < 2:
                continue

            # Split by baseline
            values_array = np.array(series.values, dtype=np.float64)
            times_array = np.array(series.times, dtype=np.int64)

            pre_mask = times_array < self.baseline_boundary
            post_mask = times_array >= self.baseline_boundary

            if pre_mask.sum() < 2 or post_mask.sum() < 1:
                continue

            pre_values = values_array[pre_mask].tolist()
            post_values = values_array[post_mask].tolist()

            # Maximum post-breach value
            max_post = max(post_values) if post_values else 0.0

            # Robust z-score against pre-baseline. Score is log1p(|z|):
            # unbounded and strictly monotone in |z|, so a z=6000 metric
            # always outranks a z=4 one instead of both clipping to 1.0
            # and being ordered by incidental CSV column order.
            z_score = RobustScaler.robust_z_score(pre_values, max_post)

            if abs(z_score) > 0.3:  # Filter weak signals
                svc, metric = key.split(":")
                item = EvidenceItem(
                    id=f"kpi:{svc}:{metric}",
                    type="kpi",
                    score=math.log1p(abs(z_score)),
                    description=f"{key} spiked to {max_post:.1f} (z={z_score:.1f})",
                    service=svc,
                    z_score=z_score,
                )
                items.append(item)

        return sorted(items, key=_sort_key)

    def rank_spans(self) -> list[EvidenceItem]:
        """Rank spans by error-ratio change."""
        items = []

        if not self.case.traces:
            return items

        # Group spans by (parent_service, child_service) edge
        edges: dict[tuple[str, str], list[Span]] = defaultdict(list)
        by_id = {s.span_id: s for s in self.case.traces}

        for span in self.case.traces:
            if span.parent_span_id and span.parent_span_id in by_id:
                parent = by_id[span.parent_span_id]
                if parent.service != span.service:
                    edges[(parent.service, span.service)].append(span)

        # Compute error-ratio change for each edge
        for (caller, callee), spans in edges.items():
            if len(spans) < 2:
                continue

            # Split by baseline (baseline_boundary is in seconds, start_time_ms is in milliseconds)
            baseline_ms = self.baseline_boundary * 1000 if self.baseline_boundary > 0 else float('inf')
            pre_spans = [s for s in spans if s.start_time_ms < baseline_ms]
            post_spans = [s for s in spans if s.start_time_ms >= baseline_ms]

            if not pre_spans or not post_spans:
                continue

            pre_error_ratio = sum(
                1 for s in pre_spans if s.status_code and s.status_code >= 400
            ) / len(pre_spans)
            post_error_ratio = sum(
                1 for s in post_spans if s.status_code and s.status_code >= 400
            ) / len(post_spans)

            error_change = post_error_ratio - pre_error_ratio
            if error_change > 0.1:  # Significant error increase
                trace_id = post_spans[0].trace_id
                item = EvidenceItem(
                    id=f"span:{trace_id}",
                    type="span",
                    score=min(1.0, error_change),
                    description=f"{caller}→{callee} errors {pre_error_ratio:.0%}→{post_error_ratio:.0%}",
                    service=callee,
                )
                items.append(item)

        return sorted(items, key=_sort_key)

    def rank_logs(self) -> list[EvidenceItem]:
        """Rank log templates by novelty (post-window only)."""
        items = []

        if not self.case.logs:
            return items

        # Split logs by baseline
        pre_templates = Counter(
            l.template_hash for l in self.case.logs if l.time < self.baseline_boundary
        )
        post_templates = Counter(
            l.template_hash for l in self.case.logs if l.time >= self.baseline_boundary
        )

        # Novelty score: appears post but not pre (or mostly post)
        for logtpl_hash, post_count in post_templates.items():
            pre_count = pre_templates.get(logtpl_hash, 0)
            novelty = post_count / (pre_count + post_count) if (pre_count + post_count) > 0 else 1.0

            if novelty > 0.5:  # Favor templates with post-window dominance
                # Find the log event for context
                log_event = next(
                    (l for l in self.case.logs if l.template_hash == logtpl_hash),
                    None,
                )

                item = EvidenceItem(
                    id=f"logtpl:{logtpl_hash}",
                    type="log",
                    score=novelty,
                    description=f"{log_event.service}: {log_event.template[:60]}" if log_event else logtpl_hash,
                    service=log_event.service if log_event else None,
                )
                items.append(item)

        return sorted(items, key=_sort_key)

    def _distances_from_alert(self) -> dict[str, int]:
        """Undirected hop count from the alert's service to every reachable
        service. Empty when there is no topology or no alert service."""
        topo = self.case.topology
        alerting_svc = self.alert.service
        if not alerting_svc or topo is None or topo.number_of_nodes() == 0:
            return {}
        undirected = topo.to_undirected()
        if alerting_svc not in undirected:
            return {}
        return nx.single_source_shortest_path_length(undirected, alerting_svc)

    def boost_graph_path(self, items: list[EvidenceItem]) -> list[EvidenceItem]:
        """Attach graph distance to every item, boost items within 2 hops of
        the alert's service by 10%, and return the pack in ranked order."""
        distances = self._distances_from_alert()

        out = []
        for item in items:
            dist = distances.get(item.service) if item.service else None
            score = item.score * 1.1 if (dist is not None and dist <= 2) else item.score
            out.append(replace(item, score=score, graph_distance=dist))

        return sorted(out, key=_sort_key)

    def rank(self) -> EvidencePack:
        """Rank all evidence and return a capped pack."""
        # Rank all evidence types
        kpi_items = self.rank_kpis()
        span_items = self.rank_spans()
        log_items = self.rank_logs()

        # Merge and deduplicate
        all_items = kpi_items + span_items + log_items
        seen_ids = set()
        deduped = []
        for item in all_items:
            if item.id not in seen_ids:
                deduped.append(item)
                seen_ids.add(item.id)

        # Boost items on critical path
        boosted = self.boost_graph_path(deduped)

        # Cap at 40 items
        capped = boosted[:40]

        # Estimate token count (rough: ~4 tokens per word, 60 chars per item description)
        token_estimate = sum(
            len(item.description.split()) for item in capped
        ) * 2  # Conservative estimate

        return EvidencePack(
            case_id=self.case.case_id,
            items=capped,
            token_estimate=token_estimate,
        )
