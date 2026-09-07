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

from collections import Counter, defaultdict
from dataclasses import dataclass
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
    score: float  # Anomaly score [0, 1]
    description: str  # One-line description for humans
    service: Optional[str] = None  # Service this evidence implicates


@dataclass(frozen=True)
class EvidencePack:
    """Ranked evidence for root cause analysis."""

    case_id: str
    items: list[EvidenceItem]  # Sorted by score descending, capped at 40
    token_estimate: int  # Approximate token count for LLM consumption


class RobustScaler:
    """Robust z-score using median and MAD (median absolute deviation)."""

    @staticmethod
    def robust_z_score(values: list[float], target: float) -> float:
        """Compute robust z-score: (x - median) / (1.4826 * MAD)."""
        if len(values) < 2:
            return 0.0

        values_arr = np.array(values, dtype=np.float64)
        median = np.median(values_arr)
        mad = np.median(np.abs(values_arr - median))

        if mad < 1e-9:  # Prevent division by zero on flat data
            mad = 1e-9

        # 1.4826 is the consistent estimator for normal distribution
        scaling_factor = 1.4826 * mad if mad > 0 else 1.0
        return (target - median) / scaling_factor


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

            # Robust z-score against pre-baseline
            z_score = RobustScaler.robust_z_score(pre_values, max_post)
            anomaly_score = min(1.0, abs(z_score) / 3.0)  # Normalize to [0,1]

            if anomaly_score > 0.1:  # Filter weak signals
                svc, metric = key.split(":")
                item = EvidenceItem(
                    id=f"kpi:{svc}:{metric}",
                    type="kpi",
                    score=anomaly_score,
                    description=f"{key} spiked to {max_post:.1f} (z={z_score:.1f})",
                    service=svc,
                )
                items.append(item)

        return sorted(items, key=lambda x: x.score, reverse=True)

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

        return sorted(items, key=lambda x: x.score, reverse=True)

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

        return sorted(items, key=lambda x: x.score, reverse=True)

    def boost_graph_path(self, items: list[EvidenceItem]) -> list[EvidenceItem]:
        """Boost evidence scores if their service is 2 hops from alert service."""
        if not self.alert.service or not self.case.topology:
            return items

        # Find all services within 2 hops
        alerting_svc = self.alert.service
        critical_path_svcs = {alerting_svc}

        # One hop
        if alerting_svc in self.case.topology:
            critical_path_svcs.update(self.case.topology.successors(alerting_svc))
            critical_path_svcs.update(self.case.topology.predecessors(alerting_svc))

        # Two hops
        for svc in list(critical_path_svcs):
            if svc in self.case.topology:
                critical_path_svcs.update(self.case.topology.successors(svc))
                critical_path_svcs.update(self.case.topology.predecessors(svc))

        # Boost items on critical path
        boosted = []
        for item in items:
            if item.service and item.service in critical_path_svcs:
                # Boost score by 10% (capped at 1.0)
                boosted_score = min(1.0, item.score * 1.1)
                boosted.append(
                    EvidenceItem(
                        id=item.id,
                        type=item.type,
                        score=boosted_score,
                        description=item.description,
                        service=item.service,
                    )
                )
            else:
                boosted.append(item)

        return sorted(boosted, key=lambda x: x.score, reverse=True)

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
