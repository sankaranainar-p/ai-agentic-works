"""
pre/signals/types.py — Shared data model for failure-signal adapters.

Every adapter under pre/signals/ (RCAEval, and future OpenRCA/other
benchmark adapters) normalises its raw telemetry into these types so the
rest of the pipeline (classifiers, agents, benchmark harness) never has to
know which benchmark a case came from.

Design invariant: GroundTruth must never be reachable from a FailureCase
instance (no back-reference, no shared mutable container). Adapters hand
agents/classifiers a FailureCase and keep GroundTruth only for scoring in
the benchmark harness. See tests/test_rcaeval_adapter.py for an automated
check of this invariant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import networkx as nx
import pandas as pd


@dataclass(frozen=True)
class MetricSeries:
    """A single `svc:metric` time series.

    `times` are Unix seconds (int), `values` are floats aligned by index.
    """

    key: str  # normalised "svc:metric", e.g. "productcatalogservice:cpu"
    times: tuple[int, ...]
    values: tuple[float, ...]

    def __len__(self) -> int:
        return len(self.times)

    def to_series(self) -> pd.Series:
        return pd.Series(self.values, index=pd.Index(self.times, name="time"), name=self.key)


@dataclass(frozen=True)
class LogEvent:
    """A single parsed log line.

    `template` is the Drain-style masked template (variable tokens such as
    numbers, hex ids, and UUIDs replaced with `<*>`); `template_hash` is a
    short stable hash of that template, used to cluster log lines into
    events without relying on any dataset-provided cluster id.
    """

    time: int  # unix nanoseconds if the source had sub-second precision, else seconds
    service: str
    message: str
    template: str
    template_hash: str
    level: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Span:
    """A single trace span with an optional parent link."""

    span_id: str
    trace_id: str
    service: str
    operation: str
    start_time_ms: int
    duration_us: int
    status_code: Optional[float] = None
    parent_span_id: Optional[str] = None


@dataclass
class FailureCase:
    """Normalised, ground-truth-free view of one benchmark failure case.

    This is the only object handed to classifiers/agents. It intentionally
    carries no reference to the GroundTruth for the same case.
    """

    case_id: str
    dataset: str  # e.g. "RE1-OB", "RE2-TT"
    system: str  # e.g. "online_boutique", "train_ticket"
    metrics: dict[str, MetricSeries]  # keyed "svc:metric"
    logs: list[LogEvent]
    traces: list[Span]
    topology: nx.DiGraph  # nodes = services, edges = caller -> callee


@dataclass(frozen=True)
class GroundTruth:
    """Ground-truth root cause for one failure case. Held back from agents."""

    case_id: str
    root_cause_service: str
    fault_type: str  # normalised to data/taxonomy.yaml fault_class where possible
    raw_fault_type: str  # the benchmark's original fault code, e.g. RCAEval's "mem"
    inject_time: int  # unix seconds
