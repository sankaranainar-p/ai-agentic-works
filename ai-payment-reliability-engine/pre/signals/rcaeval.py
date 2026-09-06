"""
pre/signals/rcaeval.py — Adapter for the RCAEval benchmark (RE1, RE2).

RCAEval ships failure cases on disk as:

    {dataset}/{service}_{fault}/{repeat}/
        data.csv            RE1: wide time-series, `time` + one
                             `{service}_{metric}` column per pair
        simple_metrics.csv  RE2: the same `time` + `{service}_{metric}`
                             format as RE1's data.csv (RE2 cases have no
                             data.csv; they instead carry a much larger
                             metrics.csv using raw Prometheus metric names,
                             which this adapter does not use — confirmed
                             against the real Zenodo RE2-OB/RE2-TT
                             archives, not just RCAEval's own smaller
                             multi-source demo release)
        inject_time.txt     unix-seconds fault injection timestamp
        logs.csv            RE2 only: raw log lines with a `container_name`
                             (service) column
        traces.csv          RE2 only: spans with `parentSpanID` links

`RCAEvalAdapter(root, dataset)` walks `root/{dataset}/*/*/` and yields one
`(FailureCase, GroundTruth)` pair per case directory, in sorted order for
reproducibility. `dataset` selects the RE1 or RE2 top-level directory name
(e.g. "RE1-OB", "RE2-TT"); RE3 (code-level faults) is out of scope for this
adapter — RE3 case directories use the same file layout but different
fault codes (f1-f5) that don't have a service+metric-based ground truth
the same way.

Ground truth in RCAEval is inferred entirely from the directory name
(`{service}_{fault}/{repeat}`), matching how RCAEval's own `main.py`
recovers it (`basename(dirname(dirname(data_path))).split("_")`).
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Iterator

import networkx as nx
import pandas as pd

from pre.signals.log_template import extract_template
from pre.signals.types import FailureCase, GroundTruth, LogEvent, MetricSeries, Span

# RCAEval RE1/RE2 fault codes -> this project's fault_class taxonomy
# (data/taxonomy.yaml). RE3 code-level faults (f1-f5) are out of scope.
_FAULT_TYPE_MAP = {
    "cpu": "cpu",
    "mem": "memory",
    "disk": "disk",
    "delay": "delay",
    "loss": "loss",
    "socket": "socket",
}

# RCAEval dataset suffix -> this project's `system` label
_SYSTEM_MAP = {
    "OB": "online_boutique",
    "SS": "sock_shop",
    "TT": "train_ticket",
}

_METRIC_COL_RE = re.compile(
    r"^(?P<svc>.+)_(?P<metric>cpu|mem|latency|latency-50|latency-90|load|error|diskio|socket|workload)$"
)


def _clean(value):
    """Normalise a raw CSV cell: NaN/empty -> None, everything else passed through."""
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, str) and value == "":
        return None
    return value


def _system_for(dataset: str) -> str:
    suffix = dataset.rsplit("-", 1)[-1].upper()
    return _SYSTEM_MAP.get(suffix, dataset.lower())


def _parse_case_dir_name(fault_service_dir: str, repeat_dir: str, dataset: str) -> tuple[str, str, str]:
    """Return (case_id, root_cause_service, raw_fault_type) from directory names."""
    service, fault = fault_service_dir.rsplit("_", 1)
    case_id = f"{dataset}_{fault_service_dir}_{repeat_dir}"
    return case_id, service, fault


def _resolve_metrics_file(case_dir: Path) -> Path:
    """Locate the per-service `svc_metric`-named metrics file in a case dir.

    RE1 cases ship this as `data.csv`. RE2 cases (confirmed against the real
    Zenodo archives, not just RCAEval's own multi-source demo release) ship
    it as `simple_metrics.csv`, alongside a much larger `metrics.csv` that
    uses raw Prometheus-style metric names instead of the curated
    `svc_metric` convention this adapter (and RCAEval's own `main.py`, via
    its documented data.csv -> simple_metrics.csv fallback) expects.
    """
    for name in ("data.csv", "simple_metrics.csv"):
        candidate = case_dir / name
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"no data.csv or simple_metrics.csv in {case_dir}"
    )


def _load_metrics(data_csv: Path) -> dict[str, MetricSeries]:
    """Load a metrics file (data.csv or simple_metrics.csv) into
    {svc:metric -> MetricSeries}.

    Drops the duplicate `time.1` column RCAEval's CSVs carry and any column
    that doesn't parse as a `{service}_{metric}` pair (there are a handful of
    cluster-wide columns like `PassthroughCluster_load` that have no owning
    service; they are kept under a synthetic "cluster" service so no data is
    silently dropped). Some RCAEval data.csv files carry trailing all-NaN
    rows (observed in the wild, e.g. RE1-OB checkoutservice_cpu/4); rows with
    a NaN `time` are dropped since they carry no usable timestamp.
    """
    df = pd.read_csv(data_csv)
    df = df.loc[:, ~df.columns.duplicated()]
    if "time.1" in df.columns:
        df = df.drop(columns=["time.1"])
    df = df.dropna(subset=["time"])

    times = tuple(int(t) for t in df["time"])
    metrics: dict[str, MetricSeries] = {}

    for col in df.columns:
        if col == "time":
            continue
        match = _METRIC_COL_RE.match(col)
        if match:
            svc, metric = match.group("svc"), match.group("metric")
        else:
            # e.g. "PassthroughCluster_load" — no per-service owner
            svc, metric = "cluster", col

        key = f"{svc}:{metric}"
        values = tuple(float(v) for v in df[col].fillna(0.0))
        metrics[key] = MetricSeries(key=key, times=times, values=values)

    return metrics


def _load_logs(logs_csv: Path) -> list[LogEvent]:
    if not logs_csv.exists():
        return []
    df = pd.read_csv(logs_csv, dtype=str, keep_default_na=False, na_values=[""])
    events: list[LogEvent] = []
    for row in df.itertuples(index=False):
        row_dict = {k: _clean(v) for k, v in row._asdict().items()}
        message = row_dict.get("message") or ""
        template, template_hash = extract_template(message)
        raw_ts = row_dict.get("timestamp")
        try:
            time_val = int(raw_ts) if raw_ts else 0
        except ValueError:
            time_val = 0
        events.append(
            LogEvent(
                time=time_val,
                service=row_dict.get("container_name") or "",
                message=message,
                template=template,
                template_hash=template_hash,
                level=row_dict.get("level"),
                raw=row_dict,
            )
        )
    return events


def _load_traces(traces_csv: Path) -> list[Span]:
    if not traces_csv.exists():
        return []
    df = pd.read_csv(traces_csv, dtype=str, keep_default_na=False, na_values=[""])
    spans: list[Span] = []
    for row in df.itertuples(index=False):
        r = {k: _clean(v) for k, v in row._asdict().items()}

        def _int(key: str, default: int = 0) -> int:
            v = r.get(key)
            try:
                return int(float(v)) if v is not None else default
            except ValueError:
                return default

        status = r.get("statusCode")
        status_code = float(status) if status is not None else None
        parent = r.get("parentSpanID")

        spans.append(
            Span(
                span_id=r.get("spanID") or "",
                trace_id=r.get("traceID") or "",
                service=r.get("serviceName") or "",
                operation=r.get("operationName") or "",
                start_time_ms=_int("startTimeMillis"),
                duration_us=_int("duration"),
                status_code=status_code,
                parent_span_id=parent,
            )
        )
    return spans


def _build_topology(spans: list[Span]) -> nx.DiGraph:
    """Build a caller -> callee service topology from span parent links.

    An edge (A -> B) means a span in service A is the parent of a span in
    service B, i.e. A called B. Self-edges (a service calling itself, or two
    spans in the same service linked as parent/child) are dropped, matching
    the caller-callee semantics of the topology graph.
    """
    graph = nx.DiGraph()
    by_id = {s.span_id: s for s in spans}

    for span in spans:
        graph.add_node(span.service)
        if span.parent_span_id and span.parent_span_id in by_id:
            parent = by_id[span.parent_span_id]
            if parent.service and span.service and parent.service != span.service:
                graph.add_edge(parent.service, span.service)

    return graph


class RCAEvalAdapter:
    """Yields (FailureCase, GroundTruth) pairs for one RCAEval dataset.

    Args:
        root: directory containing the dataset (e.g. a directory that has
              a `RE1-OB/` or `RE2-TT/` subdirectory, or the dataset
              directory itself — both `root/RE1-OB` and `root` being the
              dataset directory are accepted).
        dataset: dataset name, e.g. "RE1-OB", "RE2-TT". Must start with
                 "RE1-" or "RE2-"; RE3 is out of scope (see module docstring).
    """

    def __init__(self, root: str | Path, dataset: str) -> None:
        if not (dataset.startswith("RE1-") or dataset.startswith("RE2-")):
            raise ValueError(
                f"RCAEvalAdapter supports RE1/RE2 datasets only, got {dataset!r} "
                "(RE3 code-level faults are out of scope for this adapter)"
            )
        self.dataset = dataset
        self.root = Path(root)
        self.dataset_dir = self._resolve_dataset_dir()
        self.system = _system_for(dataset)
        self.suite = "RE1" if dataset.startswith("RE1-") else "RE2"

    def _resolve_dataset_dir(self) -> Path:
        candidate = self.root / self.dataset
        if candidate.is_dir():
            return candidate
        if self.root.name == self.dataset and self.root.is_dir():
            return self.root
        raise FileNotFoundError(
            f"Could not find dataset directory for {self.dataset!r} under {self.root}"
        )

    def __iter__(self) -> Iterator[tuple[FailureCase, GroundTruth]]:
        fault_service_dirs = sorted(
            p.name for p in self.dataset_dir.iterdir() if p.is_dir()
        )
        for fault_service_dir in fault_service_dirs:
            fs_path = self.dataset_dir / fault_service_dir
            repeat_dirs = sorted(
                p.name for p in fs_path.iterdir() if p.is_dir()
            )
            for repeat_dir in repeat_dirs:
                case_dir = fs_path / repeat_dir
                yield self._load_case(fault_service_dir, repeat_dir, case_dir)

    def _load_case(
        self, fault_service_dir: str, repeat_dir: str, case_dir: Path
    ) -> tuple[FailureCase, GroundTruth]:
        case_id, root_cause_service, raw_fault = _parse_case_dir_name(
            fault_service_dir, repeat_dir, self.dataset
        )

        metrics_csv = _resolve_metrics_file(case_dir)
        metrics = _load_metrics(metrics_csv)

        inject_path = case_dir / "inject_time.txt"
        inject_time = int(inject_path.read_text().strip()) if inject_path.exists() else 0

        logs = _load_logs(case_dir / "logs.csv")
        traces = _load_traces(case_dir / "traces.csv")
        topology = _build_topology(traces)

        failure_case = FailureCase(
            case_id=case_id,
            dataset=self.dataset,
            system=self.system,
            metrics=metrics,
            logs=logs,
            traces=traces,
            topology=topology,
        )

        ground_truth = GroundTruth(
            case_id=case_id,
            root_cause_service=root_cause_service,
            fault_type=_FAULT_TYPE_MAP.get(raw_fault, raw_fault),
            raw_fault_type=raw_fault,
            inject_time=inject_time,
        )

        return failure_case, ground_truth
