"""
pre/signals/openrca.py — Adapter for the OpenRCA "Bank" system
(https://github.com/microsoft/OpenRCA).

OpenRCA is structured very differently from RCAEval: instead of one
directory per injected fault, it ships two small per-system CSVs
(`record.csv` = ground truth, `query.csv` = natural-language RCA tasks,
row-aligned 1:1 with `record.csv` in generation order — see OpenRCA's own
`main/generate.py::query_generate`, which iterates `record.csv` rows in
order and appends one query per row) plus a large shared `telemetry/`
tree covering the *entire* observation period, split into per-date
subdirectories:

    {SYSTEM}/
        query.csv     one row per RCA task: task_index, instruction, scoring_points
        record.csv    one row per real failure: level, component, timestamp, datetime, reason
        telemetry/
            {YYYY_MM_DD}/
                log/    log_service.csv     per-second granularity
                metric/ metric_app.csv      business KPIs, 60s cadence, no per-component id
                        metric_container.csv per-pod-component KPIs, 60s cadence
                trace/  trace_span.csv      per-millisecond granularity

The Google Drive link in OpenRCA's own README requires manual download
and is not scriptable/checksummable; this adapter instead defaults to
the public, directly-downloadable Hugging Face mirror
(https://huggingface.co/datasets/cdreetz/OpenRCA), which was hand-verified
against OpenRCA's documented schema and against the byte-for-byte-record
counts in OpenRCA's own archived `rca/archive/agent-Bank.csv` (136 rows,
matching this adapter's 136 `record.csv` rows) while building this file
-- see CONVERSION.md for the exact verification steps and raw commands.
No local copy of this ~26GB telemetry tree is committed to this repo;
`data/scripts/download_openrca.py` fetches only the date-folders actually
referenced by `record.csv`/`query.csv` (never the full ~26GB) into
`data/openrca/Bank/`.

Ground truth timing/timezone (CRITICAL, verified against real data, see
CONVERSION.md): `record.csv`'s `timestamp` column is Unix seconds in UTC;
its `datetime` column is the *same instant* rendered in Asia/Shanghai
(UTC+8) — this matches OpenRCA's own README FAQ ("All faults are recorded
in the UTC+8 timezone"). The `{YYYY_MM_DD}` telemetry folder name is
therefore selected by converting `timestamp` to Asia/Shanghai first, not
by naively using the UTC date. Getting this wrong silently looks up the
*previous* day's telemetry folder for any UTC timestamp before 16:00 UTC
(00:00 Asia/Shanghai) — verified against `record.csv` row 0
(`timestamp=1614841020` -> UTC 2021-03-04 06:57:00, but the correct
folder is `2021_03_04` only because Shanghai time is 2021-03-04 14:57:00;
a case near UTC midnight would land in the wrong folder under a
UTC-date assumption).

Evidence window (verified against OpenRCA's `main/generate.py`, which is
the source of the wording every query.csv `instruction` string uses):
`timestamp2timeperiod()` buckets the ground-truth timestamp into the
containing 30-minute, minute-aligned window in Asia/Shanghai
(`minute - (minute % 30)` to `+30min`) — e.g. a failure at 14:57 Shanghai
time falls in the 14:30-15:00 window, exactly matching what every
query's instruction text says ("within the time range of 14:30 to
15:00"). This adapter's `evidence_window()` reproduces that bucketing so
the returned FailureCase's data spans exactly the window an agent solving
the corresponding query.csv task would be told about — no more (which
would leak the answer for half-hour-conflict cases, see below) and no
less (which would starve the agent of evidence within its stated window).

Granularity unification (the core requirement of this adapter): metrics
(60s), logs (1s), and traces (1ms) are resampled onto one shared 1-second
grid per case, so classifiers/agents never have to special-case which
telemetry type they're looking at:
  - Metrics: forward-filled from 60s cadence up to 1s. Every one of the
    59 synthetic in-between seconds per real sample gets
    `MetricSeries.is_forward_filled[i] = True`; the one second matching a
    real sample gets `False`. This is a lossy upsample (we invent 59x
    the sample count, all carrying stale information) and callers must
    check the flag before treating an interpolated point as a fresh
    observation -- see pre.signals.types.MetricSeries docstring.
  - Logs: already per-second; each LogEvent's second-aligned time bucket
    is used as-is, no resampling needed (multiple log lines can and do
    share a bucket -- this adapter does not deduplicate them).
  - Traces: already sub-second (millisecond); each Span's start_time_ms
    is floor-divided to its containing second for bucket alignment, but
    the original millisecond timestamp is preserved on the Span itself
    (start_time_ms is not truncated) since span ordering within a second
    matters for parent/child latency analysis.

Root cause / fault_type mapping: OpenRCA's `record.csv` `reason` values
(e.g. "high memory usage", "network packet loss") do not correspond to
RCAEval's resource/network fault codes; they map to this project's
OpenRCA-specific `data/taxonomy.yaml` fault_class entries
(`configuration_error`, `dependency_failure`) only approximately, since
neither exact match is well-established from public evidence -- honestly
tracked in `raw_fault_type` (verbatim `reason` string) with
`fault_type` mapped via `_REASON_TO_FAULT_CLASS`, which is a best-effort
categorisation this project made, not something OpenRCA itself defines.
"""

from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from pathlib import Path
from typing import Iterator, Optional

import networkx as nx
import pandas as pd
import pytz

from pre.signals.log_template import extract_template
from pre.signals.types import FailureCase, GroundTruth, LogEvent, MetricSeries, Span

_SHANGHAI = pytz.timezone("Asia/Shanghai")

# OpenRCA record.csv `reason` -> this project's fault_class taxonomy
# (data/taxonomy.yaml). Best-effort categorisation: OpenRCA does not
# define this mapping itself. Resource-exhaustion-sounding reasons map to
# RCAEval's existing resource fault_class names (reused, not duplicated,
# since e.g. "high memory usage" is conceptually the same class of fault
# as RCAEval's "memory"); reasons with no RCAEval analogue map to the
# OpenRCA-specific classes added to data/taxonomy.yaml.
_REASON_TO_FAULT_CLASS = {
    "high cpu usage": "cpu",
    "high jvm cpu load": "cpu",
    "high memory usage": "memory",
    "jvm out of memory (oom) heap": "memory",
    "high disk i/o read usage": "disk",
    "high disk space usage": "disk",
    "network latency": "delay",
    "network packet loss": "loss",
}


def _clean(value):
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, str) and value == "":
        return None
    return value


def _shanghai_date_folder(unix_seconds: float) -> str:
    """Return the `{YYYY_MM_DD}` telemetry folder name for a UTC unix
    timestamp, converting to Asia/Shanghai first (see module docstring
    for why this conversion is required, not optional).
    """
    dt = pd.Timestamp(unix_seconds, unit="s", tz="UTC").tz_convert(_SHANGHAI)
    return dt.strftime("%Y_%m_%d")


def evidence_window(record_timestamp: float) -> tuple[int, int]:
    """Return (start, end) unix-second bounds of the 30-minute,
    minute-aligned Asia/Shanghai window containing *record_timestamp*,
    reproducing OpenRCA's own `main/generate.py::timestamp2timeperiod`
    exactly (verified against every query.csv instruction string, which
    states this same window in prose -- see module docstring).
    """
    dt = pd.Timestamp(record_timestamp, unit="s", tz="UTC").tz_convert(_SHANGHAI)
    start_minute = dt.minute - (dt.minute % 30)
    start = dt.replace(minute=start_minute, second=0, microsecond=0)
    end = start + pd.Timedelta(minutes=30)
    return int(start.timestamp()), int(end.timestamp())


def _load_metric_container(
    metric_csv: Path, window_start: int, window_end: int
) -> dict[str, MetricSeries]:
    """Load metric_container.csv rows within [window_start, window_end)
    into {component:kpi_name -> MetricSeries}, resampled up to 1s cadence
    with forward-fill flags (see module docstring for the resampling
    contract).

    metric_container.csv columns: timestamp,cmdb_id,kpi_name,value
    (verified against the real Hugging Face mirror of
    Bank/telemetry/{date}/metric/metric_container.csv). `cmdb_id` is the
    pod-level component name matching record.csv's `component` column
    (verified: both use names like "Tomcat01", "MG02", "Redis02").
    """
    if not metric_csv.exists():
        return {}

    df = pd.read_csv(metric_csv, dtype={"cmdb_id": str, "kpi_name": str})
    df = df[(df["timestamp"] >= window_start) & (df["timestamp"] < window_end)]
    if df.empty:
        return {}

    metrics: dict[str, MetricSeries] = {}
    for (cmdb_id, kpi_name), group in df.groupby(["cmdb_id", "kpi_name"], sort=False):
        key = f"{cmdb_id}:{kpi_name}"
        group = group.sort_values("timestamp")
        native_times = group["timestamp"].astype(int).tolist()
        native_values = group["value"].astype(float).tolist()
        times, values, ffilled = _resample_to_1s(native_times, native_values, window_start, window_end)
        if not times:
            continue
        metrics[key] = MetricSeries(
            key=key, times=tuple(times), values=tuple(values), is_forward_filled=tuple(ffilled)
        )
    return metrics


def _load_metric_app(metric_csv: Path, window_start: int, window_end: int) -> dict[str, MetricSeries]:
    """Load metric_app.csv (business KPIs, no per-component owner) within
    the window, resampled the same way as metric_container.

    metric_app.csv columns: timestamp,rr,sr,cnt,mrt,tc (verified against
    the real mirror). `tc` names a synthetic transaction test
    ("ServiceTest1".."ServiceTest11"), not a record.csv component --
    these rows are business-KPI time series, not per-pod telemetry, so
    they are kept under a synthetic "app" service bucket (parallel to
    RCAEval's "cluster" bucket for ownerless columns) rather than force-
    mapped onto a component that doesn't own them.
    """
    if not metric_csv.exists():
        return {}

    df = pd.read_csv(metric_csv)
    df = df[(df["timestamp"] >= window_start) & (df["timestamp"] < window_end)]
    if df.empty:
        return {}

    metrics: dict[str, MetricSeries] = {}
    for tc, group in df.groupby("tc", sort=False):
        group = group.sort_values("timestamp")
        native_times = group["timestamp"].astype(int).tolist()
        for kpi in ("rr", "sr", "cnt", "mrt"):
            key = f"app.{tc}:{kpi}"
            native_values = group[kpi].astype(float).tolist()
            times, values, ffilled = _resample_to_1s(native_times, native_values, window_start, window_end)
            if not times:
                continue
            metrics[key] = MetricSeries(
                key=key, times=tuple(times), values=tuple(values), is_forward_filled=tuple(ffilled)
            )
    return metrics


def _resample_to_1s(
    native_times: list[int], native_values: list[float], window_start: int, window_end: int
) -> tuple[list[int], list[float], list[bool]]:
    """Upsample a coarser-cadence series to one sample per second across
    [window_start, window_end), forward-filling from the last real sample
    at or before each second and flagging every synthesised second.

    Leading seconds before the first native sample have no prior value to
    forward-fill from; they are dropped (not zero-filled) rather than
    inventing a value with no basis, matching this adapter's "never
    silently fabricate data" stance (see also pre/verification.py's
    NotImplementedError stubs for the same principle applied elsewhere in
    this project).
    """
    if not native_times:
        return [], [], []

    times: list[int] = []
    values: list[float] = []
    ffilled: list[bool] = []

    native_set = set(native_times)
    idx = 0
    n = len(native_times)
    last_value: Optional[float] = None
    started = False

    for t in range(window_start, window_end):
        while idx < n and native_times[idx] <= t:
            last_value = native_values[idx]
            idx += 1
            started = True
        if not started:
            continue
        times.append(t)
        values.append(last_value)
        ffilled.append(t not in native_set)

    return times, values, ffilled


def _load_logs(log_csv: Path, window_start: int, window_end: int) -> list[LogEvent]:
    """Load log_service.csv rows within [window_start, window_end).

    log_service.csv columns: log_id,timestamp,cmdb_id,log_name,value
    (verified against the real mirror; `value` is the raw log line and
    can itself contain commas/newlines, correctly unescaped by pandas'
    CSV parser when the field is quoted in the source, which it is).
    Already per-second native cadence -- no resampling needed, multiple
    events can and do share a second.
    """
    if not log_csv.exists():
        return []

    # timestamp is the 2nd column; read only rows in range without loading
    # the whole (100MB+ per date) file's `value` text for out-of-window
    # rows. pandas has no native predicate pushdown for CSV, so we do a
    # coarse chunked read filtering by timestamp instead of one big read.
    events: list[LogEvent] = []
    for chunk in pd.read_csv(
        log_csv,
        dtype=str,
        keep_default_na=False,
        na_values=[""],
        chunksize=200_000,
    ):
        chunk["timestamp"] = chunk["timestamp"].astype(int)
        chunk = chunk[(chunk["timestamp"] >= window_start) & (chunk["timestamp"] < window_end)]
        if chunk.empty:
            continue
        for row in chunk.itertuples(index=False):
            row_dict = {k: _clean(v) for k, v in row._asdict().items()}
            message = row_dict.get("value") or ""
            template, template_hash = extract_template(message)
            events.append(
                LogEvent(
                    time=int(row_dict["timestamp"]),
                    service=row_dict.get("cmdb_id") or "",
                    message=message,
                    template=template,
                    template_hash=template_hash,
                    level=row_dict.get("log_name"),
                    raw=row_dict,
                )
            )
    return events


def _load_traces(trace_csv: Path, window_start: int, window_end: int) -> list[Span]:
    """Load trace_span.csv rows within [window_start, window_end).

    trace_span.csv columns: timestamp,cmdb_id,parent_id,span_id,trace_id,
    duration (verified against the real mirror). `timestamp` is
    milliseconds (13-digit values observed, vs log_service.csv's 10-digit
    seconds -- confirmed by digit-count and by the window-arithmetic
    check documented in CONVERSION.md). `duration`'s unit is NOT
    documented anywhere in OpenRCA's README/paper; this adapter assumes
    milliseconds (consistent with the millisecond `timestamp` column and
    the observed magnitude -- duration values up to ~1700 in the sampled
    data, i.e. up to ~1.7s spans, a plausible span duration for a bank
    transaction system) and records that assumption here rather than
    silently picking a unit. If this assumption is later found wrong,
    only this function's unit conversion needs correcting -- Span.
    duration_us is populated as `duration * 1000` under the ms
    assumption.

    OpenRCA's own README states Bank traces are pod-level only, with "no
    vertical deployment structure" (only horizontal pod-to-pod spans, no
    node/container layering the way Market's traces have) -- this
    adapter does not attempt to synthesise a deployment hierarchy for
    Bank spans, matching that documented limitation.
    """
    if not trace_csv.exists():
        return []

    spans: list[Span] = []
    window_start_ms = window_start * 1000
    window_end_ms = window_end * 1000

    for chunk in pd.read_csv(
        trace_csv,
        dtype=str,
        keep_default_na=False,
        na_values=[""],
        chunksize=500_000,
    ):
        chunk["timestamp"] = chunk["timestamp"].astype("int64")
        chunk = chunk[(chunk["timestamp"] >= window_start_ms) & (chunk["timestamp"] < window_end_ms)]
        if chunk.empty:
            continue
        for row in chunk.itertuples(index=False):
            r = {k: _clean(v) for k, v in row._asdict().items()}
            duration_ms = float(r.get("duration") or 0)
            spans.append(
                Span(
                    span_id=r.get("span_id") or "",
                    trace_id=r.get("trace_id") or "",
                    service=r.get("cmdb_id") or "",
                    operation="",  # OpenRCA trace_span.csv has no operation-name column
                    start_time_ms=int(r["timestamp"]),
                    duration_us=int(duration_ms * 1000),  # see docstring: ms assumption
                    status_code=None,  # OpenRCA trace_span.csv has no status column
                    parent_span_id=r.get("parent_id"),
                )
            )
    return spans


def _build_topology(spans: list[Span]) -> nx.DiGraph:
    """Build a caller -> callee service topology from span parent links,
    identical in approach to pre.signals.rcaeval._build_topology (kept as
    a separate copy rather than a shared helper since OpenRCA's parent
    link semantics -- `parent_id` sometimes equalling `span_id` for root
    spans, see e.g. the `IG01` rows in the sample data where
    `parent_id == span_id` -- differ subtly from RCAEval's and a shared
    helper would need to special-case both anyway).
    """
    graph = nx.DiGraph()
    by_id: dict[str, Span] = {}
    for s in spans:
        if s.span_id not in by_id:
            by_id[s.span_id] = s

    for span in spans:
        graph.add_node(span.service)
        if span.parent_span_id and span.parent_span_id != span.span_id and span.parent_span_id in by_id:
            parent = by_id[span.parent_span_id]
            if parent.service and span.service and parent.service != span.service:
                graph.add_edge(parent.service, span.service)

    return graph


class OpenRCABankAdapter:
    """Yields (FailureCase, GroundTruth) pairs for OpenRCA's Bank system.

    Args:
        root: directory containing `Bank/` (a directory with
              `record.csv`, `query.csv`, and `telemetry/`), i.e. either a
              parent of `Bank/` or the `Bank/` directory itself.

    Each yielded FailureCase covers exactly the 30-minute evidence window
    OpenRCA's own query.csv instruction states for that failure (see
    module docstring `evidence_window`), at 1-second resolution across
    metrics/logs/traces.

    KNOWN LIMITATION (see also bench/baselines/openrca_agent.py's
    `scoring_points_from_record` docstring for the same caveat on the
    scoring side): when two or more record.csv failures fall in the same
    30-minute window ("half-hour-conflict" cases in OpenRCA's own
    terminology, see main/generate.py::get_half_hour_conflict_failure_flag),
    OpenRCA generates ONE multi-response query covering all of them. This
    adapter still yields one FailureCase per record.csv row (so every
    ground truth row has a corresponding FailureCase), but multiple rows
    in a conflict group will yield FailureCases with identical evidence
    windows and telemetry -- callers doing single-failure-per-case
    scoring (e.g. Avg@k across independent cases) must group by
    evidence_window to avoid double-counting a shared window as two
    independent trials. See tests/contract/test_adapter_contract.py for
    how this is handled in the cross-adapter contract test.
    """

    system = "openrca_bank"
    dataset = "OpenRCA-Bank"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.bank_dir = self._resolve_bank_dir()
        self.record_csv = self.bank_dir / "record.csv"
        self.query_csv = self.bank_dir / "query.csv"
        self.telemetry_dir = self.bank_dir / "telemetry"
        if not self.record_csv.exists():
            raise FileNotFoundError(f"no record.csv under {self.bank_dir}")

    def _resolve_bank_dir(self) -> Path:
        candidate = self.root / "Bank"
        if candidate.is_dir():
            return candidate
        if self.root.name == "Bank" and self.root.is_dir():
            return self.root
        raise FileNotFoundError(f"Could not find a Bank/ directory under {self.root}")

    def __iter__(self) -> Iterator[tuple[FailureCase, GroundTruth]]:
        record_df = pd.read_csv(self.record_csv)
        for idx, row in record_df.iterrows():
            yield self._load_case(idx, row)

    def _load_case(self, idx: int, row: pd.Series) -> tuple[FailureCase, GroundTruth]:
        timestamp = float(row["timestamp"])
        component = str(row["component"])
        reason = str(row["reason"]).strip()

        case_id = f"OpenRCA-Bank_{idx}_{component}"
        window_start, window_end = evidence_window(timestamp)
        date_folder = _shanghai_date_folder(timestamp)
        date_dir = self.telemetry_dir / date_folder

        metric_dir = date_dir / "metric"
        log_dir = date_dir / "log"
        trace_dir = date_dir / "trace"

        metrics: dict[str, MetricSeries] = {}
        metrics.update(_load_metric_container(metric_dir / "metric_container.csv", window_start, window_end))
        metrics.update(_load_metric_app(metric_dir / "metric_app.csv", window_start, window_end))

        logs = _load_logs(log_dir / "log_service.csv", window_start, window_end)
        traces = _load_traces(trace_dir / "trace_span.csv", window_start, window_end)
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
            root_cause_service=component,
            fault_type=_REASON_TO_FAULT_CLASS.get(reason.lower(), "dependency_failure"),
            raw_fault_type=reason,
            inject_time=int(timestamp),
        )

        return failure_case, ground_truth
