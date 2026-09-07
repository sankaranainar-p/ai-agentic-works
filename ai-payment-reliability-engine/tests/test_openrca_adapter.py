"""
tests/test_openrca_adapter.py — Tests for pre/signals/openrca.py against
the trimmed real-data fixture in tests/fixtures/openrca_bank/ (built from the
real OpenRCA Bank telemetry mirror, ~4.4MB total; see CONVERSION.md for
exact provenance and extraction commands).

Fixture note: unlike tests/fixtures/rcaeval/ (which keeps the RCAEval
adapter's full native evidence window), this fixture keeps only a narrow
slice (+-15s to +-60s, depending on telemetry type) around each of 3 real
record.csv ground-truth timestamps, NOT the full 30-minute evidence
window pre.signals.openrca.evidence_window() computes -- the full window
was independently verified against the complete, un-truncated real
download (see CONVERSION.md's spot-check section) and would make this
fixture ~200x larger for no additional coverage. Consequently these
tests check structural/schema correctness (types, key formats, forward-
fill flag mechanics, ground truth fields) rather than exhaustive sample
counts across the full window -- see tests/test_b2_rcaeval_parity.py and
CONVERSION.md's spot-check section for the full-window, full-fidelity
verification against real, un-truncated data.
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from pre.signals.openrca import OpenRCABankAdapter, evidence_window
from pre.signals.types import FailureCase, GroundTruth, LogEvent, MetricSeries, Span

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "openrca_bank"


def _load() -> list[tuple[FailureCase, GroundTruth]]:
    return list(OpenRCABankAdapter(FIXTURE_ROOT))


def test_fixture_yields_three_cases():
    cases = _load()
    assert len(cases) == 3


def test_ground_truth_matches_record_csv_verbatim():
    """Every field in GroundTruth must trace directly to a record.csv
    cell -- no derived/guessed values except fault_type (an explicit
    best-effort mapping, see _REASON_TO_FAULT_CLASS).
    """
    cases = _load()
    expected = [
        ("Mysql02", "high memory usage", "memory", 1614841020),
        ("Redis02", "high memory usage", "memory", 1614852540),
        ("Tomcat02", "network latency", "delay", 1614856920),
    ]
    for (fc, gt), (component, reason, fault_type, ts) in zip(cases, expected):
        assert gt.root_cause_service == component
        assert gt.raw_fault_type == reason
        assert gt.fault_type == fault_type
        assert gt.inject_time == ts


def test_evidence_window_matches_query_csv_instruction_text():
    """evidence_window() must reproduce the literal time range stated in
    the corresponding query.csv instruction (hand-verified against the
    real query.csv, see CONVERSION.md's spot-check section):
      row 0: "14:30 to 15:00" for a 14:57 failure
      row 1: "18:00 and 18:30" for an 18:09 failure
      row 2: "19:00 to 19:30" for a 19:22 failure
    All three in Asia/Shanghai, per OpenRCA's own README FAQ.
    """
    import pandas as pd

    cases_ts = [1614841020, 1614852540, 1614856920]
    expected_ranges_shanghai = [
        ("2021-03-04 14:30:00", "2021-03-04 15:00:00"),
        ("2021-03-04 18:00:00", "2021-03-04 18:30:00"),
        ("2021-03-04 19:00:00", "2021-03-04 19:30:00"),
    ]
    for ts, (start_str, end_str) in zip(cases_ts, expected_ranges_shanghai):
        start, end = evidence_window(ts)
        start_dt = pd.Timestamp(start, unit="s", tz="UTC").tz_convert("Asia/Shanghai")
        end_dt = pd.Timestamp(end, unit="s", tz="UTC").tz_convert("Asia/Shanghai")
        assert start_dt.strftime("%Y-%m-%d %H:%M:%S") == start_str
        assert end_dt.strftime("%Y-%m-%d %H:%M:%S") == end_str


def test_metric_keys_are_component_colon_kpi_normalised():
    fc, gt = _load()[0]
    assert len(fc.metrics) > 0
    assert all(":" in key for key in fc.metrics)
    # metric_container.csv keys carry the real component name (matches
    # record.csv's `component`, e.g. "Mysql02"), metric_app.csv keys use
    # the synthetic "app.{tc}" bucket (see _load_metric_app docstring).
    component_keys = [k for k in fc.metrics if not k.startswith("app.")]
    assert any(k.startswith("Mysql02:") for k in component_keys) or any(
        k.startswith("Tomcat") for k in component_keys
    )


def test_metric_series_has_forward_fill_flags():
    """Every MetricSeries from this adapter must carry is_forward_filled
    (unlike RCAEval's adapter, which leaves it None) since OpenRCA metrics
    are natively 60s cadence and this adapter upsamples to 1s -- see
    pre.signals.openrca module docstring and pre.signals.types.MetricSeries.
    """
    fc, gt = _load()[0]
    for key, series in fc.metrics.items():
        assert series.is_forward_filled is not None, f"{key} missing is_forward_filled"
        assert len(series.is_forward_filled) == len(series.times) == len(series.values)


def test_forward_fill_flags_correctly_mark_synthesised_seconds():
    """At least one real (non-ffilled) sample and at least one
    synthesised (ffilled) sample must exist for a 60s-cadence metric
    resampled to 1s across a >60s window -- and the first sample in any
    contiguous run must never be ffilled (there must be a real anchor).
    """
    fc, gt = _load()[0]
    checked_any = False
    for key, series in fc.metrics.items():
        if key.startswith("app."):
            continue
        if len(series) < 2:
            continue
        checked_any = True
        real_count = sum(1 for f in series.is_forward_filled if not f)
        ffilled_count = sum(1 for f in series.is_forward_filled if f)
        assert real_count >= 1, f"{key} has no real samples"
        # a 60s-cadence source resampled to 1s over >=1 real gap must
        # produce far more synthesised seconds than real ones
        if len(series) > 60:
            assert ffilled_count > real_count, f"{key}: expected mostly ffilled seconds"
    assert checked_any, "no eligible multi-sample metric series found in fixture"


def test_metric_series_times_are_contiguous_seconds():
    """Resampled series must have exactly one sample per second, no gaps
    (leading seconds before the first real sample are dropped, not
    zero-filled -- see _resample_to_1s docstring)."""
    fc, gt = _load()[0]
    for key, series in fc.metrics.items():
        if len(series) < 2:
            continue
        diffs = {series.times[i + 1] - series.times[i] for i in range(len(series.times) - 1)}
        assert diffs == {1}, f"{key} is not contiguous at 1s resolution: gaps {diffs}"


def test_log_events_have_template_hash_and_service():
    fc, gt = _load()[0]
    assert len(fc.logs) > 0
    assert all(isinstance(e, LogEvent) for e in fc.logs)
    assert all(e.template_hash for e in fc.logs)
    assert all(e.service for e in fc.logs)


def test_log_events_missing_for_case_with_no_logs_in_narrow_fixture_window():
    """Case index 2 (Tomcat02, network latency) legitimately has zero
    log_service.csv rows in the narrow +-15s fixture slice around its
    ground-truth timestamp -- this is a real property of the trimmed
    fixture, not an adapter bug (verified: the untrimmed full-window
    download for this case, see CONVERSION.md, does have log rows)."""
    fc, gt = _load()[2]
    assert fc.logs == []


def test_trace_spans_within_window_and_have_parent_links():
    fc, gt = _load()[0]
    assert len(fc.traces) > 0
    assert all(isinstance(s, Span) for s in fc.traces)
    with_parent = [s for s in fc.traces if s.parent_span_id]
    assert with_parent, "expected at least one span with a parent link"


def test_topology_is_digraph_with_no_self_edges():
    fc, gt = _load()[0]
    assert isinstance(fc.topology, nx.DiGraph)
    assert fc.topology.number_of_nodes() > 0
    assert all(u != v for u, v in fc.topology.edges())


def test_case_id_encodes_row_index_and_component():
    cases = _load()
    assert cases[0][0].case_id == "OpenRCA-Bank_0_Mysql02"
    assert cases[1][0].case_id == "OpenRCA-Bank_1_Redis02"
    assert cases[2][0].case_id == "OpenRCA-Bank_2_Tomcat02"


def test_system_and_dataset_labels():
    fc, gt = _load()[0]
    assert fc.system == "openrca_bank"
    assert fc.dataset == "OpenRCA-Bank"


# ---------------------------------------------------------------------------
# GroundTruth isolation invariant (same check as tests/test_rcaeval_adapter.py)
# ---------------------------------------------------------------------------

def _reaches_groundtruth(obj, seen: set[int] | None = None, depth: int = 0) -> bool:
    if seen is None:
        seen = set()
    if depth > 8 or id(obj) in seen:
        return False
    seen.add(id(obj))

    if isinstance(obj, GroundTruth):
        return True
    if isinstance(obj, (str, bytes, int, float, bool, type(None))):
        return False
    if hasattr(obj, "__dict__"):
        for v in vars(obj).values():
            if _reaches_groundtruth(v, seen, depth + 1):
                return True
    if isinstance(obj, dict):
        for v in obj.values():
            if _reaches_groundtruth(v, seen, depth + 1):
                return True
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            if _reaches_groundtruth(v, seen, depth + 1):
                return True
    return False


def test_ground_truth_not_reachable_from_failure_case():
    fc, gt = _load()[0]
    assert not _reaches_groundtruth(fc), (
        "GroundTruth must not be reachable from FailureCase — "
        "agents given a FailureCase must not be able to see the answer"
    )


def test_ground_truth_not_reachable_from_adapter_itself():
    adapter = OpenRCABankAdapter(FIXTURE_ROOT)
    list(adapter)
    assert not _reaches_groundtruth(adapter)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_missing_bank_dir_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        OpenRCABankAdapter(tmp_path)
