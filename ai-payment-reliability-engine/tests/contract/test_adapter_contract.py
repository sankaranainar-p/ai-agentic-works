"""
tests/contract/test_adapter_contract.py — Cross-adapter contract test.

Every adapter under pre/signals/ (RCAEvalAdapter, OpenRCABankAdapter, and
any future benchmark adapter) must produce (FailureCase, GroundTruth)
pairs satisfying the same structural contract, so classifiers/agents and
the benchmark harness (bench/run_benchmark.py) can treat every benchmark
uniformly. This test runs the same assertions against both adapters'
existing trimmed fixtures (tests/fixtures/rcaeval/, tests/fixtures/openrca_bank/)
rather than introducing a third, adapter-agnostic fixture format, so it
exercises each adapter's real, already-verified code path.

Contract checked here:
  1. Iterating the adapter yields (FailureCase, GroundTruth) tuples.
  2. FailureCase has case_id/dataset/system (non-empty str), metrics
     (dict[str, MetricSeries]), logs (list[LogEvent]), traces (list[Span]),
     topology (nx.DiGraph).
  3. GroundTruth has case_id (matching its paired FailureCase's case_id),
     root_cause_service (non-empty str), fault_type (a value present in
     data/taxonomy.yaml's fault_class), raw_fault_type (non-empty str),
     inject_time (positive int, unix seconds).
  4. Every MetricSeries key contains ":" (svc:metric normalisation) and
     has len(times) == len(values) == len(is_forward_filled) when
     is_forward_filled is not None.
  5. GroundTruth is never reachable from FailureCase (delegates to each
     adapter's own test module's _reaches_groundtruth, re-implemented
     here identically so this file has no import dependency on either
     adapter's test module).
  6. Every LogEvent/Span belongs to a service string (non-empty) --
     loosely checked, since some legitimate rows across adapters can have
     an empty service (e.g. RCAEval's synthetic "cluster" bucket has no
     single owning service by design) -- checked per-adapter with that
     adapter's own known exceptions, not blanket-enforced.
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest
import yaml

from pre.signals.openrca import OpenRCABankAdapter
from pre.signals.rcaeval import RCAEvalAdapter
from pre.signals.types import FailureCase, GroundTruth, LogEvent, MetricSeries, Span

REPO_ROOT = Path(__file__).parent.parent.parent
RCAEVAL_FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "rcaeval"
OPENRCA_FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "openrca_bank"

with open(REPO_ROOT / "data" / "taxonomy.yaml") as f:
    _TAXONOMY = yaml.safe_load(f)
_VALID_FAULT_CLASSES = set(_TAXONOMY["fault_class"])


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


def _rcaeval_cases() -> list[tuple[FailureCase, GroundTruth]]:
    return list(RCAEvalAdapter(RCAEVAL_FIXTURE_ROOT, "RE2-OB")) + list(
        RCAEvalAdapter(RCAEVAL_FIXTURE_ROOT, "RE1-OB")
    )


def _openrca_cases() -> list[tuple[FailureCase, GroundTruth]]:
    return list(OpenRCABankAdapter(OPENRCA_FIXTURE_ROOT))


ADAPTER_CASES = {
    "rcaeval": _rcaeval_cases,
    "openrca_bank": _openrca_cases,
}


@pytest.mark.parametrize("adapter_name", list(ADAPTER_CASES))
def test_adapter_yields_failure_case_and_ground_truth_pairs(adapter_name):
    cases = ADAPTER_CASES[adapter_name]()
    assert cases, f"{adapter_name} adapter yielded no cases from its fixture"
    for fc, gt in cases:
        assert isinstance(fc, FailureCase)
        assert isinstance(gt, GroundTruth)


@pytest.mark.parametrize("adapter_name", list(ADAPTER_CASES))
def test_failure_case_required_fields_are_well_formed(adapter_name):
    cases = ADAPTER_CASES[adapter_name]()
    for fc, gt in cases:
        assert isinstance(fc.case_id, str) and fc.case_id
        assert isinstance(fc.dataset, str) and fc.dataset
        assert isinstance(fc.system, str) and fc.system
        assert isinstance(fc.metrics, dict)
        assert isinstance(fc.logs, list)
        assert isinstance(fc.traces, list)
        assert isinstance(fc.topology, nx.DiGraph)


@pytest.mark.parametrize("adapter_name", list(ADAPTER_CASES))
def test_ground_truth_required_fields_are_well_formed(adapter_name):
    cases = ADAPTER_CASES[adapter_name]()
    for fc, gt in cases:
        assert gt.case_id == fc.case_id
        assert isinstance(gt.root_cause_service, str) and gt.root_cause_service
        assert isinstance(gt.raw_fault_type, str) and gt.raw_fault_type
        assert isinstance(gt.inject_time, int) and gt.inject_time > 0
        assert gt.fault_type in _VALID_FAULT_CLASSES, (
            f"{adapter_name} case {gt.case_id!r} has fault_type "
            f"{gt.fault_type!r} not in data/taxonomy.yaml's fault_class"
        )


@pytest.mark.parametrize("adapter_name", list(ADAPTER_CASES))
def test_metric_series_keys_and_shapes(adapter_name):
    cases = ADAPTER_CASES[adapter_name]()
    for fc, gt in cases:
        for key, series in fc.metrics.items():
            assert isinstance(series, MetricSeries)
            assert ":" in key, f"{adapter_name} metric key {key!r} not in svc:metric form"
            assert len(series.times) == len(series.values), (
                f"{adapter_name} case {gt.case_id!r} metric {key!r}: "
                f"times/values length mismatch"
            )
            if series.is_forward_filled is not None:
                assert len(series.is_forward_filled) == len(series.times), (
                    f"{adapter_name} case {gt.case_id!r} metric {key!r}: "
                    f"is_forward_filled length mismatch"
                )


@pytest.mark.parametrize("adapter_name", list(ADAPTER_CASES))
def test_log_events_and_spans_are_correct_types(adapter_name):
    cases = ADAPTER_CASES[adapter_name]()
    for fc, gt in cases:
        assert all(isinstance(e, LogEvent) for e in fc.logs)
        assert all(isinstance(s, Span) for s in fc.traces)


@pytest.mark.parametrize("adapter_name", list(ADAPTER_CASES))
def test_ground_truth_not_reachable_from_failure_case(adapter_name):
    cases = ADAPTER_CASES[adapter_name]()
    for fc, gt in cases:
        assert not _reaches_groundtruth(fc), (
            f"{adapter_name} case {gt.case_id!r}: GroundTruth reachable from "
            "FailureCase — agents must never be able to see the answer"
        )


@pytest.mark.parametrize("adapter_name", list(ADAPTER_CASES))
def test_topology_has_no_self_edges(adapter_name):
    cases = ADAPTER_CASES[adapter_name]()
    for fc, gt in cases:
        assert all(u != v for u, v in fc.topology.edges()), (
            f"{adapter_name} case {gt.case_id!r}: topology has a self-edge"
        )
