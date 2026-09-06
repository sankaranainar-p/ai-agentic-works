"""
tests/test_rcaeval_adapter.py — Tests for pre/signals/rcaeval.py against
the trimmed fixture cases in tests/fixtures/rcaeval/ (RE1-OB and RE2-OB,
both under 5MB total).

Covers:
  - RE1 (metrics-only) and RE2 (metrics+logs+traces) loading
  - metric key normalisation to `svc:metric`
  - log parsing into LogEvent with a Drain-style template hash
  - trace parsing into Span with parent links
  - topology construction as a networkx.DiGraph from caller->callee spans
  - KPI key count / span count / topology edge set assertions on the
    fixture cases specifically (not just "some data loaded")
  - GroundTruth is not reachable from any object reachable from FailureCase
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from pre.signals.rcaeval import RCAEvalAdapter
from pre.signals.types import FailureCase, GroundTruth, LogEvent, MetricSeries, Span

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "rcaeval"


def _load(dataset: str) -> list[tuple[FailureCase, GroundTruth]]:
    return list(RCAEvalAdapter(FIXTURE_ROOT, dataset))


# ---------------------------------------------------------------------------
# RE1 (metrics-only)
# ---------------------------------------------------------------------------

def test_re1_ob_fixture_yields_one_case():
    cases = _load("RE1-OB")
    assert len(cases) == 1


def test_re1_ob_ground_truth_matches_directory_encoding():
    fc, gt = _load("RE1-OB")[0]
    assert gt.case_id == "RE1-OB_productcatalogservice_cpu_1"
    assert gt.root_cause_service == "productcatalogservice"
    assert gt.fault_type == "cpu"
    assert gt.raw_fault_type == "cpu"
    assert gt.inject_time == 1685364577


def test_re1_ob_metric_key_count_and_normalisation():
    fc, gt = _load("RE1-OB")[0]
    # Fixture trimmed from the real RE1-OB productcatalogservice_cpu/1 case,
    # which has 49 distinct svc:metric series (see data.csv header).
    assert len(fc.metrics) == 49
    assert "productcatalogservice:cpu" in fc.metrics
    assert all(":" in key for key in fc.metrics)
    sample = fc.metrics["productcatalogservice:cpu"]
    assert isinstance(sample, MetricSeries)
    assert len(sample.times) == len(sample.values) == 300


def test_re1_ob_has_no_logs_or_traces():
    fc, gt = _load("RE1-OB")[0]
    assert fc.logs == []
    assert fc.traces == []
    assert fc.topology.number_of_nodes() == 0


# ---------------------------------------------------------------------------
# RE2 (metrics + logs + traces)
# ---------------------------------------------------------------------------

def test_re2_ob_fixture_yields_one_case():
    cases = _load("RE2-OB")
    assert len(cases) == 1


def test_re2_ob_ground_truth_matches_directory_encoding():
    fc, gt = _load("RE2-OB")[0]
    assert gt.case_id == "RE2-OB_checkoutservice_delay_1"
    assert gt.root_cause_service == "checkoutservice"
    assert gt.fault_type == "delay"
    assert gt.inject_time == 1705666511


def test_re2_ob_metric_key_count():
    fc, gt = _load("RE2-OB")[0]
    # Fixture trimmed simple_metrics.csv has 75 svc:metric series (76 columns - time).
    assert len(fc.metrics) == 75
    assert "checkoutservice:cpu" in fc.metrics
    assert "checkoutservice:latency-90" in fc.metrics
    # every column attributes to a real service, none fall into the
    # synthetic "cluster" bucket for this fixture
    assert not any(key.startswith("cluster:") for key in fc.metrics)


def test_re2_ob_log_count_and_template_hash():
    fc, gt = _load("RE2-OB")[0]
    assert len(fc.logs) == 400
    assert all(isinstance(e, LogEvent) for e in fc.logs)

    # Same message shape -> same template/hash even with different variable
    # (UUID) data. GetCartAsync's userId is a UUID, so it masks cleanly to a
    # single template, unlike AddItemAsync whose productId is alphanumeric
    # and legitimately stays unmasked (different products = different lines).
    get_cart_events = [e for e in fc.logs if e.template.startswith("GetCartAsync")]
    assert len(get_cart_events) > 1
    hashes = {e.template_hash for e in get_cart_events}
    assert hashes == {get_cart_events[0].template_hash}, "same template must hash identically"

    # Distinct message shapes must not collide.
    request_events = [e for e in fc.logs if e.message == "request started"]
    other_events = [e for e in fc.logs if e.message == "request complete"]
    assert request_events and other_events
    assert request_events[0].template_hash != other_events[0].template_hash


def test_re2_ob_span_count_and_parent_links():
    fc, gt = _load("RE2-OB")[0]
    assert len(fc.traces) == 400
    assert all(isinstance(s, Span) for s in fc.traces)
    with_parent = [s for s in fc.traces if s.parent_span_id]
    assert len(with_parent) == 373


def test_re2_ob_topology_edge_set():
    fc, gt = _load("RE2-OB")[0]
    assert isinstance(fc.topology, nx.DiGraph)
    expected_nodes = {
        "checkoutservice", "currencyservice", "emailservice", "frontendservice",
        "paymentservice", "productcatalogservice", "recommendationservice",
    }
    assert set(fc.topology.nodes()) == expected_nodes

    expected_edges = {
        ("checkoutservice", "currencyservice"),
        ("checkoutservice", "emailservice"),
        ("checkoutservice", "paymentservice"),
        ("checkoutservice", "productcatalogservice"),
        ("frontendservice", "checkoutservice"),
        ("frontendservice", "currencyservice"),
        ("frontendservice", "productcatalogservice"),
        ("frontendservice", "recommendationservice"),
        ("recommendationservice", "productcatalogservice"),
    }
    assert set(fc.topology.edges()) == expected_edges


def test_re2_ob_topology_has_no_self_edges():
    fc, gt = _load("RE2-OB")[0]
    assert all(u != v for u, v in fc.topology.edges())


# ---------------------------------------------------------------------------
# GroundTruth isolation invariant
# ---------------------------------------------------------------------------

def _reaches_groundtruth(obj, seen: set[int] | None = None, depth: int = 0) -> bool:
    """Recursively check whether *obj* contains a GroundTruth instance
    anywhere in its object graph (attributes, list/tuple/set/dict values).
    """
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


@pytest.mark.parametrize("dataset", ["RE1-OB", "RE2-OB"])
def test_ground_truth_not_reachable_from_failure_case(dataset):
    fc, gt = _load(dataset)[0]
    assert not _reaches_groundtruth(fc), (
        "GroundTruth must not be reachable from FailureCase — "
        "agents given a FailureCase must not be able to see the answer"
    )


def test_ground_truth_not_reachable_from_adapter_itself():
    """Even the adapter object handed around during iteration must not
    expose GroundTruth via attributes an agent might stumble onto."""
    adapter = RCAEvalAdapter(FIXTURE_ROOT, "RE1-OB")
    list(adapter)  # exhaust the iterator, forcing internal state if any
    assert not _reaches_groundtruth(adapter)


# ---------------------------------------------------------------------------
# RE3 rejected
# ---------------------------------------------------------------------------

def test_re3_dataset_rejected():
    with pytest.raises(ValueError, match="RE1/RE2"):
        RCAEvalAdapter(FIXTURE_ROOT, "RE3-OB")


def test_unknown_dataset_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        RCAEvalAdapter(FIXTURE_ROOT, "RE1-NONEXISTENT")
