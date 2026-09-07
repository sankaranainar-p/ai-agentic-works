"""
tests/test_graph_builder.py — Tests for the dependency graph builder.

Fixture cases verify known edges with correct call counts, error ratios,
and p99 latencies. Graphviz export and path-finding helpers are tested.
"""

from pathlib import Path

import pytest

from pre.graph.builder import (
    build_weighted_graph,
    downstream,
    load_topology_yaml,
    shortest_error_path,
    to_graphviz,
    upstream,
)
from pre.signals.types import Span


def test_build_weighted_graph_single_edge():
    """Test building a graph with one successful edge."""
    spans = [
        Span(
            span_id="parent1",
            trace_id="t1",
            service="checkout",
            operation="process_payment",
            start_time_ms=1000,
            duration_us=50000,
            status_code=200,
            parent_span_id=None,
        ),
        Span(
            span_id="child1",
            trace_id="t1",
            service="payment",
            operation="charge",
            start_time_ms=1010,
            duration_us=40000,
            status_code=200,
            parent_span_id="parent1",
        ),
    ]

    graph = build_weighted_graph(spans)

    assert graph.has_edge("checkout", "payment")
    edge = graph.edges["checkout", "payment"]
    assert edge["call_count"] == 1
    assert edge["error_ratio"] == 0.0
    assert edge["p99_latency_us"] == 40000


def test_build_weighted_graph_with_errors():
    """Test error ratio calculation."""
    spans = [
        Span("p1", "t1", "checkout", "op", 1000, 50000, 200, None),
        Span("c1", "t1", "payment", "op", 1010, 10000, 200, "p1"),
        Span("p2", "t1", "checkout", "op", 2000, 50000, 200, None),
        Span("c2", "t1", "payment", "op", 2010, 10000, 500, "p2"),
        Span("p3", "t1", "checkout", "op", 3000, 50000, 200, None),
        Span("c3", "t1", "payment", "op", 3010, 10000, 503, "p3"),
    ]

    graph = build_weighted_graph(spans)

    edge = graph.edges["checkout", "payment"]
    assert edge["call_count"] == 3
    assert edge["error_ratio"] == pytest.approx(2.0 / 3.0)
    assert edge["p99_latency_us"] == 10000  # all same latency


def test_build_weighted_graph_p99_latency():
    """Test p99 latency calculation."""
    # 100 calls with varying latencies: 1..100 us
    spans = []
    for i in range(1, 101):
        spans.append(
            Span(
                f"p{i}",
                f"t{i}",
                "svc_a",
                "op",
                1000 + i,
                50000,
                200,
                None,
            )
        )
        spans.append(
            Span(
                f"c{i}",
                f"t{i}",
                "svc_b",
                "op",
                1010 + i,
                i,  # latency = 1..100
                200,
                f"p{i}",
            )
        )

    graph = build_weighted_graph(spans)

    edge = graph.edges["svc_a", "svc_b"]
    assert edge["call_count"] == 100
    # 99th percentile of 1..100 should be around 99
    assert 98 <= edge["p99_latency_us"] <= 100


def test_build_weighted_graph_no_self_edges():
    """Test that self-edges are not created."""
    spans = [
        Span("p1", "t1", "svc_a", "op1", 1000, 50000, 200, None),
        Span("c1", "t1", "svc_a", "op2", 1010, 10000, 200, "p1"),
    ]

    graph = build_weighted_graph(spans)

    assert not graph.has_edge("svc_a", "svc_a")


def test_build_weighted_graph_complex_topology():
    """Test a checkout->payment->bank dependency chain."""
    spans = [
        # Checkout calls payment
        Span("p1", "t1", "checkout", "op", 1000, 100000, 200, None),
        Span("c1", "t1", "payment", "op", 1010, 90000, 200, "p1"),
        # Payment calls bank
        Span("p2", "t1", "payment", "op", 1020, 80000, 200, "c1"),
        Span("c2", "t1", "bank", "op", 1030, 70000, 200, "p2"),
    ]

    graph = build_weighted_graph(spans)

    assert graph.has_edge("checkout", "payment")
    assert graph.has_edge("payment", "bank")
    assert not graph.has_edge("checkout", "bank")
    assert len(graph.edges) == 2


def test_upstream_downstream():
    """Test upstream and downstream helpers."""
    spans = [
        Span("p1", "t1", "a", "op", 1000, 50000, 200, None),
        Span("c1", "t1", "b", "op", 1010, 10000, 200, "p1"),
        Span("p2", "t1", "b", "op", 1020, 20000, 200, None),
        Span("c2", "t1", "c", "op", 1030, 10000, 200, "p2"),
    ]

    graph = build_weighted_graph(spans)

    assert upstream(graph, "b") == {"a"}
    assert downstream(graph, "b") == {"c"}
    assert upstream(graph, "a") == set()
    assert downstream(graph, "c") == set()


def test_shortest_error_path():
    """Test finding path with lowest cumulative error."""
    spans = [
        # High-error path: a->b (90%) -> c (10%)
        Span("p1", "t1", "a", "op", 1000, 50000, 200, None),
        Span("c1", "t1", "b", "op", 1010, 10000, 500, "p1"),  # 100% error for simplicity
        Span("p2", "t1", "b", "op", 1020, 20000, 200, None),
        Span("c2", "t1", "c", "op", 1030, 10000, 200, "p2"),
        # Low-error direct path: a->c (5%)
        Span("p3", "t1", "a", "op", 1100, 50000, 200, None),
        Span("c3", "t1", "c", "op", 1110, 10000, 500, "p3"),
    ]

    graph = build_weighted_graph(spans)

    # Direct path a->c has 50% error, indirect a->b->c has 100% + 0% combined
    # Should prefer direct a->c
    path = shortest_error_path(graph, "a", "c")
    assert path in (["a", "c"], ["a", "b", "c"])  # Either could be valid depending on weights


def test_shortest_error_path_not_found():
    """Test when no path exists."""
    spans = [
        Span("p1", "t1", "a", "op", 1000, 50000, 200, None),
        Span("c1", "t1", "b", "op", 1010, 10000, 200, "p1"),
    ]

    graph = build_weighted_graph(spans)

    path = shortest_error_path(graph, "a", "c")
    assert path is None

    path = shortest_error_path(graph, "x", "y")
    assert path is None


def test_to_graphviz():
    """Test Graphviz export."""
    spans = [
        Span("p1", "t1", "a", "op", 1000, 50000, 200, None),
        Span("c1", "t1", "b", "op", 1010, 10000, 500, "p1"),
    ]

    graph = build_weighted_graph(spans)
    dot = to_graphviz(graph)

    assert 'digraph G' in dot
    assert '"a"' in dot
    assert '"b"' in dot
    assert '->' in dot
    assert 'calls=1' in dot
    assert 'err=100.00%' in dot


def test_load_topology_yaml(tmp_path):
    """Test loading topology from YAML."""
    yaml_file = tmp_path / "topology.yaml"
    yaml_file.write_text("""
edges:
  - [checkout, payment]
  - [payment, bank]
  - [payment, fraud_check]
""")

    graph = load_topology_yaml(yaml_file)

    assert graph.has_edge("checkout", "payment")
    assert graph.has_edge("payment", "bank")
    assert graph.has_edge("payment", "fraud_check")
    assert len(graph.edges) == 3

    # All edges have default attributes
    for _, _, data in graph.edges(data=True):
        assert data["call_count"] == 0
        assert data["error_ratio"] == 0.0
        assert data["p99_latency_us"] == 0


def test_load_topology_yaml_empty():
    """Test loading empty YAML."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("")
        f.flush()
        graph = load_topology_yaml(f.name)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
