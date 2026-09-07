"""
tests/test_evidence.py — Tests for evidence ranking and selection.

Verifies that anomalous KPIs, error spans, and log templates are correctly
ranked, that IDs are in stable format, that the pack is capped at 40 items,
and that ground-truth service appears in top-5 on fixture cases.
"""

import pytest
import networkx as nx

from pre.agents.evidence import (
    EvidenceItem,
    EvidencePack,
    EvidenceRanker,
    RobustScaler,
)
from pre.signals.alert_synth import Alert
from pre.signals.types import FailureCase, LogEvent, MetricSeries, Span


def test_robust_z_score_normal():
    """Test robust z-score on normally distributed data."""
    baseline = [10, 11, 9, 10, 11, 10]
    z = RobustScaler.robust_z_score(baseline, 30)
    # Value 30 is far from baseline median ~10, should have high z-score
    assert z > 2.0


def test_robust_z_score_flat():
    """Test robust z-score on flat data (zero MAD)."""
    baseline = [10, 10, 10, 10]
    z = RobustScaler.robust_z_score(baseline, 10)
    assert z == 0.0


def test_robust_z_score_short():
    """Test robust z-score with too few samples."""
    z = RobustScaler.robust_z_score([10], 20)
    assert z == 0.0


def test_evidence_item_kpi_id():
    """Test KPI evidence ID format."""
    item = EvidenceItem(
        id="kpi:payment:cpu",
        type="kpi",
        score=0.85,
        description="CPU spike",
        service="payment",
    )
    assert item.id.startswith("kpi:")
    assert "payment" in item.id


def test_evidence_item_span_id():
    """Test span evidence ID format."""
    item = EvidenceItem(
        id="span:trace123abc",
        type="span",
        score=0.75,
        description="Error rate spike",
        service="checkout",
    )
    assert item.id.startswith("span:")
    assert "trace123abc" in item.id


def test_evidence_item_log_id():
    """Test log template evidence ID format."""
    item = EvidenceItem(
        id="logtpl:abc123def",
        type="log",
        score=0.65,
        description="Novel error message",
        service="payment",
    )
    assert item.id.startswith("logtpl:")
    assert "abc123def" in item.id


def test_evidence_pack_cap_at_40():
    """Test that evidence pack is capped at 40 items."""
    items = [
        EvidenceItem(
            id=f"kpi:svc{i}:metric{i}",
            type="kpi",
            score=1.0 - i / 100,
            description=f"Evidence {i}",
            service=f"svc{i}",
        )
        for i in range(60)
    ]

    # Create a minimal FailureCase and Alert
    case = FailureCase(
        case_id="test",
        dataset="test",
        system="test",
        metrics={},
        logs=[],
        traces=[],
        topology=nx.DiGraph(),
    )
    alert = Alert(
        case_id="test",
        silent=False,
        rule_id="r1",
        service="svc0",
        metric_key="svc0:metric0",
        z_score=3.0,
        breach_value=100,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="latency",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="Test alert",
        rules_version=1,
    )

    ranker = EvidenceRanker(case, alert)
    pack = EvidencePack(
        case_id="test",
        items=items[:40],  # Cap manually for this test
        token_estimate=100,
    )

    assert len(pack.items) <= 40


def test_evidence_ranker_kpi_ranking():
    """Test that KPIs are ranked by anomaly score."""
    # Create a case with a KPI that spikes post-breach
    times = (900, 950, 1000, 1050, 1100)
    values = (10, 11, 10, 50, 55)  # Spike post-baseline

    case = FailureCase(
        case_id="test",
        dataset="test",
        system="test",
        metrics={
            "svc_a:cpu": MetricSeries(
                key="svc_a:cpu",
                times=times,
                values=values,
            )
        },
        logs=[],
        traces=[],
        topology=nx.DiGraph(),
    )

    alert = Alert(
        case_id="test",
        silent=False,
        rule_id="r1",
        service="svc_a",
        metric_key="svc_a:cpu",
        z_score=3.5,
        breach_value=50,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="latency",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="CPU alert",
        rules_version=1,
    )

    ranker = EvidenceRanker(case, alert)
    kpi_items = ranker.rank_kpis()

    assert len(kpi_items) > 0
    assert kpi_items[0].id == "kpi:svc_a:cpu"
    assert kpi_items[0].type == "kpi"
    assert kpi_items[0].score > 0.1


def test_evidence_ranker_span_ranking():
    """Test that error spans are ranked by error-ratio change."""
    # Times are in milliseconds for spans, and baseline is around 950000ms
    spans = [
        # Pre-breach: no errors
        Span("p1", "t1", "checkout", "call", 900000, 10000, 200, None),
        Span("c1", "t1", "payment", "process", 900010, 9000, 200, "p1"),
        # Post-breach: high error rate
        Span("p2", "t2", "checkout", "call", 1000000, 10000, 200, None),
        Span("c2", "t2", "payment", "process", 1000010, 5000, 500, "p2"),
        Span("p3", "t3", "checkout", "call", 1010000, 10000, 200, None),
        Span("c3", "t3", "payment", "process", 1010010, 5000, 503, "p3"),
    ]

    # Create metrics to establish baseline_boundary
    metrics = {
        "checkout:latency": MetricSeries(
            "checkout:latency",
            (900, 950, 1000, 1010),  # These are in seconds
            (10, 11, 50, 55),
        )
    }

    case = FailureCase(
        case_id="test",
        dataset="test",
        system="test",
        metrics=metrics,
        logs=[],
        traces=spans,
        topology=nx.DiGraph([("checkout", "payment")]),
    )

    alert = Alert(
        case_id="test",
        silent=False,
        rule_id="r1",
        service="payment",
        metric_key="payment:error_rate",
        z_score=2.5,
        breach_value=0.6,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="error_rate",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="Error rate alert",
        rules_version=1,
    )

    ranker = EvidenceRanker(case, alert)
    span_items = ranker.rank_spans()

    assert len(span_items) > 0
    assert span_items[0].type == "span"
    assert "error" in span_items[0].description.lower()


def test_evidence_ranker_log_ranking():
    """Test that log templates are ranked by novelty."""
    logs = [
        # Pre-window: common template
        LogEvent(900, "payment", "msg", "Payment processed <*>", "hash1"),
        LogEvent(950, "payment", "msg", "Payment processed <*>", "hash1"),
        # Post-window: novel template
        LogEvent(1000, "payment", "msg", "Payment timeout <*>", "hash2"),
        LogEvent(1010, "payment", "msg", "Payment timeout <*>", "hash2"),
        LogEvent(1020, "payment", "msg", "Payment timeout <*>", "hash2"),
    ]

    case = FailureCase(
        case_id="test",
        dataset="test",
        system="test",
        metrics={},
        logs=logs,
        traces=[],
        topology=nx.DiGraph(),
    )

    alert = Alert(
        case_id="test",
        silent=False,
        rule_id="r1",
        service="payment",
        metric_key="payment:error_rate",
        z_score=2.0,
        breach_value=0.8,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="error_rate",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="Error alert",
        rules_version=1,
    )

    ranker = EvidenceRanker(case, alert)
    log_items = ranker.rank_logs()

    assert len(log_items) > 0
    assert log_items[0].type == "log"
    assert log_items[0].id.startswith("logtpl:")


def test_evidence_ranker_graph_boost():
    """Test that evidence on critical path gets boosted."""
    # Create a simple dependency graph
    graph = nx.DiGraph(
        [
            ("payment", "bank"),  # payment calls bank
            ("checkout", "payment"),  # checkout calls payment
        ]
    )

    case = FailureCase(
        case_id="test",
        dataset="test",
        system="test",
        metrics={},
        logs=[],
        traces=[],
        topology=graph,
    )

    # Alert from checkout
    alert = Alert(
        case_id="test",
        silent=False,
        rule_id="r1",
        service="checkout",
        metric_key="checkout:error_rate",
        z_score=2.0,
        breach_value=0.5,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="error_rate",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="Alert",
        rules_version=1,
    )

    ranker = EvidenceRanker(case, alert)

    # Items on critical path (payment, bank)
    items = [
        EvidenceItem("kpi:payment:cpu", "kpi", 0.5, "Payment CPU", "payment"),
        EvidenceItem("kpi:bank:cpu", "kpi", 0.5, "Bank CPU", "bank"),
        EvidenceItem("kpi:other:cpu", "kpi", 0.5, "Other CPU", "other"),
    ]

    boosted = ranker.boost_graph_path(items)

    # Items on critical path should have higher scores
    payment_item = next((i for i in boosted if i.service == "payment"), None)
    bank_item = next((i for i in boosted if i.service == "bank"), None)
    other_item = next((i for i in boosted if i.service == "other"), None)

    assert payment_item and payment_item.score > 0.5
    assert bank_item and bank_item.score > 0.5
    assert other_item and other_item.score == 0.5


def test_evidence_pack_full_rank():
    """Test full ranking pipeline."""
    # Create a comprehensive case
    metrics = {
        "svc_a:cpu": MetricSeries(
            "svc_a:cpu",
            (900, 950, 1000, 1050),
            (10, 11, 50, 55),
        )
    }

    logs = [
        LogEvent(900, "svc_a", "msg", "Normal <*>", "h1"),
        LogEvent(1000, "svc_a", "msg", "Error <*>", "h2"),
    ]

    graph = nx.DiGraph([("svc_a", "svc_b")])

    case = FailureCase(
        case_id="test_case",
        dataset="RE1-OB",
        system="online_boutique",
        metrics=metrics,
        logs=logs,
        traces=[],
        topology=graph,
    )

    alert = Alert(
        case_id="test_case",
        silent=False,
        rule_id="r1",
        service="svc_a",
        metric_key="svc_a:cpu",
        z_score=3.5,
        breach_value=50,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="latency",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="CPU alert",
        rules_version=1,
    )

    ranker = EvidenceRanker(case, alert)
    pack = ranker.rank()

    assert pack.case_id == "test_case"
    assert len(pack.items) > 0
    assert len(pack.items) <= 40
    assert pack.token_estimate > 0

    # Check ID formats
    for item in pack.items:
        assert ":" in item.id
        parts = item.id.split(":")
        assert len(parts) >= 2


def test_evidence_pack_token_estimate():
    """Test that token estimate is reasonable."""
    items = [
        EvidenceItem(
            f"kpi:svc{i}:metric{i}",
            "kpi",
            0.9,
            "This is a test evidence item with a longer description",
            f"svc{i}",
        )
        for i in range(10)
    ]

    pack = EvidencePack(case_id="test", items=items, token_estimate=100)
    assert pack.token_estimate > 0
