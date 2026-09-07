"""
tests/test_alert_synth.py — Tests for pre/signals/alert_synth.py (A5).

Two kinds of coverage, per the A5 task's own verification requirement:
  1. Unit tests for each rule in data/alert_rules.yaml, using small
     synthetic FailureCase objects built with `_make_case` below so each
     rule's pattern/threshold logic is tested in isolation, independent
     of any real dataset's noise. Real-data coverage (does this module
     actually detect real injected faults) lives in
     scripts/alert_detection_delay_report.py's report, run against the
     real RCAEval/OpenRCA fixtures — see CONVERSION.md's alert_synth
     section for that report's actual output on real data.
  2. A Hypothesis property test asserting `synthesize_alert` is a pure,
     deterministic function of its input FailureCase: the same case
     (same metrics, same case_id) must always render byte-identical
     Alert.text, not just an equal Alert object by chance of a single
     run.
"""

from __future__ import annotations

import networkx as nx
from hypothesis import given, settings
from hypothesis import strategies as st

from pre.signals.alert_synth import (
    _robust_z_scores,
    _select_template_style,
    synthesize_alert,
    synthesize_alerts_summary,
)
from pre.signals.types import FailureCase, MetricSeries

_TIMES = tuple(range(0, 1200, 60))  # 20 samples, 60s apart, matching OpenRCA's native metric cadence
_MIDPOINT_INDEX = len(_TIMES) // 2  # baseline/breach boundary index, mirrors synthesize_alert's own split


def _make_case(
    case_id: str,
    metrics: dict[str, tuple[float, ...]],
    system: str = "online_boutique",
) -> FailureCase:
    """Build a minimal FailureCase from {svc:metric -> values} at the
    fixed _TIMES cadence, for isolated rule testing.
    """
    series = {
        key: MetricSeries(key=key, times=_TIMES, values=values)
        for key, values in metrics.items()
    }
    return FailureCase(
        case_id=case_id,
        dataset="synthetic",
        system=system,
        metrics=series,
        logs=[],
        traces=[],
        topology=nx.DiGraph(),
    )


def _flat_then_spike(flat_value: float, spike_value: float) -> tuple[float, ...]:
    """10 flat samples (pre-window) followed by 10 samples with one huge
    spike partway through the post-window, guaranteed to breach any
    reasonable z-threshold since the pre-window has zero variance
    (exercises the MAD-floor path deliberately, not accidentally).
    """
    before = tuple(flat_value for _ in range(_MIDPOINT_INDEX))
    after = tuple(
        spike_value if i == 3 else flat_value
        for i in range(len(_TIMES) - _MIDPOINT_INDEX)
    )
    return before + after


# ---------------------------------------------------------------------------
# Per-rule unit tests
# ---------------------------------------------------------------------------

def test_memory_saturation_rule_fires_on_mem_suffix_spike():
    case = _make_case("t-mem", {"redis:mem": _flat_then_spike(100.0, 100_000.0)})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "memory_saturation"
    assert alert.service == "redis"


def test_cpu_saturation_rule_fires_on_cpu_suffix_spike():
    case = _make_case("t-cpu", {"frontend:cpu": _flat_then_spike(5.0, 95.0)})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "cpu_saturation"
    assert alert.service == "frontend"


def test_latency_degradation_rule_fires_on_latency_suffix_spike():
    case = _make_case("t-lat", {"checkoutservice:latency-90": _flat_then_spike(0.2, 40.0)})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "latency_degradation"
    assert alert.payment_sli == "checkout_latency_p99"
    assert alert.sli_source == "sli_map_exact"


def test_error_rate_spike_rule_fires_on_error_suffix_spike():
    case = _make_case("t-err", {"paymentservice:error": _flat_then_spike(0.0, 50.0)})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "error_rate_spike"
    assert alert.payment_sli == "authorisation_success_rate"
    assert alert.sli_source == "sli_map_exact"


def test_disk_pressure_rule_fires_on_diskio_suffix_spike():
    case = _make_case("t-disk", {"cartservice:diskio": _flat_then_spike(10.0, 5000.0)})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "disk_pressure"


def test_socket_saturation_rule_fires_on_socket_suffix_spike():
    case = _make_case("t-sock", {"adservice:socket": _flat_then_spike(1.0, 999.0)})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "socket_saturation"


def test_generic_anomaly_rule_fires_on_unrecognised_suffix_spike():
    """An unrecognised metric suffix must still be caught by the
    catch-all rule (higher threshold, since it has no domain-specific
    interpretation) rather than silently ignored.
    """
    case = _make_case("t-generic", {"mysteryservice:widget_count": _flat_then_spike(1.0, 100_000.0)})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "generic_anomaly"


def test_no_breach_returns_silent_alert():
    """A metric that stays essentially flat across the whole window
    (no real spike, only sub-relative-floor noise) must not fire any
    rule."""
    values = tuple(100.0 + (0.001 * i) for i in range(len(_TIMES)))
    case = _make_case("t-silent", {"redis:mem": values})
    alert = synthesize_alert(case)
    assert alert.silent
    assert alert.text == ""
    assert alert.rule_id is None
    assert alert.detection_delay_seconds == 0


def test_empty_case_returns_silent_alert():
    case = _make_case("t-empty", {})
    alert = synthesize_alert(case)
    assert alert.silent


def test_earliest_breach_wins_over_larger_later_breach():
    """A small-but-earlier breach must be selected over a much larger
    later one — "first breach", not "biggest breach"."""
    # metric A breaches (barely) at index _MIDPOINT_INDEX; metric B
    # breaches enormously two samples later. A's earlier timestamp must win.
    times = _TIMES
    a_values = tuple(
        (10.0 if i != _MIDPOINT_INDEX else 40.0) for i in range(len(times))
    )
    b_values = tuple(
        (10.0 if i != _MIDPOINT_INDEX + 2 else 10_000.0) for i in range(len(times))
    )
    case = _make_case("t-earliest", {"svc_a:cpu": a_values, "svc_b:cpu": b_values})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.service == "svc_a"
    assert alert.breach_time == times[_MIDPOINT_INDEX]


def test_rule_order_breaks_same_timestamp_tie():
    """Two metrics breaching at the EXACT same timestamp must be
    resolved by rule order (data/alert_rules.yaml file order), not by
    z-score magnitude or metric-key order alone."""
    # memory_saturation is listed before cpu_saturation in
    # data/alert_rules.yaml; both breach at the same index here, so
    # memory_saturation must win even though the cpu spike is larger.
    mem_values = _flat_then_spike(10.0, 20.0)
    cpu_values = _flat_then_spike(10.0, 9999.0)
    case = _make_case("t-tie", {"svc:mem": mem_values, "svc:cpu": cpu_values})
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.rule_id == "memory_saturation"


def test_openrca_bank_sli_falls_back_to_rule_hint():
    """openrca_bank's sli_map service names ("payment-gateway",
    "core-banking") don't match OpenRCA's real component names
    ("Tomcat01" etc, see CONVERSION.md) -- for a real OpenRCA-shaped
    service name, SLI attachment must fall back to the rule's hint via
    a keyword match or the rule_hint tier, never raise or silently
    return None."""
    case = _make_case("t-bank", {"Tomcat01:cpu": _flat_then_spike(5.0, 95.0)}, system="openrca_bank")
    alert = synthesize_alert(case)
    assert not alert.silent
    assert alert.payment_sli is not None
    assert alert.sli_source in ("sli_map_keyword", "rule_hint")


# ---------------------------------------------------------------------------
# rules_version / silent counting
# ---------------------------------------------------------------------------

def test_alert_carries_committed_rules_version():
    case = _make_case("t-version", {"redis:mem": _flat_then_spike(1.0, 100.0)})
    alert = synthesize_alert(case)
    assert alert.rules_version >= 1


def test_synthesize_alerts_summary_counts_silent_and_detected():
    detected_case = _make_case("t-detected", {"redis:mem": _flat_then_spike(1.0, 100.0)})
    silent_case = _make_case("t-silent2", {"redis:mem": tuple(1.0 for _ in _TIMES)})
    alerts, summary = synthesize_alerts_summary([detected_case, silent_case])
    assert summary.total_cases == 2
    assert summary.silent_count == 1
    assert summary.detected_count == 1
    assert summary.silent_rate == 0.5
    assert len(summary.detection_delays_seconds) == 1
    assert len(alerts) == 2


# ---------------------------------------------------------------------------
# Property test: determinism
# ---------------------------------------------------------------------------

_metric_key_strategy = st.sampled_from(
    ["redis:mem", "frontend:cpu", "checkoutservice:latency-90", "paymentservice:error", "cartservice:diskio"]
)
_value_strategy = st.floats(min_value=0.0, max_value=1_000_000.0, allow_nan=False, allow_infinity=False)


@given(
    case_id=st.text(min_size=1, max_size=40, alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_-")),
    metric_key=_metric_key_strategy,
    values=st.lists(_value_strategy, min_size=len(_TIMES), max_size=len(_TIMES)),
)
@settings(max_examples=200, deadline=None)
def test_same_case_always_renders_the_same_alert(case_id, metric_key, values):
    """The core A5 property test: synthesize_alert(case) is a pure
    function of case -- calling it twice (or building an equivalent
    FailureCase with identical field values twice) must produce
    byte-identical Alert.text and identical every other field, in every
    call, regardless of process/run.
    """
    case1 = _make_case(case_id, {metric_key: tuple(values)})
    case2 = _make_case(case_id, {metric_key: tuple(values)})  # separately-constructed but equal

    alert1 = synthesize_alert(case1)
    alert2 = synthesize_alert(case2)
    alert1_again = synthesize_alert(case1)

    assert alert1 == alert2
    assert alert1 == alert1_again
    assert alert1.text == alert2.text == alert1_again.text


@given(case_id=st.text(min_size=1, max_size=60))
@settings(max_examples=100, deadline=None)
def test_template_style_selection_is_deterministic_per_case_id(case_id):
    style1 = _select_template_style(case_id)
    style2 = _select_template_style(case_id)
    assert style1 == style2
    assert style1 in ("prometheus", "datadog")


# ---------------------------------------------------------------------------
# _robust_z_scores unit tests (the MAD-floor fix, see CONVERSION.md)
# ---------------------------------------------------------------------------

def test_robust_z_score_relative_floor_avoids_absurd_scores_on_near_flat_metric():
    """A pre-window that is technically not perfectly constant (MAD
    rounds to 0.0 in floating point, e.g. values like 52.2403/52.2532/
    52.2660 -- genuinely observed in real OpenRCA Bank telemetry, see
    CONVERSION.md) must not produce absurd millions-scale z-scores for
    a tiny post-window fluctuation of the same relative magnitude.
    """
    times = tuple(range(6))
    before = (52.2403, 52.2532, 52.2660)
    after = (52.2660, 52.2789, 52.2917)  # same tiny scale of movement as `before`
    scores = _robust_z_scores(times, before + after, 3)
    # None of these tiny, same-scale post-window values should score as
    # an extreme outlier -- z should stay in a normal, bounded range.
    assert all(z < 100 for _, _, z in scores), f"expected bounded z-scores, got {scores}"


def test_robust_z_score_still_detects_a_real_large_spike():
    times = tuple(range(6))
    before = (52.24, 52.25, 52.26)
    after = (52.27, 52.28, 9999.0)  # a genuine, large spike
    scores = _robust_z_scores(times, before + after, 3)
    assert max(z for _, _, z in scores) > 50, "a genuine large spike should still score as a clear outlier"


def test_robust_z_score_requires_at_least_two_pre_boundary_samples():
    times = (0, 1, 2)
    values = (1.0, 2.0, 3.0)
    assert _robust_z_scores(times, values, 1) == []  # only 1 pre-boundary sample


def test_robust_z_score_empty_after_returns_empty():
    times = (0, 1, 2)
    values = (1.0, 2.0, 3.0)
    assert _robust_z_scores(times, values, 10) == []  # boundary after all samples
