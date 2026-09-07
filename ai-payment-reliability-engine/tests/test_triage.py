"""
tests/test_triage.py — Tests for the calibrated triage agent.

Verifies KPI feature extraction, ML/LLM ensemble, abstention logic,
and metrics computation.
"""

import pytest

from pre.agents.triage import KPIFeatures, TriageModel, TriageResult
from pre.signals.alert_synth import Alert
from pre.signals.types import FailureCase, MetricSeries
from bench.metrics import coverage_at_tau, precision_at_tau


def test_triage_result_creation():
    """Test TriageResult dataclass."""
    result = TriageResult(
        fault_class="cpu",
        sli="latency",
        severity="SEV-2",
        posterior=0.85,
        abstain=False,
    )

    assert result.fault_class == "cpu"
    assert result.sli == "latency"
    assert result.severity == "SEV-2"
    assert result.posterior == 0.85
    assert result.abstain is False


def test_triage_result_with_abstention():
    """Test TriageResult with abstention."""
    result = TriageResult(
        fault_class="unknown",
        sli=None,
        severity="SEV-3",
        posterior=0.35,
        abstain=True,
    )

    assert result.abstain is True
    assert result.posterior == 0.35


def test_kpi_breach_magnitude():
    """Test breach magnitude feature."""
    alert = Alert(
        case_id="test1",
        silent=False,
        rule_id="r1",
        service="svc_a",
        metric_key="svc_a:cpu",
        z_score=3.5,
        breach_value=95.0,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="latency",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="CPU saturation alert",
        rules_version=1,
    )

    assert KPIFeatures.breach_magnitude(alert, None) == 3.5


def test_kpi_co_breaching_services():
    """Test co-breaching services count."""
    case = FailureCase(
        case_id="test1",
        dataset="RE1-OB",
        system="online_boutique",
        metrics={
            "svc_a:cpu": MetricSeries("svc_a:cpu", (900, 950, 1000), (10, 20, 85)),
            "svc_b:cpu": MetricSeries("svc_b:cpu", (900, 950, 1000), (10, 15, 30)),
        },
        logs=[],
        traces=[],
        topology=None,
    )

    alert = Alert(
        case_id="test1",
        silent=False,
        rule_id="r1",
        service="svc_a",
        metric_key="svc_a:cpu",
        z_score=3.5,
        breach_value=85.0,
        breach_time=1000,
        t0=900,
        detection_delay_seconds=100,
        payment_sli="latency",
        sli_source="sli_map_exact",
        template_style="prometheus",
        text="CPU saturation alert",
        rules_version=1,
    )

    co_breaching = KPIFeatures.co_breaching_services(alert, case)
    assert co_breaching >= 1  # At least svc_a itself


def test_kpi_sli_embedding():
    """Test SLI one-hot encoding."""
    vec = KPIFeatures.sli_embedding("latency")
    assert len(vec) == 5
    assert vec[1] == 1.0  # latency is index 1
    assert sum(vec) == 1.0

    vec_unknown = KPIFeatures.sli_embedding("unknown_sli")
    assert sum(vec_unknown) == 0.0


def test_triage_model_severity_mapping():
    """Test severity mapping for fault classes."""
    model = TriageModel()

    assert model._severity_for_class("cpu") == "SEV-2"
    assert model._severity_for_class("logic_error") == "SEV-1"
    assert model._severity_for_class("dependency_failure") == "SEV-1"
    assert model._severity_for_class("unknown") == "SEV-3"


def test_triage_model_ensemble():
    """Test ensemble probability computation."""
    model = TriageModel()

    # ML predicts "cpu", LLM predicts "memory"
    prob_cpu = model._ensemble_probability("cpu", "cpu", "memory")
    prob_memory = model._ensemble_probability("memory", "cpu", "memory")
    prob_other = model._ensemble_probability("disk", "cpu", "memory")

    assert prob_cpu > prob_other
    assert prob_memory > prob_other
    assert prob_cpu + prob_memory + prob_other > 0


def test_coverage_at_tau():
    """Test coverage metric at different thresholds."""
    posteriors = [0.1, 0.3, 0.5, 0.7, 0.9]

    assert coverage_at_tau(posteriors, 0.0) == 1.0  # All pass
    assert coverage_at_tau(posteriors, 1.0) == 0.0  # None pass
    assert coverage_at_tau(posteriors, 0.5) == 0.6  # 3 out of 5 pass (0.5, 0.7, 0.9)


def test_precision_at_tau():
    """Test precision on non-abstained predictions."""
    y_true = ["cpu", "memory", "cpu", "disk", "memory"]
    y_pred = ["cpu", "memory", "disk", "disk", "memory"]
    posteriors = [0.9, 0.8, 0.3, 0.85, 0.95]

    # At tau=0.5: keep indices 0,1,3,4
    # True: cpu, memory, disk, memory
    # Pred: cpu, memory, disk, memory
    # All 4 correct, precision = 1.0
    prec = precision_at_tau(y_true, y_pred, posteriors, 0.5)
    assert prec == 1.0

    # At tau=0.9: keep only index 4
    # True: memory, Pred: memory, correct
    prec = precision_at_tau(y_true, y_pred, posteriors, 0.9)
    assert prec == 1.0


def test_precision_at_tau_partial_correct():
    """Test precision with some incorrect predictions."""
    y_true = ["cpu", "memory", "cpu"]
    y_pred = ["cpu", "disk", "cpu"]
    posteriors = [0.9, 0.8, 0.85]

    # At tau=0.0: all kept, 2 correct out of 3
    prec = precision_at_tau(y_true, y_pred, posteriors, 0.0)
    assert prec == pytest.approx(2.0 / 3.0)


def test_precision_at_tau_all_abstained():
    """Test precision when all predictions are abstained (coverage=0)."""
    y_true = ["cpu", "memory"]
    y_pred = ["disk", "disk"]
    posteriors = [0.2, 0.3]

    # At tau=0.5, nothing passes, vacuously perfect
    prec = precision_at_tau(y_true, y_pred, posteriors, 0.5)
    assert prec == 1.0


def test_triage_model_save_load(tmp_path):
    """Test model serialization."""
    model = TriageModel(abstention_tau=0.75)
    path = tmp_path / "model.joblib"

    model.save(path)
    loaded = TriageModel.load(path)

    assert loaded.abstention_tau == 0.75
