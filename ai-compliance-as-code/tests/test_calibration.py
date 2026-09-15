"""
tests/test_calibration.py — Verification suite for confidence elicitation & calibration engine.

Covers:
  - Test 1 (Murphy Identity): Verify |BS - (REL - RES + UNC)| < 10^{-6} across synthetic distributions.
  - Test 2 (Metric Bounds):
      * Perfect predictor (p_i = y_i): BS = 0.0, REL = 0.0, ECE = 0.0.
      * Inverted predictor (p_i = 1 - y_i): BS = 1.0, ECE = 1.0.
      * Uninformative base-rate predictor (p_i = y_bar): RES = 0.0, BS = UNC.
  - Test 3 (Bin Conservation): Assert sum(n_m) = N under both quantile and uniform strategies.
  - Test 4 (Quantile Clumping Edge Case): Discrete spikes (70%, 95%, 100% identical values)
    execute without crashing, without ValueError, and with non-negative bin sizes.
  - Test 5 (Empty & Boundary Inputs): ValueError on empty/mismatched inputs, graceful zero-bin handling.
  - Schema Confidence Validation: Bounded float in [0.0, 1.0], neutral sentinel 0.50 on missing/invalid.
  - Export Utility: End-to-end execution and metrics serialization.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import pytest

from api.schemas import ComplianceFinding
from harness.export_calibration import export_calibration, load_records
from harness.metrics import (
    CalibrationBin,
    CalibrationReport,
    compute_calibration_analysis,
)


# ===========================================================================
# Test 1: Murphy's (1973) Decomposition Identity
# ===========================================================================

class TestMurphyDecomposition:
    """Verify that the Murphy decomposition BS = REL - RES + UNC holds to within 1e-6."""

    @pytest.mark.parametrize("strategy", ["quantile", "uniform"])
    @pytest.mark.parametrize("num_bins", [3, 5, 10])
    def test_murphy_identity_uniform_distribution(self, strategy: str, num_bins: int):
        rng = np.random.RandomState(42)
        confs = rng.uniform(0.0, 1.0, size=1000)
        labels = rng.binomial(1, confs, size=1000)

        report = compute_calibration_analysis(confs, labels, num_bins=num_bins, strategy=strategy)
        diff = abs(report.brier_score - (report.reliability - report.resolution + report.uncertainty))
        assert diff < 1e-6, f"Murphy identity failed for strategy={strategy}, num_bins={num_bins}: diff={diff}"

    @pytest.mark.parametrize("strategy", ["quantile", "uniform"])
    def test_murphy_identity_beta_distributions(self, strategy: str):
        rng = np.random.RandomState(123)
        # Skewed low (Beta(2, 5)) and skewed high (Beta(5, 2))
        for a, b in [(2, 5), (5, 2), (0.5, 0.5)]:
            confs = rng.beta(a, b, size=800)
            labels = rng.binomial(1, confs, size=800)
            report = compute_calibration_analysis(confs, labels, num_bins=5, strategy=strategy)
            diff = abs(report.brier_score - (report.reliability - report.resolution + report.uncertainty))
            assert diff < 1e-6, f"Murphy identity failed for Beta({a},{b}), strategy={strategy}: diff={diff}"

    def test_murphy_identity_discrete_scores(self):
        rng = np.random.RandomState(999)
        levels = np.array([0.40, 0.60, 0.75, 0.85, 0.95])
        confs = rng.choice(levels, size=600)
        labels = rng.binomial(1, confs, size=600)

        for strat in ["quantile", "uniform"]:
            report = compute_calibration_analysis(confs, labels, num_bins=5, strategy=strat)
            diff = abs(report.brier_score - (report.reliability - report.resolution + report.uncertainty))
            assert diff < 1e-6


# ===========================================================================
# Test 2: Theoretical Metric Bounds
# ===========================================================================

class TestMetricBounds:
    """Verify theoretical boundary values for perfect, inverted, and uninformative predictors."""

    @pytest.fixture
    def ground_truth(self) -> np.ndarray:
        return np.array([0, 1, 0, 1, 1, 0, 0, 1, 1, 1] * 50, dtype=int)

    @pytest.mark.parametrize("strategy", ["quantile", "uniform"])
    def test_perfect_predictor_bounds(self, ground_truth: np.ndarray, strategy: str):
        """Perfect predictor (p_i = y_i): BS = 0.0, REL = 0.0, ECE = 0.0."""
        confs = ground_truth.astype(float)
        report = compute_calibration_analysis(confs, ground_truth, num_bins=5, strategy=strategy)

        assert np.isclose(report.brier_score, 0.0, atol=1e-6), f"Expected BS=0, got {report.brier_score}"
        assert np.isclose(report.reliability, 0.0, atol=1e-6), f"Expected REL=0, got {report.reliability}"
        assert np.isclose(report.ece, 0.0, atol=1e-6), f"Expected ECE=0, got {report.ece}"
        assert np.isclose(report.mce, 0.0, atol=1e-6), f"Expected MCE=0, got {report.mce}"

    @pytest.mark.parametrize("strategy", ["quantile", "uniform"])
    def test_inverted_predictor_bounds(self, ground_truth: np.ndarray, strategy: str):
        """Inverted predictor (p_i = 1 - y_i): BS = 1.0, ECE = 1.0."""
        confs = (1.0 - ground_truth).astype(float)
        report = compute_calibration_analysis(confs, ground_truth, num_bins=5, strategy=strategy)

        assert np.isclose(report.brier_score, 1.0, atol=1e-6), f"Expected BS=1, got {report.brier_score}"
        assert np.isclose(report.ece, 1.0, atol=1e-6), f"Expected ECE=1, got {report.ece}"
        assert np.isclose(report.reliability, 1.0, atol=1e-6), f"Expected REL=1, got {report.reliability}"

    @pytest.mark.parametrize("strategy", ["quantile", "uniform"])
    def test_uninformative_base_rate_predictor_bounds(self, ground_truth: np.ndarray, strategy: str):
        """Uninformative base-rate predictor (p_i = y_bar): RES = 0.0, BS = UNC."""
        y_bar = float(np.mean(ground_truth))
        confs = np.full_like(ground_truth, fill_value=y_bar, dtype=float)
        report = compute_calibration_analysis(confs, ground_truth, num_bins=5, strategy=strategy)

        assert np.isclose(report.resolution, 0.0, atol=1e-6), f"Expected RES=0, got {report.resolution}"
        assert np.isclose(report.brier_score, report.uncertainty, atol=1e-6), (
            f"Expected BS={report.uncertainty}, got {report.brier_score}"
        )
        assert np.isclose(report.reliability, 0.0, atol=1e-6), f"Expected REL=0, got {report.reliability}"


# ===========================================================================
# Test 3: Bin Conservation
# ===========================================================================

class TestBinConservation:
    """Verify sum(n_m) = N and sum(prop) = 1.0 across diverse sample sizes."""

    @pytest.mark.parametrize("n_samples", [7, 23, 100, 887])
    @pytest.mark.parametrize("num_bins", [3, 5, 8])
    @pytest.mark.parametrize("strategy", ["quantile", "uniform"])
    def test_bin_conservation_property(self, n_samples: int, num_bins: int, strategy: str):
        rng = np.random.RandomState(n_samples)
        confs = rng.uniform(0.0, 1.0, size=n_samples)
        labels = rng.binomial(1, 0.5, size=n_samples)

        report = compute_calibration_analysis(confs, labels, num_bins=num_bins, strategy=strategy)

        total_counted = sum(b.count for b in report.bins)
        assert total_counted == n_samples, f"Sum of bin counts ({total_counted}) != N ({n_samples})"

        total_prop = sum(b.prop for b in report.bins)
        assert np.isclose(total_prop, 1.0, atol=1e-6), f"Sum of proportions ({total_prop}) != 1.0"

        assert all(b.count >= 0 for b in report.bins), "Negative bin count encountered"


# ===========================================================================
# Test 4: Quantile Clumping Edge Case
# ===========================================================================

class TestQuantileClumping:
    """Verify robust quantile tie handling with severe value repetition."""

    def test_70_percent_identical_values(self):
        """Provide an array with 70% identical values ([0.85]*700 + [0.50]*300)."""
        confs = [0.85] * 700 + [0.50] * 300
        labels = [1] * 500 + [0] * 500

        report = compute_calibration_analysis(confs, labels, num_bins=5, strategy="quantile")

        assert report.num_samples == 1000
        assert len(report.bins) == 5
        assert all(b.count >= 0 for b in report.bins)
        assert sum(b.count for b in report.bins) == 1000

        # Verify no NaN values in metrics
        assert not math.isnan(report.ece)
        assert not math.isnan(report.brier_score)
        assert not math.isnan(report.reliability)

    def test_95_percent_identical_values(self):
        """Severe clumping: 95% identical scores."""
        confs = [0.90] * 950 + [0.20] * 50
        labels = [1] * 700 + [0] * 300

        report = compute_calibration_analysis(confs, labels, num_bins=5, strategy="quantile")
        assert sum(b.count for b in report.bins) == 1000
        assert all(b.count >= 0 for b in report.bins)

    def test_100_percent_identical_values(self):
        """Degenerate case: all confidences exactly equal."""
        confs = [0.80] * 500
        labels = [1] * 200 + [0] * 300

        for strat in ["quantile", "uniform"]:
            report = compute_calibration_analysis(confs, labels, num_bins=5, strategy=strat)
            assert sum(b.count for b in report.bins) == 500
            assert all(b.count >= 0 for b in report.bins)
            assert not math.isnan(report.brier_score)


# ===========================================================================
# Test 5: Empty & Boundary Inputs
# ===========================================================================

class TestEmptyAndBoundaryInputs:
    """Verify input validation and empty bin handling."""

    def test_empty_inputs_raise_value_error(self):
        with pytest.raises(ValueError, match="must not be empty"):
            compute_calibration_analysis([], [])

        with pytest.raises(ValueError, match="must not be empty"):
            compute_calibration_analysis([0.5], [])

    def test_mismatched_lengths_raise_value_error(self):
        with pytest.raises(ValueError, match="match labels length"):
            compute_calibration_analysis([0.5, 0.6], [1])

    def test_invalid_num_bins_raises_value_error(self):
        with pytest.raises(ValueError, match="num_bins must be a positive integer"):
            compute_calibration_analysis([0.5], [1], num_bins=0)

    def test_invalid_strategy_raises_value_error(self):
        with pytest.raises(ValueError, match="strategy must be 'quantile' or 'uniform'"):
            compute_calibration_analysis([0.5], [1], strategy="invalid")

    def test_empty_uniform_bins_graceful_handling(self):
        """When confidences cluster in a narrow interval, empty uniform bins have n_m = 0 without error."""
        # All confidences in [0.81, 0.89], with 10 uniform bins (width 0.1)
        confs = [0.85] * 50
        labels = [1] * 40 + [0] * 10

        report = compute_calibration_analysis(confs, labels, num_bins=10, strategy="uniform")

        empty_bins = [b for b in report.bins if b.count == 0]
        assert len(empty_bins) > 0, "Expected multiple empty bins"

        for b in empty_bins:
            assert b.prop == 0.0
            assert b.mean_confidence == 0.0
            assert b.empirical_accuracy == 0.0
            assert b.margin_of_error == 0.0
            assert b.calibration_error == 0.0

        diff = abs(report.brier_score - (report.reliability - report.resolution + report.uncertainty))
        assert diff < 1e-6


# ===========================================================================
# Test 6: Pydantic Finding Schema Confidence Validation
# ===========================================================================

class TestSchemaConfidenceValidation:
    """Verify ComplianceFinding confidence field parsing, defaults, and boundary clamping."""

    def test_default_confidence_is_calibrated_baseline(self):
        finding = ComplianceFinding(
            rule_id="GDPR-Art.32",
            title="Weak hashing",
            severity="high",
            violation="MD5 used for passwords.",
            remediation="Switch to Argon2id.",
        )
        assert finding.confidence == 0.50

    def test_none_confidence_coerced_to_default(self):
        finding = ComplianceFinding(
            rule_id="GDPR-Art.32",
            title="Weak hashing",
            severity="high",
            violation="MD5 used.",
            remediation="Switch to Argon2id.",
            confidence=None,
        )
        assert finding.confidence == 0.50

    def test_invalid_string_confidence_coerced_to_default(self):
        finding = ComplianceFinding(
            rule_id="GDPR-Art.32",
            title="Weak hashing",
            severity="high",
            violation="MD5 used.",
            remediation="Switch to Argon2id.",
            confidence="not-a-number",  # type: ignore
        )
        assert finding.confidence == 0.50

    def test_out_of_range_confidence_clamped(self):
        finding_high = ComplianceFinding(
            rule_id="GDPR-Art.32",
            title="Weak hashing",
            severity="high",
            violation="MD5 used.",
            remediation="Switch to Argon2id.",
            confidence=1.45,
        )
        assert finding_high.confidence == 1.0

        finding_low = ComplianceFinding(
            rule_id="GDPR-Art.32",
            title="Weak hashing",
            severity="high",
            violation="MD5 used.",
            remediation="Switch to Argon2id.",
            confidence=-0.35,
        )
        assert finding_low.confidence == 0.0

    def test_valid_float_preserved(self):
        finding = ComplianceFinding(
            rule_id="GDPR-Art.32",
            title="Weak hashing",
            severity="high",
            violation="MD5 used.",
            remediation="Switch to Argon2id.",
            confidence=0.875,
        )
        assert finding.confidence == 0.875


# ===========================================================================
# Test 7: Export Calibration CLI & Artifact Generation
# ===========================================================================

class TestExportCalibration:
    """Verify export_calibration end-to-end execution, JSON serialization, and table output."""

    def test_export_calibration_generates_valid_artifacts(self, tmp_path: Path):
        # Create a synthetic JSONL results file
        sample_file = tmp_path / "test_results.jsonl"
        items = [
            {"predicted": [32], "ground_truth": [32], "confidence": 0.90},
            {"predicted": [5], "ground_truth": [6], "confidence": 0.70},
            {"predicted": [13, 25], "ground_truth": [13, 25], "confidence": 0.85},
            {"predicted": [], "ground_truth": [12], "confidence": 0.50},
            {"predicted": [6], "ground_truth": [6], "confidence": 0.95},
        ] * 10
        with sample_file.open("w", encoding="utf-8") as f:
            for item in items:
                f.write(json.dumps(item) + "\n")

        out_dir = tmp_path / "calibration_out"
        report = export_calibration(
            results_path=sample_file,
            output_dir=out_dir,
            num_bins=3,
            strategy="quantile",
        )

        assert isinstance(report, CalibrationReport)
        assert report.num_samples == 50

        # Verify metrics.json
        metrics_json_path = out_dir / "metrics.json"
        assert metrics_json_path.exists()
        data = json.loads(metrics_json_path.read_text(encoding="utf-8"))
        assert data["num_samples"] == 50
        assert data["strategy"] == "quantile"
        assert "ece" in data
        assert "brier_score" in data
        assert len(data["bins"]) == 3

        # Verify ASCII table format
        table = report.format_ascii_table()
        assert "| Bin | Count | Mean Conf | Empirical Acc | ±95% MoE |" in table
        assert "+-----+-------+-----------+---------------+----------+" in table
