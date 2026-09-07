"""
tests/test_bench_metrics.py — Unit tests for bench/metrics.py against
hand-computed values (see PROTOCOL.md metric definitions).
"""

from __future__ import annotations

import math

import pytest

from bench.metrics import (
    accuracy_at_k,
    average_at_k,
    brier_score,
    expected_calibration_error,
    faithfulness,
    macro_f1,
)


# ---------------------------------------------------------------------------
# macro_f1
# ---------------------------------------------------------------------------

def test_macro_f1_perfect_predictions():
    y_true = ["cpu", "memory", "cpu", "disk"]
    y_pred = ["cpu", "memory", "cpu", "disk"]
    assert macro_f1(y_true, y_pred) == 1.0


def test_macro_f1_hand_computed_two_class():
    # y_true: A A B B, y_pred: A B B B
    # Class A: TP=1, FP=0, FN=1 -> P=1.0, R=0.5, F1=2*1*0.5/1.5=0.6667
    # Class B: TP=2, FP=1, FN=0 -> P=2/3, R=1.0, F1=2*(2/3)*1/(2/3+1)=0.8
    # macro F1 = (0.6667 + 0.8) / 2 = 0.7333
    y_true = ["A", "A", "B", "B"]
    y_pred = ["A", "B", "B", "B"]
    result = macro_f1(y_true, y_pred)
    assert math.isclose(result, 0.7333333333333334, rel_tol=1e-9)


def test_macro_f1_all_wrong():
    y_true = ["A", "A", "B", "B"]
    y_pred = ["B", "B", "A", "A"]
    assert macro_f1(y_true, y_pred) == 0.0


def test_macro_f1_length_mismatch_raises():
    with pytest.raises(ValueError):
        macro_f1(["A"], ["A", "B"])


def test_macro_f1_empty_raises():
    with pytest.raises(ValueError):
        macro_f1([], [])


# ---------------------------------------------------------------------------
# expected_calibration_error
# ---------------------------------------------------------------------------

def test_ece_perfectly_calibrated_is_zero():
    # 10 predictions, all confidence 0.9, 9/10 correct -> matches confidence exactly
    confidences = [0.9] * 10
    correct = [True] * 9 + [False]
    result = expected_calibration_error(confidences, correct, n_bins=10)
    assert math.isclose(result, 0.0, abs_tol=1e-9)


def test_ece_hand_computed_single_bin():
    # All in bin for [0.9, 1.0): confidence 0.95, but only 50% correct
    # |0.95 - 0.5| * (weight 1.0) = 0.45
    confidences = [0.95, 0.95]
    correct = [True, False]
    result = expected_calibration_error(confidences, correct, n_bins=10)
    assert math.isclose(result, 0.45, rel_tol=1e-9)


def test_ece_length_mismatch_raises():
    with pytest.raises(ValueError):
        expected_calibration_error([0.5], [True, False])


# ---------------------------------------------------------------------------
# brier_score
# ---------------------------------------------------------------------------

def test_brier_score_perfect_confidence_correct():
    # confidence 1.0, always correct -> (1-1)^2 = 0
    assert brier_score([1.0, 1.0], [True, True]) == 0.0


def test_brier_score_perfect_confidence_wrong():
    # confidence 1.0, always wrong -> (1-0)^2 = 1
    assert brier_score([1.0, 1.0], [False, False]) == 1.0


def test_brier_score_hand_computed():
    # conf=0.7 correct: (0.7-1)^2=0.09; conf=0.3 wrong: (0.3-0)^2=0.09
    # mean = 0.09
    result = brier_score([0.7, 0.3], [True, False])
    assert math.isclose(result, 0.09, rel_tol=1e-9)


def test_brier_score_uncertain_prediction():
    # conf=0.5 for both outcomes -> (0.5-1)^2=0.25, (0.5-0)^2=0.25, mean=0.25
    assert math.isclose(brier_score([0.5, 0.5], [True, False]), 0.25, rel_tol=1e-9)


# ---------------------------------------------------------------------------
# accuracy_at_k / average_at_k — must match RCAEval's Evaluator semantics
# ---------------------------------------------------------------------------

def test_accuracy_at_k_hand_computed():
    # 3 cases: answer in top-1 for case 1, top-3 (not top-1) for case 2, never for case 3
    cases = [
        (["svcA", "svcB", "svcC"], "svcA"),  # in top-1
        (["svcB", "svcC", "svcA"], "svcA"),  # in top-3, not top-1
        (["svcB", "svcC", "svcD"], "svcA"),  # never
    ]
    assert accuracy_at_k(cases, k=1) == pytest.approx(1 / 3)
    assert accuracy_at_k(cases, k=3) == pytest.approx(2 / 3)


def test_accuracy_at_k_all_hit_top_1():
    cases = [(["A", "B"], "A"), (["C", "D"], "C")]
    assert accuracy_at_k(cases, k=1) == 1.0


def test_average_at_k_matches_mean_of_ac_1_through_k():
    cases = [
        (["svcA", "svcB", "svcC"], "svcA"),
        (["svcB", "svcC", "svcA"], "svcA"),
        (["svcB", "svcC", "svcD"], "svcA"),
    ]
    # AC@1 = 1/3, AC@2 = 1/3, AC@3 = 2/3
    expected = (1 / 3 + 1 / 3 + 2 / 3) / 3
    assert average_at_k(cases, k=3) == pytest.approx(expected)


def test_accuracy_at_k_invalid_k_raises():
    with pytest.raises(ValueError):
        accuracy_at_k([(["A"], "A")], k=0)


def test_accuracy_at_k_empty_raises():
    with pytest.raises(ValueError):
        accuracy_at_k([], k=1)


# ---------------------------------------------------------------------------
# faithfulness
# ---------------------------------------------------------------------------

def test_faithfulness_all_grounded():
    assert faithfulness(["m1", "m2"], ["m1", "m2", "m3"]) == 1.0


def test_faithfulness_none_grounded():
    assert faithfulness(["m9"], ["m1", "m2"]) == 0.0


def test_faithfulness_partial():
    # 1 of 2 cited keys is present
    assert faithfulness(["m1", "m9"], ["m1", "m2"]) == pytest.approx(0.5)


def test_faithfulness_duplicate_citations_count_once():
    assert faithfulness(["m1", "m1", "m9"], ["m1"]) == pytest.approx(0.5)


def test_faithfulness_empty_citations_raises():
    with pytest.raises(ValueError):
        faithfulness([], ["m1"])


# ---------------------------------------------------------------------------
# Abstention metrics tests
# ---------------------------------------------------------------------------

def test_coverage_at_tau_all_pass():
    from bench.metrics import coverage_at_tau

    posteriors = [0.5, 0.6, 0.7, 0.8, 0.9]
    assert coverage_at_tau(posteriors, 0.0) == 1.0


def test_coverage_at_tau_none_pass():
    from bench.metrics import coverage_at_tau

    posteriors = [0.1, 0.2, 0.3, 0.4, 0.5]
    assert coverage_at_tau(posteriors, 1.0) == 0.0


def test_coverage_at_tau_partial():
    from bench.metrics import coverage_at_tau

    posteriors = [0.1, 0.3, 0.5, 0.7, 0.9]
    assert coverage_at_tau(posteriors, 0.5) == 0.6  # 3 out of 5 >= 0.5


def test_precision_at_tau_all_correct():
    from bench.metrics import precision_at_tau

    y_true = ["a", "b", "c"]
    y_pred = ["a", "b", "c"]
    posteriors = [0.9, 0.8, 0.85]
    assert precision_at_tau(y_true, y_pred, posteriors, 0.0) == 1.0


def test_precision_at_tau_partial_correct():
    from bench.metrics import precision_at_tau

    y_true = ["a", "b", "c"]
    y_pred = ["a", "x", "c"]
    posteriors = [0.9, 0.8, 0.85]
    # 2 correct out of 3
    assert precision_at_tau(y_true, y_pred, posteriors, 0.0) == pytest.approx(2.0 / 3.0)


def test_precision_at_tau_filtered():
    from bench.metrics import precision_at_tau

    y_true = ["a", "b", "c", "d"]
    y_pred = ["a", "x", "c", "y"]
    posteriors = [0.9, 0.3, 0.85, 0.2]
    # At tau=0.5: keep indices 0,2 (both correct)
    assert precision_at_tau(y_true, y_pred, posteriors, 0.5) == 1.0


def test_precision_at_tau_no_predictions():
    from bench.metrics import precision_at_tau

    y_true = ["a", "b"]
    y_pred = ["x", "y"]
    posteriors = [0.2, 0.1]
    # At tau=0.5, none pass, vacuously perfect
    assert precision_at_tau(y_true, y_pred, posteriors, 0.5) == 1.0


def test_coverage_at_tau_empty_raises():
    from bench.metrics import coverage_at_tau

    with pytest.raises(ValueError):
        coverage_at_tau([], 0.5)
