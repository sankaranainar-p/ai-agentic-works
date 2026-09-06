"""
tests/test_b5_openrca_agent.py — B5 parity test: our port of OpenRCA's
scoring algorithm (bench.baselines.openrca_agent.evaluate) must reproduce
OpenRCA's own published scores for its archived RCA-agent-on-Bank
predictions (rca/archive/agent-Bank.csv, fetched from
https://github.com/microsoft/OpenRCA and committed as a fixture — no
Google Drive telemetry download needed since this compares scores, not
whether the underlying agent reasoning is correct).

Known and documented limitation: OpenRCA batches two-or-more failures
that land in the same 30-minute window into one multi-response query,
which requires the full sorted record.csv to detect; the archived
per-row CSV doesn't carry that context. This test therefore verifies
exact parity on single-failure rows (where the archived score is
reproducible from that row alone) and checks that multi-failure rows are
still scored (not crashing), without asserting exact parity on them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd
import pytest

from bench.baselines.openrca_agent import (
    _parse_record_block,
    evaluate,
    scoring_points_from_record,
    score_predictions,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "openrca" / "agent-Bank.csv"


def _n_predicted_failures(prediction: str) -> int:
    return len(re.findall(r'"[0-9]+":\s*{', prediction))


@pytest.fixture(scope="module")
def archived() -> pd.DataFrame:
    return pd.read_csv(FIXTURE_PATH)


@pytest.fixture(scope="module")
def our_scores() -> pd.DataFrame:
    return score_predictions(FIXTURE_PATH)


def test_fixture_has_136_bank_cases(archived):
    assert len(archived) == 136


def test_exact_parity_on_single_failure_rows(archived, our_scores):
    single_failure = archived["prediction"].apply(_n_predicted_failures) == 1
    diff = (our_scores["score"] - archived["score"]).abs()

    mismatches = diff[single_failure][diff[single_failure] > 0.005]
    assert mismatches.empty, (
        f"single-failure rows must match OpenRCA's published score exactly, "
        f"found {len(mismatches)} mismatches at rows {mismatches.index.tolist()}"
    )

    # sanity: this fixture actually contains a substantial number of
    # single-failure rows, or the "exact parity" claim above is vacuous
    assert single_failure.sum() >= 100


def test_multi_failure_rows_still_score_without_crashing(archived, our_scores):
    multi_failure = archived["prediction"].apply(_n_predicted_failures) > 1
    assert multi_failure.sum() > 0, "fixture should contain some multi-failure rows"
    # scores exist and are valid floats in [0, 1] even though they may not
    # match the published multi-response score exactly (documented limitation)
    scores = our_scores["score"][multi_failure]
    assert scores.between(0.0, 1.0).all()


def test_evaluate_matches_openrca_readme_example():
    """The evaluate() function's docstring example from OpenRCA's own README:
    a fully correct component+reason prediction scores 1.0.
    """
    prediction = (
        '{"1": {"root cause component": "Redis02", '
        '"root cause reason": "high memory usage"}}'
    )
    scoring_points = (
        "The only predicted root cause component is Redis02\n"
        "The only predicted root cause reason is high memory usage\n"
    )
    result = evaluate(prediction, scoring_points)
    assert result.score == 1.0


def test_evaluate_partial_credit():
    prediction = (
        '{"1": {"root cause component": "WrongComponent", '
        '"root cause reason": "high memory usage"}}'
    )
    scoring_points = (
        "The only predicted root cause component is Redis02\n"
        "The only predicted root cause reason is high memory usage\n"
    )
    result = evaluate(prediction, scoring_points)
    assert result.score == 0.5


def test_parse_record_block():
    block = "level: pod\ncomponent: Redis02\ndatetime: 2021-03-04 18:09:00\nreason: high memory usage"
    parsed = _parse_record_block(block)
    assert parsed == {
        "level": "pod",
        "component": "Redis02",
        "datetime": "2021-03-04 18:09:00",
        "reason": "high memory usage",
    }


def test_scoring_points_from_record_task_6():
    record = {"component": "Redis02", "reason": "high memory usage"}
    points = scoring_points_from_record(record, "task_6")
    assert "The only predicted root cause component is Redis02" in points
    assert "The only predicted root cause reason is high memory usage" in points


def test_scoring_points_from_record_unknown_task_raises():
    with pytest.raises(ValueError, match="unknown task_index"):
        scoring_points_from_record({}, "task_99")


def test_score_predictions_requires_task_index_with_groundtruth(tmp_path):
    bad_csv = tmp_path / "bad.csv"
    pd.DataFrame({"prediction": ["{}"], "groundtruth": ["component: X"]}).to_csv(bad_csv, index=False)
    with pytest.raises(ValueError, match="task_index"):
        score_predictions(bad_csv)
