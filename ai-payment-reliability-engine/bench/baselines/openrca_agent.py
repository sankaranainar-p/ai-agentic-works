"""
bench/baselines/openrca_agent.py — B5: OpenRCA's RCA-agent baseline,
scored on OpenRCA's Bank system cases with OpenRCA's own scoring logic.

OpenRCA (https://github.com/microsoft/OpenRCA) is a different benchmark
from RCAEval: instead of ranking candidate root-cause services, it poses
natural-language queries ("what was the root cause component/reason/
occurrence time of the failure between 14:30 and 15:00?") and scores a
JSON-like prediction against per-task scoring points (see
main/task_specification.json in the OpenRCA repo).

The full OpenRCA telemetry (query.csv/record.csv/telemetry/) for Bank,
Telecom, and Market is distributed via Google Drive, not the GitHub repo,
and is not reproducible from a checksummed public URL the way RCAEval's
Zenodo archive is. This baseline therefore operates in two modes:

  1. `score_predictions(prediction_csv, query_csv)` — OpenRCA's own scoring
     algorithm (evaluate(), ported here field-for-field from
     main/evaluate.py), run against prediction/query CSV pairs in
     OpenRCA's documented schema. This works against OpenRCA's own
     archived reproduction of RCA-agent's Bank predictions
     (rca/archive/agent-Bank.csv on GitHub, no Google Drive access
     needed) for "same weights" comparison, and against a fresh run's
     output once the real telemetry is available locally.
  2. `run_agent(...)` — placeholder for driving a live RCA-agent-style
     loop over the real Bank telemetry once downloaded; raises
     NotImplementedError with a pointer to OpenRCA's own
     `rca.run_agent_standard --dataset Bank`, since reimplementing its
     multi-step Python-code-generation agent here would fork behaviour
     away from "the same weights" the task requires.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

_PREDICT_PATTERN = (
    r'{\s*'
    r'(?:"root cause occurrence datetime":\s*"(.*?)")?,?\s*'
    r'(?:"root cause component":\s*"(.*?)")?,?\s*'
    r'(?:"root cause reason":\s*"(.*?)")?\s*}'
)
_COMPONENT_PATTERN = r"The (?:\d+-th|only) predicted root cause component is ([^\n]+)"
_REASON_PATTERN = r"The (?:\d+-th|only) predicted root cause reason is ([^\n]+)"
_TIME_PATTERN = r"The (?:\d+-th|only) root cause occurrence time is within 1 minutes \(i\.e\., <=1min\) of ([^\n]+)"

_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Per-task scoring point templates, from OpenRCA's main/task_specification.json.
# Ported verbatim so B5 scores against the same criteria OpenRCA's own
# leaderboard uses, not a reinterpretation of them.
_TASK_SCORING_TEMPLATES: dict[str, list[str]] = {
    "task_1": ["The {idx} root cause occurrence time is within 1 minutes (i.e., <=1min) of {datetime}"],
    "task_2": ["The {idx} predicted root cause reason is {reason}"],
    "task_3": ["The {idx} predicted root cause component is {component}"],
    "task_4": [
        "The {idx} root cause occurrence time is within 1 minutes (i.e., <=1min) of {datetime}",
        "The {idx} predicted root cause reason is {reason}",
    ],
    "task_5": [
        "The {idx} root cause occurrence time is within 1 minutes (i.e., <=1min) of {datetime}",
        "The {idx} predicted root cause component is {component}",
    ],
    "task_6": [
        "The {idx} predicted root cause component is {component}",
        "The {idx} predicted root cause reason is {reason}",
    ],
    "task_7": [
        "The {idx} root cause occurrence time is within 1 minutes (i.e., <=1min) of {datetime}",
        "The {idx} predicted root cause component is {component}",
        "The {idx} predicted root cause reason is {reason}",
    ],
}


def _parse_record_block(groundtruth: str) -> dict[str, str]:
    """Parse a `key: value` per-line record block (OpenRCA's archived
    reproduction format, e.g. rca/archive/agent-Bank.csv's `groundtruth`
    column) into a dict.
    """
    fields: dict[str, str] = {}
    for line in groundtruth.strip().splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def scoring_points_from_record(record: dict[str, str], task_index: str) -> str:
    """Synthesise the scoring_points string for a single-failure record
    and task_index, matching OpenRCA's own main/generate.py::query_generate
    single-response path (`idx="only"`) exactly.

    KNOWN LIMITATION: OpenRCA's generate.py groups two-or-more failures
    that fall in the same 30-minute window into one multi-response query
    (see get_half_hour_conflict_failure_flag / get_multi_response_dict in
    OpenRCA's main/generate.py), scored across all permutations of the
    predicted failures. Detecting that grouping requires the full sorted
    record.csv for the system, which archived per-row reproductions like
    rca/archive/agent-Bank.csv do not carry (each row's `groundtruth`
    column has only that row's own record). This function therefore always
    renders a single-response scoring_points string. Verified against
    OpenRCA's own archived agent-Bank.csv scores: this reproduces the
    published score exactly for all 116 single-failure rows (where the
    prediction also names exactly one failure); the 20 multi-failure rows
    necessarily diverge and are excluded from the B5 parity claim (see
    tests/test_b5_openrca_agent.py).
    """
    template = _TASK_SCORING_TEMPLATES.get(task_index)
    if template is None:
        raise ValueError(f"unknown task_index {task_index!r}")

    lines = []
    for point in template:
        lines.append(
            point.format(
                idx="only",
                datetime=record.get("datetime", ""),
                component=record.get("component", ""),
                reason=record.get("reason", ""),
            )
        )
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class ScoreResult:
    passing_criteria: list[str]
    failing_criteria: list[str]
    score: float


def _time_within_one_minute(time1_str: str, time2_str: str) -> bool:
    try:
        time1 = datetime.strptime(time1_str, _TIME_FORMAT)
        time2 = datetime.strptime(time2_str, _TIME_FORMAT)
    except ValueError:
        return False
    return abs((time1 - time2).total_seconds()) <= 60


def evaluate(prediction: str, scoring_points: str) -> ScoreResult:
    """Score a single JSON-like prediction against OpenRCA scoring points.

    Direct port of OpenRCA's main/evaluate.py::evaluate, field-for-field,
    so B5's scores are computed exactly the way OpenRCA's own leaderboard
    computes them — not a reinterpretation.
    """
    predict_matches = re.findall(_PREDICT_PATTERN, prediction)
    predict_results = [
        {
            "root cause occurrence datetime": dt,
            "root cause component": component,
            "root cause reason": reason,
        }
        for dt, component, reason in predict_matches
    ]
    prediction_length = len(predict_results)

    components = re.findall(_COMPONENT_PATTERN, scoring_points)
    reasons = re.findall(_REASON_PATTERN, scoring_points)
    times = re.findall(_TIME_PATTERN, scoring_points)

    scoringpoints_length = max(len(components), len(reasons), len(times))
    scores_num = len(components) + len(reasons) + len(times)

    scores_get = 0
    passing_criteria: list[str] = []

    if scoringpoints_length == prediction_length and scoringpoints_length > 0:
        best_score = -1
        for perm in itertools.permutations(predict_results):
            current_score = 0
            current_passing = []
            for i in range(scoringpoints_length):
                if len(components) == scoringpoints_length and perm[i]["root cause component"] == components[i]:
                    current_score += 1
                    current_passing.append(components[i])
                if len(reasons) == scoringpoints_length and perm[i]["root cause reason"] == reasons[i]:
                    current_score += 1
                    current_passing.append(reasons[i])
                if len(times) == scoringpoints_length and _time_within_one_minute(
                    times[i], perm[i]["root cause occurrence datetime"]
                ):
                    current_score += 1
                    current_passing.append(times[i])
            if current_score > best_score:
                best_score = current_score
                passing_criteria = current_passing
        scores_get = best_score

    failing_criteria = list(set(components + reasons + times) - set(passing_criteria))
    final_score = scores_get / scores_num if scores_num else 0.0
    return ScoreResult(passing_criteria=passing_criteria, failing_criteria=failing_criteria, score=round(final_score, 2))


def score_predictions(prediction_csv: str | Path, query_csv: str | Path | None = None) -> pd.DataFrame:
    """Score a prediction CSV against scoring points.

    If *query_csv* is given, it must have a `scoring_points` column aligned
    row-for-row with `prediction_csv`'s `prediction` column (OpenRCA's
    documented two-file schema). If *prediction_csv* already has a
    `groundtruth` column, it is used instead: OpenRCA's own archived
    reproductions under rca/archive/ (e.g. agent-Bank.csv) store the raw
    `key: value` record block there rather than a pre-rendered
    scoring_points string, so this path also requires `task_index` to
    render the matching scoring template (see scoring_points_from_record).
    """
    pred_df = pd.read_csv(prediction_csv)
    if "row_id" in pred_df.columns:
        pred_df = pred_df.sort_values("row_id").reset_index(drop=True)

    if query_csv is not None:
        query_df = pd.read_csv(query_csv)
        if len(pred_df) != len(query_df):
            raise ValueError("prediction and query files must have the same length")
        scoring_points_col = query_df["scoring_points"]
    elif "groundtruth" in pred_df.columns:
        if "task_index" not in pred_df.columns:
            raise ValueError(
                "prediction_csv's 'groundtruth' column needs a matching "
                "'task_index' column to render scoring points from"
            )
        scoring_points_col = pd.Series(
            [
                scoring_points_from_record(
                    _parse_record_block(str(pred_df.loc[i, "groundtruth"])),
                    str(pred_df.loc[i, "task_index"]),
                )
                for i in range(len(pred_df))
            ]
        )
    else:
        raise ValueError(
            "score_predictions needs either query_csv, or a 'groundtruth' "
            "column in prediction_csv carrying the scoring points inline"
        )

    rows = []
    for idx in range(len(pred_df)):
        result = evaluate(pred_df.loc[idx, "prediction"], str(scoring_points_col.iloc[idx]))
        rows.append(
            {
                "row_id": pred_df.loc[idx].get("row_id", idx),
                "task_index": pred_df.loc[idx].get("task_index"),
                "score": result.score,
                "passed": result.passing_criteria,
                "failed": result.failing_criteria,
            }
        )
    return pd.DataFrame(rows)


def run_agent(*args, **kwargs):
    """Drive OpenRCA's RCA-agent over live Bank telemetry.

    Not implemented here: OpenRCA's RCA-agent is a multi-step Python-
    code-generation loop over the real telemetry (main/rca/run_agent_standard
    in the OpenRCA repo), and the full Bank telemetry is distributed via
    Google Drive (see OpenRCA's README), not a checksummed public URL this
    project can script a downloader against the way
    data/scripts/download_rcaeval.py does for RCAEval.

    To run B5 with live weights against fresh Bank cases: download the
    Bank telemetry per OpenRCA's README into OpenRCA's `dataset/Bank/`,
    configure `rca/api_config.yaml` with the same model/weights used
    elsewhere in this benchmark, and run
    `python -m rca.run_agent_standard --dataset Bank` from a clone of
    https://github.com/microsoft/OpenRCA. Score the resulting predictions
    CSV with `score_predictions()` above, which reproduces OpenRCA's own
    evaluate() scoring exactly.
    """
    raise NotImplementedError(
        "B5's live agent loop requires OpenRCA's own Bank telemetry "
        "(Google Drive, see OpenRCA README) and its RCA-agent "
        "implementation; use score_predictions() against a prediction "
        "CSV produced by `python -m rca.run_agent_standard --dataset "
        "Bank` in a clone of https://github.com/microsoft/OpenRCA, or "
        "against OpenRCA's own archived agent-Bank.csv for a same-weights "
        "comparison without needing the telemetry download."
    )
