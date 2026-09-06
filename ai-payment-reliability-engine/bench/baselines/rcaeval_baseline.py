"""
bench/baselines/rcaeval_baseline.py — B2: wraps RCAEval's own BARO
baseline, run against the same FailureCase objects pre.signals.rcaeval
produces, so B2 scores are directly comparable to every other baseline in
this harness on identical inputs.

Requires the `RCAEval` package (`pip install RCAEval[default]`, Python
3.12/3.14 per RCAEval's own requirement — see
https://github.com/phamquiluan/RCAEval). Raises ImportError with a clear
message if it isn't installed, rather than silently no-op'ing like B4:
B2's entire purpose is parity with a specific published baseline, so a
missing dependency must be loud.

IMPORTANT — verified parity, do not weaken without re-verifying:
tests/test_b2_rcaeval_parity.py reproduces the RCAEval README's published
Avg@5 table for RE2-TT (CPU 0.72, MEM 0.99, DISK 1.0, SOCKET 0.83,
DELAY 0.63, LOSS 0.64) via this exact code path (FailureCase ->
_to_dataframe -> RCAEval.e2e.baro), against the real Zenodo dataset. That
test requires the real RE2-TT download and is skipped by default (see
its module docstring) — CI runs the smaller fixture-based sanity checks
in this module's own tests instead.
"""

from __future__ import annotations

import pandas as pd

from pre.signals.types import FailureCase

try:
    from RCAEval.e2e import baro as _rcaeval_baro
except ImportError as exc:  # pragma: no cover - exercised via skip in tests
    _rcaeval_baro = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def to_rcaeval_dataframe(case: FailureCase) -> pd.DataFrame:
    """Reconstruct the wide `time` + `{service}_{metric}` DataFrame RCAEval
    baselines expect, from a FailureCase's normalised `svc:metric` series.

    This is the inverse of pre.signals.rcaeval._load_metrics's
    normalisation, so B2 runs on exactly the same numbers every other
    baseline in this harness sees — no separate, potentially-diverging
    data path into RCAEval.
    """
    if not case.metrics:
        return pd.DataFrame({"time": []})

    all_times = sorted({t for series in case.metrics.values() for t in series.times})
    time_index = {t: i for i, t in enumerate(all_times)}

    columns: dict[str, list] = {"time": all_times}
    for key, series in case.metrics.items():
        svc, metric = key.split(":", 1)
        col = f"{svc}_{metric}"
        values: list = [None] * len(all_times)
        for t, v in zip(series.times, series.values):
            values[time_index[t]] = v
        columns[col] = values

    # Build via one concat instead of repeated df[col] = assignment, which
    # pandas warns is O(n^2)-ish ("highly fragmented") at this column count
    # (RE2-TT cases have 300+ metric columns).
    df = pd.concat({name: pd.Series(vals) for name, vals in columns.items()}, axis=1)
    return df.ffill().fillna(0.0)


def rank(case: FailureCase, inject_time: int, window_minutes: int = 20) -> list[str]:
    """Rank services using RCAEval's BARO, via the shared FailureCase data path.

    Replicates RCAEval's own main.py preprocessing exactly, since BARO's
    output is sensitive to it (verified: without this, B2 does not
    reproduce the published RE2-TT table — see
    tests/test_b2_rcaeval_parity.py):
      - drop `_latency-50` columns (RCAEval keeps only `_latency-90`)
      - window to the last/first `window_minutes * 60 // 2` samples
        before/after inject_time (RCAEval's `--length` default is 20)
      - pass a non-None `dataset=` string to RCAEval.e2e.baro: this flips
        its internal `preprocess()` from a no-op into dropping constant
        columns and converting memory metrics to MB (RCAEval.io.time_series
        .preprocess branches on `dataset is None` vs not — the *value*
        of the string doesn't matter for RE1/RE2 datasets, only that it's
        not None).

    Raises ImportError if the RCAEval package is not installed.
    """
    if _rcaeval_baro is None:
        raise ImportError(
            "bench.baselines.rcaeval_baseline requires the RCAEval package "
            "(pip install RCAEval[default], Python 3.12/3.14). "
            f"Original import error: {_IMPORT_ERROR}"
        )

    df = to_rcaeval_dataframe(case)
    if df.empty or "time" not in df.columns or len(df.columns) <= 1:
        return []

    df = df.loc[:, ~df.columns.str.endswith("_latency-50")]

    window = window_minutes * 60 // 2
    normal_df = df[df["time"] < inject_time].tail(window)
    anomal_df = df[df["time"] >= inject_time].head(window)
    df = pd.concat([normal_df, anomal_df], ignore_index=True)
    if df.empty:
        return []

    # svc_metric column -> service, built from the case's own metric keys so
    # multi-hyphen/underscore service names (e.g. "ts-order-service") are
    # never mis-split by a naive column.split("_")[0].
    column_to_service = {
        f"{key.split(':', 1)[0]}_{key.split(':', 1)[1]}": key.split(":", 1)[0]
        for key in case.metrics
    }

    result = _rcaeval_baro(df, inject_time=inject_time, dataset=case.dataset)
    ranks = result.get("ranks", [])

    seen: list[str] = []
    for candidate in ranks:
        service = column_to_service.get(candidate)
        if service is None:
            # BARO's internal renaming (e.g. latency-90 -> latency, see
            # RCAEval.io.time_series) can alter the candidate string;
            # fall back to the longest matching known service prefix.
            service = max(
                (s for s in column_to_service.values() if candidate.startswith(s + "_")),
                key=len,
                default=candidate,
            )
        if service not in seen:
            seen.append(service)
    return seen
