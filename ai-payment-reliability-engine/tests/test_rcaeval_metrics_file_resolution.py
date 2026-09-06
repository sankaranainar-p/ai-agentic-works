"""
tests/test_rcaeval_metrics_file_resolution.py — Regression test for a real
bug: RE2 datasets (confirmed against the actual Zenodo RE2-OB/RE2-TT
archives) ship metrics as `simple_metrics.csv`, not `data.csv`. An earlier
version of pre/signals/rcaeval.py assumed `data.csv` unconditionally
(true for RE1, and true for RCAEval's own smaller multi-source demo
release, but false for the real RE2 Zenodo archives), which would have
silently loaded zero cases from any real RE2 dataset.
"""

from __future__ import annotations

import pytest

from pre.signals.rcaeval import _resolve_metrics_file


def test_prefers_data_csv_when_present(tmp_path):
    (tmp_path / "data.csv").write_text("time\n1\n")
    (tmp_path / "simple_metrics.csv").write_text("time\n1\n")
    assert _resolve_metrics_file(tmp_path).name == "data.csv"


def test_falls_back_to_simple_metrics_csv(tmp_path):
    """This is the real RE2 case shape: no data.csv, only simple_metrics.csv."""
    (tmp_path / "simple_metrics.csv").write_text("time\n1\n")
    assert _resolve_metrics_file(tmp_path).name == "simple_metrics.csv"


def test_raises_when_neither_file_present(tmp_path):
    with pytest.raises(FileNotFoundError, match="data.csv or simple_metrics.csv"):
        _resolve_metrics_file(tmp_path)


def test_does_not_pick_up_raw_metrics_csv(tmp_path):
    """metrics.csv (raw Prometheus names) must never be picked up as the
    fallback — only simple_metrics.csv (curated svc_metric names) is valid."""
    (tmp_path / "metrics.csv").write_text("time\n1\n")
    with pytest.raises(FileNotFoundError):
        _resolve_metrics_file(tmp_path)
