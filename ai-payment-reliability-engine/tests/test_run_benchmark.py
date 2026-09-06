"""
tests/test_run_benchmark.py — Tests for bench/run_benchmark.py's
YAML-config-driven harness, using the small RCAEval fixtures from A3
(tests/fixtures/rcaeval) so this runs fast and needs no external data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from bench.run_benchmark import (
    load_config,
    run_benchmark,
    run_one_baseline,
)
from pre.signals.rcaeval import RCAEvalAdapter

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "rcaeval"


def _base_config(tmp_path: Path, **overrides) -> dict:
    config = {
        "run_id": "test_run",
        "adapter": {"name": "rcaeval", "root": str(FIXTURE_ROOT), "dataset": "RE1-OB"},
        "system_variant": "full",
        "baselines": ["B1"],
        "repeats": 1,
        "output_dir": str(tmp_path),
    }
    config.update(overrides)
    return config


def test_load_config_rejects_missing_keys(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.dump({"run_id": "x"}))
    with pytest.raises(ValueError, match="missing required keys"):
        load_config(path)


def test_load_config_rejects_unknown_baseline(tmp_path):
    config = _base_config(tmp_path, baselines=["B99"])
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(config))
    with pytest.raises(ValueError, match="unknown baselines"):
        load_config(path)


def test_load_config_rejects_zero_repeats(tmp_path):
    config = _base_config(tmp_path, repeats=0)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(config))
    with pytest.raises(ValueError, match="repeats must be"):
        load_config(path)


def test_load_config_accepts_valid_config(tmp_path):
    config = _base_config(tmp_path)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(config))
    loaded = load_config(path)
    assert loaded["run_id"] == "test_run"


def test_run_one_baseline_b1_on_re1_ob_fixture():
    cases = list(RCAEvalAdapter(FIXTURE_ROOT, "RE1-OB"))
    results = run_one_baseline("B1", cases)
    assert "cpu" in results
    assert results["cpu"]["n_cases"] == 1
    assert results["cpu"]["errors"] == 0
    assert 0.0 <= results["cpu"]["avg_at_5"] <= 1.0


def test_run_one_baseline_unknown_raises():
    with pytest.raises(ValueError, match="unknown baseline"):
        run_one_baseline("B99", [])


def test_run_one_baseline_b5_rejected():
    """B5 scores OpenRCA-format prediction CSVs, not FailureCase objects
    -- it must not silently no-op inside the generic per-case loop."""
    with pytest.raises(ValueError, match="B5"):
        run_one_baseline("B5", [])


def test_run_benchmark_writes_manifest_and_metrics(tmp_path):
    config = _base_config(tmp_path)
    output_dir = run_benchmark(config)

    manifest_path = output_dir / "manifest.json"
    metrics_path = output_dir / "metrics.csv"
    assert manifest_path.exists()
    assert metrics_path.exists()

    with manifest_path.open() as fh:
        manifest = json.load(fh)
    assert manifest["run_id"] == "test_run"
    assert manifest["config"]["baselines"] == ["B1"]
    assert len(manifest["repeats"]) == 1
    assert manifest["repeats"][0]["baselines"]["B1"]["status"] == "ok"
    assert "duration_seconds" in manifest

    metrics_text = metrics_path.read_text()
    assert "run_id,repeat_index,system_variant,baseline,fault_type,n_cases,avg_at_5,errors" in metrics_text
    assert "test_run" in metrics_text
    assert "B1" in metrics_text


def test_run_benchmark_respects_repeats(tmp_path):
    config = _base_config(tmp_path, repeats=3)
    output_dir = run_benchmark(config)

    with (output_dir / "manifest.json").open() as fh:
        manifest = json.load(fh)
    assert len(manifest["repeats"]) == 3
    assert [r["repeat_index"] for r in manifest["repeats"]] == [0, 1, 2]


def test_run_benchmark_multiple_baselines(tmp_path):
    config = _base_config(tmp_path, baselines=["B1", "B3"])
    output_dir = run_benchmark(config)

    metrics_text = (output_dir / "metrics.csv").read_text()
    assert "B1" in metrics_text
    assert "B3" in metrics_text


def test_run_benchmark_records_system_variant(tmp_path):
    config = _base_config(tmp_path, system_variant="A1")
    output_dir = run_benchmark(config)
    metrics_text = (output_dir / "metrics.csv").read_text()
    assert ",A1," in metrics_text


def test_run_benchmark_baseline_failure_does_not_abort_run(tmp_path, monkeypatch):
    """If a baseline's rank function raises for every case, the run must
    still complete and record the failure, not crash the whole harness."""
    config = _base_config(tmp_path, baselines=["B2"])  # B2 needs RCAEval; likely absent in this env
    output_dir = run_benchmark(config)

    with (output_dir / "manifest.json").open() as fh:
        manifest = json.load(fh)
    # Either B2 imported fine (rare in this 3.9 env) or it failed gracefully;
    # either way the manifest must exist and record a definite status.
    status = manifest["repeats"][0]["baselines"]["B2"]["status"]
    assert status in ("ok", "failed")
