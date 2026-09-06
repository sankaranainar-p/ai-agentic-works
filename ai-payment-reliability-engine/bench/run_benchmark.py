"""
bench/run_benchmark.py — YAML-config-driven benchmark harness.

Usage:
    python -m bench.run_benchmark --config bench/configs/re1_ob_smoke.yaml

A config selects:
    adapter        which pre.signals adapter to pull FailureCase/GroundTruth
                   pairs from, and its constructor args (root, dataset)
    system_variant which variant of the full pipeline to score ("full" or
                   an ablation label A1-A6 — this harness does not
                   interpret the label itself; it is recorded in the
                   manifest for downstream analysis and passed to any
                   baseline/pipeline hook that wants to branch on it)
    baselines      list of baseline IDs to run (B1-B5, see
                   bench.baselines.BASELINE_IDS)
    model          optional model identifier, recorded in the manifest
                   (baselines that call an LLM read their own provider
                   config from the environment, same as the live pipeline)
    repeats        number of times to repeat the whole run (LLM-backed
                   baselines are non-deterministic; deterministic
                   baselines like B1/B2/B3 produce identical repeats)
    output_dir     results/<run_id>/ is created under this directory

Every run writes:
    results/<run_id>/manifest.json   config + environment + per-repeat status
    results/<run_id>/metrics.csv     one row per (baseline, fault_type, repeat)
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from bench.baselines import BASELINE_IDS
from bench.metrics import average_at_k
from pre.signals.types import FailureCase, GroundTruth

_ADAPTERS = {
    "rcaeval": "pre.signals.rcaeval.RCAEvalAdapter",
}


def _load_adapter(adapter_config: dict[str, Any]):
    name = adapter_config["name"]
    if name != "rcaeval":
        raise ValueError(f"unknown adapter {name!r}; known adapters: {list(_ADAPTERS)}")

    from pre.signals.rcaeval import RCAEvalAdapter

    return RCAEvalAdapter(root=adapter_config["root"], dataset=adapter_config["dataset"])


def _load_baseline_rank_fn(baseline_id: str):
    if baseline_id == "B1":
        from bench.baselines.rules import rank
        return rank
    if baseline_id == "B2":
        from bench.baselines.rcaeval_baseline import rank
        return rank
    if baseline_id == "B3":
        from bench.baselines.ml_triage import rank
        return rank
    if baseline_id == "B4":
        from bench.baselines.single_prompt_llm import rank
        return rank
    if baseline_id == "B5":
        raise ValueError(
            "B5 (bench.baselines.openrca_agent) is not a per-FailureCase "
            "ranking baseline like B1-B4 -- it scores OpenRCA-format "
            "prediction CSVs directly via score_predictions(). Run it "
            "separately; it is not wired into this generic harness loop."
        )
    raise ValueError(f"unknown baseline {baseline_id!r}; known: {BASELINE_IDS}")


def load_config(path: str | Path) -> dict[str, Any]:
    with open(path) as fh:
        config = yaml.safe_load(fh)

    required = {"run_id", "adapter", "system_variant", "baselines", "repeats", "output_dir"}
    missing = required - config.keys()
    if missing:
        raise ValueError(f"config missing required keys: {sorted(missing)}")

    unknown_baselines = set(config["baselines"]) - set(BASELINE_IDS)
    if unknown_baselines:
        raise ValueError(f"config names unknown baselines: {sorted(unknown_baselines)}")

    if config["repeats"] < 1:
        raise ValueError("repeats must be >= 1")

    return config


def run_one_baseline(
    baseline_id: str,
    cases: list[tuple[FailureCase, GroundTruth]],
) -> dict[str, Any]:
    """Run one baseline over all cases, grouped by fault_type.

    Returns {fault_type: {"n_cases": int, "avg_at_5": float, "errors": int}}.
    A baseline raising (e.g. B2 without RCAEval installed, B4 without an
    LLM provider raising instead of degrading) is caught per-case so one
    bad case doesn't abort the whole run; the case is excluded from that
    fault_type's AC@k/Avg@5 and counted in "errors".
    """
    rank_fn = _load_baseline_rank_fn(baseline_id)

    per_fault: dict[str, list[tuple[list[str], str]]] = {}
    error_counts: dict[str, int] = {}

    for case, ground_truth in cases:
        fault_type = ground_truth.fault_type
        per_fault.setdefault(fault_type, [])
        error_counts.setdefault(fault_type, 0)
        try:
            ranks = rank_fn(case, inject_time=ground_truth.inject_time)
        except Exception:
            error_counts[fault_type] += 1
            continue
        per_fault[fault_type].append((ranks, ground_truth.root_cause_service))

    results: dict[str, Any] = {}
    for fault_type, ranked_answers in per_fault.items():
        results[fault_type] = {
            "n_cases": len(ranked_answers),
            "avg_at_5": average_at_k(ranked_answers, k=5) if ranked_answers else None,
            "errors": error_counts[fault_type],
        }
    return results


def run_benchmark(config: dict[str, Any]) -> Path:
    """Execute *config*, writing results/<run_id>/manifest.json and
    metrics.csv. Returns the run's output directory.
    """
    run_id = config["run_id"]
    output_dir = Path(config["output_dir"]) / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    started_at = time.time()
    manifest: dict[str, Any] = {
        "run_id": run_id,
        "config": config,
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
        },
        "started_at": started_at,
        "repeats": [],
    }

    metrics_rows: list[dict[str, Any]] = []

    for repeat_index in range(config["repeats"]):
        adapter = _load_adapter(config["adapter"])
        cases = list(adapter)

        repeat_record: dict[str, Any] = {
            "repeat_index": repeat_index,
            "n_cases": len(cases),
            "baselines": {},
        }

        for baseline_id in config["baselines"]:
            try:
                per_fault_results = run_one_baseline(baseline_id, cases)
                repeat_record["baselines"][baseline_id] = {"status": "ok"}
            except Exception as exc:
                repeat_record["baselines"][baseline_id] = {
                    "status": "failed",
                    "error": str(exc),
                }
                continue

            for fault_type, stats in per_fault_results.items():
                metrics_rows.append(
                    {
                        "run_id": run_id,
                        "repeat_index": repeat_index,
                        "system_variant": config["system_variant"],
                        "baseline": baseline_id,
                        "fault_type": fault_type,
                        "n_cases": stats["n_cases"],
                        "avg_at_5": stats["avg_at_5"],
                        "errors": stats["errors"],
                    }
                )

        manifest["repeats"].append(repeat_record)

    manifest["finished_at"] = time.time()
    manifest["duration_seconds"] = manifest["finished_at"] - started_at

    manifest_path = output_dir / "manifest.json"
    with manifest_path.open("w") as fh:
        json.dump(manifest, fh, indent=2, default=str)

    metrics_path = output_dir / "metrics.csv"
    _write_metrics_csv(metrics_path, metrics_rows)

    return output_dir


def _write_metrics_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    import csv

    fieldnames = [
        "run_id", "repeat_index", "system_variant", "baseline",
        "fault_type", "n_cases", "avg_at_5", "errors",
    ]
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="path to a YAML benchmark config")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    output_dir = run_benchmark(config)
    print(f"Wrote {output_dir / 'manifest.json'} and {output_dir / 'metrics.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
