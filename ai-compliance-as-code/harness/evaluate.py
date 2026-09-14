"""
harness/evaluate.py — Batch evaluation runner for GDPR-Bench-Android.

Supports:
  - Task 1: Multi-granularity localization (Accuracy@1..5 at file, module, line)
  - Task 2: Snippet-level multi-label classification (Exact-match, Macro-P/R/F1)
  - Detectors: 'static', 'llm', 'both'
  - Checkpointing every 25 items
  - Throttled concurrency with exponential backoff
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, TypeVar

# Bootstrap project root
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.schemas import ComplianceFinding
from arbitration.fixed_confidence import FixedConfidenceMerge
from detectors import LLMDetector, StaticScannerDetector
from harness.ast_resolver import ASTNodeInfo, ASTResolver
from harness.label_mapper import (
    BenchmarkRecord,
    LabelMapper,
    load_task1_dataset,
    load_task2_dataset,
)
from harness.metrics import (
    compute_multilabel_metrics,
    compute_task1_metrics,
)

logger = logging.getLogger("harness.evaluate")

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Throttling & Exponential Backoff
# ---------------------------------------------------------------------------

def run_with_backoff(
    fn: Callable[[], T],
    max_retries: int = 4,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 30.0,
) -> T:
    """Execute fn() with exponential backoff on exceptions."""
    delay = initial_delay
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt == max_retries:
                logger.error("All %d retries failed: %s", max_retries, exc)
                raise
            logger.warning(
                "Attempt %d/%d failed with: %s. Backing off for %.2fs...",
                attempt + 1,
                max_retries,
                exc,
                delay,
            )
            time.sleep(delay)
            delay = min(delay * backoff_factor, max_delay)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Unexpected error in run_with_backoff")


# ---------------------------------------------------------------------------
# Detector Execution Helper
# ---------------------------------------------------------------------------

class EvaluationDetector:
    """Unified detector wrapper handling 'static', 'llm', or 'both'."""

    def __init__(self, mode: str, dry_run: bool = False) -> None:
        self.mode = mode.lower()
        self.dry_run = dry_run
        self.static_detector = StaticScannerDetector() if self.mode in ("static", "both") else None
        self.llm_detector = LLMDetector() if self.mode in ("llm", "both") else None
        self.arbitrator = FixedConfidenceMerge() if self.mode == "both" else None

    def analyze(
        self,
        code: str,
        file_path: str = "untitled",
        regulation: str = "GDPR",
    ) -> List[ComplianceFinding]:
        """Run the configured detector with exponential backoff."""
        if self.dry_run or not code:
            return []

        def _invoke() -> List[ComplianceFinding]:
            if self.mode == "static" and self.static_detector is not None:
                return self.static_detector.detect(code, file_path=file_path, regulation=regulation)

            if self.mode == "llm" and self.llm_detector is not None:
                return self.llm_detector.detect(code, file_path=file_path, regulation=regulation)

            if self.mode == "both" and self.static_detector is not None and self.llm_detector is not None:
                static_findings = self.static_detector.detect(code, file_path=file_path, regulation=regulation)
                llm_findings = self.llm_detector.detect(code, file_path=file_path, regulation=regulation)
                if self.arbitrator is not None:
                    return self.arbitrator.arbitrate(static_findings, llm_findings)
                return list(llm_findings) + list(static_findings)

            return []

        return run_with_backoff(_invoke)


# ---------------------------------------------------------------------------
# Checkpointing
# ---------------------------------------------------------------------------

class CheckpointManager:
    """Manages disk flushes and resumption for batch evaluation runs."""

    def __init__(self, checkpoint_path: Path, flush_interval: int = 25) -> None:
        self.path = checkpoint_path
        self.flush_interval = flush_interval
        self._buffer: List[dict[str, Any]] = []
        self.completed_keys: Set[str] = set()
        self._load_existing()

    def _load_existing(self) -> None:
        if not self.path.exists():
            return
        logger.info("Loading existing checkpoint from %s", self.path)
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        record = json.loads(line)
                        if "key" in record:
                            self.completed_keys.add(record["key"])
                    except json.JSONDecodeError:
                        continue
        logger.info("Resumed %d completed items from checkpoint", len(self.completed_keys))

    def record_completed(self, key: str, data: dict[str, Any]) -> None:
        data_with_key = dict(data)
        data_with_key["key"] = key
        self._buffer.append(data_with_key)
        self.completed_keys.add(key)

        if len(self._buffer) >= self.flush_interval:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            for item in self._buffer:
                f.write(json.dumps(item) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._buffer.clear()

    def get_all_records(self) -> List[dict[str, Any]]:
        """Read all completed records from checkpoint file and buffer."""
        self.flush()
        if not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records


EvaluationCheckpoint = CheckpointManager


# ---------------------------------------------------------------------------
# Evaluation Workers
# ---------------------------------------------------------------------------

def _rank_of_first_hit(predictions: Sequence[int], target: int) -> Optional[int]:
    """Return 1-based rank of target in predictions, or None if not present."""
    try:
        return predictions.index(target) + 1
    except ValueError:
        return None


def evaluate_task1_instance(
    record: BenchmarkRecord,
    detector: EvaluationDetector,
    mapper: LabelMapper,
    ast_resolver: ASTResolver,
) -> dict[str, Any]:
    """Evaluate a single Task 1 instance across file, module, and line granularities."""
    code = record.code_snippet
    file_path = record.file_path or record.code_snippet_path or "Sample.java"
    lang = ast_resolver.detect_language(file_path)

    target_article = (
        record.violated_article
        if isinstance(record.violated_article, int)
        else (record.violated_article[0] if record.violated_article else None)
    )

    findings = detector.analyze(code, file_path=file_path)

    # Sort findings defensively by confidence
    findings.sort(key=lambda f: getattr(f, "confidence", 1.0), reverse=True)

    # 1. File level: all predictions in this file
    file_preds: List[int] = []
    for f in findings:
        art = mapper.rule_to_article(f.rule_id)
        if art is not None and art not in file_preds:
            file_preds.append(art)

    # 2. Module level: filter to findings in enclosing class / method AST node
    gt_module = ast_resolver.resolve_span(
        code,
        record.start_line,
        record.end_line,
        language=lang,
        file_path=file_path,
    )

    module_preds: List[int] = []
    for f in findings:
        art = mapper.rule_to_article(f.rule_id)
        if art is None:
            continue

        f_start = f.line_start
        f_end = f.line_end or f.line_start
        f_module = ast_resolver.resolve_span(
            code,
            f_start,
            f_end,
            language=lang,
            file_path=file_path,
        )

        in_module = False
        if gt_module and f_module:
            if gt_module.qualified_name and gt_module.qualified_name == f_module.qualified_name:
                in_module = True
            elif gt_module.overlaps_span(f_module.start_line, f_module.end_line):
                in_module = True
        elif gt_module and f_start is not None and f_end is not None:
            in_module = gt_module.overlaps_span(f_start, f_end)
        else:
            # When AST is not available, module level matches same file
            in_module = True

        if in_module and art not in module_preds:
            module_preds.append(art)

    # 3. Line level: filter to findings overlapping ground-truth line span
    line_preds: List[int] = []
    gt_start = record.start_line
    gt_end = record.end_line or record.start_line

    for f in findings:
        art = mapper.rule_to_article(f.rule_id)
        if art is None:
            continue

        f_start = f.line_start
        f_end = f.line_end or f.line_start

        on_line = False
        if gt_start is not None and gt_end is not None and f_start is not None and f_end is not None:
            # Check for line overlap
            on_line = not (f_end < gt_start or f_start > gt_end)
        elif gt_start is None:
            on_line = True

        if on_line and art not in line_preds:
            line_preds.append(art)

    rank_file = _rank_of_first_hit(file_preds, target_article) if target_article else None
    rank_module = _rank_of_first_hit(module_preds, target_article) if target_article else None
    rank_line = _rank_of_first_hit(line_preds, target_article) if target_article else None

    return {
        "app_name": record.app_name,
        "repo_url": record.repo_url,
        "commit_id": record.commit_id,
        "code_snippet_path": record.code_snippet_path,
        "target_article": target_article,
        "file_preds": file_preds,
        "module_preds": module_preds,
        "line_preds": line_preds,
        "rank_file": rank_file,
        "rank_module": rank_module,
        "rank_line": rank_line,
    }


def evaluate_task2_instance(
    record: BenchmarkRecord,
    detector: EvaluationDetector,
    mapper: LabelMapper,
) -> dict[str, Any]:
    """Evaluate a single Task 2 instance for multi-label classification."""
    code = record.code_snippet
    file_path = record.file_path or record.code_snippet_path or "Sample.java"

    if isinstance(record.violated_article, list):
        gt_articles = [int(a) for a in record.violated_article]
    elif record.violated_article is not None:
        gt_articles = [int(record.violated_article)]
    else:
        gt_articles = []

    findings = detector.analyze(code, file_path=file_path)

    predicted_articles: List[int] = []
    for f in findings:
        art = mapper.rule_to_article(f.rule_id)
        if art is not None and art not in predicted_articles:
            predicted_articles.append(art)

    predicted_articles.sort()

    return {
        "app_name": record.app_name,
        "repo_url": record.repo_url,
        "commit_id": record.commit_id,
        "code_snippet_path": record.code_snippet_path,
        "ground_truth": sorted(gt_articles),
        "predicted": predicted_articles,
    }


# ---------------------------------------------------------------------------
# Main Evaluation Orchestration
# ---------------------------------------------------------------------------

def run_evaluation(
    task: int,
    detector_name: str = "static",
    benchmark_dir: Optional[Union[str, Path]] = None,
    output_dir: Optional[Union[str, Path]] = None,
    limit: Optional[int] = None,
    dry_run: bool = False,
    workers: int = 4,
    checkpoint_interval: int = 25,
) -> Tuple[dict[str, Any], Path]:
    """Run the batch evaluation pipeline and write results to output_dir."""
    out_dir = Path(output_dir) if output_dir else Path("./results")
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = out_dir / "checkpoint.jsonl"
    cp_manager = CheckpointManager(checkpoint_path, flush_interval=checkpoint_interval)

    mapper = LabelMapper()
    ast_resolver = ASTResolver()
    detector = EvaluationDetector(detector_name, dry_run=dry_run)

    # 1. Load dataset
    if benchmark_dir is not None and Path(benchmark_dir).exists():
        bench_path = Path(benchmark_dir)
        if task == 1:
            records = load_task1_dataset(bench_path)
        else:
            records = load_task2_dataset(bench_path)
    elif dry_run:
        records = [
            BenchmarkRecord(
                app_name="SampleApp",
                repo_url="https://github.com/sample/app",
                commit_id="commit1",
                violated_article=[32] if task == 2 else 32,
                code_snippet_path="Sample.java:5-10",
                code_snippet="public class Sample { void test() {} }",
                file_path="Sample.java",
                start_line=5,
                end_line=10,
            )
        ]
    else:
        raise FileNotFoundError(f"Benchmark directory does not exist: {benchmark_dir}")

    if limit is not None and limit > 0:
        records = records[:limit]

    logger.info("Loaded %d records for Task %d (limit=%s)", len(records), task, limit)

    # 2. Filter out already checkpointed records
    pending_items: List[Tuple[int, BenchmarkRecord, str]] = []
    for idx, r in enumerate(records):
        key = f"{r.app_name}::{r.commit_id}::{r.code_snippet_path}::{idx}"
        if key not in cp_manager.completed_keys:
            pending_items.append((idx, r, key))

    logger.info("%d items pending execution (%d already completed)", len(pending_items), len(cp_manager.completed_keys))

    # 3. Process pending items with thread pool
    if pending_items:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_key = {}
            for idx, r, key in pending_items:
                if task == 1:
                    future = executor.submit(evaluate_task1_instance, r, detector, mapper, ast_resolver)
                else:
                    future = executor.submit(evaluate_task2_instance, r, detector, mapper)
                future_to_key[future] = (idx, key)

            for future in as_completed(future_to_key):
                idx, key = future_to_key[future]
                try:
                    res = future.result()
                    cp_manager.record_completed(key, res)
                except Exception as exc:
                    logger.error("Error evaluating item index %d (%s): %s", idx, key, exc)

        cp_manager.flush()

    # 4. Gather all completed records and compute final metrics
    all_completed = cp_manager.get_all_records()

    if task == 1:
        file_ranks = [r.get("rank_file") for r in all_completed]
        module_ranks = [r.get("rank_module") for r in all_completed]
        line_ranks = [r.get("rank_line") for r in all_completed]
        task1_metrics = compute_task1_metrics(file_ranks, module_ranks, line_ranks)
        metrics_dict = task1_metrics.to_dict()
    else:
        predictions = [r.get("predicted", []) for r in all_completed]
        ground_truths = [r.get("ground_truth", []) for r in all_completed]
        task2_metrics = compute_multilabel_metrics(predictions, ground_truths)
        metrics_dict = task2_metrics.to_dict()

    # Add unmapped labels report
    metrics_dict["unmapped_summary"] = mapper.get_unmapped_summary()
    metrics_dict["evaluation_config"] = {
        "task": task,
        "detector": detector_name,
        "benchmark_dir": str(benchmark_dir),
        "output_dir": str(output_dir),
        "limit": limit,
        "dry_run": dry_run,
        "total_evaluated": len(all_completed),
    }

    # 5. Write final output files
    metrics_file = output_dir / "metrics.json"
    metrics_file.write_text(json.dumps(metrics_dict, indent=2), encoding="utf-8")

    predictions_file = output_dir / "predictions.json"
    predictions_file.write_text(json.dumps(all_completed, indent=2), encoding="utf-8")

    return metrics_dict, metrics_file


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GDPR-Bench-Android Adapter & Batch Evaluation Runner"
    )
    parser.add_argument(
        "--task",
        type=int,
        choices=[1, 2],
        required=True,
        help="Evaluation task: 1 (localization) or 2 (multi-label classification)",
    )
    parser.add_argument(
        "--detector",
        type=str,
        choices=["static", "llm", "both"],
        default="static",
        help="Detector to evaluate: 'static', 'llm', or 'both' (default: static)",
    )
    parser.add_argument(
        "--benchmark-dir",
        type=str,
        default=None,
        help="Directory containing benchmark dataset files",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./results",
        help="Directory where predictions, checkpoints, and metrics are written (default: ./results)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit evaluation to first N items",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without invoking detectors or external APIs",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent workers (default: 4)",
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=int,
        default=25,
        help="Flush checkpoint every N items (default: 25)",
    )
    return parser.parse_args(args)


def main(args: Optional[List[str]] = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    cli_args = parse_args(args)

    benchmark_dir = Path(cli_args.benchmark_dir) if cli_args.benchmark_dir else None
    output_dir = Path(cli_args.output_dir) if cli_args.output_dir else Path("./results")

    metrics_dict, metrics_file = run_evaluation(
        task=cli_args.task,
        detector_name=cli_args.detector,
        benchmark_dir=benchmark_dir,
        output_dir=output_dir,
        limit=cli_args.limit,
        dry_run=cli_args.dry_run,
        workers=cli_args.workers,
        checkpoint_interval=cli_args.checkpoint_interval,
    )

    print("\n" + "=" * 60)
    print(f"GDPR-Bench Evaluation Complete — Task {cli_args.task} ({cli_args.detector})")
    print("=" * 60)
    print(json.dumps(metrics_dict, indent=2))
    print(f"\nMetrics written to: {metrics_file}")


if __name__ == "__main__":
    main()
