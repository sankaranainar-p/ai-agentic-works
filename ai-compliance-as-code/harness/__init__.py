"""
harness — Evaluation and CLI runner harness for compliance detectors.
"""

from harness.ast_resolver import ASTNodeInfo, ASTResolver
from harness.label_mapper import (
    BenchmarkRecord,
    LabelMapper,
    load_dataset,
    load_task1_dataset,
    load_task2_dataset,
    parse_code_snippet_path,
)
def __getattr__(name: str):
    if name in {
        "ComplementarityEngine",
        "ComplementarityMetrics",
        "ContingencyCellCounts",
        "DisagreementModelResult",
        "FeatureModelStats",
        "align_detector_runs",
        "benjamini_hochberg",
        "compute_contingency_cells",
        "fit_disagreement_model",
        "run_complementarity_analysis",
    }:
        from harness import complementarity
        return getattr(complementarity, name)
    if name in {
        "ArbitrationBenchmarkMetrics",
        "PolicyEvaluationResult",
        "compute_wilson_ci",
        "generate_pareto_frontier",
        "run_arbitration_benchmark",
        "run_nested_cross_validation",
    }:
        from harness import arbitration_bench
        return getattr(arbitration_bench, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


from harness.metrics import (
    CalibrationBin,
    CalibrationReport,
    MultiLabelMetrics,
    Task1Metrics,
    compute_accuracy_at_k,
    compute_accuracy_at_k_range,
    compute_calibration_analysis,
    compute_multilabel_metrics,
    compute_task1_metrics,
)

__all__ = [
    "ASTNodeInfo",
    "ASTResolver",
    "ArbitrationBenchmarkMetrics",
    "BenchmarkRecord",
    "CalibrationBin",
    "CalibrationReport",
    "ComplementarityEngine",
    "ComplementarityMetrics",
    "ContingencyCellCounts",
    "DisagreementModelResult",
    "FeatureModelStats",
    "LabelMapper",
    "MultiLabelMetrics",
    "PolicyEvaluationResult",
    "Task1Metrics",
    "align_detector_runs",
    "benjamini_hochberg",
    "compute_accuracy_at_k",
    "compute_accuracy_at_k_range",
    "compute_calibration_analysis",
    "compute_contingency_cells",
    "compute_multilabel_metrics",
    "compute_task1_metrics",
    "compute_wilson_ci",
    "fit_disagreement_model",
    "generate_pareto_frontier",
    "load_dataset",
    "load_task1_dataset",
    "load_task2_dataset",
    "parse_code_snippet_path",
    "run_arbitration_benchmark",
    "run_complementarity_analysis",
    "run_nested_cross_validation",
]
