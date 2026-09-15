"""
harness/arbitration_bench.py — Offline Simulation & Nested Cross-Validation Harness (Contribution C2).

Evaluates four arbitration policies:
  1. Policy 1: FixedConfidenceMerge (Baseline)
  2. Policy 2: OracleUpperBound (Theoretical clairvoyant ceiling)
  3. Policy 3: LearnedFeatureRouter (Phase 2 feature routing)
  4. Policy 4: CostSensitiveRejectRouter (Chow-type reject option under asymmetric costs)

Implements:
  - 5 x 3 Nested Cross-Validation (outer 5-fold for unbiased risk/Macro-F1;
    inner 3-fold for threshold tau grid-search over [0.1, 0.9]).
  - Wilson 95% Confidence Intervals across out-of-fold decisions.
  - Paired McNemar's test and Wilcoxon signed-rank test comparing Policy 4 against Policy 1.
  - Pareto frontier coordinates trading off Macro-F1 against normalized operational cost.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
import scipy.stats as stats
from sklearn.model_selection import KFold

# Bootstrap project root
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from arbitration.cost_router import (
    DEFAULT_ROUTER_WEIGHTS,
    CostSensitiveRejectRouter,
    LearnedFeatureRouter,
    RoutingDecision,
    extract_runtime_features,
)
from arbitration.fixed_confidence import FixedConfidenceMerge
from harness.complementarity import (
    align_detector_runs,
    load_records,
)
from harness.metrics import compute_multilabel_metrics

logger = logging.getLogger("harness.arbitration_bench")


# ---------------------------------------------------------------------------
# Wilson 95% Confidence Interval
# ---------------------------------------------------------------------------

def compute_wilson_ci(k: int, n: int, z: float = 1.95996398) -> Tuple[float, float]:
    """Calculate Wilson score interval for a proportion k/n."""
    if n <= 0:
        return 0.0, 0.0
    if k <= 0:
        denom = 1.0 + (z ** 2) / n
        upper = (z ** 2 / n) / denom
        return 0.0, float(min(1.0, upper))
    if k >= n:
        denom = 1.0 + (z ** 2) / n
        lower = 1.0 / denom
        return float(max(0.0, lower)), 1.0

    p = float(k) / float(n)
    denom = 1.0 + (z ** 2) / n
    center = (p + (z ** 2) / (2.0 * n)) / denom
    margin = (z * math.sqrt((p * (1.0 - p) / n) + ((z ** 2) / (4.0 * (n ** 2))))) / denom
    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return float(lower), float(upper)



# ---------------------------------------------------------------------------
# Evaluation Data Structures
# ---------------------------------------------------------------------------

@dataclass
class PolicyEvaluationResult:
    """Out-of-fold evaluation summary for an arbitration policy."""

    name: str
    accuracy: float
    accuracy_ci_95: Tuple[float, float]
    macro_f1: float
    mean_cost: float
    cost_std: float
    abstention_rate: float
    symbolic_routing_rate: float
    neural_routing_rate: float
    predictions: List[List[int]] = field(default_factory=list)
    costs: List[float] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "accuracy": round(self.accuracy, 4),
            "accuracy_ci_95": [round(self.accuracy_ci_95[0], 4), round(self.accuracy_ci_95[1], 4)],
            "macro_f1": round(self.macro_f1, 4),
            "mean_cost": round(self.mean_cost, 4),
            "cost_std": round(self.cost_std, 4),
            "abstention_rate": round(self.abstention_rate, 4),
            "symbolic_routing_rate": round(self.symbolic_routing_rate, 4),
            "neural_routing_rate": round(self.neural_routing_rate, 4),
        }


@dataclass
class ArbitrationBenchmarkMetrics:
    """Full benchmark results including nested CV, hypothesis tests, and Pareto frontier."""

    num_instances: int
    policies: Dict[str, PolicyEvaluationResult]
    mcnemar_stat: float
    mcnemar_p_value: float
    wilcoxon_stat: float
    wilcoxon_p_value: float
    best_tau: float
    pareto_frontier: List[Dict[str, float]]
    markdown_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "num_instances": self.num_instances,
            "policies": {k: v.to_dict() for k, v in self.policies.items()},
            "hypothesis_testing": {
                "mcnemar": {
                    "statistic": round(self.mcnemar_stat, 4),
                    "p_value": round(self.mcnemar_p_value, 6),
                    "comparison": "Policy 4 (CostSensitiveReject) vs Policy 1 (FixedConfidenceMerge)",
                },
                "wilcoxon": {
                    "statistic": round(self.wilcoxon_stat, 4),
                    "p_value": round(self.wilcoxon_p_value, 6),
                    "comparison": "Policy 4 (CostSensitiveReject) vs Policy 1 (FixedConfidenceMerge)",
                },
            },
            "nested_cv": {
                "best_tau": round(self.best_tau, 4),
                "grid": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
            },
            "pareto_frontier": self.pareto_frontier,
            "summary_table_markdown": self.markdown_summary,
        }


# ---------------------------------------------------------------------------
# Per-Instance Evaluation Helpers
# ---------------------------------------------------------------------------

def calculate_instance_loss(
    predicted: Sequence[int],
    ground_truth: Sequence[int],
    c_fn: float = 1.0,
    c_fp: float = 0.1,
) -> float:
    """Calculate regulatory compliance error loss between predicted and ground truth sets."""
    p_set = set(predicted)
    g_set = set(ground_truth)

    fn_count = len(g_set - p_set)
    fp_count = len(p_set - g_set)

    return (fn_count * c_fn) + (fp_count * c_fp)


def simulate_oracle_instance(
    rec: Dict[str, Any],
    c_fn: float = 1.0,
    c_fp: float = 0.1,
    c_h: float = 0.25,
    c_l: float = 0.01,
    c_s: float = 0.0,
    epsilon_h: float = 0.02,
) -> Tuple[List[int], float, str]:
    """Evaluate clairvoyant Oracle Upper Bound on an instance."""
    gt = rec.get("ground_truth", [])
    s_pred = rec.get("static_record", {}).get("predicted", [])
    l_pred = rec.get("llm_record", {}).get("predicted", [])

    s_loss = c_s + calculate_instance_loss(s_pred, gt, c_fn=c_fn, c_fp=c_fp)
    l_loss = c_l + calculate_instance_loss(l_pred, gt, c_fn=c_fn, c_fp=c_fp)
    h_loss = c_h + (epsilon_h * ((c_fn + c_fp) / 2.0))

    best_loss = min(s_loss, l_loss, h_loss)

    if best_loss == s_loss:
        return list(s_pred), s_loss, "symbolic"
    elif best_loss == l_loss:
        return list(l_pred), l_loss, "neural"
    else:
        # Human resolves with probability 1 - epsilon_h
        return list(gt), h_loss, "abstain"


def evaluate_policy_predictions(
    predictions: Sequence[Sequence[int]],
    ground_truths: Sequence[Sequence[int]],
    costs: Sequence[float],
    actions: Sequence[str],
    policy_name: str,
) -> PolicyEvaluationResult:
    """Compute aggregate accuracy, macro F1, and cost distributions."""
    n = len(ground_truths)
    if n == 0:
        return PolicyEvaluationResult(
            name=policy_name,
            accuracy=0.0,
            accuracy_ci_95=(0.0, 0.0),
            macro_f1=0.0,
            mean_cost=0.0,
            cost_std=0.0,
            abstention_rate=0.0,
            symbolic_routing_rate=0.0,
            neural_routing_rate=0.0,
        )

    exact_matches = sum(1 for p, g in zip(predictions, ground_truths) if set(p) == set(g))
    acc = float(exact_matches) / float(n)
    acc_ci = compute_wilson_ci(exact_matches, n)

    f1_res = compute_multilabel_metrics(predictions, ground_truths)
    macro_f1 = f1_res.macro_f1

    cost_arr = np.array(costs, dtype=float)
    mean_cost = float(np.mean(cost_arr))
    cost_std = float(np.std(cost_arr))

    abstain_count = sum(1 for a in actions if a == "abstain")
    sym_count = sum(1 for a in actions if a == "symbolic")
    neu_count = sum(1 for a in actions if a == "neural")

    return PolicyEvaluationResult(
        name=policy_name,
        accuracy=acc,
        accuracy_ci_95=acc_ci,
        macro_f1=macro_f1,
        mean_cost=mean_cost,
        cost_std=cost_std,
        abstention_rate=float(abstain_count) / float(n),
        symbolic_routing_rate=float(sym_count) / float(n),
        neural_routing_rate=float(neu_count) / float(n),
        predictions=[list(p) for p in predictions],
        costs=list(costs),
        actions=list(actions),
    )


# ---------------------------------------------------------------------------
# Nested Cross-Validation Engine
# ---------------------------------------------------------------------------

def run_nested_cross_validation(
    aligned_records: List[Dict[str, Any]],
    outer_folds: int = 5,
    inner_folds: int = 3,
    tau_grid: Sequence[float] = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9),
    c_fn: float = 1.0,
    c_fp: float = 0.1,
    c_h: float = 0.25,
    c_l: float = 0.01,
    c_s: float = 0.0,
    epsilon_h: float = 0.02,
) -> Tuple[Dict[str, PolicyEvaluationResult], float]:
    """Execute 5x3 Nested Cross-Validation to evaluate Policy 1-4 without data leakage."""
    n = len(aligned_records)
    if n == 0:
        raise ValueError("Cannot run cross-validation on empty dataset.")

    outer_k = min(outer_folds, n)
    if outer_k < 2:
        # Fallback to single split if dataset too small
        outer_k = 2

    kf_outer = KFold(n_splits=outer_k, shuffle=True, random_state=42)

    # Accumulators for out-of-fold decisions
    oof_data: Dict[str, Dict[str, List[Any]]] = {
        "Policy 1 (Baseline)": {"preds": [], "costs": [], "actions": []},
        "Policy 2 (Oracle)": {"preds": [], "costs": [], "actions": []},
        "Policy 3 (Learned)": {"preds": [], "costs": [], "actions": []},
        "Policy 4 (CostReject)": {"preds": [], "costs": [], "actions": []},
    }

    selected_taus: List[float] = []

    # Map records to list for indexing
    records_arr = list(aligned_records)

    for fold_idx, (train_idx, test_idx) in enumerate(kf_outer.split(records_arr)):
        train_records = [records_arr[i] for i in train_idx]
        test_records = [records_arr[i] for i in test_idx]

        # Inner CV on train_records to tune threshold tau for Policy 4
        best_tau = c_h
        if len(train_records) >= inner_folds and inner_folds >= 2:
            kf_inner = KFold(n_splits=inner_folds, shuffle=True, random_state=fold_idx)
            tau_scores: Dict[float, List[float]] = {t: [] for t in tau_grid}

            for in_tr_idx, in_val_idx in kf_inner.split(train_records):
                in_val = [train_records[i] for i in in_val_idx]
                for t in tau_grid:
                    router = CostSensitiveRejectRouter(
                        c_fn=c_fn, c_fp=c_fp, c_h=t, c_l=c_l, c_s=c_s, epsilon_h=epsilon_h, tau=t
                    )
                    t_costs = []
                    for r in in_val:
                        s_preds = r.get("static_record", {}).get("predicted", [])
                        l_preds = r.get("llm_record", {}).get("predicted", [])
                        gt = r.get("ground_truth", [])

                        features = extract_runtime_features(record=r)
                        rs, rl, rh, _ = router.compute_risks(
                            static_findings=[{"rule_id": str(p)} for p in s_preds],  # type: ignore
                            llm_findings=[{"rule_id": str(p)} for p in l_preds],  # type: ignore
                            features=features,
                        )
                        if min(rs, rl) >= rh:
                            t_costs.append(rh)
                        elif rs < rl:
                            t_costs.append(c_s + calculate_instance_loss(s_preds, gt, c_fn, c_fp))
                        else:
                            t_costs.append(c_l + calculate_instance_loss(l_preds, gt, c_fn, c_fp))
                    tau_scores[t].append(float(np.mean(t_costs)))

            # Select tau with lowest inner validation cost
            mean_tau_scores = {t: float(np.mean(scores)) for t, scores in tau_scores.items() if scores}
            if mean_tau_scores:
                best_tau = min(mean_tau_scores, key=mean_tau_scores.get)

        selected_taus.append(best_tau)

        # Initialize policy routers
        p3_router = LearnedFeatureRouter()
        p4_router = CostSensitiveRejectRouter(
            c_fn=c_fn, c_fp=c_fp, c_h=best_tau, c_l=c_l, c_s=c_s, epsilon_h=epsilon_h, tau=best_tau
        )

        # Evaluate on outer test fold
        for r in test_records:
            gt = r.get("ground_truth", [])
            s_preds = r.get("static_record", {}).get("predicted", [])
            l_preds = r.get("llm_record", {}).get("predicted", [])
            features = extract_runtime_features(record=r)

            # Policy 1: FixedConfidenceMerge Baseline
            # Always combines/runs both
            p1_pred = sorted(list(set(s_preds) | set(l_preds))) if l_preds else list(s_preds)
            p1_loss = c_s + c_l + calculate_instance_loss(p1_pred, gt, c_fn=c_fn, c_fp=c_fp)
            oof_data["Policy 1 (Baseline)"]["preds"].append(p1_pred)
            oof_data["Policy 1 (Baseline)"]["costs"].append(p1_loss)
            oof_data["Policy 1 (Baseline)"]["actions"].append("combined")

            # Policy 2: Oracle Upper Bound
            p2_pred, p2_loss, p2_act = simulate_oracle_instance(
                r, c_fn=c_fn, c_fp=c_fp, c_h=c_h, c_l=c_l, c_s=c_s, epsilon_h=epsilon_h
            )
            oof_data["Policy 2 (Oracle)"]["preds"].append(p2_pred)
            oof_data["Policy 2 (Oracle)"]["costs"].append(p2_loss)
            oof_data["Policy 2 (Oracle)"]["actions"].append(p2_act)

            # Policy 3: LearnedFeatureRouter
            prob_s = p3_router.weights.get("Intercept", 0.0)
            for fname, val in features.items():
                prob_s += p3_router.weights.get(fname, 0.0) * val
            prob_s_sig = 1.0 / (1.0 + math.exp(-max(-35.0, min(35.0, prob_s))))

            if set(s_preds) == set(l_preds):
                p3_pred = list(s_preds)
                p3_loss = c_s + calculate_instance_loss(p3_pred, gt, c_fn, c_fp)
                p3_act = "symbolic"
            elif prob_s_sig >= 0.5:
                p3_pred = list(s_preds)
                p3_loss = c_s + calculate_instance_loss(p3_pred, gt, c_fn, c_fp)
                p3_act = "symbolic"
            else:
                p3_pred = list(l_preds)
                p3_loss = c_l + calculate_instance_loss(p3_pred, gt, c_fn, c_fp)
                p3_act = "neural"

            oof_data["Policy 3 (Learned)"]["preds"].append(p3_pred)
            oof_data["Policy 3 (Learned)"]["costs"].append(p3_loss)
            oof_data["Policy 3 (Learned)"]["actions"].append(p3_act)

            # Policy 4: CostSensitiveRejectRouter
            rs, rl, rh, _ = p4_router.compute_risks(
                static_findings=[{"rule_id": str(p)} for p in s_preds],  # type: ignore
                llm_findings=[{"rule_id": str(p)} for p in l_preds],  # type: ignore
                features=features,
            )

            if min(rs, rl) >= rh:
                p4_pred = list(gt) if np.random.rand() >= epsilon_h else ([99] if 99 not in gt else [98])
                p4_loss = rh
                p4_act = "abstain"
            elif rs < rl:
                p4_pred = list(s_preds)
                p4_loss = c_s + calculate_instance_loss(p4_pred, gt, c_fn, c_fp)
                p4_act = "symbolic"
            else:
                p4_pred = list(l_preds)
                p4_loss = c_l + calculate_instance_loss(p4_pred, gt, c_fn, c_fp)
                p4_act = "neural"

            oof_data["Policy 4 (CostReject)"]["preds"].append(p4_pred)
            oof_data["Policy 4 (CostReject)"]["costs"].append(p4_loss)
            oof_data["Policy 4 (CostReject)"]["actions"].append(p4_act)

    all_gts = [r.get("ground_truth", []) for r in records_arr]
    results: Dict[str, PolicyEvaluationResult] = {}
    for name, data in oof_data.items():
        results[name] = evaluate_policy_predictions(
            predictions=data["preds"],
            ground_truths=all_gts,
            costs=data["costs"],
            actions=data["actions"],
            policy_name=name,
        )

    median_best_tau = float(np.median(selected_taus)) if selected_taus else c_h
    return results, median_best_tau


# ---------------------------------------------------------------------------
# Hypothesis Testing & Pareto Frontier
# ---------------------------------------------------------------------------

def compute_hypothesis_tests(
    p4_preds: Sequence[Sequence[int]],
    p1_preds: Sequence[Sequence[int]],
    p4_costs: Sequence[float],
    p1_costs: Sequence[float],
    ground_truths: Sequence[Sequence[int]],
) -> Tuple[float, float, float, float]:
    """Execute paired McNemar's test and Wilcoxon signed-rank test."""
    n = len(ground_truths)
    if n == 0:
        return 0.0, 1.0, 0.0, 1.0

    p4_correct = [set(p) == set(g) for p, g in zip(p4_preds, ground_truths)]
    p1_correct = [set(p) == set(g) for p, g in zip(p1_preds, ground_truths)]

    # McNemar 2x2 contingency:
    # b: p1 incorrect, p4 correct
    # c: p1 correct, p4 incorrect
    b = sum(1 for c4, c1 in zip(p4_correct, p1_correct) if c4 and not c1)
    c = sum(1 for c4, c1 in zip(p4_correct, p1_correct) if not c4 and c1)

    if (b + c) > 0:
        chi2 = float((abs(b - c) - 1.0) ** 2) / float(b + c)
        mcnemar_p = float(stats.chi2.sf(chi2, df=1))
    else:
        chi2 = 0.0
        mcnemar_p = 1.0

    # Wilcoxon signed-rank test on cost differences
    diffs = np.array(p1_costs) - np.array(p4_costs)
    nonzero_diffs = diffs[diffs != 0]

    if len(nonzero_diffs) >= 5:
        try:
            res = stats.wilcoxon(p1_costs, p4_costs, alternative="two-sided")
            wilcoxon_stat = float(res.statistic)
            wilcoxon_p = float(res.pvalue)
        except Exception:
            wilcoxon_stat = 0.0
            wilcoxon_p = 1.0
    else:
        wilcoxon_stat = float(np.sum(diffs > 0))
        wilcoxon_p = 1.0

    return chi2, mcnemar_p, wilcoxon_stat, wilcoxon_p


def generate_pareto_frontier(
    aligned_records: List[Dict[str, Any]],
    policy_results: Dict[str, PolicyEvaluationResult],
    c_fn: float = 1.0,
    c_fp: float = 0.1,
    c_l: float = 0.01,
    c_s: float = 0.0,
    epsilon_h: float = 0.02,
) -> List[Dict[str, float]]:
    """Compute trade-off coordinates (Mean Cost vs Macro-F1) across swept tau thresholds."""
    all_gts = [r.get("ground_truth", []) for r in aligned_records]
    candidate_points: List[Dict[str, Any]] = []

    # Sweep Policy 4 over a dense threshold grid
    for tau in np.linspace(0.05, 0.95, 19):
        router = CostSensitiveRejectRouter(
            c_fn=c_fn, c_fp=c_fp, c_h=tau, c_l=c_l, c_s=c_s, epsilon_h=epsilon_h, tau=tau
        )
        preds = []
        costs = []
        for r in aligned_records:
            gt = r.get("ground_truth", [])
            s_preds = r.get("static_record", {}).get("predicted", [])
            l_preds = r.get("llm_record", {}).get("predicted", [])
            features = extract_runtime_features(record=r)
            rs, rl, rh, _ = router.compute_risks(
                static_findings=[{"rule_id": str(p)} for p in s_preds],  # type: ignore
                llm_findings=[{"rule_id": str(p)} for p in l_preds],  # type: ignore
                features=features,
            )
            if min(rs, rl) >= rh:
                preds.append(gt)
                costs.append(rh)
            elif rs < rl:
                preds.append(s_preds)
                costs.append(c_s + calculate_instance_loss(s_preds, gt, c_fn, c_fp))
            else:
                preds.append(l_preds)
                costs.append(c_l + calculate_instance_loss(l_preds, gt, c_fn, c_fp))

        f1 = compute_multilabel_metrics(preds, all_gts).macro_f1
        mean_c = float(np.mean(costs))
        candidate_points.append({
            "label": f"Policy 4 (tau={tau:.2f})",
            "cost": round(mean_c, 4),
            "macro_f1": round(f1, 4),
        })

    # Add other policies
    for name, res in policy_results.items():
        candidate_points.append({
            "label": name,
            "cost": round(res.mean_cost, 4),
            "macro_f1": round(res.macro_f1, 4),
        })

    # Filter non-dominated Pareto optimal points (lower cost is better, higher f1 is better)
    pareto: List[Dict[str, float]] = []
    for pt in sorted(candidate_points, key=lambda x: (x["cost"], -x["macro_f1"])):
        # Dominated if there is an existing point with <= cost and >= f1
        is_dominated = any(p["cost"] <= pt["cost"] and p["macro_f1"] >= pt["macro_f1"] for p in pareto)
        if not is_dominated:
            pareto.append(pt)

    return sorted(pareto, key=lambda x: x["cost"])


# ---------------------------------------------------------------------------
# Output Summary Generation
# ---------------------------------------------------------------------------

def generate_markdown_summary(
    metrics: ArbitrationBenchmarkMetrics,
) -> str:
    """Render an ASCII/Markdown summary report of arbitration benchmarking."""
    lines: List[str] = []

    lines.append("# Phase 3 Cost-Sensitive Arbitration Benchmark (Contribution C2)")
    lines.append("")
    lines.append(f"- **Evaluated Benchmark Instances (N):** {metrics.num_instances}")
    lines.append(f"- **Optimal Abstention Threshold (tau*):** {metrics.best_tau:.4f}")
    lines.append("")

    lines.append("## 1. Out-of-Fold Policy Performance Comparison (5x3 Nested CV)")
    lines.append("| Policy | Exact-Match Acc | 95% Wilson CI | Macro-F1 | Mean Cost | Cost Std | Abstain % | Symbolic % | Neural % |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

    for name, res in metrics.policies.items():
        ci_str = f"[{res.accuracy_ci_95[0]*100:.1f}%, {res.accuracy_ci_95[1]*100:.1f}%]"
        lines.append(
            f"| **{name}** | {res.accuracy*100:.2f}% | {ci_str} | **{res.macro_f1:.4f}** | "
            f"{res.mean_cost:.4f} | {res.cost_std:.4f} | {res.abstention_rate*100:.1f}% | "
            f"{res.symbolic_routing_rate*100:.1f}% | {res.neural_routing_rate*100:.1f}% |"
        )
    lines.append("")

    lines.append("## 2. Statistical Significance Testing (Policy 4 vs Policy 1)")
    lines.append(f"- **McNemar's Chi-Square Test:** chi2 = {metrics.mcnemar_stat:.4f}, p = {metrics.mcnemar_p_value:.4e}")
    lines.append(f"- **Wilcoxon Signed-Rank Test:** W = {metrics.wilcoxon_stat:.4f}, p = {metrics.wilcoxon_p_value:.4e}")
    if metrics.wilcoxon_p_value < 0.05:
        lines.append("  *(Statistically significant cost reduction at alpha = 0.05)*")
    lines.append("")

    lines.append("## 3. Pareto Frontier Coordinates (Normalized Cost vs Macro-F1)")
    lines.append("| Policy Configuration | Normalized Cost | Macro-F1 |")
    lines.append("| :--- | :---: | :---: |")
    for pt in metrics.pareto_frontier:
        lines.append(f"| {pt['label']} | {pt['cost']:.4f} | **{pt['macro_f1']:.4f}** |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Runner Execution Orchestration
# ---------------------------------------------------------------------------

def run_arbitration_benchmark(
    static_results: Union[str, Path],
    llm_results: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
    outer_folds: int = 5,
    inner_folds: int = 3,
) -> ArbitrationBenchmarkMetrics:
    """Run full Phase 3 arbitration benchmark pipeline and export results."""
    out_dir = Path(output_dir) if output_dir else Path("results/arbitration")
    out_dir.mkdir(parents=True, exist_ok=True)

    static_recs = load_records(static_results)
    llm_recs = load_records(llm_results)

    aligned, _, _ = align_detector_runs(static_recs, llm_recs)
    if not aligned:
        raise ValueError("No matched instances found between static and LLM results.")

    # 1. 5x3 Nested Cross-Validation
    policy_results, best_tau = run_nested_cross_validation(
        aligned,
        outer_folds=outer_folds,
        inner_folds=inner_folds,
    )

    # 2. Statistical hypothesis testing
    p4 = policy_results["Policy 4 (CostReject)"]
    p1 = policy_results["Policy 1 (Baseline)"]
    chi2, mcnemar_p, w_stat, w_p = compute_hypothesis_tests(
        p4_preds=p4.predictions,
        p1_preds=p1.predictions,
        p4_costs=p4.costs,
        p1_costs=p1.costs,
        ground_truths=[r.get("ground_truth", []) for r in aligned],
    )

    # 3. Pareto frontier
    pareto_pts = generate_pareto_frontier(aligned, policy_results)

    benchmark_metrics = ArbitrationBenchmarkMetrics(
        num_instances=len(aligned),
        policies=policy_results,
        mcnemar_stat=chi2,
        mcnemar_p_value=mcnemar_p,
        wilcoxon_stat=w_stat,
        wilcoxon_p_value=w_p,
        best_tau=best_tau,
        pareto_frontier=pareto_pts,
    )

    summary_md = generate_markdown_summary(benchmark_metrics)
    benchmark_metrics.markdown_summary = summary_md

    # 4. Serialize to disk
    json_path = out_dir / "metrics.json"
    json_path.write_text(json.dumps(benchmark_metrics.to_dict(), indent=2), encoding="utf-8")

    md_path = out_dir / "summary.md"
    md_path.write_text(summary_md, encoding="utf-8")

    return benchmark_metrics


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phase 3 Cost-Sensitive Arbitration & Nested CV Benchmark (Contribution C2)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--static-results",
        required=True,
        type=str,
        help="Path to static detector results (file or directory).",
    )
    parser.add_argument(
        "--llm-results",
        required=True,
        type=str,
        help="Path to LLM detector results (file or directory).",
    )
    parser.add_argument(
        "--output-dir",
        default="results/arbitration",
        type=str,
        help="Directory to save metrics.json and summary.md.",
    )
    return parser.parse_args(args)


def main(args: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    cli_args = parse_args(args)

    metrics = run_arbitration_benchmark(
        static_results=cli_args.static_results,
        llm_results=cli_args.llm_results,
        output_dir=cli_args.output_dir,
    )

    print("\n" + metrics.markdown_summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
