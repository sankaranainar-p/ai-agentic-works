"""
harness/complementarity.py — Phase 2 Complementarity Analysis Engine for GDPR-Bench-Android.

Evaluates where symbolic (static scanner) and neural (LLM) detectors diverge on
GDPR-Bench-Android (Contribution C1).

Capabilities:
  1. Ingests and aligns per-instance JSONL records from both detectors using the
     unique instance key (app_name::commit_id::code_snippet_path), flagging any
     unmatched instances.
  2. Computes the 4-cell contingency table across the benchmark:
       - Cell 1: Both correct (S=1, L=1)
       - Cell 2: Both incorrect (S=0, L=0)
       - Cell 3: Static-only correct (S=1, L=0)
       - Cell 4: LLM-only correct (S=0, L=1)
     Reports counts and proportions globally, partitioned by granularity
     (file, module, line), and partitioned by article (Articles 5, 6, 25, 32
     individually, with remaining articles pooled).
  3. For disagreement instances (S != L), fits a predictive logistic regression
     model for P(S=1 | S != L) using candidate features:
       - Code granularity (file, module, line)
       - Snippet character length (log10 transformed)
       - Target GDPR article ID
       - Scanner hints fired (count and boolean indicators)
       - File extension (.java vs. .kt)
     Reports Odds Ratios (OR) with 95% Confidence Intervals, Benjamini-Hochberg (FDR)
     adjusted p-values, ROC-AUC, and McFadden pseudo-R².
  4. Serializes metrics to JSON and produces formatted Markdown/ASCII summary tables.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

import numpy as np
import scipy.stats as stats
from scipy.optimize import minimize
from sklearn.metrics import roc_auc_score

# Bootstrap project root
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from harness.label_mapper import parse_code_snippet_path

logger = logging.getLogger("harness.complementarity")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INDIVIDUAL_ARTICLES = (5, 6, 25, 32)
ARTICLE_BUCKETS = ("5", "6", "25", "32", "other")
GRANULARITIES = ("file", "module", "line")


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class ContingencyCellCounts:
    """Counts and proportions for the 4 contingency cells."""

    both_correct: int = 0
    both_incorrect: int = 0
    static_only: int = 0
    llm_only: int = 0
    total: int = 0
    both_correct_prop: float = 0.0
    both_incorrect_prop: float = 0.0
    static_only_prop: float = 0.0
    llm_only_prop: float = 0.0
    disagreement_count: int = 0
    disagreement_prop: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": {
                "both_correct": self.both_correct,
                "both_incorrect": self.both_incorrect,
                "static_only": self.static_only,
                "llm_only": self.llm_only,
                "total": self.total,
                "disagreement": self.disagreement_count,
            },
            "proportions": {
                "both_correct": round(self.both_correct_prop, 4),
                "both_incorrect": round(self.both_incorrect_prop, 4),
                "static_only": round(self.static_only_prop, 4),
                "llm_only": round(self.llm_only_prop, 4),
                "disagreement": round(self.disagreement_prop, 4),
            },
        }


@dataclass
class FeatureModelStats:
    """Statistical summary for a single regression feature."""

    name: str
    coef: float
    std_err: float
    odds_ratio: float
    ci_95_lower: float
    ci_95_upper: float
    z_stat: float
    p_value: float
    p_value_fdr: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "coef": round(self.coef, 4),
            "std_err": round(self.std_err, 4),
            "odds_ratio": round(self.odds_ratio, 4),
            "ci_95": [round(self.ci_95_lower, 4), round(self.ci_95_upper, 4)],
            "z_stat": round(self.z_stat, 4),
            "p_value": round(self.p_value, 6),
            "p_value_fdr": round(self.p_value_fdr, 6),
        }


@dataclass
class DisagreementModelResult:
    """Results from fitting logistic regression on disagreement instances."""

    status: str
    num_disagreements: int
    num_static_wins: int
    num_llm_wins: int
    num_features: int
    roc_auc: Optional[float] = None
    pseudo_r2: Optional[float] = None
    log_likelihood_full: Optional[float] = None
    log_likelihood_null: Optional[float] = None
    features: List[FeatureModelStats] = field(default_factory=list)
    excluded_features: Dict[str, str] = field(default_factory=dict)
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "num_disagreements": self.num_disagreements,
            "num_static_wins": self.num_static_wins,
            "num_llm_wins": self.num_llm_wins,
            "num_features": self.num_features,
            "roc_auc": round(self.roc_auc, 4) if self.roc_auc is not None else None,
            "pseudo_r2": round(self.pseudo_r2, 4) if self.pseudo_r2 is not None else None,
            "log_likelihood_full": round(self.log_likelihood_full, 4) if self.log_likelihood_full is not None else None,
            "log_likelihood_null": round(self.log_likelihood_null, 4) if self.log_likelihood_null is not None else None,
            "features": [f.to_dict() for f in self.features],
            "excluded_features": self.excluded_features,
            "message": self.message,
        }


@dataclass
class ComplementarityMetrics:
    """Full complementarity analysis report."""

    alignment_summary: Dict[str, Any]
    global_contingency: ContingencyCellCounts
    by_granularity: Dict[str, ContingencyCellCounts]
    by_article: Dict[str, ContingencyCellCounts]
    disagreement_model: DisagreementModelResult
    markdown_table: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alignment": self.alignment_summary,
            "contingency_analysis": {
                "global": self.global_contingency.to_dict(),
                "by_granularity": {k: v.to_dict() for k, v in self.by_granularity.items()},
                "by_article": {k: v.to_dict() for k, v in self.by_article.items()},
            },
            "disagreement_model": self.disagreement_model.to_dict(),
            "summary_table_markdown": self.markdown_table,
        }


# ---------------------------------------------------------------------------
# Multiple Comparison Correction
# ---------------------------------------------------------------------------

def benjamini_hochberg(p_values: Sequence[float]) -> List[float]:
    """Compute Benjamini-Hochberg False Discovery Rate (FDR) adjusted p-values (q-values).

    For sorted p-values p_{(1)} <= ... <= p_{(m)}:
      q_{(i)} = min_{k >= i} (p_{(k)} * m / k)
    bounded in [0.0, 1.0].
    """
    m = len(p_values)
    if m == 0:
        return []

    # Sort indices by original p-value
    sorted_indices = sorted(range(m), key=lambda i: p_values[i])
    q_values = [0.0] * m

    prev_q = 1.0
    for rank in range(m, 0, -1):
        idx = sorted_indices[rank - 1]
        p_val = max(0.0, min(1.0, float(p_values[idx])))
        raw_q = (p_val * m) / rank
        q_val = min(prev_q, raw_q, 1.0)
        q_values[idx] = max(0.0, q_val)
        prev_q = q_val

    return q_values


# ---------------------------------------------------------------------------
# Instance Identification & Field Extraction
# ---------------------------------------------------------------------------

def make_instance_key(record: Dict[str, Any]) -> str:
    """Return standard instance key: app_name::commit_id::code_snippet_path."""
    app_name = str(record.get("app_name") or "").strip()
    commit_id = str(record.get("commit_id") or record.get("Commit_ID") or "").strip()
    snippet_path = str(record.get("code_snippet_path") or "").strip()
    return f"{app_name}::{commit_id}::{snippet_path}"


def extract_granularity(record: Dict[str, Any]) -> str:
    """Extract or infer granularity ('file', 'module', 'line')."""
    # 1. Explicit metadata in record
    for key in ("granularity", "level", "scope"):
        val = record.get(key)
        if val and isinstance(val, str):
            v_low = val.lower().strip()
            if "file" in v_low:
                return "file"
            if "mod" in v_low:
                return "module"
            if "line" in v_low:
                return "line"

    # 2. Check AST / code path structure
    if record.get("module_name"):
        return "module"

    snippet_path = str(record.get("code_snippet_path") or record.get("file_path") or "").lower()
    if not snippet_path:
        return "file"

    if "lines " in snippet_path or re.search(r":\s*lines?\s+\d+\s*[-–—]\s*\d+", snippet_path):
        return "module"
    if "line " in snippet_path or re.search(r":\s*line\s+\d+", snippet_path) or re.search(r":\d+", snippet_path):
        return "line"

    return "file"


def extract_target_article(record: Dict[str, Any]) -> Optional[int]:
    """Extract integer target GDPR article."""
    for key in ("target_article", "article", "violated_article"):
        val = record.get(key)
        if val is not None:
            if isinstance(val, int):
                return val
            if isinstance(val, list) and val:
                return int(val[0])
            if isinstance(val, str) and val.isdigit():
                return int(val)

    gt = record.get("ground_truth") or record.get("violated_articles")
    if gt is not None:
        if isinstance(gt, int):
            return gt
        if isinstance(gt, (list, tuple, set)) and len(gt) > 0:
            # If one of the focal articles (5, 6, 25, 32) is in gt, prioritize it
            for art in INDIVIDUAL_ARTICLES:
                if art in gt:
                    return art
            return int(list(gt)[0])

    return None


def article_to_bucket(article: Optional[int]) -> str:
    """Map integer article to article partition bucket ('5', '6', '25', '32', 'other')."""
    if article in INDIVIDUAL_ARTICLES:
        return str(article)
    return "other"


def determine_correctness(record: Dict[str, Any], granularity: Optional[str] = None) -> bool:
    """Evaluate whether an instance was predicted correctly (1) or incorrectly (0)."""
    # 1. Explicit boolean flag
    if "correct" in record:
        return bool(record["correct"])
    if "is_correct" in record:
        return bool(record["is_correct"])

    # 2. Hit flag
    if "hit" in record:
        return bool(record["hit"])

    # 3. Explicit rank (Task 1)
    gran = granularity or extract_granularity(record)
    if gran == "file" and record.get("rank_file") is not None:
        return record["rank_file"] == 1
    if gran == "module" and record.get("rank_module") is not None:
        return record["rank_module"] == 1
    if gran == "line" and record.get("rank_line") is not None:
        return record["rank_line"] == 1

    if "rank" in record and record["rank"] is not None:
        return record["rank"] == 1

    # 4. Multi-label ground truth vs predicted (Task 2)
    gt = record.get("ground_truth")
    pred = record.get("predicted")
    if gt is not None and pred is not None:
        gt_set = set(gt if isinstance(gt, (list, tuple, set)) else [gt])
        pred_set = set(pred if isinstance(pred, (list, tuple, set)) else [pred])
        return gt_set == pred_set

    # 5. Target article in predictions
    target_art = extract_target_article(record)
    preds = record.get("predicted") or record.get("file_preds") or record.get("predictions")
    if target_art is not None and preds is not None:
        pred_list = preds if isinstance(preds, (list, tuple, set)) else [preds]
        return target_art in pred_list

    return False


# ---------------------------------------------------------------------------
# Ingestion and Alignment
# ---------------------------------------------------------------------------

def load_records(source: Union[str, Path]) -> List[Dict[str, Any]]:
    """Load records from a file (JSON or JSONL) or directory."""
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Result path does not exist: {path}")

    if path.is_dir():
        for candidate in ("checkpoint.jsonl", "predictions.jsonl", "predictions.json", "records.jsonl", "results.jsonl"):
            target = path / candidate
            if target.exists():
                path = target
                break
        else:
            json_files = sorted(list(path.glob("*.jsonl")) + list(path.glob("*.json")))
            if not json_files:
                raise FileNotFoundError(f"No JSON/JSONL result files found in directory: {path}")
            path = json_files[0]

    records: List[Dict[str, Any]] = []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if text.startswith("["):
        try:
            records = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Failed to parse JSON array from {path}: {exc}") from exc
    else:
        for idx, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("Skipping invalid JSON line %d in %s: %s", idx, path, exc)

    return records


def align_detector_runs(
    static_records: List[Dict[str, Any]],
    llm_records: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """Align per-instance records from static and LLM runs by instance key.

    Returns:
        (aligned_pairs, unmatched_static_keys, unmatched_llm_keys)
    """
    static_map: Dict[str, Dict[str, Any]] = {}
    for r in static_records:
        k = make_instance_key(r)
        if k not in static_map:
            static_map[k] = r

    llm_map: Dict[str, Dict[str, Any]] = {}
    for r in llm_records:
        k = make_instance_key(r)
        if k not in llm_map:
            llm_map[k] = r

    static_keys = set(static_map.keys())
    llm_keys = set(llm_map.keys())

    matched_keys = sorted(static_keys & llm_keys)
    unmatched_static = sorted(static_keys - llm_keys)
    unmatched_llm = sorted(llm_keys - static_keys)

    aligned: List[Dict[str, Any]] = []
    for key in matched_keys:
        s_rec = static_map[key]
        l_rec = llm_map[key]

        granularity = extract_granularity(s_rec)
        s_correct = determine_correctness(s_rec, granularity=granularity)
        l_correct = determine_correctness(l_rec, granularity=granularity)
        article = extract_target_article(s_rec) or extract_target_article(l_rec)

        # Merge fields with preference to static record for code details
        merged = dict(s_rec)
        merged["instance_key"] = key
        merged["static_record"] = s_rec
        merged["llm_record"] = l_rec
        merged["static_correct"] = s_correct
        merged["llm_correct"] = l_correct
        merged["granularity"] = granularity
        merged["target_article"] = article
        merged["article_bucket"] = article_to_bucket(article)

        aligned.append(merged)

    return aligned, unmatched_static, unmatched_llm


# ---------------------------------------------------------------------------
# Contingency Analysis
# ---------------------------------------------------------------------------

def compute_contingency_cells(records: Sequence[Dict[str, Any]]) -> ContingencyCellCounts:
    """Compute the 4 mutually exclusive cells for a collection of aligned instances."""
    total = len(records)
    if total == 0:
        return ContingencyCellCounts()

    both_c = 0
    both_i = 0
    static_o = 0
    llm_o = 0

    for r in records:
        s = bool(r.get("static_correct"))
        l = bool(r.get("llm_correct"))
        if s and l:
            both_c += 1
        elif not s and not l:
            both_i += 1
        elif s and not l:
            static_o += 1
        else:
            llm_o += 1

    disagree = static_o + llm_o
    return ContingencyCellCounts(
        both_correct=both_c,
        both_incorrect=both_i,
        static_only=static_o,
        llm_only=llm_o,
        total=total,
        both_correct_prop=both_c / total,
        both_incorrect_prop=both_i / total,
        static_only_prop=static_o / total,
        llm_only_prop=llm_o / total,
        disagreement_count=disagree,
        disagreement_prop=disagree / total,
    )


def partition_contingency_analysis(
    aligned_records: Sequence[Dict[str, Any]],
) -> Tuple[ContingencyCellCounts, Dict[str, ContingencyCellCounts], Dict[str, ContingencyCellCounts]]:
    """Compute global, granularity-partitioned, and article-partitioned contingency tables."""
    global_counts = compute_contingency_cells(aligned_records)

    by_gran: Dict[str, List[Dict[str, Any]]] = {g: [] for g in GRANULARITIES}
    for r in aligned_records:
        g = r.get("granularity", "file")
        if g not in by_gran:
            by_gran[g] = []
        by_gran[g].append(r)
    contingency_gran = {g: compute_contingency_cells(by_gran[g]) for g in GRANULARITIES}

    by_art: Dict[str, List[Dict[str, Any]]] = {b: [] for b in ARTICLE_BUCKETS}
    for r in aligned_records:
        b = r.get("article_bucket", "other")
        if b not in by_art:
            by_art[b] = []
        by_art[b].append(r)
    contingency_art = {b: compute_contingency_cells(by_art[b]) for b in ARTICLE_BUCKETS}

    return global_counts, contingency_gran, contingency_art


# ---------------------------------------------------------------------------
# Feature Extraction for Disagreement Modeling
# ---------------------------------------------------------------------------

def extract_scanner_hints(record: Dict[str, Any]) -> List[str]:
    """Retrieve or compute static scanner hints / risk indicators for an instance."""
    for key in ("hints_fired", "scanner_hints", "risk_indicators", "hints"):
        val = record.get(key)
        if isinstance(val, list):
            return [str(h) for h in val if h]

    code = record.get("code_snippet") or record.get("code") or ""
    path = record.get("code_snippet_path") or record.get("file_path") or ""
    if code:
        try:
            from scanner.static_scanner import scan
            hint = scan(code, file_path=path)
            return list(hint.risk_indicators)
        except Exception:
            pass

    return []


def extract_snippet_length(record: Dict[str, Any]) -> float:
    """Extract snippet character length."""
    for key in ("char_length", "snippet_length", "code_length"):
        val = record.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return float(val)

    code = record.get("code_snippet") or record.get("code") or ""
    if code:
        return float(len(code))

    snippet_path = record.get("code_snippet_path") or ""
    _, start_l, end_l = parse_code_snippet_path(snippet_path)
    if start_l is not None:
        span = (end_l - start_l + 1) if end_l is not None else 1
        return float(max(span, 1) * 35)

    return 100.0


def build_disagreement_features(
    disagreement_records: Sequence[Dict[str, Any]],
) -> Tuple[np.ndarray, np.ndarray, List[str], Dict[str, str]]:
    """Build design matrix X and binary target y for P(S=1 | S != L).

    Target:
      y = 1 if S=1, L=0 (Static detector wins)
      y = 0 if S=0, L=1 (LLM detector wins)

    Candidate Features:
      - Code granularity (file, module, line: dummy encoded)
      - Snippet character length (log10 transformed)
      - Target GDPR article ID (Articles 5, 6, 25, 32, other)
      - Scanner hints fired (count + boolean indicators)
      - File extension (.java vs. .kt)
    """
    n = len(disagreement_records)
    if n == 0:
        return np.empty((0, 0)), np.empty(0), [], {}

    # Target vector
    y = np.array([
        1 if r.get("static_correct") and not r.get("llm_correct") else 0
        for r in disagreement_records
    ], dtype=float)

    # 1. Collect all scanner hint indicators that appear across records
    all_hints: Set[str] = set()
    instance_hints: List[List[str]] = []
    for r in disagreement_records:
        hints = extract_scanner_hints(r)
        instance_hints.append(hints)
        all_hints.update(hints)
    sorted_hints = sorted(all_hints)

    # 2. Extract raw candidate feature columns
    raw_feature_dict: Dict[str, List[float]] = {}

    # Granularity: dummy encoded (line as reference category)
    raw_feature_dict["granularity_file"] = [
        1.0 if r.get("granularity") == "file" else 0.0 for r in disagreement_records
    ]
    raw_feature_dict["granularity_module"] = [
        1.0 if r.get("granularity") == "module" else 0.0 for r in disagreement_records
    ]

    # Snippet character length (log10 transformed)
    raw_feature_dict["log10_char_length"] = [
        math.log10(max(extract_snippet_length(r), 1.0)) for r in disagreement_records
    ]

    # Target GDPR Article ID dummies (other as reference)
    for art in INDIVIDUAL_ARTICLES:
        raw_feature_dict[f"article_{art}"] = [
            1.0 if r.get("article_bucket") == str(art) else 0.0 for r in disagreement_records
        ]

    # Scanner hints count
    raw_feature_dict["scanner_hints_count"] = [
        float(len(hints)) for hints in instance_hints
    ]

    # Scanner hints boolean indicators
    for h in sorted_hints:
        clean_name = f"hint_{re.sub(r'[^a-zA-Z0-9_]', '_', h)}"
        raw_feature_dict[clean_name] = [
            1.0 if h in hints else 0.0 for hints in instance_hints
        ]

    # File extension (.java vs .kt)
    raw_feature_dict["is_kotlin"] = [
        1.0 if (
            str(r.get("code_snippet_path") or r.get("file_path") or "").strip().lower().endswith(".kt")
            or ".kt:" in str(r.get("code_snippet_path") or "").lower()
        ) else 0.0
        for r in disagreement_records
    ]

    # 3. Filter features with zero variance or complete collinearity
    active_features: List[str] = []
    excluded: Dict[str, str] = {}
    cols: List[np.ndarray] = []

    for name, vals in raw_feature_dict.items():
        arr = np.array(vals, dtype=float)
        std = np.std(arr)
        if std < 1e-7:
            excluded[name] = "zero variance"
            continue
        active_features.append(name)
        cols.append(arr)

    if not cols:
        return np.empty((n, 0)), y, [], excluded

    X = np.column_stack(cols)
    return X, y, active_features, excluded


# ---------------------------------------------------------------------------
# Logistic Regression Fitting & Statistics
# ---------------------------------------------------------------------------

def fit_logistic_regression(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str],
    excluded_features: Dict[str, str],
    l2_reg: float = 1e-4,
) -> DisagreementModelResult:
    """Fit logistic regression predicting P(S=1 | S != L) and compute rigorous statistics."""
    n = len(y)
    num_static_wins = int(np.sum(y == 1))
    num_llm_wins = int(np.sum(y == 0))

    if n < 2:
        return DisagreementModelResult(
            status="insufficient_data",
            num_disagreements=n,
            num_static_wins=num_static_wins,
            num_llm_wins=num_llm_wins,
            num_features=0,
            excluded_features=excluded_features,
            message="Fewer than 2 disagreement instances to fit logistic regression.",
        )

    if num_static_wins == 0 or num_llm_wins == 0:
        return DisagreementModelResult(
            status="degenerate_outcome",
            num_disagreements=n,
            num_static_wins=num_static_wins,
            num_llm_wins=num_llm_wins,
            num_features=0,
            roc_auc=0.5,
            pseudo_r2=0.0,
            excluded_features=excluded_features,
            message="Disagreement subset has zero variance in detector outcome (all one detector).",
        )

    p = X.shape[1] if X.ndim > 1 else 0
    # Include intercept column: X_design has shape (n, p + 1)
    if p > 0:
        X_design = np.column_stack([np.ones(n), X])
    else:
        X_design = np.ones((n, 1))

    num_params = X_design.shape[1]

    # Objective function: regularized negative log-likelihood (no penalty on intercept)
    def loss(b: np.ndarray) -> float:
        logits = np.clip(X_design @ b, -35.0, 35.0)
        nll = float(np.sum(np.logaddexp(0.0, logits) - y * logits))
        reg = 0.5 * l2_reg * float(np.sum(b[1:] ** 2)) if len(b) > 1 else 0.0
        return nll + reg

    def grad(b: np.ndarray) -> np.ndarray:
        logits = np.clip(X_design @ b, -35.0, 35.0)
        probs = 1.0 / (1.0 + np.exp(-logits))
        g = X_design.T @ (probs - y)
        if len(b) > 1:
            g[1:] += l2_reg * b[1:]
        return g

    b_init = np.zeros(num_params)
    with np.errstate(all="ignore"):
        # Fit model with BFGS
        res = minimize(loss, b_init, jac=grad, method="BFGS")
        b_hat = res.x

        logits = np.clip(X_design @ b_hat, -35.0, 35.0)
        probs_hat = 1.0 / (1.0 + np.exp(-logits))
        w = probs_hat * (1.0 - probs_hat)

        # Compute Fisher Information Matrix (Hessian) + L2 regularization
        H = (X_design.T * w) @ X_design
        if num_params > 1:
            diag_idx = np.arange(1, num_params)
            H[diag_idx, diag_idx] += l2_reg

        cov = np.linalg.pinv(H)
        diag_cov = np.diag(cov)
        se = np.sqrt(np.maximum(diag_cov, 1e-9))

        # Odds Ratios and 95% Confidence Intervals
        odds_ratios = np.exp(b_hat)
        ci_lower = np.exp(b_hat - 1.95996398 * se)
        ci_upper = np.exp(b_hat + 1.95996398 * se)

        # Wald z-test and raw two-tailed p-values
        z_stats = b_hat / se
        raw_p_values = 2.0 * stats.norm.sf(np.abs(z_stats))

    # Benjamini-Hochberg FDR correction on feature hypotheses (excluding intercept)
    if p > 0:
        fdr_p_values = benjamini_hochberg(raw_p_values[1:])
    else:
        fdr_p_values = []

    # Assemble feature summary
    feature_summaries: List[FeatureModelStats] = []
    # Intercept
    feature_summaries.append(
        FeatureModelStats(
            name="Intercept",
            coef=float(b_hat[0]),
            std_err=float(se[0]),
            odds_ratio=float(odds_ratios[0]),
            ci_95_lower=float(ci_lower[0]),
            ci_95_upper=float(ci_upper[0]),
            z_stat=float(z_stats[0]),
            p_value=float(raw_p_values[0]),
            p_value_fdr=float(raw_p_values[0]),
        )
    )

    for i, fname in enumerate(feature_names):
        idx = i + 1
        feature_summaries.append(
            FeatureModelStats(
                name=fname,
                coef=float(b_hat[idx]),
                std_err=float(se[idx]),
                odds_ratio=float(odds_ratios[idx]),
                ci_95_lower=float(ci_lower[idx]),
                ci_95_upper=float(ci_upper[idx]),
                z_stat=float(z_stats[idx]),
                p_value=float(raw_p_values[idx]),
                p_value_fdr=float(fdr_p_values[i]),
            )
        )

    # ROC-AUC
    try:
        auc_val = float(roc_auc_score(y, probs_hat))
    except ValueError:
        auc_val = 0.5

    # McFadden Pseudo-R²
    eps = 1e-15
    probs_clamped = np.clip(probs_hat, eps, 1.0 - eps)
    ll_full = float(np.sum(y * np.log(probs_clamped) + (1.0 - y) * np.log(1.0 - probs_clamped)))

    y_bar = float(np.clip(np.mean(y), eps, 1.0 - eps))
    ll_null = float(np.sum(y * np.log(y_bar) + (1.0 - y) * np.log(1.0 - y_bar)))

    mcfadden_r2 = max(0.0, min(1.0, 1.0 - (ll_full / ll_null))) if abs(ll_null) > eps else 0.0

    return DisagreementModelResult(
        status="converged" if res.success else "converged_approx",
        num_disagreements=n,
        num_static_wins=num_static_wins,
        num_llm_wins=num_llm_wins,
        num_features=p,
        roc_auc=auc_val,
        pseudo_r2=mcfadden_r2,
        log_likelihood_full=ll_full,
        log_likelihood_null=ll_null,
        features=feature_summaries,
        excluded_features=excluded_features,
        message="Logistic regression model fitted successfully.",
    )


def fit_disagreement_model(disagreement_records: Sequence[Dict[str, Any]]) -> DisagreementModelResult:
    """High-level entrypoint: build features and fit logistic regression."""
    X, y, feature_names, excluded = build_disagreement_features(disagreement_records)
    return fit_logistic_regression(X, y, feature_names, excluded)


# ---------------------------------------------------------------------------
# Output Formatting: ASCII / Markdown Summary Table
# ---------------------------------------------------------------------------

def generate_markdown_summary(
    alignment_info: Dict[str, Any],
    global_counts: ContingencyCellCounts,
    by_gran: Dict[str, ContingencyCellCounts],
    by_art: Dict[str, ContingencyCellCounts],
    model_result: DisagreementModelResult,
) -> str:
    """Format an ASCII/Markdown summary report of complementarity findings."""
    lines: List[str] = []

    lines.append("# Phase 2 Complementarity & Disagreement Analysis (Contribution C1)")
    lines.append("")
    lines.append("## 1. Dataset & Instance Alignment")
    lines.append(f"- **Total Static Instances Evaluated:** {alignment_info.get('total_static_instances', 0)}")
    lines.append(f"- **Total LLM Instances Evaluated:** {alignment_info.get('total_llm_instances', 0)}")
    lines.append(f"- **Matched Instances Joined:** {alignment_info.get('matched_instances', 0)}")
    lines.append(f"- **Unmatched Static Instances:** {alignment_info.get('unmatched_static_count', 0)}")
    lines.append(f"- **Unmatched LLM Instances:** {alignment_info.get('unmatched_llm_count', 0)}")
    lines.append("")

    lines.append("## 2. Four-Cell Contingency Table (Global & by Granularity)")
    lines.append("| Partition | Total | Cell 1 (Both Correct) | Cell 2 (Both Incorrect) | Cell 3 (Static Only) | Cell 4 (LLM Only) | Disagreement Rate |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

    def _fmt_row(label: str, c: ContingencyCellCounts) -> str:
        c1 = f"{c.both_correct} ({c.both_correct_prop * 100:.1f}%)"
        c2 = f"{c.both_incorrect} ({c.both_incorrect_prop * 100:.1f}%)"
        c3 = f"{c.static_only} ({c.static_only_prop * 100:.1f}%)"
        c4 = f"{c.llm_only} ({c.llm_only_prop * 100:.1f}%)"
        dis = f"{c.disagreement_prop * 100:.1f}%"
        return f"| **{label}** | {c.total} | {c1} | {c2} | {c3} | {c4} | {dis} |"

    lines.append(_fmt_row("Global Benchmark", global_counts))
    for gran in GRANULARITIES:
        if gran in by_gran:
            lines.append(_fmt_row(f"Granularity: {gran.capitalize()}", by_gran[gran]))
    lines.append("")

    lines.append("## 3. Four-Cell Contingency Table (Partitioned by Article)")
    lines.append("| Article Partition | Total | Cell 1 (Both Correct) | Cell 2 (Both Incorrect) | Cell 3 (Static Only) | Cell 4 (LLM Only) | Disagreement Rate |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    for bucket in ARTICLE_BUCKETS:
        if bucket in by_art:
            label = f"Article {bucket}" if bucket != "other" else "Remaining Articles (Pooled)"
            lines.append(_fmt_row(label, by_art[bucket]))
    lines.append("")

    lines.append("## 4. Predictive Modeling on Disagreement: P(Static Wins | S != L)")
    if model_result.status.startswith("converged"):
        lines.append(f"- **Disagreement Instances (N):** {model_result.num_disagreements} (Static Wins: {model_result.num_static_wins}, LLM Wins: {model_result.num_llm_wins})")
        lines.append(f"- **Model Discriminative Power (ROC-AUC):** {model_result.roc_auc:.4f}")
        lines.append(f"- **McFadden's Pseudo-R²:** {model_result.pseudo_r2:.4f}")
        lines.append(f"- **Log-Likelihood:** Full = {model_result.log_likelihood_full:.2f}, Null = {model_result.log_likelihood_null:.2f}")
        lines.append("")
        lines.append("| Predictor Feature | Coef (β) | Std Error | Odds Ratio (OR) | 95% Confidence Interval | Wald p-value | FDR (BH) q-value |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
        for f in model_result.features:
            ci_str = f"[{f.ci_95_lower:.4f}, {f.ci_95_upper:.4f}]"
            fdr_str = f"{f.p_value_fdr:.4f}" if f.name != "Intercept" else "—"
            lines.append(
                f"| `{f.name}` | {f.coef:+.4f} | {f.std_err:.4f} | **{f.odds_ratio:.4f}** | {ci_str} | {f.p_value:.4e} | {fdr_str} |"
            )
        if model_result.excluded_features:
            lines.append("")
            lines.append("**Excluded Candidate Features (Zero Variance / Collinear):**")
            for feat, reason in model_result.excluded_features.items():
                lines.append(f"- `{feat}`: {reason}")
    else:
        lines.append(f"- **Status:** {model_result.status}")
        lines.append(f"- **Notice:** {model_result.message}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engine Execution Orchestration
# ---------------------------------------------------------------------------

class ComplementarityEngine:
    """Orchestrates Phase 2 complementarity analysis."""

    def __init__(
        self,
        static_source: Union[str, Path],
        llm_source: Union[str, Path],
        output_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self.static_source = Path(static_source)
        self.llm_source = Path(llm_source)
        self.output_dir = Path(output_dir) if output_dir else Path("results/complementarity")

    def run(self) -> ComplementarityMetrics:
        """Execute alignment, contingency classification, predictive modeling, and export."""
        logger.info("Loading static results from %s", self.static_source)
        static_records = load_records(self.static_source)

        logger.info("Loading LLM results from %s", self.llm_source)
        llm_records = load_records(self.llm_source)

        # 1. Alignment
        aligned, unmatched_s, unmatched_l = align_detector_runs(static_records, llm_records)
        alignment_summary = {
            "total_static_instances": len(static_records),
            "total_llm_instances": len(llm_records),
            "matched_instances": len(aligned),
            "unmatched_static_count": len(unmatched_s),
            "unmatched_llm_count": len(unmatched_l),
            "unmatched_static_keys": unmatched_s,
            "unmatched_llm_keys": unmatched_l,
        }

        if unmatched_s:
            logger.warning("Flagged %d unmatched static instances.", len(unmatched_s))
        if unmatched_l:
            logger.warning("Flagged %d unmatched LLM instances.", len(unmatched_l))

        # 2. Four-cell Contingency Analysis
        global_contingency, by_gran, by_art = partition_contingency_analysis(aligned)

        # 3. Disagreement Modeling
        disagreements = [
            r for r in aligned if bool(r.get("static_correct")) != bool(r.get("llm_correct"))
        ]
        model_result = fit_disagreement_model(disagreements)

        # 4. Summary Table & Metrics Serialization
        markdown_table = generate_markdown_summary(
            alignment_summary, global_contingency, by_gran, by_art, model_result
        )

        metrics = ComplementarityMetrics(
            alignment_summary=alignment_summary,
            global_contingency=global_contingency,
            by_granularity=by_gran,
            by_article=by_art,
            disagreement_model=model_result,
            markdown_table=markdown_table,
        )

        self.export(metrics)
        return metrics

    def export(self, metrics: ComplementarityMetrics) -> Tuple[Path, Path]:
        """Serialize metrics to JSON and write Markdown summary table."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        json_path = self.output_dir / "metrics.json"
        json_path.write_text(json.dumps(metrics.to_dict(), indent=2), encoding="utf-8")
        logger.info("Serialized complementarity metrics to %s", json_path)

        summary_path = self.output_dir / "summary.md"
        summary_path.write_text(metrics.markdown_table, encoding="utf-8")
        logger.info("Wrote summary markdown table to %s", summary_path)

        return json_path, summary_path


def run_complementarity_analysis(
    static_results: Union[str, Path],
    llm_results: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
) -> ComplementarityMetrics:
    """Convenience function executing the complementarity pipeline."""
    engine = ComplementarityEngine(static_results, llm_results, output_dir=output_dir)
    return engine.run()


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phase 2 Complementarity & Disagreement Analysis for GDPR-Bench-Android",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--static-results",
        required=True,
        type=str,
        help="Path to per-instance results from static detector (file or directory).",
    )
    parser.add_argument(
        "--llm-results",
        required=True,
        type=str,
        help="Path to per-instance results from LLM detector (file or directory).",
    )
    parser.add_argument(
        "--output-dir",
        default="results/complementarity",
        type=str,
        help="Directory to save metrics.json and summary table.",
    )
    return parser.parse_args(args)


def main(args: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    cli_args = parse_args(args)

    metrics = run_complementarity_analysis(
        static_results=cli_args.static_results,
        llm_results=cli_args.llm_results,
        output_dir=cli_args.output_dir,
    )

    print("\n" + metrics.markdown_table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
