"""
arbitration/cost_router.py — Cost-Sensitive Tri-Choice Router (Contribution C2).

Implements:
  1. LearnedFeatureRouter (Policy 3):
     Routes between Symbolic (S) and Neural (L) using Phase 2 empirical feature weights
     predicting P(S=1 | S != L, x) = sigma(beta_0 + beta^T phi(x)).
     When detectors agree, executes S at c_S ~ 0.
  2. CostSensitiveRejectRouter (Policy 4):
     Calculates expected conditional risks under asymmetric error costs:
       R(S | x) = c_S + c_FN P(Y=1, y_S=0 | x) + c_FP P(Y=0, y_S=1 | x)
       R(L | x) = c_L + c_FN P(Y=1, y_L=0 | x) + c_FP P(Y=0, y_L=1 | x)
       R(H | x) = c_H + epsilon_H * l_H(x)
     Partitions decision space into {S, L, H}:
       - If min(R(S | x), R(L | x)) >= R(H | x) -> action="abstain" (deferred_to_human)
       - Otherwise -> argmin_{a in {S, L}} R(a | x)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Sequence

from api.schemas import ComplianceFinding
from arbitration.strategy import ArbitrationStrategy
from audit.prov_receipt import AuditReceiptBuilder
from audit.sink import AuditSink, NullAuditSink
from harness.complementarity import (
    extract_granularity,
    extract_scanner_hints,
    extract_snippet_length,
    extract_target_article,
)

logger = logging.getLogger("arbitration.cost_router")

# Default empirical weights derived from Phase 2 benchmark evaluation
DEFAULT_ROUTER_WEIGHTS: Dict[str, float] = {
    "Intercept": 0.15,
    "granularity_file": -0.85,
    "granularity_module": 0.45,
    "log10_char_length": -0.65,
    "article_5": 0.80,
    "article_6": -0.30,
    "article_25": 0.60,
    "article_32": 0.75,
    "scanner_hints_count": 0.50,
    "hint_unencrypted_http_outbound": 1.20,
    "hint_password_field_present": 0.90,
    "hint_personal_data_in_scope": 0.40,
    "is_kotlin": 0.20,
}


@dataclass
class RoutingDecision:
    """Detailed metadata for a tri-choice routing decision."""

    action: Literal["symbolic", "neural", "abstain"]
    status: Literal["completed", "deferred_to_human"]
    estimated_risk: float
    findings: List[ComplianceFinding]
    risk_s: float
    risk_l: float
    risk_h: float
    prob_s_wins: float
    prov_receipt: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Feature Extraction Helper for Runtime Routing
# ---------------------------------------------------------------------------

def extract_runtime_features(
    code: str = "",
    file_path: str = "untitled",
    record: Optional[Dict[str, Any]] = None,
) -> Dict[str, float]:
    """Extract Phase 2 feature dictionary phi(x) from runtime inputs or record."""
    rec: Dict[str, Any] = dict(record) if record else {}
    if code:
        rec.setdefault("code_snippet", code)
    if file_path:
        rec.setdefault("code_snippet_path", file_path)
        rec.setdefault("file_path", file_path)

    gran = extract_granularity(rec)
    target_art = extract_target_article(rec)
    char_len = extract_snippet_length(rec)
    hints = extract_scanner_hints(rec)

    path_str = str(rec.get("code_snippet_path") or rec.get("file_path") or "").lower()
    is_kt = 1.0 if path_str.endswith(".kt") or ".kt:" in path_str else 0.0

    features: Dict[str, float] = {
        "granularity_file": 1.0 if gran == "file" else 0.0,
        "granularity_module": 1.0 if gran == "module" else 0.0,
        "log10_char_length": math.log10(max(char_len, 1.0)),
        "article_5": 1.0 if target_art == 5 else 0.0,
        "article_6": 1.0 if target_art == 6 else 0.0,
        "article_25": 1.0 if target_art == 25 else 0.0,
        "article_32": 1.0 if target_art == 32 else 0.0,
        "scanner_hints_count": float(len(hints)),
        "is_kotlin": is_kt,
    }

    for h in hints:
        clean_name = f"hint_{h.replace('-', '_').replace('.', '_')}"
        features[clean_name] = 1.0

    return features


def compute_prob_s_wins(features: Dict[str, float], weights: Dict[str, float]) -> float:
    """Compute P(S=1 | S != L, x) = sigma(beta_0 + beta^T phi(x))."""
    logit = float(weights.get("Intercept", 0.0))
    for fname, val in features.items():
        if fname in weights:
            logit += float(weights[fname]) * float(val)

    # Numerically stable sigmoid
    logit = max(-35.0, min(35.0, logit))
    return 1.0 / (1.0 + math.exp(-logit))


# ---------------------------------------------------------------------------
# Policy 3: LearnedFeatureRouter
# ---------------------------------------------------------------------------

class LearnedFeatureRouter(ArbitrationStrategy):
    """Policy 3: Routes between Symbolic and Neural detectors via learned Phase 2 features."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        self.weights = dict(weights) if weights is not None else dict(DEFAULT_ROUTER_WEIGHTS)
        self.audit_sink: AuditSink = audit_sink if audit_sink is not None else NullAuditSink()
        self.last_decision: Optional[RoutingDecision] = None

    def decide(
        self,
        static_findings: Sequence[ComplianceFinding],
        llm_findings: Sequence[ComplianceFinding],
        code: str = "",
        file_path: str = "untitled",
        record: Optional[Dict[str, Any]] = None,
        regulation: str = "GDPR",
    ) -> RoutingDecision:
        """Evaluate routing action and return rich decision metadata."""
        s_rules = {f.rule_id for f in static_findings}
        l_rules = {f.rule_id for f in llm_findings}
        agree = (s_rules == l_rules)

        features = extract_runtime_features(code=code, file_path=file_path, record=record)
        prob_s = compute_prob_s_wins(features, self.weights)

        if agree:
            # When detectors agree, route to S at near-zero execution cost
            action: Literal["symbolic", "neural", "abstain"] = "symbolic"
            chosen_findings = list(static_findings)
        else:
            if prob_s >= 0.5:
                action = "symbolic"
                chosen_findings = list(static_findings)
            else:
                action = "neural"
                chosen_findings = list(llm_findings)

        decision = RoutingDecision(
            action=action,
            status="completed",
            estimated_risk=round(1.0 - (prob_s if action == "symbolic" else (1.0 - prob_s)), 4),
            findings=chosen_findings,
            risk_s=round(1.0 - prob_s, 4),
            risk_l=round(prob_s, 4),
            risk_h=0.25,
            prob_s_wins=round(prob_s, 4),
        )

        receipt = (
            AuditReceiptBuilder(code=code, file_path=file_path, regulation=regulation)
            .set_static_results(static_findings)
            .set_llm_results(llm_findings)
            .set_arbitration_decision(
                findings=chosen_findings,
                routing_action=action,
                status="completed",
                estimated_risk=decision.estimated_risk,
                cost_parameters={"prob_s_wins": prob_s},
            )
            .to_prov_json()
        )
        decision.prov_receipt = receipt
        self.last_decision = decision

        self.audit_sink.emit({
            "action": f"routed_{action}",
            "agree": agree,
            "prob_s_wins": decision.prob_s_wins,
            "finding_count": len(chosen_findings),
        })

        return decision

    def arbitrate(
        self,
        static_findings: Sequence[ComplianceFinding],
        llm_findings: Sequence[ComplianceFinding],
        code: str = "",
        file_path: str = "untitled",
        record: Optional[Dict[str, Any]] = None,
        regulation: str = "GDPR",
        **kwargs: Any,
    ) -> List[ComplianceFinding]:
        decision = self.decide(
            static_findings=static_findings,
            llm_findings=llm_findings,
            code=code,
            file_path=file_path,
            record=record,
            regulation=regulation,
        )
        return decision.findings


# ---------------------------------------------------------------------------
# Policy 4: CostSensitiveRejectRouter
# ---------------------------------------------------------------------------

class CostSensitiveRejectRouter(ArbitrationStrategy):
    """Policy 4: Cost-sensitive tri-choice router with Chow-type reject option.

    Partitions decision space into {symbolic, neural, abstain}.
    """

    def __init__(
        self,
        c_fn: float = 1.0,
        c_fp: float = 0.1,
        c_h: float = 0.25,
        c_l: float = 0.01,
        c_s: float = 0.0,
        epsilon_h: float = 0.02,
        tau: Optional[float] = None,
        weights: Optional[Dict[str, float]] = None,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        self.c_fn = float(c_fn)
        self.c_fp = float(c_fp)
        self.c_h = float(c_h)
        self.c_l = float(c_l)
        self.c_s = float(c_s)
        self.epsilon_h = float(epsilon_h)
        # tau optionally overrides c_h during threshold grid-search
        self.tau = float(tau) if tau is not None else None

        self.weights = dict(weights) if weights is not None else dict(DEFAULT_ROUTER_WEIGHTS)
        self.audit_sink: AuditSink = audit_sink if audit_sink is not None else NullAuditSink()
        self.last_decision: Optional[RoutingDecision] = None

    def compute_risks(
        self,
        static_findings: Sequence[ComplianceFinding],
        llm_findings: Sequence[ComplianceFinding],
        features: Dict[str, float],
    ) -> Tuple[float, float, float, float]:
        """Calculate conditional expected risks R(S | x), R(L | x), R(H | x)."""
        prob_s = compute_prob_s_wins(features, self.weights)
        s_fired = len(static_findings) > 0
        l_fired = len(llm_findings) > 0

        # Cost of human review
        effective_ch = self.tau if self.tau is not None else self.c_h
        avg_error_loss = (self.c_fn + self.c_fp) / 2.0
        risk_h = effective_ch + (self.epsilon_h * avg_error_loss)

        # Disagreement vs agreement risk calculation
        if s_fired == l_fired:
            # Agreement: detectors corroborate each other; low error probability
            agree_err_prob = 0.02
            cost_err = self.c_fp if s_fired else self.c_fn
            risk_s = self.c_s + (agree_err_prob * cost_err)
            risk_l = self.c_l + (agree_err_prob * cost_err)
        else:
            # Disagreement: exactly one detector fired; probability of error is 1 - p
            # For S: if S misses (s_fired=False), error is FN with prob (1 - prob_s)
            #        if S flags (s_fired=True), error is FP with prob (1 - prob_s)
            s_cost_type = self.c_fp if s_fired else self.c_fn
            risk_s = self.c_s + ((1.0 - prob_s) * s_cost_type)

            # For L: L is wrong when S is right (prob_s)
            l_cost_type = self.c_fp if l_fired else self.c_fn
            risk_l = self.c_l + (prob_s * l_cost_type)

        return float(risk_s), float(risk_l), float(risk_h), float(prob_s)

    def decide(
        self,
        static_findings: Sequence[ComplianceFinding],
        llm_findings: Sequence[ComplianceFinding],
        code: str = "",
        file_path: str = "untitled",
        record: Optional[Dict[str, Any]] = None,
        regulation: str = "GDPR",
    ) -> RoutingDecision:
        """Compute expected risks, make tri-choice decision, and generate PROV receipt."""
        features = extract_runtime_features(code=code, file_path=file_path, record=record)
        risk_s, risk_l, risk_h, prob_s = self.compute_risks(static_findings, llm_findings, features)

        min_auto_risk = min(risk_s, risk_l)

        # Decision Rule
        if min_auto_risk >= risk_h:
            action: Literal["symbolic", "neural", "abstain"] = "abstain"
            status: Literal["completed", "deferred_to_human"] = "deferred_to_human"
            estimated_risk = risk_h
            # For human deferral, preserve all candidate findings for review
            chosen_findings = list(llm_findings) if llm_findings else list(static_findings)
        else:
            status = "completed"
            if risk_s < risk_l:
                action = "symbolic"
                estimated_risk = risk_s
                chosen_findings = list(static_findings)
            else:
                action = "neural"
                estimated_risk = risk_l
                chosen_findings = list(llm_findings)

        decision = RoutingDecision(
            action=action,
            status=status,
            estimated_risk=round(estimated_risk, 4),
            findings=chosen_findings,
            risk_s=round(risk_s, 4),
            risk_l=round(risk_l, 4),
            risk_h=round(risk_h, 4),
            prob_s_wins=round(prob_s, 4),
        )

        receipt = (
            AuditReceiptBuilder(code=code, file_path=file_path, regulation=regulation)
            .set_static_results(static_findings)
            .set_llm_results(llm_findings)
            .set_arbitration_decision(
                findings=chosen_findings,
                routing_action=action,
                status=status,
                estimated_risk=decision.estimated_risk,
                cost_parameters={
                    "c_fn": self.c_fn,
                    "c_fp": self.c_fp,
                    "c_h": self.tau if self.tau is not None else self.c_h,
                    "c_l": self.c_l,
                    "c_s": self.c_s,
                    "risk_s": risk_s,
                    "risk_l": risk_l,
                    "risk_h": risk_h,
                },
            )
            .to_prov_json()
        )
        decision.prov_receipt = receipt
        self.last_decision = decision

        self.audit_sink.emit({
            "action": action,
            "status": status,
            "risk_s": risk_s,
            "risk_l": risk_l,
            "risk_h": risk_h,
            "estimated_risk": estimated_risk,
        })

        return decision

    def arbitrate(
        self,
        static_findings: Sequence[ComplianceFinding],
        llm_findings: Sequence[ComplianceFinding],
        code: str = "",
        file_path: str = "untitled",
        record: Optional[Dict[str, Any]] = None,
        regulation: str = "GDPR",
        **kwargs: Any,
    ) -> List[ComplianceFinding]:
        decision = self.decide(
            static_findings=static_findings,
            llm_findings=llm_findings,
            code=code,
            file_path=file_path,
            record=record,
            regulation=regulation,
        )
        return decision.findings
