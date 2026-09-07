"""
bench/faithfulness.py — Two-stage faithfulness checking for RCA claims.

Stage 1: Existence and anomaly checks
  - Verify claimed evidence IDs exist in the evidence pack
  - Confirm evidence items have sufficient anomaly scores

Stage 2: Entailment judgment
  - Check if rendered evidence text entails the claim text
  - Two judge backends: NLI cross-encoder or chat model
  - Store outputs for human-rating agreement study (Cohen's kappa)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from pre.agents.evidence import EvidencePack
from pre.agents.rca import Claim, RCAResult


class JudgeBackend(Enum):
    """Available entailment judge backends."""

    NLI_CROSS_ENCODER = "nli_cross_encoder"  # Sentence-transformers cross-encoder
    CHAT_MODEL = "chat_model"  # LLM-based judge (different family than RCA model)


@dataclass(frozen=True)
class FaithfulnessScore:
    """Faithfulness score for a claim."""

    claim_text: str
    evidence_ids: list[str]
    stage1_pass: bool  # All IDs exist and are anomalous
    stage1_reason: str  # Why stage 1 passed/failed
    stage2_score: float  # Entailment score [0, 1], if stage 1 passed
    stage2_judge: str  # Backend used for stage 2
    judge_output: str  # Raw judge output for later analysis
    overall_faithful: bool  # True if both stages pass


class FaithfulnessChecker:
    """Two-stage faithfulness checker for RCA claims."""

    # Minimum anomaly score for evidence to be considered anomalous
    MIN_ANOMALY_SCORE = 0.3

    def __init__(
        self,
        evidence_pack: EvidencePack,
        judge_backend: JudgeBackend = JudgeBackend.NLI_CROSS_ENCODER,
    ):
        self.evidence_pack = evidence_pack
        self.judge_backend = judge_backend
        self.evidence_by_id = {item.id: item for item in evidence_pack.items}

    def stage1_check(self, claim: Claim) -> tuple[bool, str]:
        """Stage 1: Check evidence existence and anomaly.

        Returns:
            (passed: bool, reason: str)
        """
        missing_ids = []
        weak_anomalies = []

        for eid in claim.evidence_ids:
            if eid not in self.evidence_by_id:
                missing_ids.append(eid)
            else:
                evidence = self.evidence_by_id[eid]
                if evidence.score < self.MIN_ANOMALY_SCORE:
                    weak_anomalies.append((eid, evidence.score))

        if missing_ids:
            return False, f"Missing evidence IDs: {missing_ids}"

        if weak_anomalies:
            weak_list = ", ".join(f"{eid}({score:.2f})" for eid, score in weak_anomalies)
            return False, f"Weak anomalies: {weak_list}"

        return True, "All evidence IDs present and anomalous"

    def stage2_check(self, claim: Claim) -> tuple[float, str]:
        """Stage 2: Run entailment judge.

        Returns:
            (score: float [0, 1], raw_output: str)
        """
        evidence_texts = [
            self.evidence_by_id[eid].description
            for eid in claim.evidence_ids
            if eid in self.evidence_by_id
        ]

        if not evidence_texts:
            return 0.0, "No evidence texts available"

        combined_evidence = " | ".join(evidence_texts)

        if self.judge_backend == JudgeBackend.NLI_CROSS_ENCODER:
            return self._judge_nli(combined_evidence, claim.text)
        else:
            return self._judge_chat(combined_evidence, claim.text)

    def _judge_nli(self, evidence_text: str, claim_text: str) -> tuple[float, str]:
        """Judge entailment using NLI cross-encoder (placeholder).

        In production, this would use sentence-transformers.cross_encoder or
        a similar NLI model. For now, return a placeholder.
        """
        # Placeholder implementation
        # Real: score = cross_encoder.predict([[evidence_text, claim_text]])
        similarity = 0.5  # Default placeholder
        return similarity, f"[NLI] evidence: {evidence_text[:50]}... | claim: {claim_text[:50]}..."

    def _judge_chat(self, evidence_text: str, claim_text: str) -> tuple[float, str]:
        """Judge entailment using chat model (placeholder).

        In production, this would call the chat model (Ollama/Groq) with
        an entailment prompt, asking if the evidence entails the claim.
        """
        # Placeholder implementation
        # Real: response = client.call_chat_model(prompt=f"Does '{evidence_text}' entail '{claim_text}'?")
        similarity = 0.5  # Default placeholder
        return similarity, f"[CHAT] evidence: {evidence_text[:50]}... | claim: {claim_text[:50]}..."

    def check_claim(self, claim: Claim) -> FaithfulnessScore:
        """Run full two-stage faithfulness check on a claim.

        Returns:
            FaithfulnessScore with stage 1 and stage 2 results
        """
        stage1_pass, stage1_reason = self.stage1_check(claim)

        if not stage1_pass:
            return FaithfulnessScore(
                claim_text=claim.text,
                evidence_ids=claim.evidence_ids,
                stage1_pass=False,
                stage1_reason=stage1_reason,
                stage2_score=0.0,
                stage2_judge="none",
                judge_output="",
                overall_faithful=False,
            )

        # Stage 2: only if stage 1 passed
        stage2_score, judge_output = self.stage2_check(claim)
        stage2_pass = stage2_score >= 0.5  # Threshold for entailment

        return FaithfulnessScore(
            claim_text=claim.text,
            evidence_ids=claim.evidence_ids,
            stage1_pass=True,
            stage1_reason=stage1_reason,
            stage2_score=stage2_score,
            stage2_judge=self.judge_backend.value,
            judge_output=judge_output,
            overall_faithful=stage2_pass,
        )

    def check_rca_result(self, rca: RCAResult) -> list[FaithfulnessScore]:
        """Check faithfulness of all claims in an RCA result.

        Returns:
            List of FaithfulnessScores, one per claim
        """
        return [self.check_claim(claim) for claim in rca.claims]


def compute_faithfulness_metrics(scores: list[FaithfulnessScore]) -> dict[str, float]:
    """Compute aggregate faithfulness metrics from a set of scores.

    Metrics:
      - stage1_pass_rate: fraction passing stage 1
      - stage2_pass_rate: fraction passing stage 2 (of those that passed stage 1)
      - overall_faithful_rate: fraction passing both stages
      - avg_entailment_score: mean stage2 score
    """
    if not scores:
        return {
            "stage1_pass_rate": 0.0,
            "stage2_pass_rate": 0.0,
            "overall_faithful_rate": 0.0,
            "avg_entailment_score": 0.0,
        }

    stage1_passes = sum(1 for s in scores if s.stage1_pass)
    overall_passes = sum(1 for s in scores if s.overall_faithful)

    stage2_scores = [s.stage2_score for s in scores if s.stage1_pass]
    avg_entailment = sum(stage2_scores) / len(stage2_scores) if stage2_scores else 0.0

    stage2_pass_rate = (
        sum(1 for s in scores if s.stage1_pass and s.overall_faithful)
        / len([s for s in scores if s.stage1_pass])
        if stage1_passes > 0
        else 0.0
    )

    return {
        "stage1_pass_rate": stage1_passes / len(scores),
        "stage2_pass_rate": stage2_pass_rate,
        "overall_faithful_rate": overall_passes / len(scores),
        "avg_entailment_score": avg_entailment,
    }
