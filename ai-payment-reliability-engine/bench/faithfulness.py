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

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import numpy as np

from pre.agents.evidence import EvidencePack
from pre.agents.rca import Claim, RCAResult
from pre.llm.client import LLMClient


class JudgeBackend(Enum):
    """Available entailment judge backends."""

    NLI_CROSS_ENCODER = "nli_cross_encoder"  # Sentence-transformers cross-encoder
    CHAT_MODEL = "chat_model"  # LLM-based judge (different family than RCA model)


# --------------------------------------------------------------------------- #
# NLI cross-encoder backend
# --------------------------------------------------------------------------- #
# cross-encoder/nli-deberta-v3-base emits 3 logits in this fixed order.
NLI_MODEL_NAME = "cross-encoder/nli-deberta-v3-base"
_NLI_LABELS = ("contradiction", "entailment", "neutral")
_nli_model = None  # lazy singleton — loading the model is ~1s and ~440MB on disk


def _get_nli_model():
    global _nli_model
    if _nli_model is None:
        from sentence_transformers import CrossEncoder

        _nli_model = CrossEncoder(NLI_MODEL_NAME)
    return _nli_model


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x))
    return e / e.sum()


def nli_probs(premise: str, hypothesis: str) -> dict[str, float]:
    """Softmax {contradiction, entailment, neutral} for one (premise, hypothesis)."""
    logits = np.asarray(_get_nli_model().predict([(premise, hypothesis)])).reshape(-1)
    return {lbl: float(v) for lbl, v in zip(_NLI_LABELS, _softmax(logits))}


# --------------------------------------------------------------------------- #
# Chat-model backend
# --------------------------------------------------------------------------- #
# Judge with a DIFFERENT model family than the one that generated the RCA
# (RCA path defaults to ollama:llama3.1, so judge defaults to ollama:qwen).
DEFAULT_CHAT_JUDGE_DIGEST = "ollama:qwen3.8:27b"

_CHAT_JUDGE_SYSTEM = (
    "You are a strict entailment judge for incident root-cause analysis. "
    "You are given monitoring EVIDENCE and a CLAIM. Decide how strongly the "
    "evidence supports the claim. Be skeptical: unrelated or contradicting "
    "evidence must score low even if both mention the same system."
)

_CHAT_JUDGE_PROMPT = """EVIDENCE:
{evidence}

CLAIM:
{claim}

Does the EVIDENCE support the CLAIM? Reply with ONLY a JSON object:
{{"entailment": <integer 0-100>, "reason": "<one short sentence>"}}
0 = evidence is unrelated to or contradicts the claim.
100 = evidence directly and fully supports the claim."""


def _parse_chat_score(text: str) -> tuple[Optional[float], str]:
    """Extract an entailment integer 0-100 from the judge's reply -> [0,1]."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    try:
        obj = json.loads(re.search(r"\{.*\}", text, re.DOTALL).group(0))
        val = float(obj["entailment"])
        return max(0.0, min(100.0, val)) / 100.0, "json"
    except Exception:
        m = re.search(r"\b(\d{1,3})\b", text)
        if m:
            return max(0.0, min(100.0, float(m.group(1)))) / 100.0, "regex-fallback"
    return None, "unparsed"


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
    stage2_valid: bool = True  # False if the judge reply was truncated/unparseable


class FaithfulnessChecker:
    """Two-stage faithfulness checker for RCA claims."""

    # Minimum anomaly score for evidence to be considered anomalous
    MIN_ANOMALY_SCORE = 0.3

    def __init__(
        self,
        evidence_pack: EvidencePack,
        judge_backend: JudgeBackend = JudgeBackend.NLI_CROSS_ENCODER,
        *,
        chat_model_digest: str = DEFAULT_CHAT_JUDGE_DIGEST,
        llm_client: Optional[LLMClient] = None,
    ):
        self.evidence_pack = evidence_pack
        self.judge_backend = judge_backend
        self.chat_model_digest = chat_model_digest
        self._llm_client = llm_client
        self.evidence_by_id = {item.id: item for item in evidence_pack.items}

    @property
    def llm_client(self) -> LLMClient:
        if self._llm_client is None:
            self._llm_client = LLMClient()
        return self._llm_client

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

    def stage2_check(self, claim: Claim) -> tuple[float, str, bool]:
        """Stage 2: Run entailment judge.

        Returns:
            (score: float [0, 1], raw_output: str, valid: bool)
            `valid` is False when the judge reply could not be trusted
            (truncated after retry, or unparseable).
        """
        evidence_texts = [
            self.evidence_by_id[eid].description
            for eid in claim.evidence_ids
            if eid in self.evidence_by_id
        ]

        if not evidence_texts:
            return 0.0, "No evidence texts available", False

        combined_evidence = " | ".join(evidence_texts)

        if self.judge_backend == JudgeBackend.NLI_CROSS_ENCODER:
            return self._judge_nli(combined_evidence, claim.text)
        return self._judge_chat(combined_evidence, claim.text)

    def _judge_nli(self, evidence_text: str, claim_text: str) -> tuple[float, str, bool]:
        """Raw P(entailment) from a 3-class NLI cross-encoder (softmax over
        contradiction / entailment / neutral).

        DO NOT reinterpret this as a faithfulness score. On this data the model
        is a *shallow restatement detector*, not an entailment judge over RCA
        reasoning (see PROTOCOL.md "Faithfulness Judging" for the full probe):

        - Its entailment head works on general-language paraphrase.
        - It fires entailment only when the claim is at most ONE lexical /
          directional substitution from the evidence's literal text
          ("spiked to 100.0" -> "rose to 100" / "reached 100 percent" / "high
          CPU usage": P(entail) > 0.9).
        - It CANNOT name a failure mode the evidence implies but does not state
          ("was saturated", "memory leak", "bottleneck") or interpret the
          z-score ("far above baseline") -> `neutral` -> P(entail) ~0, even for
          a genuinely-grounded paraphrased claim.

        So a HIGH score is meaningful (near-verbatim support); a LOW score is
        not (fabrication and true-but-abstractive claims both land at ~0). It
        is a comparison point only and does not gate `overall_faithful`.

        An earlier version returned 0.5*(1 + P(entail) - P(contra)); that put
        every `neutral` claim at exactly 0.5 — the pass/fail threshold — which
        silently turned "model is uncertain" into a coin-flip verdict.
        """
        p = nli_probs(evidence_text, claim_text)
        raw = (
            f"[NLI {NLI_MODEL_NAME}] contradiction={p['contradiction']:.3f} "
            f"entailment={p['entailment']:.3f} neutral={p['neutral']:.3f}"
        )
        return p["entailment"], raw, True

    # ponytail: 800 covers a reasoning model's hidden <think> budget + the JSON
    # answer; the retry triples it. Drop the base if the judge is not a
    # reasoning model.
    CHAT_JUDGE_MAX_TOKENS = 800
    CHAT_JUDGE_RETRY_MAX_TOKENS = 2400

    def _judge_chat(self, evidence_text: str, claim_text: str) -> tuple[float, str, bool]:
        """Entailment score from a chat model, routed through pre/llm/client.py
        (digest-pinned, disk-cached). Model family must differ from the RCA
        generator's — see DEFAULT_CHAT_JUDGE_DIGEST.

        If the model's reply was cut off at the token limit
        (``LLMResponse.truncated``), retry once with a bigger budget; if it is
        STILL truncated the score is marked invalid rather than trusting a
        partial response (the entailment integer may have printed before the
        cut, but that is luck, not a guarantee).
        """
        prompt = _CHAT_JUDGE_PROMPT.format(evidence=evidence_text, claim=claim_text)

        def _call(max_tokens):
            return self.llm_client.call(
                prompt=prompt,
                model_digest=self.chat_model_digest,
                system_prompt=_CHAT_JUDGE_SYSTEM,
                max_tokens=max_tokens,
                seed=0,
            )

        resp = _call(self.CHAT_JUDGE_MAX_TOKENS)
        if resp.truncated:
            resp = _call(self.CHAT_JUDGE_RETRY_MAX_TOKENS)

        score, how = _parse_chat_score(resp.text)
        tag = f"parse={how}"
        if resp.cached:
            tag += " cached"
        if resp.truncated:
            tag += f" TRUNCATED@{resp.tokens_used}tok"
        raw = f"[CHAT {resp.model_digest} {tag}] {resp.text.strip()}"

        if resp.truncated:
            # Retried and still cut off — do not trust the partial reply.
            return 0.5, raw + "  <<TRUNCATED after retry -> invalid>>", False
        if score is None:
            return 0.5, raw + "  <<UNPARSED -> invalid>>", False
        return score, raw, True

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

        # Stage 2: only if stage 1 passed.
        stage2_score, judge_output, stage2_valid = self.stage2_check(claim)
        # For the chat judge this is "evidence supports the claim". For NLI it
        # is "P(strict textual entailment) >= 0.5" — a deliberately strict,
        # low-recall bar; per PROTOCOL.md NLI is a comparison point and its
        # verdict is not the reported faithfulness gate. An invalid stage-2
        # result (truncated/unparseable judge reply) is never faithful.
        stage2_pass = stage2_valid and stage2_score >= 0.5

        return FaithfulnessScore(
            claim_text=claim.text,
            evidence_ids=claim.evidence_ids,
            stage1_pass=True,
            stage1_reason=stage1_reason,
            stage2_score=stage2_score,
            stage2_judge=self.judge_backend.value,
            judge_output=judge_output,
            overall_faithful=stage2_pass,
            stage2_valid=stage2_valid,
        )

    def check_rca_result(self, rca: RCAResult) -> list[FaithfulnessScore]:
        """Check faithfulness of all claims in an RCA result.

        Returns:
            List of FaithfulnessScores, one per claim
        """
        return [self.check_claim(claim) for claim in rca.claims]


# A HIGH NLI score independently confirms near-verbatim support; a low one
# carries no information on this data (PROTOCOL.md). NLI therefore enters
# aggregates ONLY through this one-directional corroboration threshold.
NLI_CONFIRM_THRESHOLD = 0.8


def _is_nli(score: FaithfulnessScore) -> bool:
    return "nli" in score.stage2_judge


def compute_faithfulness_metrics(
    scores: list[FaithfulnessScore],
    nli_scores: Optional[list[FaithfulnessScore]] = None,
) -> dict:
    """Aggregate faithfulness stats.

    `scores` — the PRIMARY (chat-model) judge's FaithfulnessScores, one per
    claim. The faithfulness metric is defined by this judge (PROTOCOL.md).

    `nli_scores` — optional NLI FaithfulnessScores for the same claims. Used
    ONLY for `nli_corroboration_rate` (fraction of chat-faithful claims that
    NLI independently scores >= NLI_CONFIRM_THRESHOLD — near-verbatim support).
    NLI scores are never averaged into a faithfulness number: on this data a
    low NLI score carries zero information.

    If `scores` contains NLI entries (a caller passing a mixed list) they are
    split out and treated as `nli_scores`, so the primary numbers stay
    chat-only either way.

    Claims whose stage-2 judge reply was invalid (truncated after retry, or
    unparseable — `stage2_valid is False`) are EXCLUDED from `stage2_pass_rate`
    and `avg_faithfulness_score` and counted in `n_stage2_invalid`; they still
    count against `overall_faithful_rate` (an unjudgeable claim is not faithful).

    Keys: stage1_pass_rate, stage2_pass_rate, overall_faithful_rate,
    avg_faithfulness_score (all None if no chat-judge scores), n_stage2_invalid,
    judges, caveats, and — when NLI scores are supplied — nli_corroboration_rate
    / nli_confirm_threshold.
    """
    nli = list(nli_scores or [])
    chat_all = []
    for s in scores:
        (nli if _is_nli(s) else chat_all).append(s)

    n = len(chat_all)
    passed = [s for s in chat_all if s.stage1_pass]
    scored = [s for s in passed if s.stage2_valid]  # stage-1 passed AND judge reply usable

    out: dict = {
        "n": n,
        "n_stage2_invalid": sum(1 for s in passed if not s.stage2_valid),
        "judges": sorted({s.stage2_judge for s in chat_all + nli}),
        "caveats": [],
    }

    if chat_all:
        out["stage1_pass_rate"] = len(passed) / n
        out["stage2_pass_rate"] = (
            sum(1 for s in scored if s.overall_faithful) / len(scored) if scored else 0.0
        )
        out["overall_faithful_rate"] = sum(1 for s in chat_all if s.overall_faithful) / n
        out["avg_faithfulness_score"] = (
            sum(s.stage2_score for s in scored) / len(scored) if scored else 0.0
        )
        if out["n_stage2_invalid"]:
            out["caveats"].append(
                f"{out['n_stage2_invalid']} claim(s) had an invalid (truncated/"
                "unparseable) judge reply — excluded from stage2_pass_rate and "
                "avg_faithfulness_score, counted as not-faithful."
            )
    else:
        out["stage1_pass_rate"] = (
            sum(1 for s in nli if s.stage1_pass) / len(nli) if nli else 0.0
        )
        for k in ("stage2_pass_rate", "overall_faithful_rate", "avg_faithfulness_score"):
            out[k] = None
        out["caveats"].append(
            "No chat-judge scores: the reported faithfulness metric (PROTOCOL.md) "
            "cannot be computed from NLI alone."
        )

    if nli:
        nli_by_claim = {(s.claim_text, tuple(s.evidence_ids)): s for s in nli}
        matched = [
            nli_by_claim[(s.claim_text, tuple(s.evidence_ids))]
            for s in chat_all
            if s.overall_faithful and (s.claim_text, tuple(s.evidence_ids)) in nli_by_claim
        ]
        out["nli_corroboration_rate"] = (
            sum(1 for m in matched if m.stage2_score >= NLI_CONFIRM_THRESHOLD) / len(matched)
            if matched
            else None
        )
        out["nli_confirm_threshold"] = NLI_CONFIRM_THRESHOLD
        out["caveats"].append(
            "NLI scores are NOT averaged into any faithfulness number; only "
            f"nli_corroboration_rate (chat-faithful claims NLI also rates "
            f">= {NLI_CONFIRM_THRESHOLD}) is reported. See PROTOCOL.md."
        )

    return out
