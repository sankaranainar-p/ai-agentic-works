"""
pre/agents/rca.py — RCA agent producing structured RCAResult with validated claims.

Every claim is grounded in evidence IDs that were actually shown to the model,
and a claim whose text names a service none of its cited evidence belongs to is
dropped (see `_claim_drop_reason`). The headline `root_cause_service` is then
verified against the surviving claims — an unverified headline is reported as
"needs_review", never as a specific service.

Schema enforced with Pydantic for type safety and validation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, Field, ValidationError, field_validator

from pre.agents.evidence import EvidencePack
from pre.llm.client import LLMClient


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class Claim(BaseModel):
    """A single RCA claim with supporting evidence."""

    text: str  # The claim itself
    evidence_ids: list[str] = Field(min_length=1)  # At least one evidence ID
    confidence: float = Field(ge=0.0, le=1.0)  # Confidence in [0, 1]

    @field_validator("evidence_ids")
    def validate_evidence_ids(cls, v):
        """Validate that evidence IDs are non-empty."""
        if not v:
            raise ValueError("evidence_ids must contain at least one ID")
        return v


class RCAResult(BaseModel):
    """Root Cause Analysis result with validated claims.

    `root_cause_service` is the VERIFIED root cause: it equals
    `proposed_root_cause_service` (the model's own summary line) only when a
    surviving, validated claim cites evidence belonging to that service.
    Otherwise it is "needs_review" (or "unknown" when the model abstained) and
    `review_reason` explains why — the headline is never presented as a fact
    the per-claim validation does not also support.
    """

    case_id: str
    root_cause_service: str
    probable_cause: str
    contributing_factors: list[str] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    dropped_claims: int = 0  # Number of claims dropped in validation
    drop_reasons: list[str] = Field(default_factory=list)  # one string per dropped claim
    proposed_root_cause_service: str = ""  # the model's raw summary value (audit trail)
    root_cause_verified: bool = False
    review_reason: str = ""


# ---------------------------------------------------------------------------
# RCA Agent
# ---------------------------------------------------------------------------

_RCA_SYSTEM = (
    "You are a site-reliability incident analyst. You are given a monitoring "
    "alert and a ranked list of evidence items, each with a stable ID. Produce "
    "a root-cause analysis whose every claim cites one or more of those exact "
    "evidence IDs. Never invent an ID. Never cite an ID that is not in the list."
)

_RCA_PROMPT = """CASE: {case_id}
ALERT: {alert}

EVIDENCE (ranked; cite these IDs verbatim):
{evidence}

Reply with ONLY a JSON object:
{{
  "root_cause_service": "<service name>",
  "probable_cause": "<one sentence>",
  "contributing_factors": ["<factor>", ...],
  "claims": [
    {{"text": "<claim>", "evidence_ids": ["<id from the list>", ...], "confidence": <0.0-1.0>}}
  ]
}}
Produce 3-6 claims. Each claim's evidence_ids must be a non-empty subset of the IDs above."""


def _extract_json_object(text: str) -> dict:
    """Parse the first {...} object out of an LLM reply, tolerating code fences."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError(f"no JSON object in LLM reply: {text[:200]!r}")
    return json.loads(m.group(0))


# Service names shorter than this are excluded from the claim-text scan to
# avoid matching common English words ("main", "redis" are pseudo-services in
# the RCAEval Online-Boutique data). Real payment services are longer
# ("currencyservice", "checkoutservice", "frontend", ...).
_MIN_SERVICE_NAME_LEN = 6


def _service_of(eid: str) -> Optional[str]:
    """Service named by a KPI evidence id: "kpi:checkoutservice:latency-50" ->
    "checkoutservice". None for span:/logtpl:/cluster ids with no owning service."""
    parts = eid.split(":")
    if len(parts) >= 3 and parts[0] == "kpi" and parts[1] != "cluster":
        return parts[1]
    return None


class RCAAgent:
    """Generates RCA with evidence-grounded claims."""

    def __init__(self, evidence_pack: EvidencePack):
        self.evidence_pack = evidence_pack
        self.valid_evidence_ids = {item.id for item in evidence_pack.items}
        self.pack_services = {
            it.service for it in evidence_pack.items
            if it.service and len(it.service) >= _MIN_SERVICE_NAME_LEN
        }

    def generate(
        self,
        alert_text: str,
        llm_client: LLMClient,
        model_digest: str = "ollama:llama3.1",
        top_k: int = 12,
        seed: int = 0,
        max_tokens: int = 900,
    ) -> RCAResult:
        """Prompt an LLM with the top-k evidence items and parse an RCAResult.

        The RCA model family should differ from the faithfulness chat-judge's
        (see bench/faithfulness.py). Claims that fail Pydantic validation are
        skipped; claims are then validated against the evidence IDs ACTUALLY
        SHOWN in the prompt (items[:top_k]) — not the full pack — and against
        evidence-service consistency (see `_claim_drop_reason`).
        """
        items = self.evidence_pack.items[:top_k]
        shown_ids = {it.id for it in items}
        rendered = "\n".join(
            f"- {it.id}  (score {it.score:.2f}, {it.service}): {it.description}" for it in items
        )
        prompt = _RCA_PROMPT.format(
            case_id=self.evidence_pack.case_id,
            alert=alert_text or "[silent alert]",
            evidence=rendered,
        )
        resp = llm_client.call(
            prompt=prompt,
            model_digest=model_digest,
            system_prompt=_RCA_SYSTEM,
            max_tokens=max_tokens,
            seed=seed,
        )
        if resp.truncated and not resp.text.strip():
            # A reasoning-model generator (e.g. a "thinking" family) can burn the
            # entire budget on hidden <think> content before any JSON is emitted.
            # One retry at 3x the budget, same pattern as the chat judge's retry
            # (bench/faithfulness.py CHAT_JUDGE_RETRY_MAX_TOKENS).
            resp = llm_client.call(
                prompt=prompt, model_digest=model_digest, system_prompt=_RCA_SYSTEM,
                max_tokens=max_tokens * 3, seed=seed,
            )
        parsed = _extract_json_object(resp.text)

        claims: list[Claim] = []
        for raw in parsed.get("claims", []):
            try:
                claims.append(
                    Claim(
                        text=str(raw["text"]),
                        evidence_ids=list(raw["evidence_ids"]),
                        confidence=float(raw.get("confidence", 0.5)),
                    )
                )
            except (KeyError, TypeError, ValueError, ValidationError):
                continue

        return self.create_result(
            root_cause_service=str(parsed.get("root_cause_service", "unknown")),
            probable_cause=str(parsed.get("probable_cause", "")),
            claims=claims,
            contributing_factors=[str(f) for f in parsed.get("contributing_factors", [])],
            allowed_ids=shown_ids,
        )

    def _claim_drop_reason(self, claim: Claim, allowed_ids: set[str]) -> Optional[str]:
        """Return why a claim should be dropped, or None if it is acceptable.

        1. Every cited id must be in `allowed_ids` (for `generate`, the subset
           rendered in the prompt; otherwise the whole pack).
        2. Evidence-service consistency: if the claim's text names a known
           service that none of its cited KPI ids belong to, the claim is
           attributing evidence to the wrong service.
        """
        outside = [e for e in claim.evidence_ids if e not in allowed_ids]
        if outside:
            return f"cites evidence not shown in the prompt: {outside}"

        cited_services = {s for e in claim.evidence_ids if (s := _service_of(e))}
        named = {
            s for s in self.pack_services
            if re.search(rf"\b{re.escape(s)}\b", claim.text, re.IGNORECASE)
        }
        if named and not (named & cited_services):
            return (
                f"names service(s) {sorted(named)} but cites evidence only for "
                f"{sorted(cited_services) or ['(no service)']}"
            )
        return None

    def _validate(
        self, claims: list[Claim], allowed_ids: set[str]
    ) -> tuple[list[Claim], list[str]]:
        valid, reasons = [], []
        for claim in claims:
            reason = self._claim_drop_reason(claim, allowed_ids)
            if reason is None:
                valid.append(claim)
            else:
                reasons.append(f"{claim.text[:70]!r}: {reason}")
        return valid, reasons

    def validate_and_filter_claims(self, claims: list[Claim]) -> tuple[list[Claim], int]:
        """Back-compat wrapper: validate against the full pack, return a count."""
        valid, reasons = self._validate(claims, self.valid_evidence_ids)
        return valid, len(reasons)

    def _resolve_root_cause(
        self, proposed: str, valid_claims: list[Claim]
    ) -> tuple[str, bool, str]:
        """Only present `proposed` as THE root cause if a surviving claim cites
        evidence for it; otherwise "needs_review" / "unknown"."""
        proposed = (proposed or "").strip()
        backed = {s for c in valid_claims for e in c.evidence_ids if (s := _service_of(e))}
        if proposed.lower() in ("", "unknown", "none", "n/a"):
            return "unknown", False, "the model did not identify a specific root-cause service"
        if proposed in backed:
            return proposed, True, ""
        return "needs_review", False, (
            f"the model named {proposed!r} but no surviving claim cites evidence "
            f"for it (services backed by surviving claims: {sorted(backed) or 'none'})"
        )

    def create_result(
        self,
        root_cause_service: str,
        probable_cause: str,
        claims: list[Claim],
        contributing_factors: Optional[list[str]] = None,
        allowed_ids: Optional[set[str]] = None,
    ) -> RCAResult:
        """Create an RCAResult, dropping claims that fail validation and
        verifying the headline `root_cause_service` against what survives.

        `allowed_ids` is the set citations are checked against — the prompt's
        shown subset when called from `generate`, else the whole pack.
        """
        valid_claims, reasons = self._validate(
            claims, allowed_ids if allowed_ids is not None else self.valid_evidence_ids
        )
        resolved, verified, review_reason = self._resolve_root_cause(
            root_cause_service, valid_claims
        )

        try:
            return RCAResult(
                case_id=self.evidence_pack.case_id,
                root_cause_service=resolved,
                proposed_root_cause_service=(root_cause_service or "").strip(),
                root_cause_verified=verified,
                review_reason=review_reason,
                probable_cause=probable_cause,
                contributing_factors=contributing_factors or [],
                claims=valid_claims,
                dropped_claims=len(reasons),
                drop_reasons=reasons,
            )
        except Exception:
            # If schema validation fails, return empty result
            return RCAResult(
                case_id=self.evidence_pack.case_id,
                root_cause_service="unknown",
                proposed_root_cause_service=(root_cause_service or "").strip(),
                probable_cause="",
                claims=[],
                dropped_claims=len(claims),
                drop_reasons=["RCAResult schema validation failed"],
                review_reason="RCAResult schema validation failed",
            )
