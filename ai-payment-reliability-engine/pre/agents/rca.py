"""
pre/agents/rca.py — RCA agent producing structured RCAResult with validated claims.

Every claim is grounded in at least one evidence ID from the evidence pack.
Claims with unknown evidence IDs are dropped, and the drop count is recorded.

Schema enforced with Pydantic for type safety and validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from pre.agents.evidence import EvidencePack


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
    """Root Cause Analysis result with validated claims."""

    case_id: str
    root_cause_service: str
    probable_cause: str
    contributing_factors: list[str] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    dropped_claims: int = 0  # Number of claims dropped due to missing evidence


# ---------------------------------------------------------------------------
# RCA Agent
# ---------------------------------------------------------------------------

class RCAAgent:
    """Generates RCA with evidence-grounded claims."""

    def __init__(self, evidence_pack: EvidencePack):
        self.evidence_pack = evidence_pack
        self.valid_evidence_ids = {item.id for item in evidence_pack.items}

    def validate_and_filter_claims(self, claims: list[Claim]) -> tuple[list[Claim], int]:
        """Filter claims to keep only those with valid evidence IDs.

        Returns:
            (valid_claims, dropped_count)
        """
        valid_claims = []
        dropped = 0

        for claim in claims:
            # Check if all evidence IDs are in the pack
            has_valid_evidence = all(
                eid in self.valid_evidence_ids for eid in claim.evidence_ids
            )

            if has_valid_evidence:
                valid_claims.append(claim)
            else:
                dropped += 1

        return valid_claims, dropped

    def create_result(
        self,
        root_cause_service: str,
        probable_cause: str,
        claims: list[Claim],
        contributing_factors: Optional[list[str]] = None,
    ) -> RCAResult:
        """Create an RCAResult with evidence-validated claims.

        Claims with unknown evidence IDs are filtered out and counted.
        """
        valid_claims, dropped_count = self.validate_and_filter_claims(claims)

        try:
            return RCAResult(
                case_id=self.evidence_pack.case_id,
                root_cause_service=root_cause_service,
                probable_cause=probable_cause,
                contributing_factors=contributing_factors or [],
                claims=valid_claims,
                dropped_claims=dropped_count,
            )
        except Exception as e:
            # If schema validation fails, return empty result
            return RCAResult(
                case_id=self.evidence_pack.case_id,
                root_cause_service="unknown",
                probable_cause="",
                claims=[],
                dropped_claims=len(claims),
            )
