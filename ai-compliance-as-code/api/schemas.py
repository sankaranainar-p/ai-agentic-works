"""
api/schemas.py — Pydantic v2 request/response models for the
AI Compliance-as-Code /analyze endpoint.

All models use strict field declarations so that partial JSON from
the LLM is caught at validation time rather than silently missing data.
"""

from __future__ import annotations

import uuid
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Payload sent by the VS Code plugin to POST /analyze."""

    code: str = Field(
        ...,
        description="Raw source code of the file under analysis.",
        min_length=1,
    )
    file_path: str = Field(
        default="untitled",
        description="Path of the file — used for display and language detection.",
    )
    regulation: str = Field(
        default="GDPR",
        description='Active regulation, e.g. "GDPR" or "PCI DSS v4.0".',
    )
    extra_context: Optional[str] = Field(
        default=None,
        description="Optional developer-supplied context: git diff, PR description, etc.",
    )

    @field_validator("regulation")
    @classmethod
    def regulation_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("regulation must not be blank")
        return v.strip()


# ---------------------------------------------------------------------------
# Individual finding
# ---------------------------------------------------------------------------

class ComplianceFinding(BaseModel):
    """One compliance violation found in the analysed file."""

    violation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this finding (UUID).",
    )
    rule_id: str = Field(
        ...,
        description='Regulation article / requirement ID, e.g. "GDPR-Art.32" or "PCI-REQ-3".',
    )
    title: str = Field(..., description="Short human-readable title.")
    severity: Literal["high", "medium", "low"] = Field(
        ..., description="Severity level assigned to this finding."
    )
    severity_override: bool = Field(
        default=False,
        description="True when the LLM escalated severity beyond the rule's default.",
    )
    file: str = Field(
        default="N/A",
        description="File path where the violation was found.",
    )
    line_start: Optional[int] = Field(
        default=None,
        description="First line of the offending code (1-indexed). Null for structural violations.",
        ge=1,
    )
    line_end: Optional[int] = Field(
        default=None,
        description="Last line of the offending code (1-indexed). Null for structural violations.",
        ge=1,
    )
    snippet: Optional[str] = Field(
        default=None,
        description="Up to 10 lines of offending source code.",
    )
    violation: str = Field(
        ..., description="One-sentence description of what is wrong."
    )
    remediation: str = Field(
        ..., description="One-sentence actionable fix."
    )
    references: List[str] = Field(
        default_factory=list,
        description="Regulation article URLs or official guidance links.",
    )
    confidence: float = Field(
        default=1.0,
        description="Confidence score 0–1. Set < 1 by the fallback path when LLM is unavailable.",
        ge=0.0,
        le=1.0,
    )


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class AnalyzeResponse(BaseModel):
    """Response returned by POST /analyze."""

    findings: List[ComplianceFinding] = Field(
        default_factory=list,
        description="Compliance violations found, ordered high → medium → low.",
    )
    llm_unavailable: bool = Field(
        default=False,
        description=(
            "True when the Anthropic API could not be reached and findings were "
            "derived from static analysis only."
        ),
    )
    scanner_hint: dict = Field(
        default_factory=dict,
        description="Raw context_hint dict returned by static_scanner.scan().",
    )
    duration_ms: float = Field(
        default=0.0,
        description="Wall-clock time for the full analysis in milliseconds.",
        ge=0.0,
    )
    regulation: str = Field(
        default="",
        description="The active regulation used for this analysis.",
    )
    file_path: str = Field(
        default="untitled",
        description="The file path that was analysed.",
    )
    llm_provider: str = Field(
        default="none",
        description='Which LLM provider fired: "ollama", "anthropic", or "none" (fallback).',
    )
