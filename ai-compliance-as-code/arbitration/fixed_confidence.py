"""
arbitration/fixed_confidence.py — FixedConfidenceMerge baseline arbitration strategy.

Implements the baseline arbitration logic:
  - LLM confidence 1.0, static scanner confidence 0.6 / 0.4.
  - Conflict detection: exact rule_id match + title similarity >= 0.80 (via SequenceMatcher).
  - Higher confidence wins; ties keep the earlier finding.
  - Emits one structured event per arbitration decision to the configured AuditSink.
"""

from __future__ import annotations

import difflib
from typing import Any, Dict, List, Optional, Sequence

from api.schemas import ComplianceFinding
from audit.sink import AuditSink, NullAuditSink

_DEFAULT_TITLE_SIMILARITY_THRESHOLD = 0.80
_SEV_ORDER: Dict[str, int] = {"high": 0, "medium": 1, "low": 2}


class FixedConfidenceMerge:
    """Baseline arbitration strategy using fixed confidence weighting and SequenceMatcher title similarity."""

    def __init__(
        self,
        audit_sink: Optional[AuditSink] = None,
        title_similarity_threshold: float = _DEFAULT_TITLE_SIMILARITY_THRESHOLD,
    ) -> None:
        self.audit_sink: AuditSink = audit_sink if audit_sink is not None else NullAuditSink()
        self.title_similarity_threshold: float = title_similarity_threshold

    def arbitrate(
        self,
        static_findings: Sequence[ComplianceFinding],
        llm_findings: Sequence[ComplianceFinding],
    ) -> List[ComplianceFinding]:
        """Reconcile findings from static and LLM detectors.

        When LLM findings are present (LLM succeeded), LLM findings (confidence 1.0)
        are merged with static findings (confidence 0.6/0.4).
        When LLM findings are empty (LLM failed/unavailable), only static findings
        are deduplicated.
        """
        if llm_findings:
            combined = list(llm_findings) + list(static_findings)
        else:
            combined = list(static_findings)

        return self.deduplicate(combined)

    def deduplicate(
        self,
        findings: Sequence[ComplianceFinding],
    ) -> List[ComplianceFinding]:
        """Remove near-duplicate findings from a findings list.

        Two findings are considered duplicates when:
          1. They share the same rule_id (exact match), AND
          2. Their titles have SequenceMatcher similarity >= title_similarity_threshold (0.80).

        When a duplicate pair is found, the finding with higher confidence is kept.
        If confidence is equal, the earlier finding (lower index) wins.
        """
        kept: List[ComplianceFinding] = []

        for candidate in findings:
            duplicate_index: int = -1
            matched_similarity: float = 0.0

            for i, existing in enumerate(kept):
                if existing.rule_id != candidate.rule_id:
                    continue
                similarity = difflib.SequenceMatcher(
                    None, existing.title.lower(), candidate.title.lower()
                ).ratio()
                if similarity >= self.title_similarity_threshold:
                    duplicate_index = i
                    matched_similarity = similarity
                    break

            if duplicate_index == -1:
                kept.append(candidate)
                candidate_detector = "llm" if candidate.confidence >= 1.0 else "static"
                # Emit decision: finding accepted uncontested
                self.audit_sink.emit({
                    "action": "accepted_uncontested",
                    "finding_id": candidate.violation_id,
                    "rule_id": candidate.rule_id,
                    "title": candidate.title,
                    "confidence": candidate.confidence,
                    "winning_detector": candidate_detector,
                    "decision_rationale": f"Finding for rule '{candidate.rule_id}' accepted without conflict.",
                    "rationale": f"Finding for rule '{candidate.rule_id}' accepted without conflict.",
                    "source_file": candidate.file,
                })
            else:
                existing = kept[duplicate_index]
                candidate_detector = "llm" if candidate.confidence >= 1.0 else "static"
                existing_detector = "llm" if existing.confidence >= 1.0 else "static"

                if candidate.confidence > existing.confidence:
                    kept[duplicate_index] = candidate
                    # Emit decision: candidate replaced existing due to higher confidence
                    self.audit_sink.emit({
                        "action": "superseded_existing",
                        "winner_id": candidate.violation_id,
                        "loser_id": existing.violation_id,
                        "rule_id": candidate.rule_id,
                        "candidate_title": candidate.title,
                        "existing_title": existing.title,
                        "candidate_confidence": candidate.confidence,
                        "existing_confidence": existing.confidence,
                        "original_confidences": {
                            "candidate": candidate.confidence,
                            "existing": existing.confidence,
                        },
                        "similarity": matched_similarity,
                        "winning_detector": candidate_detector,
                        "losing_detector": existing_detector,
                        "decision_rationale": (
                            f"Candidate finding from '{candidate_detector}' (confidence {candidate.confidence}) "
                            f"superseded existing finding from '{existing_detector}' (confidence {existing.confidence}) "
                            f"matching rule '{candidate.rule_id}' (title similarity {matched_similarity:.2f} >= {self.title_similarity_threshold:.2f})."
                        ),
                        "rationale": (
                            f"Candidate finding from '{candidate_detector}' (confidence {candidate.confidence}) "
                            f"superseded existing finding from '{existing_detector}' (confidence {existing.confidence}) "
                            f"matching rule '{candidate.rule_id}' (title similarity {matched_similarity:.2f} >= {self.title_similarity_threshold:.2f})."
                        ),
                    })
                else:
                    # Emit decision: candidate discarded; existing retained
                    self.audit_sink.emit({
                        "action": "candidate_discarded",
                        "winner_id": existing.violation_id,
                        "loser_id": candidate.violation_id,
                        "rule_id": candidate.rule_id,
                        "candidate_title": candidate.title,
                        "existing_title": existing.title,
                        "candidate_confidence": candidate.confidence,
                        "existing_confidence": existing.confidence,
                        "original_confidences": {
                            "candidate": candidate.confidence,
                            "existing": existing.confidence,
                        },
                        "similarity": matched_similarity,
                        "winning_detector": existing_detector,
                        "losing_detector": candidate_detector,
                        "decision_rationale": (
                            f"Existing finding from '{existing_detector}' (confidence {existing.confidence}) "
                            f"retained over candidate finding from '{candidate_detector}' (confidence {candidate.confidence}) "
                            f"matching rule '{candidate.rule_id}' (title similarity {matched_similarity:.2f} >= {self.title_similarity_threshold:.2f})."
                        ),
                        "rationale": (
                            f"Existing finding from '{existing_detector}' (confidence {existing.confidence}) "
                            f"retained over candidate finding from '{candidate_detector}' (confidence {candidate.confidence}) "
                            f"matching rule '{candidate.rule_id}' (title similarity {matched_similarity:.2f} >= {self.title_similarity_threshold:.2f})."
                        ),
                    })

        kept.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))
        return kept
