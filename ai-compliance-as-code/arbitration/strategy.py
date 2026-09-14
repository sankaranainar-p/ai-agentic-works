"""
arbitration/strategy.py — Protocol for pluggable arbitration strategies.
"""

from __future__ import annotations

from typing import List, Protocol, Sequence, runtime_checkable

from api.schemas import ComplianceFinding


@runtime_checkable
class ArbitrationStrategy(Protocol):
    """Protocol for reconciling and merging findings from multiple detector sources."""

    def arbitrate(
        self,
        static_findings: Sequence[ComplianceFinding],
        llm_findings: Sequence[ComplianceFinding],
    ) -> List[ComplianceFinding]:
        """Arbitrate between findings produced by static and LLM detectors."""
        ...
