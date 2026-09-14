"""
detectors/base.py — Protocol for compliance detectors.
"""

from __future__ import annotations

from typing import List, Optional, Protocol, runtime_checkable

from api.schemas import ComplianceFinding


@runtime_checkable
class Detector(Protocol):
    """Protocol for standalone compliance detectors."""

    def detect(
        self,
        code: str,
        *,
        file_path: str = "untitled",
        regulation: str = "GDPR",
        extra_context: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        """Analyze code for compliance violations and return finding objects."""
        ...
