"""
detectors/static.py — Static regex scanner detector implementing the Detector protocol.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from api.fallback import build_fallback_findings
from api.schemas import ComplianceFinding
from scanner.static_scanner import scan


class StaticScannerDetector:
    """Regex-based static scanner detector returning fallback compliance findings."""

    def detect(
        self,
        code: str,
        *,
        file_path: str = "untitled",
        regulation: str = "GDPR",
        extra_context: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        """Scan code using regex pattern matching and return compliance findings."""
        hint = scan(code, file_path=file_path)
        return self.detect_with_hint(code, hint, file_path=file_path)

    def detect_with_hint(
        self,
        code: str,
        hint: Dict[str, Any],
        *,
        file_path: str = "untitled",
    ) -> List[ComplianceFinding]:
        """Convert a pre-computed static_scanner hint into compliance findings."""
        return build_fallback_findings(hint, file_path=file_path)


# Alias for ergonomic imports
StaticDetector = StaticScannerDetector
