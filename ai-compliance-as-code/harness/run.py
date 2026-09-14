"""
harness/run.py — CLI entrypoint for running compliance detectors standalone.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

# Bootstrap project root
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.schemas import ComplianceFinding
from detectors import LLMDetector, StaticScannerDetector


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Standalone Compliance Detector CLI Runner")
    parser.add_argument(
        "--detector",
        choices=["static", "llm"],
        required=True,
        help="Detector to execute: 'static' or 'llm'",
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to source code file to analyze",
    )
    parser.add_argument(
        "--regulation",
        type=str,
        default="GDPR",
        help="Regulation name (default: GDPR)",
    )
    parser.add_argument(
        "--extra-context",
        type=str,
        default=None,
        help="Optional extra context (diff, notes, etc.)",
    )
    return parser.parse_args(args)


def run_detector(
    detector_name: str,
    input_path: str,
    regulation: str = "GDPR",
    extra_context: str | None = None,
) -> List[ComplianceFinding]:
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    code = path.read_text(encoding="utf-8")

    if detector_name == "static":
        detector = StaticScannerDetector()
        return detector.detect(code, file_path=str(path), regulation=regulation)
    elif detector_name == "llm":
        detector = LLMDetector()
        return detector.detect(
            code,
            file_path=str(path),
            regulation=regulation,
            extra_context=extra_context,
        )
    else:
        raise ValueError(f"Unknown detector: {detector_name}")


def main() -> None:
    args = parse_args()
    findings = run_detector(
        detector_name=args.detector,
        input_path=args.input,
        regulation=args.regulation,
        extra_context=args.extra_context,
    )
    serialized = [f.model_dump() for f in findings]
    print(json.dumps(serialized, indent=2))


if __name__ == "__main__":
    main()
