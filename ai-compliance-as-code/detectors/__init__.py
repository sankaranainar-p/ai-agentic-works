"""
detectors — Standalone compliance detectors implementing the Detector protocol.
"""

from detectors.base import Detector
from detectors.llm import LLMDetector
from detectors.static import StaticDetector, StaticScannerDetector

__all__ = ["Detector", "StaticScannerDetector", "StaticDetector", "LLMDetector"]

