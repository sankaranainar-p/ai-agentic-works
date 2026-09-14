"""
arbitration — Reconciling findings from multiple compliance detectors.
"""

from arbitration.fixed_confidence import FixedConfidenceMerge
from arbitration.strategy import ArbitrationStrategy

__all__ = ["ArbitrationStrategy", "FixedConfidenceMerge"]
