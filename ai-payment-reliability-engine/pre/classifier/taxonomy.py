"""
pre/classifier/taxonomy.py — Single source of truth for the fault
taxonomy shared by the ML classifier (pre/classifier/model.py) and the
LLM classifier (pre/classifier/llm.py).

Both classifiers import `FAULT_CLASSES` (and `ALL_CATEGORIES`, which adds
the operational "unknown" fallback bucket) from here instead of hardcoding
their own category lists. This guarantees the LLM prompt can never name a
category the ML side does not also support, and vice versa.

The taxonomy itself lives in data/taxonomy.yaml. `fault_class` values are
drawn only from RCAEval (RE1/RE2 resource + network faults, RE3 code-level
faults) and OpenRCA ground-truth labels — see that file's header comment
for the full provenance. `payment_sli` and `sli_map` are also loaded here
for use by the evaluation protocol (see PROTOCOL.md) and are re-exported
for convenience even though the live classifiers only consume
`fault_class`.

"unknown" is intentionally NOT part of data/taxonomy.yaml's fault_class
list (it is not a ground-truth fault label) but is appended in code as the
classifier's low-confidence / no-match fallback bucket.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import yaml

_TAXONOMY_PATH = Path(__file__).parent.parent.parent / "data" / "taxonomy.yaml"

UNKNOWN_CATEGORY = "unknown"

_lock = threading.Lock()
_cache: dict[str, Any] | None = None


def _load() -> dict[str, Any]:
    global _cache
    if _cache is None:
        with _lock:
            if _cache is None:
                with _TAXONOMY_PATH.open() as fh:
                    _cache = yaml.safe_load(fh)
    return _cache


def fault_classes() -> list[str]:
    """Ground-truth fault_class values from data/taxonomy.yaml."""
    return list(_load()["fault_class"])


def payment_slis() -> list[str]:
    """Payment SLI values from data/taxonomy.yaml."""
    return list(_load()["payment_sli"])


def sli_map() -> dict[str, dict[str, str]]:
    """Per-system service+metric -> SLI mapping from data/taxonomy.yaml."""
    return dict(_load()["sli_map"])


def all_categories() -> list[str]:
    """fault_class values plus the operational 'unknown' fallback bucket.

    This is the category list both classifiers should train/predict/parse
    against.
    """
    return fault_classes() + [UNKNOWN_CATEGORY]
