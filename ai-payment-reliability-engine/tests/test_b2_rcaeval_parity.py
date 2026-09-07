"""
tests/test_b2_rcaeval_parity.py — THE critical gate for A14: B2 (RCAEval's
BARO baseline) must reproduce the published RCAEval README table on
RE2-TT, run through OUR pre.signals.rcaeval.RCAEvalAdapter and
bench.baselines.rcaeval_baseline's data path, not RCAEval's own raw CSV
loader. If these numbers don't match, the adapter (not the baseline) is
wrong, and nothing downstream in the benchmark harness can be trusted.

Published table (RCAEval README, "python main.py --method baro --dataset
re2-tt --length 20"):
    Avg@5-CPU:    0.72
    Avg@5-MEM:    0.99
    Avg@5-DISK:   1.0
    Avg@5-SOCKET: 0.83
    Avg@5-DELAY:  0.63
    Avg@5-LOSS:   0.64

This test requires:
  1. `RCAEval.e2e.baro` importable (RCAEval installed with its `[default]`
     extras, which need Python 3.12/3.14 per RCAEval's own requirement --
     see CONVERSION.md). Note this checks `RCAEval.e2e.baro` specifically,
     not bare `import RCAEval`: RCAEval.e2e transitively imports
     matplotlib, torch, etc., so a bare `import RCAEval` can succeed while
     `from RCAEval.e2e import baro` still fails on a missing transitive
     dependency in whatever interpreter happens to have a stray `pip
     install RCAEval` in it without the `[default]` extras. This bit us
     once already: `import RCAEval` had been run in this project's normal
     Python 3.9 environment for unrelated research earlier in development
     and never uninstalled, so importorskip("RCAEval") stopped skipping,
     yet the test still couldn't actually run BARO -- it just failed
     later, after already paying the ~10 minute cost of loading all 90
     RE2-TT cases' logs/traces. Checking the real needed import up front
     avoids both problems: it skips correctly in a bare `import RCAEval`
     environment, and it fails fast (before any dataset I/O) if RCAEval
     is present but broken.
  2. The full real RE2-TT dataset downloaded via
     data/scripts/download_rcaeval.py --dataset RE2-TT (2.8GB) into
     RCAEVAL_RE2TT_DIR (env var) or data/rcaeval/RE2-TT by default.

Both are opt-in and skipped by default so the main test suite (and CI)
runs fast without a multi-gigabyte download or a second Python interpreter.
Run explicitly with:
    RCAEVAL_RE2TT_DIR=/path/to/RE2-TT python -m pytest tests/test_b2_rcaeval_parity.py -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Check the actual symbol bench.baselines.rcaeval_baseline.rank() needs,
# not bare `import RCAEval` -- see the module docstring for why that
# distinction matters (matplotlib/torch import chain inside RCAEval.e2e).
pytest.importorskip(
    "RCAEval.e2e",
    reason="RCAEval.e2e not importable (RCAEval[default] extras, Python 3.12/3.14 required — see CONVERSION.md)",
)

from bench.baselines.rcaeval_baseline import rank as b2_rank  # noqa: E402
from bench.metrics import average_at_k  # noqa: E402
from pre.signals.rcaeval import RCAEvalAdapter  # noqa: E402

_DEFAULT_RE2TT_DIR = Path(__file__).parent.parent / "data" / "rcaeval" / "RE2-TT"
_RE2TT_DIR = Path(os.environ.get("RCAEVAL_RE2TT_DIR", _DEFAULT_RE2TT_DIR))

pytestmark = pytest.mark.skipif(
    not _RE2TT_DIR.is_dir(),
    reason=(
        f"Full RE2-TT dataset not found at {_RE2TT_DIR}. Download it with "
        "`python data/scripts/download_rcaeval.py --dataset RE2-TT` "
        "(2.8GB) or set RCAEVAL_RE2TT_DIR to an existing extraction, then "
        "re-run this test explicitly."
    ),
)

# Published RCAEval README table for `python main.py --method baro --dataset re2-tt --length 20`
PUBLISHED_AVG_AT_5 = {
    "cpu": 0.72,
    "memory": 0.99,
    "disk": 1.0,
    "socket": 0.83,
    "delay": 0.63,
    "loss": 0.64,
}

TOLERANCE = 0.02  # published table is rounded to 2 decimals


def test_b2_reproduces_published_rcaeval_table_on_re2_tt():
    root = _RE2TT_DIR.parent
    adapter = RCAEvalAdapter(root, "RE2-TT")
    cases = list(adapter)
    assert len(cases) == 90, f"expected 90 RE2-TT cases, got {len(cases)}"

    per_fault_ranked_answers: dict[str, list] = {ft: [] for ft in PUBLISHED_AVG_AT_5}

    for case, gt in cases:
        ranks = b2_rank(case, inject_time=gt.inject_time)
        per_fault_ranked_answers[gt.fault_type].append((ranks, gt.root_cause_service))

    mismatches = []
    for fault_type, published in PUBLISHED_AVG_AT_5.items():
        ranked_answers = per_fault_ranked_answers[fault_type]
        assert ranked_answers, f"no cases collected for fault_type={fault_type}"
        observed = average_at_k(ranked_answers, k=5)
        if abs(observed - published) > TOLERANCE:
            mismatches.append((fault_type, published, observed))

    assert not mismatches, (
        "B2 (RCAEval BARO via our adapter) does not match the published "
        f"RCAEval table within tolerance {TOLERANCE}: {mismatches}. "
        "Do not proceed with A14 baselines if this fails -- it means "
        "pre.signals.rcaeval or bench.baselines.rcaeval_baseline's data "
        "path diverges from RCAEval's own, not that BARO itself is wrong."
    )
