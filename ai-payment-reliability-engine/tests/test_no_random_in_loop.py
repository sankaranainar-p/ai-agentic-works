"""
tests/test_no_random_in_loop.py — (A20 adversarial review, item 1) guards
against random.random()-based resolution/breach logic ever reappearing in
the live detection/verification path.

pre/verification.py and pre/monitor.py already replaced their earlier
random.random()-based simulation with NotImplementedError stubs (see
tests/test_verification_stub.py) before this repository's current tree
existed; no app/ directory with such logic exists now or anywhere in git
history. This test locks that in going forward by asserting the `random`
module is never imported anywhere under pre/verify/ or pre/signals/ — the
packages that own breach detection (pre.verify.kpi_verifier) and the
telemetry/case adapters (pre.signals.*).

AST-based rather than a text grep: a docstring mentioning "random.random()"
(e.g. to document that it was removed, as tests/test_verification_stub.py
does) must not fail this test; only a real `import random` / `from random
import ...` statement should.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGES = ("pre/verify", "pre/signals")


def _imports_random(path: Path) -> bool:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "random" or alias.name.startswith("random.") for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "random" or (node.module or "").startswith("random."):
                return True
    return False


def test_no_random_import_under_verify_and_signals() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    checked = []
    offenders = []

    for package in PACKAGES:
        package_dir = repo_root / package
        assert package_dir.is_dir(), f"expected package directory {package_dir} to exist"
        for py_file in sorted(package_dir.rglob("*.py")):
            checked.append(py_file)
            if _imports_random(py_file):
                offenders.append(py_file)

    assert checked, "expected to find at least one .py file under pre/verify and pre/signals"
    assert not offenders, (
        f"random module imported in files that must not use it for "
        f"resolution/breach logic: {[str(f) for f in offenders]}"
    )
