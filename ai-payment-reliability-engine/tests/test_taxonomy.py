"""
tests/test_taxonomy.py — Validates data/taxonomy.yaml: every SLI
referenced in `sli_map` must exist in the top-level `payment_sli` list,
and the shared taxonomy loader used by both classifiers stays in sync
with the YAML.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from pre.classifier.taxonomy import all_categories, fault_classes, payment_slis, sli_map

_TAXONOMY_PATH = Path(__file__).parent.parent / "data" / "taxonomy.yaml"


def _load_raw() -> dict:
    with _TAXONOMY_PATH.open() as fh:
        return yaml.safe_load(fh)


def test_every_sli_map_value_exists_in_payment_sli() -> None:
    data = _load_raw()
    valid_slis = set(data["payment_sli"])
    assert valid_slis, "payment_sli must not be empty"

    missing: list[str] = []
    for system, mapping in data["sli_map"].items():
        for service_metric, sli in mapping.items():
            if sli not in valid_slis:
                missing.append(f"{system}.{service_metric} -> {sli!r}")

    assert not missing, f"sli_map references undefined SLI(s): {missing}"


def test_sli_map_covers_all_five_target_systems() -> None:
    data = _load_raw()
    expected_systems = {
        "online_boutique",
        "sock_shop",
        "train_ticket",
        "openrca_bank",
        "otel_demo",
    }
    assert expected_systems.issubset(data["sli_map"].keys())


def test_fault_class_has_no_duplicates_and_matches_loader() -> None:
    data = _load_raw()
    raw_classes = data["fault_class"]
    assert len(raw_classes) == len(set(raw_classes)), "fault_class has duplicates"
    assert fault_classes() == raw_classes


def test_payment_sli_matches_loader() -> None:
    data = _load_raw()
    assert payment_slis() == data["payment_sli"]


def test_all_categories_appends_unknown_fallback() -> None:
    categories = all_categories()
    assert categories[-1] == "unknown"
    assert set(fault_classes()).issubset(set(categories))


def test_sli_map_loader_matches_yaml() -> None:
    data = _load_raw()
    assert sli_map() == data["sli_map"]
