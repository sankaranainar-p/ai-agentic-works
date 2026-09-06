"""
tests/test_rca_taxonomy_coverage.py — Locks in that pre/rca.py's
TEMPLATE_RCA has exactly one entry per real fault_class (data/taxonomy.yaml),
so generate_rca() never silently falls through to DEFAULT_RCA for a
supported category, and that each template's content is internally
coherent (not a stale copy-paste from a different category).
"""

from __future__ import annotations

from pre.classifier.taxonomy import fault_classes
from pre.rca import DEFAULT_RCA, TEMPLATE_RCA, generate_rca

REQUIRED_KEYS = {
    "probable_cause",
    "contributing_factors",
    "immediate_actions",
    "long_term_fixes",
    "impact_assessment",
    "estimated_resolution_time",
}


def test_template_rca_covers_every_fault_class_exactly() -> None:
    assert set(TEMPLATE_RCA.keys()) == set(fault_classes())


def test_every_template_has_all_required_fields() -> None:
    for category, template in TEMPLATE_RCA.items():
        missing = REQUIRED_KEYS - set(template.keys())
        assert not missing, f"{category} template missing fields: {missing}"


def test_no_two_templates_share_a_probable_cause() -> None:
    causes = [t["probable_cause"] for t in TEMPLATE_RCA.values()]
    assert len(causes) == len(set(causes)), "duplicate probable_cause across templates"


def test_generate_rca_uses_template_for_every_fault_class() -> None:
    for category in fault_classes():
        rca, source = generate_rca("some alert text", category, "SEV-2")
        assert source == "template", f"{category} did not resolve to a template (got {source})"
        assert rca == TEMPLATE_RCA[category]


def test_generate_rca_falls_back_to_default_for_unknown() -> None:
    rca, source = generate_rca("some alert text", "unknown", "SEV-3")
    assert source == "default"
    assert rca == DEFAULT_RCA
