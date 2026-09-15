"""
tests/test_reconstruction.py — Unit tests for Contribution C3: Audit
Sufficiency & Verdict Reconstructability Benchmark.

Verifies:
  1. Clean-room isolation: no raw source-code token (variable/function name)
     leaks into a built AuditRecord.
  2. Exact-match logic: a verdict must align on article AND severity AND
     target to count as a match — including the case where article matches
     but severity or target does not (this is the specific gap fixed in
     audit/reconstruction.py's matches_ground_truth: it previously only
     checked article+target via independent set intersections and never
     enforced severity at all).
  3. Permutation degradation: Delta_rec = Accuracy(V(R)) - Accuracy(V(R_permuted)) > 0,
     proving reconstruction is driven by each record's own evidence, not a
     fixed label prior the verifier could apply regardless of R's content.
  4. Backward ablation stopping criteria: decision_provenance is prunable
     (>=90% retention) while evidence_graph/static_predicates are not.
  5. Fallback-mode reconstructability: a simulated-timeout/abstain record
     reconstructs to the defer_to_human verdict.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from audit.reconstruction import (
    ARTICLE_METADATA,
    AuditRecord,
    CandidateViolation,
    IdentifierAnonymizer,
    ReconstructionVerifier,
    build_audit_record,
    ground_truth_metadata,
)
from harness.paper_artifacts import (
    DEFAULT_ABLATION,
    SYNTHETIC_40_ABLATION,
    generate_table5_latex,
)
from harness.reconstruction_bench import (
    evaluate_fallback_reconstructability,
    evaluate_records,
    load_or_create_audit_records,
    run_backward_ablation,
    run_permutation_baseline,
    run_reconstruction_benchmark,
)
from harness.validate_latex import validate_latex_content

# A realistic snippet with distinctive raw identifiers that must never
# appear in the anonymized record: a function name, and two variable names
# (one carrying "password", one carrying "email" — both trip static
# predicates, so this snippet also exercises real evidence_graph content).
_RAW_CODE = """
public class PaymentDataSyncHandler {
    public void transmitUserCredentials(String userPasswordToken, String userEmailAddress) {
        String userPasswordToken = "hunter2";
        String userEmailAddress = "user@example.com";
        new URL("http://payments.internal/sync").openConnection();
        logAnalyticsEvent(userEmailAddress);
    }
}
"""


# --------------------------------------------------------------------------- #
# 1. Clean-room isolation
# --------------------------------------------------------------------------- #

def test_clean_room_isolation_no_raw_tokens_leak():
    record, raw_identifiers = build_audit_record(
        code=_RAW_CODE, ground_truth=[32], routing_action="symbolic",
    )

    # Sanity: the regex extractor actually found real raw identifiers to
    # test against — otherwise this test would pass vacuously.
    assert "transmitUserCredentials" in raw_identifiers
    assert "userPasswordToken" in raw_identifiers
    assert "userEmailAddress" in raw_identifiers

    serialized = record.to_json()
    for token in raw_identifiers:
        assert token not in serialized, f"raw identifier {token!r} leaked into AuditRecord"

    ok, leaked = IdentifierAnonymizer.audit_clean_room(record, raw_identifiers)
    assert ok is True
    assert leaked == []


def test_clean_room_isolation_evidence_graph_uses_anonymized_tokens():
    """The evidence graph must still carry real, distinguishing signal
    (var_N/fn_N/sink_* nodes) — clean-room isolation is about WHICH names
    are used, not about emitting an empty graph."""
    record, _ = build_audit_record(code=_RAW_CODE, ground_truth=[32])
    node_ids = {n["id"] for n in record.evidence_graph["nodes"]}
    assert any(nid.startswith("var_") for nid in node_ids)
    assert "sink_http" in node_ids


def test_clean_room_isolation_detects_a_real_leak():
    """The audit_clean_room helper must actually be able to fail — otherwise
    the "no leak" assertions above aren't proof of anything."""
    record, _ = build_audit_record(code=_RAW_CODE, ground_truth=[32])
    # Force a leak: inject a raw token directly into the record.
    record.decision_provenance["leaked_debug_field"] = "transmitUserCredentials"
    ok, leaked = IdentifierAnonymizer.audit_clean_room(record, ["transmitUserCredentials"])
    assert ok is False
    assert "transmitUserCredentials" in leaked


# --------------------------------------------------------------------------- #
# 2. Exact-match logic (article AND severity AND target)
# --------------------------------------------------------------------------- #

def test_exact_match_all_three_align():
    verdict = [CandidateViolation(32, "high", "security_processing", 0.9, "x")]
    assert ReconstructionVerifier.matches_ground_truth(verdict, [32]) is True


def test_exact_match_fails_on_wrong_article():
    verdict = [CandidateViolation(5, "medium", "data_minimisation", 0.9, "x")]
    assert ReconstructionVerifier.matches_ground_truth(verdict, [32]) is False


def test_exact_match_fails_on_right_article_wrong_severity():
    """Regression test for the bug this task's implementation had: severity
    was part of CandidateViolation but never actually checked by
    matches_ground_truth. A candidate with the correct article but the
    wrong severity must NOT count as a match."""
    verdict = [CandidateViolation(32, "low", "security_processing", 0.9, "x")]
    assert ReconstructionVerifier.matches_ground_truth(verdict, [32]) is False


def test_exact_match_fails_on_right_article_wrong_target():
    """Same regression, for target: article 32's correct target is
    "security_processing" (ARTICLE_METADATA) — a candidate claiming the
    right article but a mismatched target must not match."""
    verdict = [CandidateViolation(32, "high", "data_minimisation", 0.9, "x")]
    assert ReconstructionVerifier.matches_ground_truth(verdict, [32]) is False


def test_exact_match_does_not_cross_pollinate_across_candidates():
    """Two candidates, each individually wrong, must not combine into a
    false match via independent set-intersection (the specific failure mode
    of the pre-fix implementation: article from one candidate + target from
    a different candidate would have passed)."""
    verdict = [
        CandidateViolation(32, "high", "data_minimisation", 0.9, "x"),   # right article, wrong target
        CandidateViolation(5, "medium", "security_processing", 0.9, "x"),  # wrong article, "right" target string
    ]
    assert ReconstructionVerifier.matches_ground_truth(verdict, [32]) is False


def test_ground_truth_metadata_matches_verifier_rules():
    """ARTICLE_METADATA (used for ground truth) and the verifier's own
    deduction rules must never drift apart — this just confirms they still
    share the same table after the refactor."""
    for article in (32, 5, 25, 6):
        meta = ground_truth_metadata(article)
        assert meta["severity"] == ARTICLE_METADATA[article]["severity"]
        assert meta["target"] == ARTICLE_METADATA[article]["target"]


def test_fallback_ground_truth_matches_defer_candidate():
    verdict = [CandidateViolation(0, "high", "defer_to_human", 0.5, "x")]
    assert ReconstructionVerifier.matches_ground_truth(verdict, [0]) is True


# --------------------------------------------------------------------------- #
# 3. Permutation degradation (Delta_rec > 0)
# --------------------------------------------------------------------------- #

def test_permutation_degrades_accuracy():
    records, ground_truths = load_or_create_audit_records(use_synthetic=True)
    acc_intact = evaluate_records(records, ground_truths)
    acc_permuted, permuted_records = run_permutation_baseline(records, ground_truths, seed=42)

    assert acc_intact > acc_permuted, (
        f"expected intact accuracy ({acc_intact}) > permuted accuracy ({acc_permuted}) — "
        "otherwise reconstruction isn't actually driven by each record's own evidence"
    )
    delta_rec = acc_intact - acc_permuted
    assert delta_rec > 0

    # The permutation must actually have moved evidence_graph/static_predicates
    # for at least one instance (a no-op "permutation" would be meaningless).
    changed = sum(
        1 for orig, perm in zip(records, permuted_records)
        if orig.evidence_graph != perm.evidence_graph
    )
    assert changed > 0


def test_full_benchmark_reports_positive_delta_rec(tmp_path: Path):
    metrics = run_reconstruction_benchmark(output_dir=tmp_path, use_synthetic=True, seed=42)
    assert metrics["delta_rec"] > 0
    assert metrics["intact_accuracy"] > metrics["permuted_accuracy"]
    assert (tmp_path / "metrics.json").exists()
    assert (tmp_path / "summary.md").exists()


# --------------------------------------------------------------------------- #
# 4. Backward ablation stopping criteria
# --------------------------------------------------------------------------- #

def test_backward_ablation_identifies_static_predicates_as_load_bearing():
    """On the synthetic fixture, static_predicates is the only field whose
    removal actually costs accuracy — decision_provenance never contains
    rule_id (see module docstring / audit/reconstruction.py's design note),
    and evidence_graph's triples are a redundant fallback signal the
    verifier's rules also check via static_predicates directly (e.g. Rule 1
    fires on hint_unencrypted_http_outbound OR an http-sink triple) — so
    both are individually prunable at >=90% retention while
    static_predicates is not."""
    records, ground_truths = load_or_create_audit_records(use_synthetic=True)
    acc_intact = evaluate_records(records, ground_truths)
    steps = run_backward_ablation(records, ground_truths, acc_intact)

    by_field = {s["dropped_field"]: s for s in steps if s["dropped_field"] != "None"}

    assert by_field["decision_provenance"]["retention_pct"] >= 90.0
    assert by_field["decision_provenance"]["is_minimal"] is True

    assert by_field["evidence_graph"]["retention_pct"] >= 90.0
    assert by_field["evidence_graph"]["is_minimal"] is True

    assert by_field["static_predicates"]["retention_pct"] < 90.0
    assert by_field["static_predicates"]["is_minimal"] is False


def test_backward_ablation_retention_curve_is_well_formed():
    records, ground_truths = load_or_create_audit_records(use_synthetic=True)
    acc_intact = evaluate_records(records, ground_truths)
    steps = run_backward_ablation(records, ground_truths, acc_intact)

    assert steps[0]["dropped_field"] == "None"
    assert steps[0]["accuracy"] == pytest.approx(acc_intact)
    assert steps[0]["retention_pct"] == 100.0

    for step in steps:
        assert 0.0 <= step["accuracy"] <= 1.0
        assert 0.0 <= step["retention_pct"] <= 100.0 + 1e-9


# --------------------------------------------------------------------------- #
# 5. Fallback mode
# --------------------------------------------------------------------------- #

def test_fallback_mode_reconstructs_defer_to_human():
    result = evaluate_fallback_reconstructability(n_samples=10)
    assert result["n_samples"] == 10
    assert result["reconstruction_accuracy"] == 1.0
    assert result["deferral_reconstructed"] is True


def test_abstain_record_reconstructs_to_defer_before_matching():
    record, _ = build_audit_record(code="public void x() {}", routing_action="abstain", status="deferred_to_human")
    verdict = ReconstructionVerifier().verify(record)
    assert len(verdict) == 1
    assert verdict[0].target == "defer_to_human"
    assert ReconstructionVerifier.matches_ground_truth(verdict, [0]) is True


# --------------------------------------------------------------------------- #
# 6. Table 5 Publication Artifact & LaTeX Validation
# --------------------------------------------------------------------------- #

def test_table5_latex_validates_without_errors():
    tex_default = generate_table5_latex(DEFAULT_ABLATION, sample_count=887)
    errors_default = validate_latex_content(tex_default, filename="table5_default.tex")
    assert errors_default == []

    tex_synth = generate_table5_latex(SYNTHETIC_40_ABLATION, sample_count=40)
    errors_synth = validate_latex_content(tex_synth, filename="table5_synth.tex")
    assert errors_synth == []


def test_table5_latex_contains_required_booktabs_and_preliminary_caveat():
    tex = generate_table5_latex(SYNTHETIC_40_ABLATION, sample_count=40)
    assert r"\toprule" in tex
    assert r"\midrule" in tex
    assert r"\bottomrule" in tex
    assert "N=40" in tex
    assert r"\textit{Note: Preliminary sample evaluation ($N=40$); final results await completion of full benchmark run.}" in tex
    assert r"\checkmark" in tex

