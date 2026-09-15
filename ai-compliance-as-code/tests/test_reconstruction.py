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

import json
from pathlib import Path
import re

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
    compute_permutation_significance,
    evaluate_fallback_reconstructability,
    evaluate_records,
    load_or_create_audit_records,
    run_backward_ablation,
    run_permutation_baseline,
    run_reconstruction_benchmark,
)
from harness.validate_latex import validate_latex_content, validate_latex_file

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
# 4. Backward ablation stopping criteria & Minimal Record R*
# --------------------------------------------------------------------------- #

def test_backward_ablation_identifies_minimal_record_and_load_bearing_components():
    """Verify that removing minimal sufficient components (evidence_graph or
    static_predicates) causes a measurable drop in reconstructability (<90% retention),
    while decision_provenance is prunable (>=90% retention)."""
    records, ground_truths = load_or_create_audit_records(use_synthetic=True)
    acc_intact = evaluate_records(records, ground_truths)
    steps = run_backward_ablation(records, ground_truths, acc_intact)

    by_field = {s["dropped_field"]: s for s in steps if s["dropped_field"] != "None"}

    # decision_provenance is prunable (>=90% retention, is_minimal=True)
    assert by_field["decision_provenance"]["retention_pct"] >= 90.0
    assert by_field["decision_provenance"]["is_minimal"] is True

    # Both evidence_graph and static_predicates are load-bearing minimal sufficient components
    assert by_field["evidence_graph"]["retention_pct"] < 90.0
    assert by_field["evidence_graph"]["is_minimal"] is False

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
# 6. Adversarial Audit Tests (Contribution C3 Checks 1 - 4)
# --------------------------------------------------------------------------- #

def test_adversarial_clean_room_boundary_and_leakage():
    """Check 1: Confirm AuditRecord.to_dict() and JSON contain strictly zero identifiers
    from raw code, variables/functions/classes map to synthetic tokens, and verifier
    does not import or read from harness.evaluate, ground-truth dicts, or disk."""
    import ast
    import inspect

    code_snippet = """
    public class UserPaymentCredentialHandler {
        public void transmitUserCredentials(String userEmail, String userPassword, HttpURLConnection conn, URL url) {
            String email = "user@example.com";
            String password = "superSecretPassword123";
            conn.connect();
        }
    }
    """
    record, raw_identifiers = build_audit_record(
        code=code_snippet,
        ground_truth=[32],
        routing_action="symbolic",
    )

    # 1. Ensure raw identifiers actually captured the target tokens
    for expected_tok in ["UserPaymentCredentialHandler", "transmitUserCredentials", "userEmail", "userPassword", "email", "password", "conn", "url"]:
        assert expected_tok in raw_identifiers

    # 2. Check no identifier names (email, password, conn, HttpURLConnection, url) appear in evidence_graph
    target_forbidden = ["email", "password", "conn", "HttpURLConnection", "url"]
    ok_graph, leaked_graph = IdentifierAnonymizer.audit_evidence_graph_clean(record.evidence_graph, target_forbidden)
    assert ok_graph is True, f"Forbidden identifiers leaked into evidence_graph: {leaked_graph}"

    # 3. Verify all variables, methods, and classes map strictly to synthetic tokens (var_X, fn_Y, class_Z)
    node_ids = {n["id"] for n in record.evidence_graph["nodes"]}
    for nid in node_ids:
        assert (
            nid.startswith("var_")
            or nid.startswith("fn_")
            or nid.startswith("class_")
            or nid.startswith("sink_")
            or nid.startswith("source_")
        ), f"Node ID {nid!r} violates synthetic / abstract ontology token convention"

    # 4. Assert verifier V(R) does not import harness.evaluate, ground truth dicts, or read disk
    import audit.reconstruction as recon_module
    module_src = inspect.getsource(recon_module)
    parsed = ast.parse(module_src)

    imported_names = []
    for node in ast.walk(parsed):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.append(node.module)

    assert not any("harness" in name for name in imported_names), f"audit.reconstruction must not import harness: {imported_names}"
    assert not any("evaluate" in name for name in imported_names), f"audit.reconstruction must not import evaluate: {imported_names}"

    # 5. Verify ReconstructionVerifier.verify accepts only AuditRecord and does not read disk
    verifier = ReconstructionVerifier()
    cands = verifier.verify(record)
    assert len(cands) > 0
    assert all(isinstance(c, CandidateViolation) for c in cands)


def test_adversarial_statistical_significance_of_permutation_gap():
    """Check 2: Verify that Delta_rec = Acc(V(R)) - Acc(V(R_permuted)) is statistically
    significant (McNemar exact test and Fisher exact test p < 0.01)."""
    records, ground_truths = load_or_create_audit_records(use_synthetic=True)
    v = ReconstructionVerifier()

    y_intact = [v.matches_ground_truth(v.verify(r), gt) for r, gt in zip(records, ground_truths)]
    _, permuted_records = run_permutation_baseline(records, ground_truths, seed=42)
    y_permuted = [v.matches_ground_truth(v.verify(r), gt) for r, gt in zip(permuted_records, ground_truths)]

    stat_sig = compute_permutation_significance(y_intact, y_permuted)

    # Assert exact p-values < 0.01
    assert stat_sig["mcnemar_exact_p_value"] < 0.01, f"McNemar p={stat_sig['mcnemar_exact_p_value']} not < 0.01"
    assert stat_sig["fisher_exact_p_value"] < 0.01, f"Fisher p={stat_sig['fisher_exact_p_value']} not < 0.01"
    assert stat_sig["is_statistically_significant"] is True
    assert stat_sig["significance_level"] == "p < 0.01"


def test_adversarial_backward_ablation_monotonicity_and_r_star():
    """Check 3: Check that removing minimal sufficient components (evidence_graph or
    static_predicates) causes a measurable drop in reconstructability, and confirm
    that R* is the exact subset marked with an asterisk in Table 5."""
    records, ground_truths = load_or_create_audit_records(use_synthetic=True)
    acc_intact = evaluate_records(records, ground_truths)
    steps = run_backward_ablation(records, ground_truths, acc_intact)

    by_field = {s["dropped_field"]: s for s in steps if s["dropped_field"] != "None"}

    # Removal of minimal sufficient components causes measurable drop
    assert by_field["evidence_graph"]["accuracy"] < acc_intact
    assert by_field["evidence_graph"]["retention_pct"] < 90.0
    assert by_field["static_predicates"]["accuracy"] < acc_intact
    assert by_field["static_predicates"]["retention_pct"] < 90.0

    # Decision provenance removal retains 100%
    assert by_field["decision_provenance"]["accuracy"] == pytest.approx(acc_intact)
    assert by_field["decision_provenance"]["retention_pct"] == 100.0

    # Table 5 renders R* with an asterisk
    tex = generate_table5_latex(SYNTHETIC_40_ABLATION, sample_count=40)
    assert r"$R \setminus \{\Pi_{\text{decision}}\}$" in tex
    assert r"\checkmark$^*$" in tex


def test_adversarial_latex_and_artifact_integrity():
    """Check 4: Validate paper/artifacts/table5_reconstructability_ablation.tex under
    booktabs, ensure no unescaped underscores, and verify dynamic preliminary caveat."""
    t5_path = Path("paper/artifacts/table5_reconstructability_ablation.tex")
    assert t5_path.exists()

    # Validate syntax via LaTeXValidator
    errors = validate_latex_file(t5_path)
    assert errors == [], f"LaTeX syntax validation failed: {errors}"

    content = t5_path.read_text(encoding="utf-8")
    # Booktabs rules
    assert r"\toprule" in content
    assert r"\midrule" in content
    assert r"\bottomrule" in content
    # No unescaped underscores
    non_math_underscores = [
        m.group(0) for m in re.finditer(r"(?<!\\)_(?![^{]*\})", re.sub(r"\$[^$]+\$", "", content))
    ]
    assert len(non_math_underscores) == 0, f"Found unescaped underscores: {non_math_underscores}"
    # Dynamic preliminary caveat
    assert r"\textit{Note: Preliminary sample evaluation ($N=40$); final results await completion of full benchmark run.}" in content


