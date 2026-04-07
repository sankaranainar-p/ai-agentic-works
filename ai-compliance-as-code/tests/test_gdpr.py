"""
tests/test_gdpr.py — Integration tests for GDPR compliance analysis.

All tests use the FastAPI TestClient with api.main.call_llm monkeypatched
so no real Anthropic or Ollama calls are made.  Tests cover:

  • Primary path: LLM returns findings → response contract verified
  • Art.32 assertion: plaintext password in log must be a HIGH finding
  • Fallback path: any LLM exception → static-scanner findings, llm_unavailable=True
  • Deduplication: LLM + static findings merged; near-duplicate (rule_id + title ≥80%) removed
  • Sorting: findings ordered high → medium → low
  • llm_provider field: shows "ollama" / "anthropic" / "none"
  • Request validation: bad regulation name, empty code
  • Clean file: LLM returns [] → zero findings (static scanner also finds none)
  • Scanner hint: password field and log risk indicator detected
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from api.main import OllamaTimeoutError, _deduplicate_findings
from api.schemas import ComplianceFinding
from tests.conftest import (
    CALL_LLM_PATH,
    CLEAN_HANDLER_CODE,
    USER_CONTROLLER_CODE,
    gdpr_art32_md5_finding,
    gdpr_art32_password_log_finding,
    gdpr_art5_pii_log_finding,
    make_call_llm_return,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _post_analyze(
    client,
    code: str,
    regulation: str = "GDPR",
    file_path: str = "user_controller.py",
):
    return client.post(
        "/analyze",
        json={"code": code, "file_path": file_path, "regulation": regulation},
    )


# ---------------------------------------------------------------------------
# 1. Response contract
# ---------------------------------------------------------------------------

class TestResponseContract:
    def test_returns_200_with_findings_list(self, client, mock_call_llm_user_controller):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.status_code == 200
        assert isinstance(resp.json()["findings"], list)

    def test_response_includes_all_metadata_fields(self, client, mock_call_llm_user_controller):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        body = resp.json()
        for field in ("findings", "llm_unavailable", "scanner_hint",
                      "duration_ms", "regulation", "file_path", "llm_provider"):
            assert field in body, f"Missing field: {field}"
        assert body["regulation"] == "GDPR"
        assert body["file_path"] == "user_controller.py"

    def test_llm_unavailable_is_false_on_success(self, client, mock_call_llm_user_controller):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.json()["llm_unavailable"] is False

    def test_each_finding_has_required_fields(self, client, mock_call_llm_user_controller):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        required = {"violation_id", "rule_id", "title", "severity", "violation", "remediation"}
        for finding in resp.json()["findings"]:
            missing = required - finding.keys()
            assert not missing, f"Finding missing fields: {missing}"

    def test_finding_severity_is_valid_enum(self, client, mock_call_llm_user_controller):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        for finding in resp.json()["findings"]:
            assert finding["severity"] in {"high", "medium", "low"}


# ---------------------------------------------------------------------------
# 2. llm_provider field
# ---------------------------------------------------------------------------

class TestLlmProvider:
    def test_provider_is_ollama_when_provider_env_is_ollama(self, client):
        rv = make_call_llm_return([gdpr_art32_password_log_finding()], provider="ollama")
        with patch(CALL_LLM_PATH, return_value=rv):
            resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.json()["llm_provider"] == "ollama"

    def test_provider_is_anthropic_when_provider_env_is_anthropic(self, client):
        rv = make_call_llm_return([gdpr_art32_password_log_finding()], provider="anthropic")
        with patch(CALL_LLM_PATH, return_value=rv):
            resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.json()["llm_provider"] == "anthropic"

    def test_provider_is_none_when_llm_unavailable(self, client, mock_call_llm_error):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.json()["llm_provider"] == "none"
        assert resp.json()["llm_unavailable"] is True

    def test_provider_is_ollama_timeout_on_timeout(self, client):
        with patch(CALL_LLM_PATH, side_effect=OllamaTimeoutError("timed out")):
            resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.json()["llm_provider"] == "ollama-timeout"
        assert resp.json()["llm_unavailable"] is True

    def test_timeout_still_returns_static_findings(self, client):
        with patch(CALL_LLM_PATH, side_effect=OllamaTimeoutError("timed out")):
            findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        assert len(findings) > 0, "Static findings must be returned on timeout"


# ---------------------------------------------------------------------------
# 3. Art.32 — plaintext password in log (primary demo assertion)
# ---------------------------------------------------------------------------

class TestArt32PasswordLog:
    def test_at_least_one_high_art32_finding(self, client, mock_call_llm_user_controller):
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        art32_high = [f for f in findings if "Art.32" in f["rule_id"] and f["severity"] == "high"]
        assert art32_high, (
            "Expected at least one HIGH Art.32 finding; got: "
            + str([(f["rule_id"], f["severity"]) for f in findings])
        )

    def test_art32_password_log_finding_present(self, client, mock_call_llm_user_controller):
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        password_log = [
            f for f in findings
            if "Art.32" in f["rule_id"] and "password" in f["title"].lower() and f["severity"] == "high"
        ]
        assert password_log, (
            "Expected a HIGH Art.32 finding mentioning 'password'; got: "
            + str([(f["rule_id"], f["title"], f["severity"]) for f in findings])
        )

    def test_art32_finding_references_correct_article_url(self, client, mock_call_llm_user_controller):
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        art32_findings = [f for f in findings if "Art.32" in f["rule_id"]]
        assert art32_findings, "No Art.32 findings at all"
        for f in art32_findings:
            refs = f.get("references", [])
            assert any("32016R0679" in r or "Art.32" in r or "art-32" in r.lower() for r in refs), (
                f"Art.32 finding has no GDPR reference URL: {refs}"
            )

    def test_art32_finding_points_to_correct_line(self, client, mock_call_llm_user_controller):
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        password_log = [
            f for f in findings
            if "Art.32" in f["rule_id"] and "password" in f["title"].lower()
        ]
        assert password_log
        assert password_log[0]["line_start"] == 11, (
            f"Expected line_start=11 for the password-log finding, got {password_log[0]['line_start']}"
        )

    def test_art32_md5_finding_also_present(self, client, mock_call_llm_user_controller):
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        md5_findings = [
            f for f in findings
            if "Art.32" in f["rule_id"]
            and ("md5" in f["title"].lower() or "md5" in (f.get("snippet") or "").lower())
        ]
        assert md5_findings, "Expected a HIGH Art.32 finding for MD5 password hashing"


# ---------------------------------------------------------------------------
# 4. Deduplication
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> ComplianceFinding:
    defaults = dict(
        rule_id="GDPR-Art.32",
        title="Plaintext password in log",
        severity="high",
        violation="Password logged in plaintext.",
        remediation="Remove password from log call.",
        confidence=1.0,
    )
    defaults.update(kwargs)
    return ComplianceFinding(**defaults)


class TestDeduplication:
    """Unit tests for _deduplicate_findings() and integration via /analyze."""

    # -- unit tests against _deduplicate_findings directly --

    def test_identical_rule_id_and_title_keeps_higher_confidence(self):
        llm = _make_finding(title="Plaintext password in log", confidence=1.0)
        static = _make_finding(title="Plaintext password in log", confidence=0.6)
        result = _deduplicate_findings([llm, static])
        assert len(result) == 1
        assert result[0].confidence == 1.0

    def test_similar_title_above_threshold_deduped(self):
        # Titles differ only in capitalisation and minor wording — >80% similar
        llm = _make_finding(title="Plaintext password written to log", confidence=1.0)
        static = _make_finding(title="Plaintext password written to logs", confidence=0.6)
        result = _deduplicate_findings([llm, static])
        assert len(result) == 1
        assert result[0].confidence == 1.0

    def test_different_rule_id_not_deduped(self):
        a = _make_finding(rule_id="GDPR-Art.32", title="Plaintext password in log")
        b = _make_finding(rule_id="GDPR-Art.5",  title="Plaintext password in log")
        result = _deduplicate_findings([a, b])
        assert len(result) == 2

    def test_dissimilar_titles_same_rule_id_not_deduped(self):
        # "Plaintext password in log" vs "MD5 used for hashing" — <80% similar
        a = _make_finding(rule_id="GDPR-Art.32", title="Plaintext password in log")
        b = _make_finding(rule_id="GDPR-Art.32", title="MD5 used for hashing passwords")
        result = _deduplicate_findings([a, b])
        assert len(result) == 2

    def test_static_finding_wins_when_higher_confidence(self):
        # Unusual but valid: static confidence > LLM confidence
        llm    = _make_finding(title="Password logged", confidence=0.4)
        static = _make_finding(title="Password logged", confidence=0.6)
        result = _deduplicate_findings([llm, static])
        assert len(result) == 1
        assert result[0].confidence == 0.6

    def test_empty_input_returns_empty(self):
        assert _deduplicate_findings([]) == []

    def test_output_sorted_high_to_low(self):
        findings = [
            _make_finding(rule_id="GDPR-Art.32", title="A", severity="low",    confidence=1.0),
            _make_finding(rule_id="GDPR-Art.5",  title="B", severity="medium", confidence=1.0),
            _make_finding(rule_id="GDPR-Art.6",  title="C", severity="high",   confidence=1.0),
        ]
        result = _deduplicate_findings(findings)
        assert [f.severity for f in result] == ["high", "medium", "low"]

    # -- integration: LLM + static merge via /analyze --

    def test_llm_findings_merged_with_static_on_success(self, client):
        """LLM returns one finding; static scanner adds more → combined total."""
        rv = make_call_llm_return([gdpr_art32_password_log_finding()])
        with patch(CALL_LLM_PATH, return_value=rv):
            findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        # LLM gave 1 finding; static scanner gives several more for this code
        assert len(findings) > 1

    def test_no_duplicate_rule_id_title_pairs_in_response(self, client, mock_call_llm_user_controller):
        """After dedup, no two findings share rule_id AND near-identical title."""
        import difflib
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        for i, a in enumerate(findings):
            for b in findings[i + 1:]:
                if a["rule_id"] != b["rule_id"]:
                    continue
                sim = difflib.SequenceMatcher(
                    None, a["title"].lower(), b["title"].lower()
                ).ratio()
                assert sim < 0.80, (
                    f"Duplicate found: rule_id={a['rule_id']!r} "
                    f"titles={a['title']!r} / {b['title']!r} similarity={sim:.2f}"
                )

    def test_llm_confidence_beats_static_on_same_finding(self, client):
        """When LLM and static both flag the same rule+title, LLM version is kept."""
        # Return exactly the same finding that the static scanner would produce
        # for 'password_field_present' — slightly different title, same rule_id
        llm_finding = {
            "rule_id": "PCI-REQ-8 / GDPR-Art.32",
            "title": "Password field detected",        # matches static scanner title
            "severity": "high",
            "violation": "Password field found — LLM version.",
            "remediation": "Use bcrypt.",
            "references": [],
        }
        rv = make_call_llm_return([llm_finding])
        with patch(CALL_LLM_PATH, return_value=rv):
            findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]

        # The merged + deduped list should contain exactly one entry for this title
        password_field = [f for f in findings if "Password field" in f["title"]]
        assert len(password_field) == 1
        # It must be the LLM version (confidence=1.0 > 0.6)
        assert password_field[0]["confidence"] == 1.0


# ---------------------------------------------------------------------------
# 6. Sorting — findings must be high → medium → low
# ---------------------------------------------------------------------------

class TestFindingOrder:
    def test_findings_ordered_high_before_medium_before_low(self, client):
        mixed = [
            {**gdpr_art32_md5_finding(), "severity": "medium"},
            {**gdpr_art32_password_log_finding(), "severity": "high"},
            {
                "rule_id": "GDPR-Art.5", "title": "Missing ROPA entry",
                "severity": "low", "severity_override": False,
                "file": "user_controller.py", "line_start": None, "line_end": None,
                "snippet": None,
                "violation": "No ROPA entry for this processing activity.",
                "remediation": "Add a ROPA entry.", "references": [],
            },
            gdpr_art5_pii_log_finding(),  # high
        ]
        with patch(CALL_LLM_PATH, return_value=make_call_llm_return(mixed)):
            resp = _post_analyze(client, USER_CONTROLLER_CODE)

        severities = [f["severity"] for f in resp.json()["findings"]]
        order = {"high": 0, "medium": 1, "low": 2}
        assert severities == sorted(severities, key=lambda s: order[s]), (
            f"Findings not in severity order: {severities}"
        )


# ---------------------------------------------------------------------------
# 7. Fallback path
# ---------------------------------------------------------------------------

class TestFallbackPath:
    def test_runtime_error_returns_200_with_llm_unavailable_true(self, client, mock_call_llm_error):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.status_code == 200
        assert resp.json()["llm_unavailable"] is True

    def test_auth_error_returns_200_with_llm_unavailable_true(self, client, mock_call_llm_auth_error):
        resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.status_code == 200
        assert resp.json()["llm_unavailable"] is True

    def test_fallback_findings_are_non_empty_for_violating_code(self, client, mock_call_llm_error):
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        assert len(findings) > 0, "Fallback should produce findings for code with violations"

    def test_fallback_findings_have_low_confidence(self, client, mock_call_llm_error):
        for f in _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]:
            assert f["confidence"] < 1.0, (
                f"Fallback finding should have confidence < 1.0 but got {f['confidence']}"
            )

    def test_fallback_findings_ordered_high_first(self, client, mock_call_llm_error):
        findings = _post_analyze(client, USER_CONTROLLER_CODE).json()["findings"]
        if len(findings) > 1:
            order = {"high": 0, "medium": 1, "low": 2}
            severities = [f["severity"] for f in findings]
            assert severities == sorted(severities, key=lambda s: order[s])

    def test_credit_error_triggers_fallback(self, client):
        with patch(CALL_LLM_PATH, side_effect=Exception("You have exceeded your credit limit")):
            resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.status_code == 200
        assert resp.json()["llm_unavailable"] is True

    def test_malformed_json_triggers_fallback(self, client):
        with patch(CALL_LLM_PATH, return_value=("this is not json", "ollama")):
            resp = _post_analyze(client, USER_CONTROLLER_CODE)
        assert resp.json()["llm_unavailable"] is True


# ---------------------------------------------------------------------------
# 8. Clean file — no violations
# ---------------------------------------------------------------------------

class TestCleanFile:
    def test_clean_handler_returns_empty_findings(self, client, mock_call_llm_empty):
        resp = _post_analyze(client, CLEAN_HANDLER_CODE, file_path="clean_handler.py")
        assert resp.status_code == 200
        assert resp.json()["findings"] == []
        assert resp.json()["llm_unavailable"] is False


# ---------------------------------------------------------------------------
# 9. Scanner hint
# ---------------------------------------------------------------------------

class TestScannerHint:
    def test_scanner_hint_present_in_response(self, client, mock_call_llm_user_controller):
        hint = _post_analyze(client, USER_CONTROLLER_CODE).json()["scanner_hint"]
        assert isinstance(hint, dict)
        assert "risk_indicators" in hint
        assert "sensitive_fields" in hint

    def test_scanner_detects_password_field(self, client, mock_call_llm_user_controller):
        hint = _post_analyze(client, USER_CONTROLLER_CODE).json()["scanner_hint"]
        field_names = [f["name"] for f in hint.get("sensitive_fields", [])]
        assert "password" in field_names, (
            f"Static scanner should detect 'password' field; found: {field_names}"
        )

    def test_scanner_detects_log_risk_indicator(self, client, mock_call_llm_user_controller):
        indicators = _post_analyze(client, USER_CONTROLLER_CODE).json()["scanner_hint"].get("risk_indicators", [])
        assert "sensitive_data_in_log_call" in indicators, (
            f"Expected 'sensitive_data_in_log_call'; got: {indicators}"
        )


# ---------------------------------------------------------------------------
# 10. Request validation
# ---------------------------------------------------------------------------

class TestRequestValidation:
    def test_unknown_regulation_returns_400(self, client):
        resp = client.post("/analyze", json={"code": "x = 1", "regulation": "HIPAA"})
        assert resp.status_code == 400

    def test_empty_code_returns_422(self, client):
        resp = client.post("/analyze", json={"code": "", "regulation": "GDPR"})
        assert resp.status_code == 422

    def test_missing_code_field_returns_422(self, client):
        resp = client.post("/analyze", json={"regulation": "GDPR"})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 11. Health check
# ---------------------------------------------------------------------------

class TestHealthCheck:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
