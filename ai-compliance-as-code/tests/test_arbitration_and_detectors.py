"""
tests/test_arbitration_and_detectors.py — Unit tests for the modularized
ArbitrationStrategy, Detector protocol, and audit emission components.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from api.main import run_analysis
from api.schemas import AnalyzeRequest, ComplianceFinding
from arbitration import ArbitrationStrategy, FixedConfidenceMerge
from audit import AuditSink, InMemoryAuditSink, NullAuditSink
from detectors import Detector, LLMDetector, StaticScannerDetector
from tests.conftest import (
    USER_CONTROLLER_CODE,
    gdpr_art32_password_log_finding,
    make_call_llm_return,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(rule_id: str, title: str, confidence: float, severity: str = "high") -> ComplianceFinding:
    return ComplianceFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        violation=f"Violation for {rule_id}",
        remediation=f"Remediation for {rule_id}",
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# 1. Detector Protocol & Standalone Execution
# ---------------------------------------------------------------------------

class TestStandaloneDetectors:
    def test_static_scanner_detector_standalone(self):
        detector = StaticScannerDetector()
        assert isinstance(detector, Detector)

        findings = detector.detect(USER_CONTROLLER_CODE, file_path="user_controller.py")
        assert isinstance(findings, list)
        assert len(findings) > 0
        for f in findings:
            assert isinstance(f, ComplianceFinding)
            assert f.confidence in (0.6, 0.4)

    def test_llm_detector_standalone(self):
        expected_raw = [gdpr_art32_password_log_finding()]
        call_mock = lambda sys_prompt, user_turn: (json.dumps(expected_raw), "mock-provider")

        detector = LLMDetector(call_llm_fn=call_mock)
        assert isinstance(detector, Detector)

        findings = detector.detect(
            USER_CONTROLLER_CODE,
            file_path="user_controller.py",
            regulation="GDPR",
        )
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert findings[0].rule_id == "GDPR-Art.32"
        assert findings[0].confidence == 1.0

    def test_llm_detector_with_provider_info(self):
        expected_raw = [gdpr_art32_password_log_finding()]
        call_mock = lambda sys_prompt, user_turn: (json.dumps(expected_raw), "custom-ollama")

        detector = LLMDetector(call_llm_fn=call_mock)
        findings, provider = detector.detect_with_provider_info(
            USER_CONTROLLER_CODE,
            file_path="user_controller.py",
            regulation="GDPR",
        )
        assert len(findings) == 1
        assert provider == "custom-ollama"


# ---------------------------------------------------------------------------
# 2. ArbitrationStrategy & FixedConfidenceMerge Baseline
# ---------------------------------------------------------------------------

class TestFixedConfidenceMerge:
    def test_arbitration_strategy_protocol_conformance(self):
        strategy = FixedConfidenceMerge()
        assert isinstance(strategy, ArbitrationStrategy)

    def test_llm_higher_confidence_wins_over_static(self):
        sink = InMemoryAuditSink()
        strategy = FixedConfidenceMerge(audit_sink=sink)

        llm = [_make_finding("GDPR-Art.32", "Plaintext password in log", 1.0)]
        static = [_make_finding("GDPR-Art.32", "Plaintext password in log", 0.6)]

        results = strategy.arbitrate(static_findings=static, llm_findings=llm)
        assert len(results) == 1
        assert results[0].confidence == 1.0

    def test_static_higher_confidence_wins_if_higher(self):
        sink = InMemoryAuditSink()
        strategy = FixedConfidenceMerge(audit_sink=sink)

        llm = [_make_finding("GDPR-Art.32", "Password in log", 0.4)]
        static = [_make_finding("GDPR-Art.32", "Password in log", 0.8)]

        # llm is evaluated first; static candidate replaces llm because 0.8 > 0.4
        results = strategy.arbitrate(static_findings=static, llm_findings=llm)
        assert len(results) == 1
        assert results[0].confidence == 0.8

    def test_fallback_when_llm_findings_empty(self):
        strategy = FixedConfidenceMerge()
        static = [
            _make_finding("GDPR-Art.32", "Password logged", 0.6),
            _make_finding("GDPR-Art.5", "PII logged", 0.6),
        ]
        results = strategy.arbitrate(static_findings=static, llm_findings=[])
        assert len(results) == 2


# ---------------------------------------------------------------------------
# 3. Audit Package: Emission Points & Sink
# ---------------------------------------------------------------------------

class TestAuditEmission:
    def test_null_audit_sink_does_not_fail(self):
        sink = NullAuditSink()
        assert isinstance(sink, AuditSink)
        sink.emit({"test": 123})

    def test_in_memory_audit_sink_records_events(self):
        sink = InMemoryAuditSink()
        assert isinstance(sink, AuditSink)
        strategy = FixedConfidenceMerge(audit_sink=sink)

        llm = [_make_finding("GDPR-Art.32", "Plaintext password in log", 1.0)]
        static = [
            _make_finding("GDPR-Art.32", "Plaintext password in log", 0.6),  # duplicate
            _make_finding("GDPR-Art.5", "PII in log", 0.6),                  # uncontested
        ]

        strategy.arbitrate(static_findings=static, llm_findings=llm)

        actions = [e.get("action") for e in sink.events]
        # 1. llm finding added uncontested
        # 2. static duplicate candidate discarded
        # 3. static PII finding added uncontested
        assert "accepted_uncontested" in actions
        assert "candidate_discarded" in actions
        assert len(sink.events) == 3


# ---------------------------------------------------------------------------
# 4. Pluggability in run_analysis
# ---------------------------------------------------------------------------

class TestPluggableRunAnalysis:
    def test_custom_arbitration_strategy_in_run_analysis(self):
        class AlwaysEmptyStrategy:
            def arbitrate(self, static_findings, llm_findings):
                return []

        req = AnalyzeRequest(code="x = 1", regulation="GDPR")
        resp = run_analysis(req, arbitration_strategy=AlwaysEmptyStrategy())
        assert resp.findings == []

    def test_custom_detector_in_run_analysis(self):
        custom_finding = _make_finding("CUSTOM-1", "Custom finding", 0.9)

        class MockStaticDetector:
            def detect(self, code, **kwargs):
                return [custom_finding]

            def detect_with_hint(self, code, hint, **kwargs):
                return [custom_finding]

        req = AnalyzeRequest(code="x = 1", regulation="GDPR")
        with patch("api.main.call_llm", return_value=make_call_llm_return([])):
            resp = run_analysis(req, static_detector=MockStaticDetector())

        assert any(f.rule_id == "CUSTOM-1" for f in resp.findings)
