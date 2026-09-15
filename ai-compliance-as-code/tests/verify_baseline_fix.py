"""
tests/verify_baseline_fix.py — Automated verification for baseline reproduction fixes.

Validates:
  1. LabelMapper bidirectional mapping for all 23 GDPR benchmark articles.
  2. LLM path detection/parsing of articles outside the initial 5 articles {5, 6, 17, 25, 32}.
  3. Partitioned metric reporting (macro_f1_global vs macro_f1_in_scope) on synthetic slices.
  4. GDPR rule pack schema completeness across all 23 benchmark articles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

from api.schemas import ComplianceFinding
from detectors.llm import LLMDetector
from harness.label_mapper import DEFAULT_SUPPORTED_ARTICLES, LabelMapper
from harness.metrics import (
    GDPR_BENCHMARK_ARTICLES,
    compute_multilabel_metrics,
)
from prompts.user_turn import build_user_turn

BENCHMARK_23_ARTICLES = sorted([
    5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 25, 28, 30, 32, 33, 34, 44, 49
])


# ===========================================================================
# 1. LabelMapper Bidirectional Mapping for all 23 Articles
# ===========================================================================

class TestLabelMapperAll23Articles:
    def test_supported_articles_set(self) -> None:
        assert sorted(DEFAULT_SUPPORTED_ARTICLES) == BENCHMARK_23_ARTICLES

    def test_bidirectional_mapping(self) -> None:
        mapper = LabelMapper()
        assert sorted(mapper.supported_articles) == BENCHMARK_23_ARTICLES

        for art in BENCHMARK_23_ARTICLES:
            rule_id = f"GDPR-Art.{art}"
            assert mapper.rule_to_article(rule_id) == art
            assert mapper.article_to_rule(art) == rule_id
            assert mapper.is_supported_article(art) is True
            assert mapper.is_supported_rule(rule_id) is True

        summary = mapper.get_unmapped_summary()
        assert summary["unmapped_rules"] == []
        assert summary["unmapped_articles"] == []

    def test_variant_and_composite_rule_strings(self) -> None:
        mapper = LabelMapper()
        assert mapper.rule_to_article("Article 7") == 7
        assert mapper.rule_to_article("Art. 13") == 13
        assert mapper.rule_to_article("Art.20") == 20
        assert mapper.rule_to_article("PCI-REQ-4 / GDPR-Art.44") == 44
        assert mapper.rule_to_article("GDPR-Art.49") == 49

        summary = mapper.get_unmapped_summary()
        assert summary["unmapped_rules"] == []
        assert summary["unmapped_articles"] == []

    def test_unsupported_article_tracking(self) -> None:
        mapper = LabelMapper()
        # Article 99 is not in the 23 benchmark articles
        rule_99 = mapper.article_to_rule(99)
        assert rule_99 == "GDPR-Art.99"
        assert 99 in mapper.unmapped_articles

        # Non-GDPR rule
        res = mapper.rule_to_article("PCI-REQ-1")
        assert res is None
        assert "PCI-REQ-1" in mapper.unmapped_rules


# ===========================================================================
# 2. LLM Path Detection & Exhaustive Multi-Label Prompting
# ===========================================================================

class TestLLMPathDetectionOutsideInitialFive:
    def test_llm_detector_parses_new_articles(self) -> None:
        mock_findings_json = json.dumps([
            {
                "rule_id": "GDPR-Art.7",
                "title": "Conditions for consent",
                "severity": "high",
                "severity_override": False,
                "file": "ConsentManager.java",
                "line_start": 10,
                "line_end": 15,
                "snippet": "boolean consent = true;",
                "violation": "Pre-ticked consent does not satisfy Article 7 requirement for affirmative action.",
                "remediation": "Require explicit opt-in checkbox before data collection.",
                "references": ["https://eur-lex.europa.eu/eli/reg/2016/679/art_7/oj"],
            },
            {
                "rule_id": "GDPR-Art.13",
                "title": "Information to be provided where personal data collected",
                "severity": "medium",
                "severity_override": False,
                "file": "ConsentManager.java",
                "line_start": 20,
                "line_end": 25,
                "snippet": "sendTelemetry(payload);",
                "violation": "Telemetry sent without clear transparent privacy notice.",
                "remediation": "Display privacy policy disclosure prior to telemetry dispatch.",
                "references": ["https://eur-lex.europa.eu/eli/reg/2016/679/art_13/oj"],
            },
            {
                "rule_id": "GDPR-Art.44",
                "title": "General principle for cross-border transfers",
                "severity": "high",
                "severity_override": False,
                "file": "ConsentManager.java",
                "line_start": 30,
                "line_end": 35,
                "snippet": "uploadToOverseasBucket(payload);",
                "violation": "Cross-border data transfer without adequacy decision or SCCs.",
                "remediation": "Enforce EU-only endpoint or standard contractual clauses.",
                "references": ["https://eur-lex.europa.eu/eli/reg/2016/679/art_44/oj"],
            },
        ])

        mock_call_llm = MagicMock(return_value=(mock_findings_json, "mock-ollama"))
        detector = LLMDetector(call_llm_fn=mock_call_llm)

        sample_code = (
            "public class ConsentManager {\n"
            "    public void init() {\n"
            "        boolean consent = true;\n"
            "        sendTelemetry(payload);\n"
            "        uploadToOverseasBucket(payload);\n"
            "    }\n"
            "}"
        )

        findings = detector.detect(sample_code, file_path="ConsentManager.java", regulation="GDPR")
        assert len(findings) == 3

        mapper = LabelMapper()
        articles = sorted(mapper.rule_to_article(f.rule_id) for f in findings)
        assert articles == [7, 13, 44]

        # Verify none of these articles were flagged as unmapped
        assert mapper.get_unmapped_summary()["unmapped_rules"] == []
        assert mapper.get_unmapped_summary()["unmapped_articles"] == []

    def test_exhaustive_multi_label_instruction_in_prompt(self) -> None:
        user_turn = build_user_turn(
            code="public class Test {}",
            file_path="Test.java",
            context_hint={"risk_indicators": []},
            regulation_name="GDPR",
        )
        assert (
            "Identify ALL applicable GDPR articles that apply to this snippet; "
            "return an exhaustive list and do not stop at the first detected violation."
        ) in user_turn


# ===========================================================================
# 3. Partitioned Metric Reporting (macro_f1_global vs macro_f1_in_scope)
# ===========================================================================

class TestPartitionedMetricReporting:
    def test_synthetic_slice_perfect_in_scope(self) -> None:
        # Ground truth only has articles 7 and 13 across 2 instances
        preds = [{7}, {13}]
        gts = [{7}, {13}]

        metrics = compute_multilabel_metrics(preds, gts)

        # In-scope classes are exactly [7, 13]
        assert metrics.in_scope_classes == [7, 13]
        # Global classes are all 23 benchmark articles
        assert metrics.classes == GDPR_BENCHMARK_ARTICLES
        assert len(metrics.classes) == 23

        # Both articles 7 and 13 have P=1, R=1, F1=1 on this slice
        assert metrics.macro_f1_in_scope == pytest.approx(1.0)
        assert metrics.macro_precision_in_scope == pytest.approx(1.0)
        assert metrics.macro_recall_in_scope == pytest.approx(1.0)

        # Global average includes the other 21 classes with F1=0, so (1.0 + 1.0) / 23 = 2 / 23
        expected_global = 2.0 / 23.0
        assert metrics.macro_f1_global == pytest.approx(expected_global, abs=1e-4)
        assert metrics.macro_precision_global == pytest.approx(expected_global, abs=1e-4)
        assert metrics.macro_recall_global == pytest.approx(expected_global, abs=1e-4)

        # Exact-match accuracy is 1.0 (both instances match perfectly)
        assert metrics.exact_match_accuracy == 1.0

        # Serialization checks
        d = metrics.to_dict()
        assert d["macro_f1_in_scope"] == 1.0
        assert d["macro_f1_global"] == round(expected_global, 4)
        assert d["in_scope_classes"] == [7, 13]
        assert len(d["classes"]) == 23

    def test_synthetic_slice_partial_overlap(self) -> None:
        # Instance 1: GT={7, 8}, Pred={7} -> art 7: TP=1, FP=0, FN=0; art 8: TP=0, FP=0, FN=1
        # Instance 2: GT={8, 9}, Pred={8, 9} -> art 8: TP=1, FP=0, FN=0; art 9: TP=1, FP=0, FN=0
        preds = [{7}, {8, 9}]
        gts = [{7, 8}, {8, 9}]

        metrics = compute_multilabel_metrics(preds, gts)

        assert metrics.in_scope_classes == [7, 8, 9]

        # Per-class breakdown:
        # Art 7: TP=1, FP=0, FN=0 -> P=1.0, R=1.0, F1=1.0
        # Art 8: TP=1, FP=0, FN=1 -> P=1.0, R=0.5, F1=2*(1.0*0.5)/1.5 = 2/3 ~= 0.6667
        # Art 9: TP=1, FP=0, FN=0 -> P=1.0, R=1.0, F1=1.0
        expected_f1_in_scope = (1.0 + (2.0 / 3.0) + 1.0) / 3.0
        assert metrics.macro_f1_in_scope == pytest.approx(expected_f1_in_scope, abs=1e-4)

        expected_f1_global = (1.0 + (2.0 / 3.0) + 1.0) / 23.0
        assert metrics.macro_f1_global == pytest.approx(expected_f1_global, abs=1e-4)
        assert metrics.exact_match_accuracy == 0.5


# ===========================================================================
# 4. GDPR Rule Pack Completeness (rules/gdpr.json)
# ===========================================================================

class TestGDPRRulePackCompleteness:
    def test_all_23_rules_present(self) -> None:
        rule_pack_path = Path(__file__).resolve().parent.parent / "rules" / "gdpr.json"
        assert rule_pack_path.exists(), f"Rule pack not found: {rule_pack_path}"

        with open(rule_pack_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        rules = data.get("rules", [])
        assert len(rules) == 23

        rule_ids = [r["id"] for r in rules]
        expected_ids = [f"GDPR-Art.{art}" for art in BENCHMARK_23_ARTICLES]
        assert rule_ids == expected_ids

        for rule in rules:
            assert "id" in rule
            assert "title" in rule and len(rule["title"]) > 0
            assert "description" in rule and len(rule["description"]) > 0
            assert "default_severity" in rule and rule["default_severity"] in ("high", "medium", "low")
            assert "check_hints" in rule and len(rule["check_hints"]) > 0
            assert "non_compliant_patterns" in rule and len(rule["non_compliant_patterns"]) > 0
            assert "remediation_guidance" in rule and len(rule["remediation_guidance"]) > 0
            assert "references" in rule and len(rule["references"]) > 0
