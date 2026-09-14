"""
tests/test_harness.py — Unit tests for GDPR-Bench harness:
  - Label mapper and dataset loading
  - AST boundary resolver (Java and Kotlin)
  - Accuracy@k and macro P/R/F1 metric calculations
  - Checkpoint manager and retry backoff
  - End-to-end evaluation runner dry-run
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from harness.ast_resolver import ASTNodeInfo, ASTResolver
from harness.evaluate import (
    CheckpointManager,
    EvaluationDetector,
    run_evaluation,
    run_with_backoff,
)
from harness.label_mapper import (
    BenchmarkRecord,
    LabelMapper,
    load_dataset,
    load_task1_dataset,
    load_task2_dataset,
    parse_code_snippet_path,
)
from harness.metrics import (
    compute_accuracy_at_k,
    compute_accuracy_at_k_range,
    compute_multilabel_metrics,
    compute_task1_metrics,
)


# ===========================================================================
# 1. Label Mapper Tests
# ===========================================================================

class TestLabelMapper:
    def test_rule_to_article_canonical(self) -> None:
        mapper = LabelMapper()
        assert mapper.rule_to_article("GDPR-Art.32") == 32
        assert mapper.rule_to_article("GDPR-Art.5") == 5
        assert mapper.rule_to_article("GDPR-Art.25") == 25
        assert mapper.rule_to_article("GDPR-Art.6") == 6
        assert mapper.rule_to_article("GDPR-Art.17") == 17

    def test_rule_to_article_variants(self) -> None:
        mapper = LabelMapper()
        assert mapper.rule_to_article("Art. 32") == 32
        assert mapper.rule_to_article("Article 5") == 5
        assert mapper.rule_to_article("GDPR-Art. 25") == 25
        assert mapper.rule_to_article("pci-req-4 / gdpr-art.32") == 32

    def test_rule_to_article_unmapped(self) -> None:
        mapper = LabelMapper()
        assert mapper.rule_to_article("PCI-REQ-3") is None
        assert mapper.rule_to_article("UNKNOWN_RULE") is None
        assert "PCI-REQ-3" in mapper.unmapped_rules
        assert "UNKNOWN_RULE" in mapper.unmapped_rules

    def test_article_to_rule_bidirectional(self) -> None:
        mapper = LabelMapper()
        for art in [5, 6, 17, 25, 32]:
            rule = mapper.article_to_rule(art)
            assert rule == f"GDPR-Art.{art}"
            assert mapper.rule_to_article(rule) == art

    def test_unsupported_article_flagged(self) -> None:
        mapper = LabelMapper(supported_articles=[5, 32])
        assert mapper.rule_to_article("GDPR-Art.6") == 6
        assert 6 in mapper.unmapped_articles
        assert mapper.is_supported_rule("GDPR-Art.32") is True
        assert mapper.is_supported_rule("GDPR-Art.6") is False

        # article_to_rule flags unsupported article too
        mapper.article_to_rule(99)
        assert 99 in mapper.unmapped_articles

        summary = mapper.get_unmapped_summary()
        assert 6 in summary["unmapped_articles"]
        assert 99 in summary["unmapped_articles"]

        mapper.reset_flags()
        assert len(mapper.unmapped_rules) == 0
        assert len(mapper.unmapped_articles) == 0


class TestSnippetPathParsing:
    def test_parse_snippet_path_range(self) -> None:
        f, s, e = parse_code_snippet_path("src/Foo.java:120-135")
        assert f == "src/Foo.java"
        assert s == 120
        assert e == 135

    def test_parse_snippet_path_single_line(self) -> None:
        f, s, e = parse_code_snippet_path("src/Foo.java:42")
        assert f == "src/Foo.java"
        assert s == 42
        assert e == 42

    def test_parse_snippet_path_prose(self) -> None:
        f, s, e = parse_code_snippet_path("app/Bar.kt lines 10-25")
        assert f == "app/Bar.kt"
        assert s == 10
        assert e == 25

    def test_parse_snippet_path_no_lines(self) -> None:
        f, s, e = parse_code_snippet_path("app/Bar.kt")
        assert f == "app/Bar.kt"
        assert s is None
        assert e is None


class TestDatasetLoading:
    def test_load_dataset_json_array(self, tmp_path: Path) -> None:
        data = [
            {
                "app_name": "TestApp",
                "repo_url": "https://github.com/test/app",
                "commit_id": "c1",
                "violated_article": 32,
                "code_snippet_path": "Foo.java:10-20",
                "code_snippet": "class Foo {}",
            }
        ]
        file_path = tmp_path / "dataset.json"
        file_path.write_text(json.dumps(data), encoding="utf-8")

        records = load_dataset(file_path)
        assert len(records) == 1
        assert records[0].app_name == "TestApp"
        assert records[0].violated_article == 32
        assert records[0].file_path == "Foo.java"
        assert records[0].start_line == 10
        assert records[0].end_line == 20

    def test_load_task2_aggregation(self, tmp_path: Path) -> None:
        # Same snippet path with two different violated articles
        data = [
            {
                "app_name": "TestApp",
                "repo_url": "https://github.com/test/app",
                "commit_id": "c1",
                "violated_article": 5,
                "code_snippet_path": "Foo.java:10-20",
                "code_snippet": "class Foo {}",
            },
            {
                "app_name": "TestApp",
                "repo_url": "https://github.com/test/app",
                "commit_id": "c1",
                "violated_article": 32,
                "code_snippet_path": "Foo.java:10-20",
                "code_snippet": "class Foo {}",
            },
        ]
        file_path = tmp_path / "raw.json"
        file_path.write_text(json.dumps(data), encoding="utf-8")

        records = load_task2_dataset(file_path)
        assert len(records) == 1
        assert sorted(records[0].violated_article) == [5, 32]


# ===========================================================================
# 2. AST Boundary Resolver Tests
# ===========================================================================

class TestASTResolver:
    @pytest.fixture
    def resolver(self) -> ASTResolver:
        return ASTResolver()

    def test_java_method_resolution(self, resolver: ASTResolver) -> None:
        java_code = (
            "package com.example;\n"
            "public class UserService {\n"
            "    private String secretKey;\n"
            "    public void saveUser(String email) {\n"
            "        System.out.println(email);\n"
            "    }\n"
            "}\n"
        )
        # Line 5: System.out.println(email) is inside saveUser method
        info = resolver.resolve_line(java_code, line=5, language="java")
        assert info is not None
        assert info.name == "saveUser"
        assert info.method_name == "saveUser"
        assert info.class_name == "UserService"
        assert info.qualified_name == "UserService.saveUser"
        assert info.start_line == 4
        assert info.end_line == 6

    def test_java_field_resolution(self, resolver: ASTResolver) -> None:
        java_code = (
            "package com.example;\n"
            "public class UserService {\n"
            "    private String secretKey;\n"
            "    public void saveUser(String email) {}\n"
            "}\n"
        )
        # Line 3: secretKey field is inside UserService class but not in a method
        info = resolver.resolve_line(java_code, line=3, language="java")
        assert info is not None
        assert info.name == "UserService"
        assert info.class_name == "UserService"
        assert info.method_name is None
        assert info.qualified_name == "UserService"
        assert info.start_line == 2
        assert info.end_line == 5

    def test_kotlin_function_resolution(self, resolver: ASTResolver) -> None:
        kt_code = (
            "package com.example\n"
            "class LocationTracker {\n"
            "    fun updateLocation(lat: Double, lng: Double) {\n"
            "        println(lat)\n"
            "    }\n"
            "}\n"
        )
        # Line 4: println(lat) is inside updateLocation function
        info = resolver.resolve_line(kt_code, line=4, language="kotlin")
        assert info is not None
        assert info.name == "updateLocation"
        assert info.class_name == "LocationTracker"
        assert info.qualified_name == "LocationTracker.updateLocation"
        assert info.start_line == 3
        assert info.end_line == 5

    def test_ast_node_helpers(self) -> None:
        node = ASTNodeInfo(
            node_type="method_declaration",
            name="doWork",
            start_line=10,
            end_line=20,
            class_name="Worker",
            method_name="doWork",
            qualified_name="Worker.doWork",
        )
        assert node.contains_line(15) is True
        assert node.contains_line(5) is False
        assert node.contains_span(12, 18) is True
        assert node.contains_span(8, 15) is False
        assert node.overlaps_span(5, 12) is True
        assert node.overlaps_span(25, 30) is False

    def test_outside_class_returns_none(self, resolver: ASTResolver) -> None:
        java_code = "package com.example;\nimport java.util.List;\npublic class A {}\n"
        # Line 1 is package declaration
        assert resolver.resolve_line(java_code, line=1, language="java") is None


# ===========================================================================
# 3. Metrics Tests (GDPR-Bench Section 6.1.4)
# ===========================================================================

class TestMetrics:
    def test_accuracy_at_k(self) -> None:
        # 4 test instances:
        # Instance 1: correct article at rank 1
        # Instance 2: correct article at rank 2
        # Instance 3: correct article at rank 4
        # Instance 4: not predicted (None)
        ranks: List[Optional[int]] = [1, 2, 4, None]

        assert compute_accuracy_at_k(ranks, 1) == 0.25
        assert compute_accuracy_at_k(ranks, 2) == 0.50
        assert compute_accuracy_at_k(ranks, 3) == 0.50
        assert compute_accuracy_at_k(ranks, 4) == 0.75
        assert compute_accuracy_at_k(ranks, 5) == 0.75

    def test_accuracy_at_k_range(self) -> None:
        ranks = [1, 3, None]
        res = compute_accuracy_at_k_range(ranks, ks=(1, 2, 3, 4, 5))
        assert res[1] == pytest.approx(1 / 3)
        assert res[2] == pytest.approx(1 / 3)
        assert res[3] == pytest.approx(2 / 3)
        assert res[4] == pytest.approx(2 / 3)
        assert res[5] == pytest.approx(2 / 3)

    def test_task1_metrics_structure(self) -> None:
        m = compute_task1_metrics([1, 2], [1, None], [None, None])
        assert m.num_instances == 2
        assert m.file_level[1] == 0.5
        assert m.file_level[2] == 1.0
        assert m.module_level[1] == 0.5
        assert m.line_level[1] == 0.0

    def test_task2_multilabel_metrics(self) -> None:
        # Instance 1: GT={5}, Pred={5, 32}
        # Instance 2: GT={32}, Pred={32}
        # Classes: 5, 32
        # Class 5: TP=1, FP=0, FN=0 -> P=1.0, R=1.0, F1=1.0
        # Class 32: TP=1, FP=1, FN=0 -> P=0.5, R=1.0, F1=2*(0.5*1)/(1.5) = 2/3
        # Exact match: 1 of 2 (only instance 2 matches exactly) -> 0.5
        # Macro-P: (1.0 + 0.5) / 2 = 0.75
        # Macro-R: (1.0 + 1.0) / 2 = 1.0
        # Macro-F1: (1.0 + 2/3) / 2 = 5/6 ~= 0.8333
        preds = [{5, 32}, {32}]
        gts = [{5}, {32}]

        metrics = compute_multilabel_metrics(preds, gts, classes=[5, 32])
        assert metrics.num_instances == 2
        assert metrics.num_classes == 2
        assert metrics.exact_match_accuracy == 0.5
        assert metrics.macro_precision == pytest.approx(0.75)
        assert metrics.macro_recall == pytest.approx(1.0)
        assert metrics.macro_f1 == pytest.approx(5 / 6, rel=1e-3)

    def test_task2_empty_dataset(self) -> None:
        metrics = compute_multilabel_metrics([], [])
        assert metrics.num_instances == 0
        assert metrics.exact_match_accuracy == 0.0
        assert metrics.macro_f1 == 0.0


# ===========================================================================
# 4. Checkpoint & Runner Tests
# ===========================================================================

class TestCheckpointAndRunner:
    def test_checkpoint_flush_and_resumption(self, tmp_path: Path) -> None:
        cp_file = tmp_path / "checkpoint.jsonl"
        mgr = CheckpointManager(cp_file, flush_interval=2)

        mgr.record_completed("k1", {"val": 10})
        # Not flushed yet because interval is 2
        assert len(mgr.completed_keys) == 1

        mgr.record_completed("k2", {"val": 20})
        # Flushed automatically
        assert cp_file.exists()

        # Create new manager pointing to same file -> must resume completed keys
        mgr2 = CheckpointManager(cp_file, flush_interval=2)
        assert "k1" in mgr2.completed_keys
        assert "k2" in mgr2.completed_keys
        all_records = mgr2.get_all_records()
        assert len(all_records) == 2

    def test_run_with_backoff_success(self) -> None:
        calls = 0

        def flaky() -> str:
            nonlocal calls
            calls += 1
            if calls < 2:
                raise ConnectionError("Temporary glitch")
            return "ok"

        res = run_with_backoff(flaky, max_retries=3, initial_delay=0.01)
        assert res == "ok"
        assert calls == 2

    def test_run_with_backoff_exhaustion(self) -> None:
        def bad() -> None:
            raise ValueError("Permanent failure")

        with pytest.raises(ValueError):
            run_with_backoff(bad, max_retries=2, initial_delay=0.01)

    def test_dry_run_task1_and_task2(self, tmp_path: Path) -> None:
        dataset = [
            {
                "app_name": "SampleApp",
                "repo_url": "https://github.com/sample/app",
                "commit_id": "commit1",
                "violated_article": 32,
                "code_snippet_path": "Sample.java:5-10",
                "code_snippet": "public class Sample { void test() {} }",
            }
        ]
        bench_dir = tmp_path / "benchmark"
        bench_dir.mkdir()
        (bench_dir / "task1.json").write_text(json.dumps(dataset), encoding="utf-8")
        (bench_dir / "task2.json").write_text(json.dumps(dataset), encoding="utf-8")

        out1 = tmp_path / "out1"
        metrics1, metrics_file1 = run_evaluation(
            task=1,
            detector_name="static",
            benchmark_dir=bench_dir,
            output_dir=out1,
            dry_run=True,
            workers=1,
        )
        assert metrics_file1.exists()
        assert "file_level" in metrics1
        assert (out1 / "predictions.json").exists()

        out2 = tmp_path / "out2"
        metrics2, metrics_file2 = run_evaluation(
            task=2,
            detector_name="static",
            benchmark_dir=bench_dir,
            output_dir=out2,
            dry_run=True,
            workers=1,
        )
        assert metrics_file2.exists()
        assert "exact_match_accuracy" in metrics2
        assert (out2 / "predictions.json").exists()
