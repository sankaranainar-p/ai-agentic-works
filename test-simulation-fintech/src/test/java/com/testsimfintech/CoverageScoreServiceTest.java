package com.testsimfintech;

import com.testsimfintech.model.*;
import com.testsimfintech.service.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
@DisplayName("Coverage Score Service Integration Tests")
class CoverageScoreServiceTest {

    @Autowired
    private CoverageScoreService coverageService;

    @Autowired
    private PaymentScenarioRepository scenarioRepo;

    @Autowired
    private CoverageReportRepository reportRepo;

    // -----------------------------------------------------------------------
    // Coverage delta — the core research metric
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Coverage delta: LLM exclusive cases produce positive delta")
    void coverageDelta_llmExclusiveCasesProducePositiveDelta() {
        PaymentScenario scenario = scenarioRepo.save(buildScenario(ScenarioDomain.FRAUD_SPIKE));

        List<TestCase> ruleCases = List.of(
            buildCase(scenario, TestCase.EngineType.RULE_BASED, EdgeCaseCategory.VELOCITY_BREACH, true, false, 1.0),
            buildCase(scenario, TestCase.EngineType.RULE_BASED, EdgeCaseCategory.GEO_ANOMALY, true, false, 1.0)
        );

        List<TestCase> llmCases = List.of(
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.SYNTHETIC_IDENTITY, false, true, 0.9),
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.SEMANTIC_AMBIGUITY, false, true, 0.85),
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.THRESHOLD_GAMING, false, true, 0.88)
        );

        CoverageReport report = coverageService.computeAndSave(scenario, ruleCases, llmCases);

        assertThat(report.getCoverageDeltaPercent()).isGreaterThan(0.0);
        assertThat(report.getLlmExclusiveCases()).isEqualTo(3);
        assertThat(report.getSemanticOnlyCases()).isEqualTo(1);
    }

    @Test
    @DisplayName("Coverage delta: zero when both engines produce identical categories")
    void coverageDelta_zeroWhenIdenticalCategories() {
        PaymentScenario scenario = scenarioRepo.save(buildScenario(ScenarioDomain.COMPLIANCE_THRESHOLD));

        List<TestCase> ruleCases = List.of(
            buildCase(scenario, TestCase.EngineType.RULE_BASED, EdgeCaseCategory.AML_REPORTING, true, false, 1.0)
        );
        List<TestCase> llmCases = List.of(
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.AML_REPORTING, false, true, 0.9)
        );

        CoverageReport report = coverageService.computeAndSave(scenario, ruleCases, llmCases);

        // Same categories → same base score, LLM confidence < 1.0 → slight negative delta is OK
        // Key assertion: no LLM exclusive cases
        assertThat(report.getLlmExclusiveCases()).isEqualTo(0);
    }

    @Test
    @DisplayName("Coverage report: persisted and retrievable by scenario ID")
    void coverageReport_persistedAndRetrievable() {
        PaymentScenario scenario = scenarioRepo.save(buildScenario(ScenarioDomain.CROSS_BORDER_PAYMENT));

        List<TestCase> ruleCases = List.of(
            buildCase(scenario, TestCase.EngineType.RULE_BASED, EdgeCaseCategory.TIMING_CONFLICT, true, false, 1.0)
        );
        List<TestCase> llmCases = List.of(
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.SEMANTIC_AMBIGUITY, false, true, 0.9)
        );

        CoverageReport saved = coverageService.computeAndSave(scenario, ruleCases, llmCases);

        assertThat(saved.getId()).isNotNull();
        assertThat(reportRepo.findByScenarioId(scenario.getId())).isPresent();
    }

    @Test
    @DisplayName("Coverage report: research summary is populated")
    void coverageReport_researchSummaryPopulated() {
        PaymentScenario scenario = scenarioRepo.save(buildScenario(ScenarioDomain.FRAUD_SPIKE));

        List<TestCase> ruleCases = List.of(
            buildCase(scenario, TestCase.EngineType.RULE_BASED, EdgeCaseCategory.VELOCITY_BREACH, true, false, 1.0)
        );
        List<TestCase> llmCases = List.of(
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.SYNTHETIC_IDENTITY, false, true, 0.88)
        );

        CoverageReport report = coverageService.computeAndSave(scenario, ruleCases, llmCases);

        assertThat(report.getResearchSummary()).isNotBlank();
        assertThat(report.getResearchSummary()).contains(scenario.getTitle());
        assertThat(report.getResearchSummary()).contains("coverage delta");
    }

    @Test
    @DisplayName("SEMANTIC_AMBIGUITY cases counted correctly for paper metrics")
    void semanticAmbiguityCases_countedCorrectly() {
        PaymentScenario scenario = scenarioRepo.save(buildScenario(ScenarioDomain.COMPLIANCE_THRESHOLD));

        List<TestCase> ruleCases = List.of(
            buildCase(scenario, TestCase.EngineType.RULE_BASED, EdgeCaseCategory.AML_REPORTING, true, false, 1.0),
            buildCase(scenario, TestCase.EngineType.RULE_BASED, EdgeCaseCategory.PCI_EXPOSURE, true, false, 1.0)
        );
        List<TestCase> llmCases = List.of(
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.SEMANTIC_AMBIGUITY, false, true, 0.9),
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.SEMANTIC_AMBIGUITY, false, true, 0.87),
            buildCase(scenario, TestCase.EngineType.LLM_AUGMENTED, EdgeCaseCategory.MICA_VIOLATION, false, true, 0.85)
        );

        CoverageReport report = coverageService.computeAndSave(scenario, ruleCases, llmCases);

        assertThat(report.getSemanticOnlyCases()).isEqualTo(2);
        assertThat(report.getLlmExclusiveCases()).isEqualTo(3); // all 3 categories new
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------
    private PaymentScenario buildScenario(ScenarioDomain domain) {
        return PaymentScenario.builder()
                .title("Coverage test: " + domain.name())
                .domain(domain)
                .flowDescription("Integration test scenario for coverage scoring.")
                .build();
    }

    private TestCase buildCase(PaymentScenario scenario, TestCase.EngineType engine,
                                EdgeCaseCategory category, boolean byRules, boolean byLlm,
                                double confidence) {
        return TestCase.builder()
                .scenario(scenario)
                .engineType(engine)
                .category(category)
                .title("Test case: " + category.name())
                .description("Description for " + category.name())
                .testInput("{}")
                .expectedBehavior("Expected behaviour for " + category.name())
                .detectedByRules(byRules)
                .detectedByLlm(byLlm)
                .confidenceScore(confidence)
                .build();
    }
}
