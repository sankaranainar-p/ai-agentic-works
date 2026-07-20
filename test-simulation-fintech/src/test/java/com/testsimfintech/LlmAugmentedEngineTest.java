package com.testsimfintech;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.testsimfintech.engine.LlmClient;
import com.testsimfintech.engine.LlmAugmentedEngine;
import com.testsimfintech.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mockito;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@DisplayName("LLM-Augmented Engine Tests")
class LlmAugmentedEngineTest {

    private LlmAugmentedEngine engine;
    private LlmClient mockClient;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setup() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        mockClient = Mockito.mock(LlmClient.class);
        engine = new LlmAugmentedEngine(mockClient, objectMapper);
    }

    // -----------------------------------------------------------------------
    // Fallback mode tests (no API key)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Fallback: cross-border generates jurisdiction and semantic cases")
    void fallback_crossBorder_generatesExpectedCases() {
        when(mockClient.isAvailable()).thenReturn(false);

        PaymentScenario scenario = buildScenario(ScenarioDomain.CROSS_BORDER_PAYMENT);
        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases).isNotEmpty();
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.JURISDICTION_OVERLAP);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.SEMANTIC_AMBIGUITY);
    }

    @Test
    @DisplayName("Fallback: fraud generates synthetic identity and structuring cases")
    void fallback_fraud_generatesExpectedCases() {
        when(mockClient.isAvailable()).thenReturn(false);

        PaymentScenario scenario = buildScenario(ScenarioDomain.FRAUD_SPIKE);
        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.SYNTHETIC_IDENTITY);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.THRESHOLD_GAMING);
    }

    @Test
    @DisplayName("Fallback: compliance generates MiCA misclassification and PCI semantic case")
    void fallback_compliance_generatesExpectedCases() {
        when(mockClient.isAvailable()).thenReturn(false);

        PaymentScenario scenario = buildScenario(ScenarioDomain.COMPLIANCE_THRESHOLD);
        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.MICA_VIOLATION
                || tc.getCategory() == EdgeCaseCategory.SEMANTIC_AMBIGUITY);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.PCI_EXPOSURE
                || tc.getCategory() == EdgeCaseCategory.SEMANTIC_AMBIGUITY);
    }

    @Test
    @DisplayName("Fallback: all cases are LLM-attributed and not rule-detected")
    void fallback_allCasesAttributedToLlm() {
        when(mockClient.isAvailable()).thenReturn(false);

        for (ScenarioDomain domain : ScenarioDomain.values()) {
            PaymentScenario scenario = buildScenario(domain);
            List<TestCase> cases = engine.generateTestCases(scenario);

            assertThat(cases).allMatch(tc -> tc.isDetectedByLlm());
            assertThat(cases).allMatch(tc -> !tc.isDetectedByRules());
            assertThat(cases).allMatch(tc -> tc.getEngineType() == TestCase.EngineType.LLM_AUGMENTED);
        }
    }

    @Test
    @DisplayName("Fallback: all cases have llmReasoning populated — key for paper")
    void fallback_allCasesHaveLlmReasoning() {
        when(mockClient.isAvailable()).thenReturn(false);

        for (ScenarioDomain domain : ScenarioDomain.values()) {
            List<TestCase> cases = engine.generateTestCases(buildScenario(domain));
            assertThat(cases).allSatisfy(tc ->
                assertThat(tc.getLlmReasoning())
                    .as("llmReasoning must be set — it's the research evidence")
                    .isNotBlank());
        }
    }

    @Test
    @DisplayName("Fallback: confidence score is less than 1.0 (heuristic, not live LLM)")
    void fallback_confidenceIsHeuristic() {
        when(mockClient.isAvailable()).thenReturn(false);

        List<TestCase> cases = engine.generateTestCases(buildScenario(ScenarioDomain.FRAUD_SPIKE));

        assertThat(cases).allMatch(tc -> tc.getConfidenceScore() < 1.0);
    }

    // -----------------------------------------------------------------------
    // Live LLM path tests (mocked API response)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("LLM path: parses Claude JSON response into test cases")
    void llmPath_parsesResponseCorrectly() {
        when(mockClient.isAvailable()).thenReturn(true);
        when(mockClient.complete(anyString(), anyString())).thenReturn(Optional.of("""
                [
                  {
                    "title": "Dual-regulation conflict",
                    "category": "JURISDICTION_OVERLAP",
                    "description": "PSD2 and Reg E both apply to this transaction.",
                    "testInput": "{ \\"sender\\": \\"DE\\", \\"recipient\\": \\"US\\" }",
                    "expectedBehavior": "Apply most restrictive regime.",
                    "llmReasoning": "Rule engine only checks sender country, misses US obligations.",
                    "confidenceScore": 0.92
                  },
                  {
                    "title": "Semantic OFAC exemption",
                    "category": "SEMANTIC_AMBIGUITY",
                    "description": "UN humanitarian org in sanctioned country.",
                    "testInput": "{ \\"country\\": \\"IR\\", \\"beneficiary\\": \\"UN_HUMANITARIAN\\" }",
                    "expectedBehavior": "Route via OFAC general license.",
                    "llmReasoning": "Static country blocklist cannot reason about exemption categories.",
                    "confidenceScore": 0.88
                  }
                ]
                """));

        List<TestCase> cases = engine.generateTestCases(buildScenario(ScenarioDomain.CROSS_BORDER_PAYMENT));

        assertThat(cases).hasSize(2);
        assertThat(cases.get(0).getTitle()).isEqualTo("Dual-regulation conflict");
        assertThat(cases.get(0).getCategory()).isEqualTo(EdgeCaseCategory.JURISDICTION_OVERLAP);
        assertThat(cases.get(0).getConfidenceScore()).isEqualTo(0.92);
        assertThat(cases.get(1).getCategory()).isEqualTo(EdgeCaseCategory.SEMANTIC_AMBIGUITY);
        assertThat(cases).allMatch(tc -> tc.isDetectedByLlm());
        assertThat(cases).allMatch(tc -> !tc.isDetectedByRules());
    }

    @Test
    @DisplayName("LLM path: falls back to heuristic when API returns empty")
    void llmPath_fallsBackWhenApiEmpty() {
        when(mockClient.isAvailable()).thenReturn(true);
        when(mockClient.complete(anyString(), anyString())).thenReturn(Optional.empty());

        List<TestCase> cases = engine.generateTestCases(buildScenario(ScenarioDomain.FRAUD_SPIKE));

        // Should get heuristic fallback cases, not empty list
        assertThat(cases).isNotEmpty();
    }

    @Test
    @DisplayName("LLM path: handles unknown category gracefully — maps to SEMANTIC_AMBIGUITY")
    void llmPath_unknownCategoryMapsToSemantic() {
        when(mockClient.isAvailable()).thenReturn(true);
        when(mockClient.complete(anyString(), anyString())).thenReturn(Optional.of("""
                [
                  {
                    "title": "Unknown category test",
                    "category": "COMPLETELY_UNKNOWN_CATEGORY",
                    "description": "Test case with unknown category.",
                    "testInput": "{}",
                    "expectedBehavior": "Handle gracefully.",
                    "llmReasoning": "Testing fallback behaviour.",
                    "confidenceScore": 0.5
                  }
                ]
                """));

        List<TestCase> cases = engine.generateTestCases(buildScenario(ScenarioDomain.FRAUD_SPIKE));

        assertThat(cases).hasSize(1);
        assertThat(cases.get(0).getCategory()).isEqualTo(EdgeCaseCategory.SEMANTIC_AMBIGUITY);
    }

    private PaymentScenario buildScenario(ScenarioDomain domain) {
        return PaymentScenario.builder()
                .id(1L)
                .title("Test: " + domain.name())
                .domain(domain)
                .flowDescription("Test flow for " + domain.getDisplayName())
                .build();
    }
}
