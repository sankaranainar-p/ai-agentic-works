package com.testsimfintech;

import com.testsimfintech.engine.RuleBasedEngine;
import com.testsimfintech.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

@DisplayName("Rule-Based Engine Tests")
class RuleBasedEngineTest {

    private RuleBasedEngine engine;

    @BeforeEach
    void setup() {
        engine = new RuleBasedEngine();
    }

    // -----------------------------------------------------------------------
    // Domain 1: Cross-border
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Cross-border: generates TIMING_CONFLICT and JURISDICTION cases")
    void crossBorder_generatesExpectedCategories() {
        PaymentScenario scenario = buildScenario(ScenarioDomain.CROSS_BORDER_PAYMENT);
        scenario.setHighRiskJurisdiction(true);
        scenario.setCurrency("EUR");

        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases).isNotEmpty();
        assertThat(cases).allMatch(tc -> tc.getEngineType() == TestCase.EngineType.RULE_BASED);
        assertThat(cases).allMatch(TestCase::isDetectedByRules);
        assertThat(cases).allMatch(tc -> !tc.isDetectedByLlm());

        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.TIMING_CONFLICT);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.JURISDICTION_OVERLAP);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.CURRENCY_ANOMALY);
    }

    @Test
    @DisplayName("Cross-border: no currency case when currency is null")
    void crossBorder_noCurrencyCaseWhenCurrencyNull() {
        PaymentScenario scenario = buildScenario(ScenarioDomain.CROSS_BORDER_PAYMENT);
        scenario.setCurrency(null);

        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases)
                .noneMatch(tc -> tc.getCategory() == EdgeCaseCategory.CURRENCY_ANOMALY);
    }

    @Test
    @DisplayName("Cross-border: no jurisdiction case when not high-risk")
    void crossBorder_noJurisdictionCaseWhenNotHighRisk() {
        PaymentScenario scenario = buildScenario(ScenarioDomain.CROSS_BORDER_PAYMENT);
        scenario.setHighRiskJurisdiction(false);

        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases)
                .noneMatch(tc -> tc.getCategory() == EdgeCaseCategory.JURISDICTION_OVERLAP);
    }

    // -----------------------------------------------------------------------
    // Domain 2: Fraud
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Fraud: generates velocity, geo, and threshold cases")
    void fraud_generatesExpectedCategories() {
        PaymentScenario scenario = buildScenario(ScenarioDomain.FRAUD_SPIKE);

        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases).hasSize(3);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.VELOCITY_BREACH);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.GEO_ANOMALY);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.THRESHOLD_GAMING);
    }

    @Test
    @DisplayName("Fraud: all cases have confidence 1.0 (deterministic rules)")
    void fraud_allCasesHaveFullConfidence() {
        PaymentScenario scenario = buildScenario(ScenarioDomain.FRAUD_SPIKE);

        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases).allMatch(tc -> tc.getConfidenceScore() == 1.0);
    }

    // -----------------------------------------------------------------------
    // Domain 3: Compliance
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Compliance: generates CTR, PCI, and MiCA cases when flags set")
    void compliance_generatesExpectedCasesWithFlags() {
        PaymentScenario scenario = buildScenario(ScenarioDomain.COMPLIANCE_THRESHOLD);
        scenario.setRegulatedAsset(true);

        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.AML_REPORTING);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.PCI_EXPOSURE);
        assertThat(cases).anyMatch(tc -> tc.getCategory() == EdgeCaseCategory.MICA_VIOLATION);
    }

    @Test
    @DisplayName("Compliance: no MiCA case when regulatedAsset is false")
    void compliance_noMicaCaseWhenNotRegulated() {
        PaymentScenario scenario = buildScenario(ScenarioDomain.COMPLIANCE_THRESHOLD);
        scenario.setRegulatedAsset(false);

        List<TestCase> cases = engine.generateTestCases(scenario);

        assertThat(cases)
                .noneMatch(tc -> tc.getCategory() == EdgeCaseCategory.MICA_VIOLATION);
    }

    @Test
    @DisplayName("All engines: test cases have required fields populated")
    void allCases_haveRequiredFields() {
        for (ScenarioDomain domain : ScenarioDomain.values()) {
            PaymentScenario scenario = buildScenario(domain);
            scenario.setRegulatedAsset(true);

            List<TestCase> cases = engine.generateTestCases(scenario);

            assertThat(cases).allSatisfy(tc -> {
                assertThat(tc.getTitle()).isNotBlank();
                assertThat(tc.getDescription()).isNotBlank();
                assertThat(tc.getTestInput()).isNotBlank();
                assertThat(tc.getExpectedBehavior()).isNotBlank();
                assertThat(tc.getCategory()).isNotNull();
                assertThat(tc.getEngineType()).isEqualTo(TestCase.EngineType.RULE_BASED);
            });
        }
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------
    private PaymentScenario buildScenario(ScenarioDomain domain) {
        return PaymentScenario.builder()
                .title("Test: " + domain.name())
                .domain(domain)
                .flowDescription("A standard " + domain.getDisplayName() + " flow for testing.")
                .build();
    }
}
