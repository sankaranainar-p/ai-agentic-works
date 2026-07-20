package com.testsimfintech.engine;

import com.testsimfintech.model.*;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Engine A: Rule-Based Scenario Engine
 *
 * Generates test cases using static decision trees, fixed thresholds,
 * and predefined patterns. Represents the industry-standard baseline.
 *
 * Research role: Control group. Its coverage gaps — relative to Engine B —
 * are the core finding of the paper.
 */
@Component
public class RuleBasedEngine {

    public List<TestCase> generateTestCases(PaymentScenario scenario) {
        List<TestCase> cases = new ArrayList<>();

        switch (scenario.getDomain()) {
            case CROSS_BORDER_PAYMENT -> cases.addAll(generateCrossBorderCases(scenario));
            case FRAUD_SPIKE          -> cases.addAll(generateFraudCases(scenario));
            case COMPLIANCE_THRESHOLD -> cases.addAll(generateComplianceCases(scenario));
        }

        // Mark all as rule-detected
        cases.forEach(tc -> {
            tc.setDetectedByRules(true);
            tc.setDetectedByLlm(false);
            tc.setConfidenceScore(1.0);
        });

        return cases;
    }

    // -----------------------------------------------------------------------
    // Domain 1: Cross-border payment delays
    // -----------------------------------------------------------------------
    private List<TestCase> generateCrossBorderCases(PaymentScenario scenario) {
        List<TestCase> cases = new ArrayList<>();

        // Rule 1: SWIFT cutoff window
        cases.add(TestCase.builder()
                .scenario(scenario)
                .engineType(TestCase.EngineType.RULE_BASED)
                .category(EdgeCaseCategory.TIMING_CONFLICT)
                .title("SWIFT cutoff exceeded")
                .description("Payment submitted after 16:00 CET — misses daily SWIFT processing window.")
                .testInput("{ \"submitTime\": \"16:30 CET\", \"channel\": \"SWIFT\", \"route\": \"correspondent\" }")
                .expectedBehavior("Payment deferred to next business day; notification sent to originator.")
                .build());

        // Rule 2: Correspondent bank holiday
        cases.add(TestCase.builder()
                .scenario(scenario)
                .engineType(TestCase.EngineType.RULE_BASED)
                .category(EdgeCaseCategory.TIMING_CONFLICT)
                .title("Correspondent bank holiday conflict")
                .description("Destination country has a public holiday; correspondent bank unavailable.")
                .testInput("{ \"destinationCountry\": \"JP\", \"processingDate\": \"national_holiday\" }")
                .expectedBehavior("Payment queued; SLA clock paused per agreement; client notified.")
                .build());

        // Rule 3: Currency settlement mismatch — simple
        if (scenario.getCurrency() != null && !scenario.getCurrency().equals("USD")) {
            cases.add(TestCase.builder()
                    .scenario(scenario)
                    .engineType(TestCase.EngineType.RULE_BASED)
                    .category(EdgeCaseCategory.CURRENCY_ANOMALY)
                    .title("Non-USD settlement in USD-primary corridor")
                    .description("Payment corridor defaults to USD; requested currency requires additional conversion leg.")
                    .testInput("{ \"currency\": \"" + scenario.getCurrency() + "\", \"corridor\": \"USD_PRIMARY\" }")
                    .expectedBehavior("Additional FX conversion step added; fees disclosed to sender.")
                    .build());
        }

        // Rule 4: High-risk jurisdiction flag (binary)
        if (scenario.isHighRiskJurisdiction()) {
            cases.add(TestCase.builder()
                    .scenario(scenario)
                    .engineType(TestCase.EngineType.RULE_BASED)
                    .category(EdgeCaseCategory.JURISDICTION_OVERLAP)
                    .title("High-risk jurisdiction — enhanced due diligence")
                    .description("Static list match: destination is FATF grey-listed country.")
                    .testInput("{ \"destinationCountry\": \"HIGH_RISK\", \"edd\": false }")
                    .expectedBehavior("Payment held pending EDD review; compliance team notified.")
                    .build());
        }

        return cases;
    }

    // -----------------------------------------------------------------------
    // Domain 2: Fraud spike detection
    // -----------------------------------------------------------------------
    private List<TestCase> generateFraudCases(PaymentScenario scenario) {
        List<TestCase> cases = new ArrayList<>();

        // Rule 1: Simple velocity — 5 transactions in 10 minutes
        cases.add(TestCase.builder()
                .scenario(scenario)
                .engineType(TestCase.EngineType.RULE_BASED)
                .category(EdgeCaseCategory.VELOCITY_BREACH)
                .title("Velocity breach — 5 transactions in 10 min")
                .description("Standard velocity rule: more than 5 transactions from same card in 10-minute window.")
                .testInput("{ \"txCount\": 6, \"windowMinutes\": 10, \"cardId\": \"CARD_001\" }")
                .expectedBehavior("Card temporarily blocked; fraud alert raised; customer SMS sent.")
                .build());

        // Rule 2: Geographic impossibility
        cases.add(TestCase.builder()
                .scenario(scenario)
                .engineType(TestCase.EngineType.RULE_BASED)
                .category(EdgeCaseCategory.GEO_ANOMALY)
                .title("Geographic impossibility — two distant locations")
                .description("Card used in New York then London within 1 hour — physically impossible.")
                .testInput("{ \"location1\": \"New York\", \"location2\": \"London\", \"intervalMinutes\": 45 }")
                .expectedBehavior("Transaction declined; fraud case created; cardholder challenged.")
                .build());

        // Rule 3: Structuring — just below $10,000
        cases.add(TestCase.builder()
                .scenario(scenario)
                .engineType(TestCase.EngineType.RULE_BASED)
                .category(EdgeCaseCategory.THRESHOLD_GAMING)
                .title("Structuring — $9,900 transaction")
                .description("Single transaction just below CTR threshold of $10,000.")
                .testInput("{ \"amount\": 9900, \"currency\": \"USD\", \"reportingThreshold\": 10000 }")
                .expectedBehavior("SAR filed for potential structuring; transaction processed with flag.")
                .build());

        return cases;
    }

    // -----------------------------------------------------------------------
    // Domain 3: Compliance threshold violations
    // -----------------------------------------------------------------------
    private List<TestCase> generateComplianceCases(PaymentScenario scenario) {
        List<TestCase> cases = new ArrayList<>();

        // Rule 1: CTR threshold breach
        cases.add(TestCase.builder()
                .scenario(scenario)
                .engineType(TestCase.EngineType.RULE_BASED)
                .category(EdgeCaseCategory.AML_REPORTING)
                .title("CTR threshold exceeded — $10,001")
                .description("Cash transaction over $10,000 triggers mandatory Currency Transaction Report.")
                .testInput("{ \"amount\": 10001, \"type\": \"CASH\", \"currency\": \"USD\" }")
                .expectedBehavior("CTR filed within 15 days; transaction proceeds; record retained 5 years.")
                .build());

        // Rule 2: PCI — card number in test data
        cases.add(TestCase.builder()
                .scenario(scenario)
                .engineType(TestCase.EngineType.RULE_BASED)
                .category(EdgeCaseCategory.PCI_EXPOSURE)
                .title("PAN present in test payload")
                .description("Test transaction payload contains real-looking 16-digit card number.")
                .testInput("{ \"cardNumber\": \"4111111111111111\", \"environment\": \"TEST\" }")
                .expectedBehavior("Payload rejected; PCI violation logged; developer alerted to use test tokens.")
                .build());

        // Rule 3: MiCA — regulated asset flag
        if (scenario.isRegulatedAsset()) {
            cases.add(TestCase.builder()
                    .scenario(scenario)
                    .engineType(TestCase.EngineType.RULE_BASED)
                    .category(EdgeCaseCategory.MICA_VIOLATION)
                    .title("MiCA token limit breach")
                    .description("E-money token transaction exceeds daily issuance limit under MiCA Art. 23.")
                    .testInput("{ \"tokenType\": \"E_MONEY\", \"dailyVolume\": 1100000, \"micaLimit\": 1000000 }")
                    .expectedBehavior("Transaction blocked; issuer notified of cap breach; regulator informed.")
                    .build());
        }

        return cases;
    }
}
