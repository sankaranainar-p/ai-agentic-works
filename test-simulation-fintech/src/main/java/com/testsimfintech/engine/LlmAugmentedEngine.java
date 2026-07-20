package com.testsimfintech.engine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.testsimfintech.model.*;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Engine B: LLM-Augmented Scenario Engine
 *
 * Uses a local Ollama model (or Claude API as cloud fallback) to reason
 * semantically about payment flows, generating edge cases that static rule
 * trees cannot enumerate — multi-jurisdiction conflicts, threshold boundary
 * conditions, temporal fraud chains, contextual compliance gaps.
 *
 * Research role: Experimental group. Its additional coverage relative to Engine A
 * demonstrates the gap that LLM reasoning closes.
 *
 * Fallback: When no LLM provider is available, applies heuristic enrichment
 * with known LLM-class edge cases from compliance literature.
 */
@Component
public class LlmAugmentedEngine {

    private static final Logger log = LoggerFactory.getLogger(LlmAugmentedEngine.class);

    private final LlmClient llmClient;
    private final ObjectMapper objectMapper;

    public LlmAugmentedEngine(LlmClient llmClient, ObjectMapper objectMapper) {
        this.llmClient = llmClient;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void logInjectedClient() {
        log.info("[LlmAugmentedEngine] injected llmClient class={}, available={}, provider={}",
                llmClient.getClass().getName(),
                llmClient.isAvailable(),
                llmClient.providerName());
    }

    public List<TestCase> generateTestCases(PaymentScenario scenario) {
        log.info("[LlmAugmentedEngine] generateTestCases called — llmClient class={}, available={}, provider={}",
                llmClient.getClass().getName(),
                llmClient.isAvailable(),
                llmClient.providerName());
        if (llmClient.isAvailable()) {
            log.info("LLM engine: using {} for scenario '{}'",
                    llmClient.providerName(), scenario.getTitle());
            return generateWithLlm(scenario);
        } else {
            log.info("LLM engine: no provider available — using heuristic fallback for '{}'",
                    scenario.getTitle());
            return generateWithFallback(scenario);
        }
    }

    // -----------------------------------------------------------------------
    // LLM path — model generates the edge cases
    // -----------------------------------------------------------------------
    private List<TestCase> generateWithLlm(PaymentScenario scenario) {
        String systemPrompt = buildSystemPrompt();
        String userPrompt = buildUserPrompt(scenario);

        Optional<String> response = llmClient.complete(systemPrompt, userPrompt);

        if (response.isEmpty()) {
            log.warn("LLM engine: Claude returned empty — falling back to heuristic mode");
            return generateWithFallback(scenario);
        }

        return parseLlmResponse(response.get(), scenario);
    }

    private String buildSystemPrompt() {
        return """
                You are a senior FinTech compliance and security testing expert specializing in
                payment system edge cases. Your role is to identify test scenarios that rule-based
                engines miss — specifically:

                1. SEMANTIC edge cases: violations that require understanding intent and context,
                   not just threshold comparisons (e.g., a series of legal transactions that
                   collectively indicate structuring without any single transaction breaching a rule).

                2. MULTI-DIMENSIONAL conflicts: scenarios where two or more regulations interact
                   in ways a single rule cannot detect (e.g., a MiCA-compliant token transaction
                   that simultaneously triggers PSD2 strong authentication and AML scrutiny).

                3. TEMPORAL chains: fraud patterns that emerge across time windows larger than
                   standard velocity rules (e.g., a dormant account reactivated to launder proceeds
                   of a previously flagged transaction on a different channel).

                4. JURISDICTIONAL ambiguity: cases where it is genuinely unclear which regulatory
                   regime applies and a compliance system must reason about applicable law rather
                   than match against a country code list.

                Respond ONLY with a valid JSON array. Each element must have these exact fields:
                - "title": string
                - "category": one of [TIMING_CONFLICT, JURISDICTION_OVERLAP, CURRENCY_ANOMALY,
                  VELOCITY_BREACH, GEO_ANOMALY, SYNTHETIC_IDENTITY, THRESHOLD_GAMING,
                  AML_REPORTING, MICA_VIOLATION, PCI_EXPOSURE, SEMANTIC_AMBIGUITY]
                - "description": string — what the edge case is
                - "testInput": either a JSON object OR a plain string describing the test inputs
                - "expectedBehavior": string — what a correct system should do
                - "llmReasoning": string — why a rule-based engine would miss this
                - "confidenceScore": number between 0.0 and 1.0

                Generate between 4 and 7 high-quality edge cases. Prioritize SEMANTIC_AMBIGUITY
                and multi-dimensional cases — these are the most valuable for the research.
                """;
    }

    private String buildUserPrompt(PaymentScenario scenario) {
        return String.format("""
                Analyze the following FinTech payment flow and generate edge case test scenarios
                that a rule-based engine would miss.

                FLOW TITLE: %s
                DOMAIN: %s (%s)
                FLOW DESCRIPTION: %s

                CONTEXT:
                - Source country: %s
                - Destination country: %s
                - Currency: %s
                - Amount: %s
                - Cross-border: %s
                - High-risk jurisdiction: %s
                - Regulated asset (crypto/securities): %s

                Focus especially on compliance-critical gaps specific to this domain.
                Return ONLY the JSON array.
                """,
                scenario.getTitle(),
                scenario.getDomain().name(),
                scenario.getDomain().getDescription(),
                scenario.getFlowDescription(),
                orUnknown(scenario.getSourceCountry()),
                orUnknown(scenario.getDestinationCountry()),
                orUnknown(scenario.getCurrency()),
                scenario.getAmount() != null ? "$" + scenario.getAmount() : "unspecified",
                scenario.isCrossBorderFlag(),
                scenario.isHighRiskJurisdiction(),
                scenario.isRegulatedAsset()
        );
    }

    private List<TestCase> parseLlmResponse(String json, PaymentScenario scenario) {
        List<TestCase> cases = new ArrayList<>();
        try {
            // Strip markdown code fences if present
            String cleaned = json.replaceAll("```json", "").replaceAll("```", "").trim();

            List<LlmTestCaseDto> dtos = objectMapper.readValue(
                    cleaned, new TypeReference<List<LlmTestCaseDto>>() {});

            for (LlmTestCaseDto dto : dtos) {
                EdgeCaseCategory category;
                try {
                    category = EdgeCaseCategory.valueOf(dto.category());
                } catch (IllegalArgumentException e) {
                    category = EdgeCaseCategory.SEMANTIC_AMBIGUITY;
                }

                TestCase tc = TestCase.builder()
                        .scenario(scenario)
                        .engineType(TestCase.EngineType.LLM_AUGMENTED)
                        .category(category)
                        .title(dto.title())
                        .description(dto.description())
                        .testInput(dto.testInput() != null ? dto.testInput().toString() : "{}")
                        .expectedBehavior(dto.expectedBehavior())
                        .llmReasoning(dto.llmReasoning())
                        .confidenceScore(dto.confidenceScore() > 0 ? dto.confidenceScore() : 0.8)
                        .detectedByRules(false)
                        .detectedByLlm(true)
                        .build();

                cases.add(tc);
            }
        } catch (Exception e) {
            log.error("Failed to parse LLM response: {}", e.getMessage());
            log.debug("Raw LLM response: {}", json);
        }
        return cases;
    }

    // -----------------------------------------------------------------------
    // Fallback path — heuristic enrichment when API is unavailable
    // -----------------------------------------------------------------------
    private List<TestCase> generateWithFallback(PaymentScenario scenario) {
        List<TestCase> cases = new ArrayList<>();

        switch (scenario.getDomain()) {
            case CROSS_BORDER_PAYMENT -> cases.addAll(fallbackCrossBorder(scenario));
            case FRAUD_SPIKE          -> cases.addAll(fallbackFraud(scenario));
            case COMPLIANCE_THRESHOLD -> cases.addAll(fallbackCompliance(scenario));
        }

        cases.forEach(tc -> {
            tc.setDetectedByRules(false);
            tc.setDetectedByLlm(true);
            tc.setConfidenceScore(0.75); // Heuristic confidence, lower than live LLM
        });

        return cases;
    }

    private List<TestCase> fallbackCrossBorder(PaymentScenario scenario) {
        return List.of(
            TestCase.builder().scenario(scenario)
                .engineType(TestCase.EngineType.LLM_AUGMENTED)
                .category(EdgeCaseCategory.JURISDICTION_OVERLAP)
                .title("Dual-regulation conflict — EU sender, US recipient, USD amount")
                .description("PSD2 (EU) and Reg E (US) both apply; conflicting dispute resolution timelines. Rule engine matches one regime; LLM reasons that both apply simultaneously.")
                .testInput("{ \"sender\": \"DE\", \"recipient\": \"US\", \"currency\": \"USD\", \"amount\": 5000 }")
                .expectedBehavior("System applies most restrictive timeline; both regulators notified per their requirements.")
                .llmReasoning("Rule engine checks sender country → applies PSD2 only. Misses that USD amount triggers US Reg E obligations on the receiving institution.")
                .build(),
            TestCase.builder().scenario(scenario)
                .engineType(TestCase.EngineType.LLM_AUGMENTED)
                .category(EdgeCaseCategory.SEMANTIC_AMBIGUITY)
                .title("Charity payment to sanctioned region — humanitarian exemption")
                .description("Payment to OFAC-listed country but beneficiary is an UN-registered humanitarian org. Rule engine blocks on country code; LLM recognises exemption category.")
                .testInput("{ \"destinationCountry\": \"IR\", \"beneficiaryType\": \"UN_HUMANITARIAN\", \"exemptionCode\": \"OFAC_GL\" }")
                .expectedBehavior("Payment routed through OFAC general license pathway; enhanced documentation required.")
                .llmReasoning("Static country blacklist blocks all payments to IR. Cannot reason about UN humanitarian exemption (OFAC General License) without semantic understanding of beneficiary context.")
                .build()
        );
    }

    private List<TestCase> fallbackFraud(PaymentScenario scenario) {
        return List.of(
            TestCase.builder().scenario(scenario)
                .engineType(TestCase.EngineType.LLM_AUGMENTED)
                .category(EdgeCaseCategory.SYNTHETIC_IDENTITY)
                .title("Synthetic identity — individually valid, collectively impossible")
                .description("SSN issued in 2010, DOB 1945, first credit file opened 2023. Each data point passes individual validation rules; LLM detects the temporal impossibility.")
                .testInput("{ \"ssn_issue_year\": 2010, \"dob\": \"1945\", \"credit_file_opened\": 2023 }")
                .expectedBehavior("Account flagged for synthetic identity review; transaction held pending manual review.")
                .llmReasoning("Rule engine validates SSN format, DOB format, credit file existence independently. Misses that a person born in 1945 cannot have an SSN issued in 2010 (SSNs are issued at birth post-1985).")
                .build(),
            TestCase.builder().scenario(scenario)
                .engineType(TestCase.EngineType.LLM_AUGMENTED)
                .category(EdgeCaseCategory.THRESHOLD_GAMING)
                .title("Multi-account structuring — same beneficial owner")
                .description("$3,000 each across four accounts, same beneficial owner, within 2 hours. Individual transactions pass velocity and threshold rules; LLM aggregates across accounts by beneficial owner.")
                .testInput("{ \"accounts\": 4, \"amountEach\": 3000, \"windowHours\": 2, \"sameBeneficialOwner\": true }")
                .expectedBehavior("Aggregate SAR filed; all four transactions flagged; beneficial owner record updated.")
                .llmReasoning("Velocity rules operate per-account, not per-beneficial-owner. A rule engine cannot link accounts by beneficial owner without semantic reasoning about ownership structure.")
                .build()
        );
    }

    private List<TestCase> fallbackCompliance(PaymentScenario scenario) {
        return List.of(
            TestCase.builder().scenario(scenario)
                .engineType(TestCase.EngineType.LLM_AUGMENTED)
                .category(EdgeCaseCategory.SEMANTIC_AMBIGUITY)
                .title("Test data with synthetic PAN passes Luhn but violates PCI intent")
                .description("Developer uses a Luhn-valid synthetic card number that matches a real BIN range. Passes format validation; LLM flags that BIN range belongs to active issuer — real data risk.")
                .testInput("{ \"pan\": \"4532015112830366\", \"environment\": \"TEST\", \"binOwner\": \"ACTIVE_ISSUER\" }")
                .expectedBehavior("Test payload rejected; warning that BIN range is assigned to active issuer; developer directed to use isolated test BINs.")
                .llmReasoning("PCI rule checks Luhn validity and detects 16-digit patterns. Cannot reason that a Luhn-valid number in an active BIN range poses real data exposure risk even in test environments.")
                .build(),
            TestCase.builder().scenario(scenario)
                .engineType(TestCase.EngineType.LLM_AUGMENTED)
                .category(EdgeCaseCategory.MICA_VIOLATION)
                .title("Stablecoin payment — e-money token misclassified as utility token")
                .description("Token is pegged to EUR and redeemable at par — legal definition of e-money token under MiCA. Issuer classified it as utility token to avoid Art. 23 limits. LLM reasons about economic substance over stated classification.")
                .testInput("{ \"tokenType\": \"UTILITY\", \"peggedTo\": \"EUR\", \"redeemable\": true, \"parValue\": true }")
                .expectedBehavior("Token reclassified as e-money token; MiCA Art. 23 limits applied; issuer notified of misclassification risk.")
                .llmReasoning("Rule engine checks the tokenType field value = UTILITY and skips MiCA e-money checks. Cannot reason about economic substance — that a EUR-pegged redeemable token IS an e-money token regardless of what the issuer calls it.")
                .build()
        );
    }

    private String orUnknown(String value) {
        return (value != null && !value.isBlank()) ? value : "unspecified";
    }

    // DTO for parsing LLM JSON response
    public record LlmTestCaseDto(
        String title,
        String category,
        String description,
        JsonNode testInput,
        String expectedBehavior,
        String llmReasoning,
        double confidenceScore
    ) {}
}
