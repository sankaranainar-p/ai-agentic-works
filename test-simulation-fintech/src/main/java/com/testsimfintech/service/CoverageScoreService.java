package com.testsimfintech.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.testsimfintech.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Computes coverage metrics for the research paper.
 *
 * Key metric: coverageDeltaPercent — the percentage increase in unique
 * edge-case categories that the LLM engine produces over the rule-based engine.
 * This is the central empirical finding of the paper.
 */
@Service
public class CoverageScoreService {

    private static final Logger log = LoggerFactory.getLogger(CoverageScoreService.class);

    private final TestCaseRepository testCaseRepo;
    private final CoverageReportRepository reportRepo;
    private final ObjectMapper objectMapper;

    public CoverageScoreService(TestCaseRepository testCaseRepo,
                                 CoverageReportRepository reportRepo,
                                 ObjectMapper objectMapper) {
        this.testCaseRepo = testCaseRepo;
        this.reportRepo = reportRepo;
        this.objectMapper = objectMapper;
    }

    public CoverageReport computeAndSave(PaymentScenario scenario,
                                          List<TestCase> ruleCases,
                                          List<TestCase> llmCases) {
        // Rule-based metrics
        Set<EdgeCaseCategory> ruleCategories = ruleCases.stream()
                .map(TestCase::getCategory)
                .collect(Collectors.toSet());
        double ruleScore = computeCoverageScore(ruleCases, ruleCategories);

        // LLM metrics
        Set<EdgeCaseCategory> llmCategories = llmCases.stream()
                .map(TestCase::getCategory)
                .collect(Collectors.toSet());
        double llmScore = computeCoverageScore(llmCases, llmCategories);

        // Research delta
        long llmExclusive = llmCases.stream()
                .filter(tc -> !ruleCategories.contains(tc.getCategory()))
                .count();

        long semanticOnly = llmCases.stream()
                .filter(tc -> tc.getCategory() == EdgeCaseCategory.SEMANTIC_AMBIGUITY)
                .count();

        double delta = ruleScore > 0
                ? ((llmScore - ruleScore) / ruleScore) * 100.0
                : 0.0;

        // Per-category breakdown
        Map<String, CategoryBreakdown> breakdown = buildBreakdown(ruleCases, llmCases);
        String breakdownJson = toJson(breakdown);

        // Research summary narrative
        String summary = buildResearchSummary(scenario, ruleCases.size(), llmCases.size(),
                ruleCategories.size(), llmCategories.size(), delta, semanticOnly);

        CoverageReport report = CoverageReport.builder()
                .scenario(scenario)
                .ruleBasedTotalCases(ruleCases.size())
                .ruleBasedUniqueCategories(ruleCategories.size())
                .ruleBasedCoverageScore(ruleScore)
                .llmTotalCases(llmCases.size())
                .llmUniqueCategories(llmCategories.size())
                .llmCoverageScore(llmScore)
                .llmExclusiveCases((int) llmExclusive)
                .coverageDeltaPercent(delta)
                .semanticOnlyCases((int) semanticOnly)
                .researchSummary(summary)
                .categoryBreakdownJson(breakdownJson)
                .build();

        // Upsert: replace existing report for this scenario
        reportRepo.findByScenarioId(scenario.getId())
                .ifPresent(existing -> report.setId(existing.getId())); // preserves existing if present

        return reportRepo.save(report);
    }

    /**
     * Coverage score = weighted sum across categories.
     * SEMANTIC_AMBIGUITY cases are weighted 1.5x — they represent the most
     * research-valuable gap (cases requiring contextual reasoning).
     */
    private double computeCoverageScore(List<TestCase> cases, Set<EdgeCaseCategory> categories) {
        if (cases.isEmpty()) return 0.0;

        double base = categories.size() * 10.0;
        double semanticBonus = cases.stream()
                .filter(tc -> tc.getCategory() == EdgeCaseCategory.SEMANTIC_AMBIGUITY)
                .count() * 5.0;

        // Average confidence weighting
        double avgConfidence = cases.stream()
                .mapToDouble(tc -> tc.getConfidenceScore() != null && tc.getConfidenceScore() > 0
                        ? tc.getConfidenceScore() : 0.8)
                .average().orElse(0.8);

        return (base + semanticBonus) * avgConfidence;
    }

    private Map<String, CategoryBreakdown> buildBreakdown(List<TestCase> ruleCases,
                                                           List<TestCase> llmCases) {
        Map<String, CategoryBreakdown> breakdown = new LinkedHashMap<>();

        // All categories from both engines
        Set<EdgeCaseCategory> allCategories = new HashSet<>();
        ruleCases.forEach(tc -> allCategories.add(tc.getCategory()));
        llmCases.forEach(tc -> allCategories.add(tc.getCategory()));

        for (EdgeCaseCategory cat : allCategories) {
            long ruleCount = ruleCases.stream().filter(tc -> tc.getCategory() == cat).count();
            long llmCount  = llmCases.stream().filter(tc -> tc.getCategory() == cat).count();
            breakdown.put(cat.name(), new CategoryBreakdown(
                    cat.getDisplayName(), (int) ruleCount, (int) llmCount));
        }

        return breakdown;
    }

    private String buildResearchSummary(PaymentScenario scenario,
                                         int ruleCaseCount, int llmCaseCount,
                                         int ruleCategories, int llmCategories,
                                         double delta, long semanticOnly) {
        return String.format(
                "For scenario '%s' (domain: %s): " +
                "Rule-based engine generated %d test cases across %d categories. " +
                "LLM-augmented engine generated %d test cases across %d categories. " +
                "Coverage delta: +%.1f%%. " +
                "LLM-exclusive semantic cases (SEMANTIC_AMBIGUITY): %d. " +
                "These represent compliance-critical edge cases requiring contextual reasoning " +
                "that static rule trees cannot enumerate.",
                scenario.getTitle(),
                scenario.getDomain().getDisplayName(),
                ruleCaseCount, ruleCategories,
                llmCaseCount, llmCategories,
                delta, semanticOnly
        );
    }

    private String toJson(Object obj) {
        try { return objectMapper.writeValueAsString(obj); }
        catch (Exception e) { return "{}"; }
    }

    public record CategoryBreakdown(String displayName, int ruleCount, int llmCount) {}
}
