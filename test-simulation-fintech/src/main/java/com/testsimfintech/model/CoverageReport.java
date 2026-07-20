package com.testsimfintech.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.Map;

@Entity
@Table(name = "coverage_reports")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CoverageReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scenario_id", nullable = false)
    private PaymentScenario scenario;

    // Rule-based engine metrics
    private int ruleBasedTotalCases;
    private int ruleBasedUniqueCategories;
    private double ruleBasedCoverageScore;

    // LLM engine metrics
    private int llmTotalCases;
    private int llmUniqueCategories;
    private double llmCoverageScore;

    // Research delta — the core finding
    private int llmExclusiveCases;          // cases only LLM found
    private double coverageDeltaPercent;    // ((llm - rule) / rule) * 100
    private int semanticOnlyCases;          // SEMANTIC_AMBIGUITY category count

    // Summary narrative (LLM-generated)
    @Column(columnDefinition = "TEXT")
    private String researchSummary;

    // Per-category breakdown stored as JSON string
    @Column(columnDefinition = "TEXT")
    private String categoryBreakdownJson;

    @Column(updatable = false)
    private LocalDateTime generatedAt;

    @PrePersist
    protected void onCreate() {
        generatedAt = LocalDateTime.now();
    }
}
