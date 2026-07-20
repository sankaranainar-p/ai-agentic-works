package com.testsimfintech.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;

@Entity
@Table(name = "test_cases")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TestCase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scenario_id", nullable = false)
    private PaymentScenario scenario;

    // Which engine generated this
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EngineType engineType;

    // Classification
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EdgeCaseCategory category;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    // The actual test case content
    @Column(columnDefinition = "TEXT")
    private String testInput;

    @Column(columnDefinition = "TEXT")
    private String expectedBehavior;

    // Research metric: was this detected by rule-based engine?
    private boolean detectedByRules;

    // Research metric: was this detected by LLM engine?
    private boolean detectedByLlm;

    // Confidence score (LLM engine populates this; rule engine = 1.0 always)
    private Double confidenceScore;

    // For LLM cases: the reasoning that explains why static rules miss this
    @Column(columnDefinition = "TEXT")
    private String llmReasoning;

    @Column(updatable = false)
    private LocalDateTime generatedAt;

    @PrePersist
    protected void onCreate() {
        generatedAt = LocalDateTime.now();
    }

    public enum EngineType {
        RULE_BASED, LLM_AUGMENTED, BOTH
    }
}
