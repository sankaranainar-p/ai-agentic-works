package com.testsimfintech.model;

public enum EdgeCaseCategory {
    // Cross-border
    TIMING_CONFLICT("Timing Conflict", "Cutoff window or settlement timing clash"),
    JURISDICTION_OVERLAP("Jurisdiction Overlap", "Multi-jurisdiction regulatory conflict"),
    CURRENCY_ANOMALY("Currency Anomaly", "FX rate threshold or settlement currency mismatch"),

    // Fraud
    VELOCITY_BREACH("Velocity Breach", "Transaction rate exceeds defined threshold"),
    GEO_ANOMALY("Geo Anomaly", "Geographic impossibility or high-risk corridor"),
    SYNTHETIC_IDENTITY("Synthetic Identity", "Identity components inconsistent or synthetic"),
    THRESHOLD_GAMING("Threshold Gaming", "Structuring near reporting threshold"),

    // Compliance
    AML_REPORTING("AML Reporting", "CTR/SAR threshold trigger"),
    MICA_VIOLATION("MiCA Violation", "EU crypto-asset regulation breach"),
    PCI_EXPOSURE("PCI Data Exposure", "Card data present in test payload"),
    SEMANTIC_AMBIGUITY("Semantic Ambiguity", "LLM-detected contextual violation not covered by rules");

    private final String displayName;
    private final String description;

    EdgeCaseCategory(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() { return displayName; }
    public String getDescription() { return description; }
}
