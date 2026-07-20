package com.testsimfintech.model;

public enum ScenarioDomain {
    CROSS_BORDER_PAYMENT("Cross-Border Payment Delays",
            "SWIFT cutoff windows, correspondent bank holidays, PSD2 timing rules, currency settlement conflicts"),
    FRAUD_SPIKE("Fraud Spike Detection",
            "Velocity rules, geo-anomaly + FX correlation, synthetic identity patterns, threshold boundary gaming"),
    COMPLIANCE_THRESHOLD("Compliance Threshold Violations",
            "AML reporting thresholds (CTR/SAR), MiCA token limits, PCI-DSS data exposure in test payloads");

    private final String displayName;
    private final String description;

    ScenarioDomain(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() { return displayName; }
    public String getDescription() { return description; }
}
