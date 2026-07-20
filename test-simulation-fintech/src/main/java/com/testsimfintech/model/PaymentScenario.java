package com.testsimfintech.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;

@Entity
@Table(name = "payment_scenarios")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PaymentScenario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false)
    private String title;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScenarioDomain domain;

    @NotBlank
    @Column(nullable = false, columnDefinition = "TEXT")
    private String flowDescription;

    // Payment metadata
    private String sourceCountry;
    private String destinationCountry;
    private String currency;
    private Double amount;

    // Context flags
    private boolean crossBorderFlag;
    private boolean highRiskJurisdiction;
    private boolean regulatedAsset;  // crypto, securities

    @Column(updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
