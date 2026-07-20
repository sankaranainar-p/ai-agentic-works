package com.testsimfintech.dto;

import com.testsimfintech.model.ScenarioDomain;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class ScenarioRequest {

    @NotBlank
    private String title;

    @NotNull
    private ScenarioDomain domain;

    @NotBlank
    private String flowDescription;

    private String sourceCountry;
    private String destinationCountry;
    private String currency;
    private Double amount;
    private boolean crossBorderFlag;
    private boolean highRiskJurisdiction;
    private boolean regulatedAsset;

    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public ScenarioDomain getDomain() { return domain; }
    public void setDomain(ScenarioDomain domain) { this.domain = domain; }

    public String getFlowDescription() { return flowDescription; }
    public void setFlowDescription(String flowDescription) { this.flowDescription = flowDescription; }

    public String getSourceCountry() { return sourceCountry; }
    public void setSourceCountry(String sourceCountry) { this.sourceCountry = sourceCountry; }

    public String getDestinationCountry() { return destinationCountry; }
    public void setDestinationCountry(String destinationCountry) { this.destinationCountry = destinationCountry; }

    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }

    public Double getAmount() { return amount; }
    public void setAmount(Double amount) { this.amount = amount; }

    public boolean isCrossBorderFlag() { return crossBorderFlag; }
    public void setCrossBorderFlag(boolean crossBorderFlag) { this.crossBorderFlag = crossBorderFlag; }

    public boolean isHighRiskJurisdiction() { return highRiskJurisdiction; }
    public void setHighRiskJurisdiction(boolean highRiskJurisdiction) { this.highRiskJurisdiction = highRiskJurisdiction; }

    public boolean isRegulatedAsset() { return regulatedAsset; }
    public void setRegulatedAsset(boolean regulatedAsset) { this.regulatedAsset = regulatedAsset; }
}
