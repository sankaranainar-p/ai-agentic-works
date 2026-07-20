package com.testsimfintech;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.testsimfintech.dto.ScenarioRequest;
import com.testsimfintech.engine.LlmClient;
import com.testsimfintech.model.ScenarioDomain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
@DisplayName("Test Simulation FinTech — Controller Integration Tests")
class TestSimControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private LlmClient llmClient;

    // -----------------------------------------------------------------------
    // Health endpoint
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/health — returns UP status")
    void health_returnsUp() throws Exception {
        when(llmClient.isAvailable()).thenReturn(false);

        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.llmAvailable").value(false))
                .andExpect(jsonPath("$.llmProvider").value("HEURISTIC_FALLBACK"));
    }

    @Test
    @DisplayName("GET /api/health — shows LLM available when provider configured")
    void health_showsLlmAvailableWhenProviderAvailable() throws Exception {
        when(llmClient.isAvailable()).thenReturn(true);
        when(llmClient.providerName()).thenReturn("Ollama/llama3.2 @ http://localhost:11434");

        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.llmAvailable").value(true))
                .andExpect(jsonPath("$.llmProvider").value("Ollama/llama3.2 @ http://localhost:11434"));
    }

    // -----------------------------------------------------------------------
    // Domains endpoint
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/domains — returns all three FinTech domains")
    void domains_returnsAllThree() throws Exception {
        mockMvc.perform(get("/api/domains"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)))
                .andExpect(jsonPath("$[*].value", containsInAnyOrder(
                        "CROSS_BORDER_PAYMENT", "FRAUD_SPIKE", "COMPLIANCE_THRESHOLD")));
    }

    // -----------------------------------------------------------------------
    // Scenario analysis
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /api/scenarios — creates scenario and runs both engines")
    void analyze_createsScenarioAndRunsBothEngines() throws Exception {
        when(llmClient.isAvailable()).thenReturn(false);

        ScenarioRequest request = buildRequest(ScenarioDomain.FRAUD_SPIKE);

        mockMvc.perform(post("/api/scenarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scenario.title").value("Fraud spike test"))
                .andExpect(jsonPath("$.scenario.domain").value("FRAUD_SPIKE"))
                .andExpect(jsonPath("$.ruleBasedCases").isArray())
                .andExpect(jsonPath("$.llmCases").isArray())
                .andExpect(jsonPath("$.coverageReport").isNotEmpty())
                .andExpect(jsonPath("$.coverageReport.coverageDeltaPercent").isNumber());
    }

    @Test
    @DisplayName("POST /api/scenarios — returns 400 for missing required fields")
    void analyze_returns400ForMissingFields() throws Exception {
        String invalidRequest = "{ \"domain\": \"FRAUD_SPIKE\" }"; // missing title and flowDescription

        mockMvc.perform(post("/api/scenarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidRequest))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /api/scenarios — compliance domain generates MiCA case when regulated")
    void analyze_complianceDomainWithRegulatedFlag() throws Exception {
        when(llmClient.isAvailable()).thenReturn(false);

        ScenarioRequest request = buildRequest(ScenarioDomain.COMPLIANCE_THRESHOLD);
        request.setRegulatedAsset(true);

        mockMvc.perform(post("/api/scenarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ruleBasedCases[*].category",
                        hasItem("MICA_VIOLATION")));
    }

    @Test
    @DisplayName("POST /api/scenarios — LLM path invoked when API key available")
    void analyze_llmPathInvokedWhenKeyAvailable() throws Exception {
        when(llmClient.isAvailable()).thenReturn(true);
        when(llmClient.complete(anyString(), anyString())).thenReturn(Optional.of("""
                [
                  {
                    "title": "Multi-account structuring",
                    "category": "THRESHOLD_GAMING",
                    "description": "4 accounts, same beneficial owner, $3k each.",
                    "testInput": "{ \\"accounts\\": 4, \\"amountEach\\": 3000 }",
                    "expectedBehavior": "Aggregate SAR filed.",
                    "llmReasoning": "Rule engine operates per-account, not per-beneficial-owner.",
                    "confidenceScore": 0.91
                  }
                ]
                """));

        ScenarioRequest request = buildRequest(ScenarioDomain.FRAUD_SPIKE);

        mockMvc.perform(post("/api/scenarios")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.llmCases[0].title").value("Multi-account structuring"))
                .andExpect(jsonPath("$.llmCases[0].confidenceScore").value(0.91));
    }

    // -----------------------------------------------------------------------
    // List and report endpoints
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/scenarios — returns list after creation")
    void listScenarios_returnsCreatedScenarios() throws Exception {
        when(llmClient.isAvailable()).thenReturn(false);

        // Create one scenario first
        mockMvc.perform(post("/api/scenarios")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(buildRequest(ScenarioDomain.FRAUD_SPIKE))));

        mockMvc.perform(get("/api/scenarios"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @DisplayName("GET /api/reports — returns coverage reports")
    void listReports_returnsReports() throws Exception {
        when(llmClient.isAvailable()).thenReturn(false);

        // Create scenario to generate a report
        mockMvc.perform(post("/api/scenarios")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(buildRequest(ScenarioDomain.CROSS_BORDER_PAYMENT))));

        mockMvc.perform(get("/api/reports"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @DisplayName("GET /api/reports/{id} — 404 for nonexistent scenario")
    void getReport_404ForNonexistent() throws Exception {
        mockMvc.perform(get("/api/reports/99999"))
                .andExpect(status().isNotFound());
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------
    private ScenarioRequest buildRequest(ScenarioDomain domain) {
        ScenarioRequest r = new ScenarioRequest();
        r.setTitle("Fraud spike test");
        r.setDomain(domain);
        r.setFlowDescription("A test payment flow for integration testing.");
        r.setSourceCountry("US");
        r.setDestinationCountry("GB");
        r.setCurrency("USD");
        r.setAmount(5000.0);
        r.setCrossBorderFlag(true);
        return r;
    }
}
