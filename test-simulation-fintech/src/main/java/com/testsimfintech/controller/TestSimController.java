package com.testsimfintech.controller;

import com.testsimfintech.dto.ScenarioRequest;
import com.testsimfintech.engine.LlmClient;
import com.testsimfintech.model.*;
import com.testsimfintech.service.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestSimController {

    private final ScenarioService scenarioService;
    private final CoverageReportRepository reportRepo;
    private final LlmClient llmClient;

    public TestSimController(ScenarioService scenarioService,
                             CoverageReportRepository reportRepo,
                             LlmClient llmClient) {
        this.scenarioService = scenarioService;
        this.reportRepo = reportRepo;
        this.llmClient = llmClient;
    }

    // -----------------------------------------------------------------------
    // POST /api/scenarios — create and immediately analyze
    // -----------------------------------------------------------------------
    @PostMapping("/scenarios")
    public ResponseEntity<ScenarioService.AnalysisResult> analyze(
            @Valid @RequestBody ScenarioRequest request) {

        PaymentScenario scenario = PaymentScenario.builder()
                .title(request.getTitle())
                .domain(request.getDomain())
                .flowDescription(request.getFlowDescription())
                .sourceCountry(request.getSourceCountry())
                .destinationCountry(request.getDestinationCountry())
                .currency(request.getCurrency())
                .amount(request.getAmount())
                .crossBorderFlag(request.isCrossBorderFlag())
                .highRiskJurisdiction(request.isHighRiskJurisdiction())
                .regulatedAsset(request.isRegulatedAsset())
                .build();

        return ResponseEntity.ok(scenarioService.analyzeScenario(scenario));
    }

    // -----------------------------------------------------------------------
    // GET /api/scenarios — list all scenarios
    // -----------------------------------------------------------------------
    @GetMapping("/scenarios")
    public ResponseEntity<List<PaymentScenario>> listScenarios() {
        return ResponseEntity.ok(scenarioService.getAllScenarios());
    }

    // -----------------------------------------------------------------------
    // GET /api/scenarios/{id}/test-cases — all test cases for a scenario
    // -----------------------------------------------------------------------
    @GetMapping("/scenarios/{id}/test-cases")
    public ResponseEntity<List<TestCase>> getTestCases(@PathVariable Long id) {
        return ResponseEntity.ok(scenarioService.getTestCasesForScenario(id));
    }

    // -----------------------------------------------------------------------
    // GET /api/scenarios/{id}/llm-exclusive — LLM-only cases (the research gap)
    // -----------------------------------------------------------------------
    @GetMapping("/scenarios/{id}/llm-exclusive")
    public ResponseEntity<List<TestCase>> getLlmExclusive(@PathVariable Long id) {
        return ResponseEntity.ok(scenarioService.getLlmExclusiveCases(id));
    }

    // -----------------------------------------------------------------------
    // GET /api/reports — all coverage reports (research data table)
    // -----------------------------------------------------------------------
    @GetMapping("/reports")
    public ResponseEntity<List<CoverageReport>> getAllReports() {
        return ResponseEntity.ok(reportRepo.findAllByOrderByGeneratedAtDesc());
    }

    // -----------------------------------------------------------------------
    // GET /api/reports/{scenarioId} — coverage report for one scenario
    // -----------------------------------------------------------------------
    @GetMapping("/reports/{scenarioId}")
    public ResponseEntity<CoverageReport> getReport(@PathVariable Long scenarioId) {
        return reportRepo.findByScenarioId(scenarioId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // -----------------------------------------------------------------------
    // GET /api/domains — domain metadata for Angular dropdowns
    // -----------------------------------------------------------------------
    @GetMapping("/domains")
    public ResponseEntity<List<Map<String, String>>> getDomains() {
        List<Map<String, String>> domains = List.of(
            Map.of("value", ScenarioDomain.CROSS_BORDER_PAYMENT.name(),
                   "label", ScenarioDomain.CROSS_BORDER_PAYMENT.getDisplayName(),
                   "description", ScenarioDomain.CROSS_BORDER_PAYMENT.getDescription()),
            Map.of("value", ScenarioDomain.FRAUD_SPIKE.name(),
                   "label", ScenarioDomain.FRAUD_SPIKE.getDisplayName(),
                   "description", ScenarioDomain.FRAUD_SPIKE.getDescription()),
            Map.of("value", ScenarioDomain.COMPLIANCE_THRESHOLD.name(),
                   "label", ScenarioDomain.COMPLIANCE_THRESHOLD.getDisplayName(),
                   "description", ScenarioDomain.COMPLIANCE_THRESHOLD.getDescription())
        );
        return ResponseEntity.ok(domains);
    }

    // -----------------------------------------------------------------------
    // GET /api/health — basic health + LLM availability check
    // -----------------------------------------------------------------------
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "llmAvailable", llmClient.isAvailable(),
            "llmProvider", llmClient.isAvailable() ? llmClient.providerName() : "HEURISTIC_FALLBACK"
        ));
    }
}
