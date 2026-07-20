package com.testsimfintech.service;

import com.testsimfintech.engine.LlmAugmentedEngine;
import com.testsimfintech.engine.RuleBasedEngine;
import com.testsimfintech.model.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class ScenarioService {

    private final PaymentScenarioRepository scenarioRepo;
    private final TestCaseRepository testCaseRepo;
    private final RuleBasedEngine ruleEngine;
    private final LlmAugmentedEngine llmEngine;
    private final CoverageScoreService coverageService;

    public ScenarioService(PaymentScenarioRepository scenarioRepo,
                           TestCaseRepository testCaseRepo,
                           RuleBasedEngine ruleEngine,
                           LlmAugmentedEngine llmEngine,
                           CoverageScoreService coverageService) {
        this.scenarioRepo = scenarioRepo;
        this.testCaseRepo = testCaseRepo;
        this.ruleEngine = ruleEngine;
        this.llmEngine = llmEngine;
        this.coverageService = coverageService;
    }

    /**
     * Create a scenario and immediately run both engines against it.
     * Returns a full AnalysisResult including test cases from both engines
     * and the computed coverage report.
     */
    public AnalysisResult analyzeScenario(PaymentScenario scenario) {
        // Persist scenario
        PaymentScenario saved = scenarioRepo.save(scenario);

        // Run both engines
        List<TestCase> ruleCases = ruleEngine.generateTestCases(saved);
        List<TestCase> llmCases  = llmEngine.generateTestCases(saved);

        // Persist test cases
        testCaseRepo.saveAll(ruleCases);
        testCaseRepo.saveAll(llmCases);

        // Compute and persist coverage report
        CoverageReport report = coverageService.computeAndSave(saved, ruleCases, llmCases);

        return new AnalysisResult(saved, ruleCases, llmCases, report);
    }

    public List<PaymentScenario> getAllScenarios() {
        return scenarioRepo.findByOrderByCreatedAtDesc();
    }

    public List<TestCase> getTestCasesForScenario(Long scenarioId) {
        return testCaseRepo.findByScenarioId(scenarioId);
    }

    public List<TestCase> getLlmExclusiveCases(Long scenarioId) {
        return testCaseRepo.findLlmExclusiveCases(scenarioId);
    }

    public record AnalysisResult(
        PaymentScenario scenario,
        List<TestCase> ruleBasedCases,
        List<TestCase> llmCases,
        CoverageReport coverageReport
    ) {}
}
