package com.testsimfintech.service;

import com.testsimfintech.model.TestCase;
import com.testsimfintech.model.EdgeCaseCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TestCaseRepository extends JpaRepository<TestCase, Long> {
    List<TestCase> findByScenarioId(Long scenarioId);
    List<TestCase> findByScenarioIdAndEngineType(Long scenarioId, TestCase.EngineType engineType);

    @Query("SELECT t FROM TestCase t WHERE t.scenario.id = :scenarioId AND t.detectedByLlm = true AND t.detectedByRules = false")
    List<TestCase> findLlmExclusiveCases(Long scenarioId);

    @Query("SELECT t FROM TestCase t WHERE t.scenario.id = :scenarioId AND t.category = :category")
    List<TestCase> findByScenarioIdAndCategory(Long scenarioId, EdgeCaseCategory category);

    @Query("SELECT COUNT(DISTINCT t.category) FROM TestCase t WHERE t.scenario.id = :scenarioId AND t.engineType = :engineType")
    int countUniqueCategoriesByEngine(Long scenarioId, TestCase.EngineType engineType);
}
