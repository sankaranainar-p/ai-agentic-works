package com.testsimfintech.service;

import com.testsimfintech.model.CoverageReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.List;

@Repository
public interface CoverageReportRepository extends JpaRepository<CoverageReport, Long> {
    Optional<CoverageReport> findByScenarioId(Long scenarioId);
    List<CoverageReport> findAllByOrderByGeneratedAtDesc();
}
