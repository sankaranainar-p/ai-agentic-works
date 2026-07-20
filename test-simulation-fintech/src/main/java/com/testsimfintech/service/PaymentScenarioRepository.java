package com.testsimfintech.service;

import com.testsimfintech.model.PaymentScenario;
import com.testsimfintech.model.ScenarioDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PaymentScenarioRepository extends JpaRepository<PaymentScenario, Long> {
    List<PaymentScenario> findByDomain(ScenarioDomain domain);
    List<PaymentScenario> findByOrderByCreatedAtDesc();
}
