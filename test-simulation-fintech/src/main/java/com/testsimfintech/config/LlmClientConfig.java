package com.testsimfintech.config;

import com.testsimfintech.engine.ClaudeApiClient;
import com.testsimfintech.engine.LlmClient;
import com.testsimfintech.engine.OllamaClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Selects the active LlmClient at startup.
 *
 * Priority:
 *   1. Ollama (local)  — preferred; no API costs, research reproducibility
 *   2. Claude API      — cloud fallback if ANTHROPIC_API_KEY is set and Ollama is down
 *   3. Heuristic       — LlmAugmentedEngine handles this internally when client unavailable
 *
 * The selected client is logged at startup so the mode is always visible.
 */
@Configuration
public class LlmClientConfig {

    private static final Logger log = LoggerFactory.getLogger(LlmClientConfig.class);

    @Bean
    @Primary
    public LlmClient activeLlmClient(OllamaClient ollamaClient,
                                      ClaudeApiClient claudeApiClient) {
        log.info("[LlmClientConfig] ollamaClient.isAvailable()={}, claudeApiClient.isAvailable()={}",
                ollamaClient.isAvailable(), claudeApiClient.isAvailable());

        if (ollamaClient.isAvailable()) {
            log.info("[LlmClientConfig] Selected ollamaClient — class={}, provider={}",
                    ollamaClient.getClass().getName(), ollamaClient.providerName());
            log.info("LLM provider: {} [PRIMARY]", ollamaClient.providerName());
            return ollamaClient;
        }

        if (claudeApiClient.isAvailable()) {
            log.info("[LlmClientConfig] Selected claudeApiClient — class={}, provider={}",
                    claudeApiClient.getClass().getName(), claudeApiClient.providerName());
            log.warn("Ollama unavailable — falling back to {}", claudeApiClient.providerName());
            return claudeApiClient;
        }

        log.info("[LlmClientConfig] No provider available — returning ollamaClient as no-op (class={})",
                ollamaClient.getClass().getName());
        log.warn("No LLM provider available (Ollama unreachable, no Claude API key). " +
                 "LLM engine will use heuristic fallback cases.");
        // Return Ollama client — isAvailable() will return false,
        // LlmAugmentedEngine handles the heuristic path when complete() is called.
        return ollamaClient;
    }
}
