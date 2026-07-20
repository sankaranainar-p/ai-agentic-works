package com.testsimfintech.engine;

import java.util.Optional;

/**
 * Common contract for any LLM backend.
 * Implementations: OllamaClient (primary), ClaudeApiClient (optional cloud fallback).
 */
public interface LlmClient {

    /**
     * Returns true when this client is configured and reachable.
     */
    boolean isAvailable();

    /**
     * Send a system + user prompt and return the model's text response.
     */
    Optional<String> complete(String systemPrompt, String userPrompt);

    /**
     * Human-readable name shown in health endpoint and logs.
     */
    String providerName();
}
