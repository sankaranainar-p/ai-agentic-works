package com.testsimfintech.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Optional;

@Component("claudeApiClient")
public class ClaudeApiClient implements LlmClient {

    private static final Logger log = LoggerFactory.getLogger(ClaudeApiClient.class);

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    @Value("${claude.api.key:}")
    private String apiKey;

    @Value("${claude.api.model:claude-sonnet-4-20250514}")
    private String model;

    @Value("${claude.api.max-tokens:2048}")
    private int maxTokens;

    public ClaudeApiClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .baseUrl("https://api.anthropic.com")
                .defaultHeader("content-type", "application/json")
                .defaultHeader("anthropic-version", "2023-06-01")
                .build();
    }

    @Override
    public boolean isAvailable() {
        return apiKey != null && !apiKey.isBlank();
    }

    @Override
    public String providerName() {
        return "Claude API/" + model;
    }

    @Override
    public Optional<String> complete(String systemPrompt, String userPrompt) {
        if (!isAvailable()) {
            log.warn("Claude API key not configured — LLM engine operating in fallback mode");
            return Optional.empty();
        }

        try {
            ObjectNode requestBody = objectMapper.createObjectNode();
            requestBody.put("model", model);
            requestBody.put("max_tokens", maxTokens);
            requestBody.put("system", systemPrompt);

            ArrayNode messages = requestBody.putArray("messages");
            ObjectNode userMessage = messages.addObject();
            userMessage.put("role", "user");
            userMessage.put("content", userPrompt);

            String responseBody = webClient.post()
                    .uri("/v1/messages")
                    .header("x-api-key", apiKey)
                    .bodyValue(requestBody.toString())
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            JsonNode response = objectMapper.readTree(responseBody);
            String text = response.path("content").get(0).path("text").asText();
            return Optional.of(text);

        } catch (Exception e) {
            log.error("Claude API call failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
