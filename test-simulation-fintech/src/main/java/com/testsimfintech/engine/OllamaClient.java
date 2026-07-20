package com.testsimfintech.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.Duration;
import java.util.Optional;

/**
 * LlmClient implementation backed by a local Ollama instance.
 *
 * Uses the Ollama /api/chat endpoint with the OpenAI-compatible message format.
 * Availability is determined by whether the Ollama base URL is configured and
 * a connectivity check succeeds on startup.
 *
 * Matches the pattern from the CaC engine: temperature 0.1, num_predict 400
 * (overridden here to 2048 to handle longer JSON scenario outputs).
 */
@Component("ollamaClient")
public class OllamaClient implements LlmClient {

    private static final Logger log = LoggerFactory.getLogger(OllamaClient.class);

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    @Value("${ollama.base-url:http://localhost:11434}")
    private String baseUrl;

    @Value("${ollama.model:llama3.2}")
    private String model;

    @Value("${ollama.num-predict:2048}")
    private int numPredict;

    @Value("${ollama.temperature:0.1}")
    private double temperature;

    @Value("${ollama.enabled:true}")
    private boolean enabled;

    @Value("${ollama.timeout-seconds:120}")
    private int timeoutSeconds;

    public OllamaClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .defaultHeader("Content-Type", "application/json")
                .build();
    }

    @PostConstruct
    public void logConfig() {
        log.info("[OllamaClient] baseUrl={}, model={}, enabled={}, available={}",
                baseUrl, model, enabled, isAvailable());
    }

    @Override
    public boolean isAvailable() {
        if (!enabled) return false;
        try {
            // Ping Ollama's tags endpoint — fast check, no model loading
            String url = baseUrl + "/api/tags";
            webClient.get()
                    .uri(url)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(3))
                    .block();
            return true;
        } catch (Exception e) {
            log.debug("Ollama not reachable at {}: {}", baseUrl, e.getMessage());
            return false;
        }
    }

    @Override
    public String providerName() {
        return "Ollama/" + model + " @ " + baseUrl;
    }

    @Override
    public Optional<String> complete(String systemPrompt, String userPrompt) {
        try {
            ObjectNode requestBody = objectMapper.createObjectNode();
            requestBody.put("model", model);
            requestBody.put("stream", false);

            // Messages array — system + user
            ArrayNode messages = requestBody.putArray("messages");

            ObjectNode sysMsg = messages.addObject();
            sysMsg.put("role", "system");
            sysMsg.put("content", systemPrompt);

            ObjectNode userMsg = messages.addObject();
            userMsg.put("role", "user");
            userMsg.put("content", userPrompt);

            // Options
            ObjectNode options = requestBody.putObject("options");
            options.put("temperature", temperature);
            options.put("num_predict", numPredict);

            String requestBodyStr = requestBody.toString();
            String callUrl = baseUrl + "/api/chat";
            log.info("[OllamaClient] POST {} — request body length={}", callUrl, requestBodyStr.length());

            String responseBody = webClient.post()
                    .uri(callUrl)
                    .bodyValue(requestBodyStr)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .block();

            log.info("[OllamaClient] Raw response (first 500 chars): {}",
                    responseBody != null ? responseBody.substring(0, Math.min(500, responseBody.length())) : "null");

            JsonNode response = objectMapper.readTree(responseBody);
            String text = response.path("message").path("content").asText();

            log.info("[OllamaClient] Extracted text (first 500 chars): {}",
                    text.substring(0, Math.min(500, text.length())));

            if (text.isBlank()) {
                log.warn("Ollama returned empty content");
                return Optional.empty();
            }

            log.info("Ollama response: {} chars", text.length());
            return Optional.of(text);

        } catch (WebClientResponseException e) {
            log.error("Ollama HTTP error {}: {}", e.getStatusCode(), e.getResponseBodyAsString());
            return Optional.empty();
        } catch (Exception e) {
            log.error("Ollama call failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
