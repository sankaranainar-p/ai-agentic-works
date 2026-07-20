"""
llm_client.py
-------------
Thin wrapper around a locally-running Ollama instance.

Why local: for an FDP audience the privacy story matters — unpublished
manuscripts, grant drafts, and proprietary data never leave the machine.
Nothing here calls a cloud API.

Requires Ollama running locally (default http://localhost:11434) with a
model pulled, e.g.:  `ollama pull llama3.1:8b`
"""

from __future__ import annotations

import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.1:latest"


class OllamaError(RuntimeError):
    """Raised when the local Ollama server is unreachable or errors."""


def generate(prompt: str, model: str = DEFAULT_MODEL,
             system: str | None = None, temperature: float = 0.2) -> str:
    """Send a single-shot prompt to Ollama and return the text completion.

    Low temperature by default — research summarisation wants determinism,
    not creativity.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if system:
        payload["system"] = system

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise OllamaError(
            f"Could not reach Ollama at {OLLAMA_URL}. "
            f"Is it running? (`ollama serve`). Original error: {exc}"
        ) from exc

    return resp.json().get("response", "").strip()


def generate_json(prompt: str, model: str = DEFAULT_MODEL,
                  system: str | None = None) -> dict:
    """Ask the model for JSON and parse it defensively.

    Local models drift from strict JSON, so we strip code fences and grab the
    outermost braces before parsing. This is the single most common failure
    point when building LLM pipelines — handle it explicitly.
    """
    raw = generate(prompt, model=model, system=system, temperature=0.1)
    cleaned = raw.replace("```json", "").replace("```", "").strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1:
        cleaned = cleaned[start:end + 1]
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {"_parse_error": True, "_raw": raw}
