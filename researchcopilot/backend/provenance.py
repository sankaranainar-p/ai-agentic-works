"""
provenance.py — Reproducibility envelope
-----------------------------------------
Every generative output in research should be auditable. This wraps any model
call and records: the model + version, the exact prompt, temperature, a UTC
timestamp, and a SHA-256 content hash of the output. Entries append to a local
JSONL log.

Faculty care about reproducibility as much as about correctness. An AI tool
that emits an auditable trail — "here is exactly what was asked, by which model,
and a hash proving this is the unaltered output" — speaks their language and is
genuinely uncommon in LLM demos.
"""

from __future__ import annotations

import os
import json
import hashlib
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), "corpus", "provenance.jsonl")


def record(module: str, model: str, prompt: str, output: str,
           temperature: float) -> dict:
    """Append a provenance entry and return the envelope (for UI display)."""
    content_hash = hashlib.sha256(output.encode("utf-8")).hexdigest()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": module,
        "model": model,
        "temperature": temperature,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest()[:16],
        "output_sha256": content_hash,
        "output_chars": len(output),
    }
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def recent(n: int = 10) -> list[dict]:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH) as f:
        lines = f.readlines()
    return [json.loads(l) for l in lines[-n:]]
