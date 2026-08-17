"""
api/main.py — FastAPI application for the AI Compliance-as-Code VS Code plugin.

Single endpoint:
    POST /analyze
        • Runs static_scanner.scan() on the submitted code.
        • Builds the system + user prompts.
        • Dispatches to the configured LLM provider (Ollama or Anthropic).
        • Parses the JSON array response into ComplianceFinding objects.
        • Falls back to static-analysis-only findings when the LLM is unavailable.

Environment variables:
    LLM_PROVIDER        "ollama" (default) or "anthropic"
    OLLAMA_BASE_URL     Base URL for the Ollama server (default: http://localhost:11434)
    OLLAMA_MODEL        Model tag to use with Ollama (default: llama3.2)
    ANTHROPIC_API_KEY   Required when LLM_PROVIDER=anthropic.
    RULE_PACK_DIR       Optional. Directory that contains the JSON rule packs.
                        Defaults to "<project_root>/rules/".
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import re
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple

import anthropic
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Path bootstrap — allow running the API from the project root directly
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent          # api/
_ROOT = _HERE.parent                              # project root
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.fallback import build_fallback_findings  # noqa: E402
from api.schemas import AnalyzeRequest, AnalyzeResponse, ComplianceFinding  # noqa: E402
from prompts.system_prompt import build_system_prompt  # noqa: E402
from prompts.user_turn import build_user_turn  # noqa: E402
from scanner.static_scanner import scan  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DEFAULT_RULE_PACK_DIR = _ROOT / "rules"

# Map regulation name keywords to rule pack filenames.
# Keys are lowercase; _resolve_rule_pack() normalises input before lookup.
_REGULATION_TO_PACK: dict[str, str] = {
    "gdpr":    "gdpr.json",
    "pci":     "pci_dss.json",
    "pci dss": "pci_dss.json",
    "mica":    "mica.json",
}

# Errors that mean the Anthropic API itself is unavailable / unrecoverable
_LLM_UNAVAILABLE_EXCEPTIONS = (
    anthropic.AuthenticationError,
    anthropic.PermissionDeniedError,
)

# ---------------------------------------------------------------------------
# LLM provider config (read once at import time; tests may patch os.getenv)
# ---------------------------------------------------------------------------
def _llm_provider() -> str:
    return os.getenv("LLM_PROVIDER", "ollama").lower().strip()

def _ollama_base_url() -> str:
    return os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

def _ollama_model() -> str:
    return os.getenv("OLLAMA_MODEL", "llama3.2")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI Compliance-as-Code",
    description="Analyses source code for GDPR / PCI DSS compliance violations using Claude.",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Helper: resolve rule pack path
# ---------------------------------------------------------------------------

def _resolve_rule_pack(regulation: str) -> Path:
    """Return the Path to the rule pack JSON for *regulation*.

    Raises HTTPException(400) if no matching pack is found.
    """
    rule_pack_dir = Path(os.getenv("RULE_PACK_DIR", str(_DEFAULT_RULE_PACK_DIR)))
    key = regulation.lower().strip()

    for keyword, filename in _REGULATION_TO_PACK.items():
        if keyword in key:
            pack_path = rule_pack_dir / filename
            if pack_path.exists():
                return pack_path
            raise HTTPException(
                status_code=500,
                detail=f"Rule pack file not found: {pack_path}",
            )

    raise HTTPException(
        status_code=400,
        detail=(
            f"Unknown regulation '{regulation}'. "
            f"Supported values: gdpr, mica, pci, pci dss"
        ),
    )


# ---------------------------------------------------------------------------
# Helper: cached system-prompt construction
# ---------------------------------------------------------------------------


@lru_cache(maxsize=32)
def _build_system_prompt_cached(
    regulation: str,
    rule_pack_path: str,
    _mtime_ns: int,
) -> str:
    """Cached wrapper around build_system_prompt().

    The rule packs are static JSON files, but the previous implementation
    re-read and re-rendered them on every /analyze request.  ``_mtime_ns`` is
    part of the cache key rather than being unused: editing a rule pack changes
    the mtime and therefore transparently invalidates the entry, so operators
    can still tune rules without restarting the service.
    """
    return build_system_prompt(regulation, Path(rule_pack_path))


def _system_prompt_for(regulation: str, rule_pack_path: Path) -> str:
    """Return the (cached) system prompt for *regulation*."""
    try:
        mtime_ns = rule_pack_path.stat().st_mtime_ns
    except OSError:
        # Cannot stat — fall back to an uncached build so the real error
        # surfaces from build_system_prompt() itself.
        return build_system_prompt(regulation, rule_pack_path)
    return _build_system_prompt_cached(regulation, str(rule_pack_path), mtime_ns)


# ---------------------------------------------------------------------------
# Helper: strip markdown fences from raw LLM text
# ---------------------------------------------------------------------------

def _strip_fences(text: str) -> str:
    """Remove markdown code fences that wrap an LLM response.

    Only fence markers at the start of a line are removed.  Backticks that
    appear inside the payload are preserved, because they are frequently part
    of a finding's ``snippet`` field and stripping them corrupts the source
    code we report back to the developer.
    """
    text = text.strip()
    if not text.startswith("```"):
        return text

    lines = text.splitlines()
    # Drop the opening fence line (```/```json/```JSON etc.)
    lines = lines[1:]
    # Drop the matching closing fence if present.
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip().startswith("```"):
            del lines[i]
            break
    return "\n".join(lines).strip()


def _iter_json_candidates(text: str):
    """Yield every syntactically valid JSON array/object embedded in *text*.

    Uses ``json.JSONDecoder.raw_decode`` at each ``[``/``{`` position, so a
    candidate is only produced when it actually parses.  This avoids the
    greedy-regex failure modes where prose brackets ("[see rule 5]") or a
    leading object followed by an array produce unparseable slices.

    Yields:
        Tuples of (start_index, parsed_value).
    """
    decoder = json.JSONDecoder()
    for match in re.finditer(r'[\[{]', text):
        start = match.start()
        try:
            value, _ = decoder.raw_decode(text, start)
        except ValueError:
            continue
        yield start, value


def _extract_json_array(text: str) -> str:
    """Extract the first JSON array or object block from *text*.

    Scans for genuinely parseable JSON values and normalises whatever it finds
    into a JSON array string.  Preference order:
      1. The first valid top-level array.
      2. The first valid object — unwrapped when it carries a
         "violations"/"findings"/"results"/"issues" list, otherwise treated as
         a single finding and wrapped in an array.
      3. The original text unchanged, so the caller surfaces the parse error.

    This handles:
      • Properly formatted array:           [{"rule_id": ...}, ...]
      • Object wrapper:                      {"violations": [...]}
      • Single finding object:               {"rule_id": ..., "severity": "high", ...}
      • Array or object buried in prose:     "Here are the findings: [...]"
      • Prose brackets before the array:     "Note [see rule 5]: [{...}]"
      • An object preceding the array:       "{\"a\": 1} then [{...}]"
    """
    first_object: Optional[dict] = None

    for _, value in _iter_json_candidates(text):
        # A list of findings is exactly what we want.
        if isinstance(value, list):
            return json.dumps(value)
        # Remember the first object, but keep scanning for a real array —
        # a wrapper object may appear before the findings array in prose.
        if isinstance(value, dict) and first_object is None:
            first_object = value

    if first_object is not None:
        for key in ("violations", "findings", "results", "issues"):
            nested = first_object.get(key)
            if isinstance(nested, list):
                return json.dumps(nested)
        # Single finding object — wrap it in an array.
        return json.dumps([first_object])

    return text


# ---------------------------------------------------------------------------
# Provider: Ollama
# ---------------------------------------------------------------------------

class OllamaTimeoutError(RuntimeError):
    """Raised when the Ollama HTTP request exceeds the configured timeout."""


@lru_cache(maxsize=32)
def _condense_system_prompt(system_prompt: str) -> str:
    """Strip the system prompt down to rule IDs + titles only for Ollama.

    The full system prompt includes long rule descriptions, check_hints, and a
    verbose severity rubric — often 3-5 KB of text that Ollama must process
    before even reaching the source code.  For local models the scanner_hint
    in the user turn already provides the key context, so we only need the
    rule ID/title list to anchor citation IDs.

    Keeps:
      • The role/constraints header (concise instruction about what to do)
      • The active regulation metadata block
      • A compact rule index: one line per rule — "[ID]  Title  (severity)"
      • The OUTPUT FORMAT block verbatim (critical for JSON schema)

    Strips:
      • Full rule descriptions
      • check_hints bullet lists
      • The verbose SEVERITY RUBRIC (examples and SLO text)
    """
    # Extract just the [ID]  Title  (default severity: X) lines —
    # these are already present in the full prompt produced by build_system_prompt.
    rule_lines = re.findall(
        r'^\s+\[(\S+)\]\s+(.+?)\s+\(default severity: (\w+)\)',
        system_prompt,
        re.MULTILINE,
    )

    # Build a compact rules block
    compact_rules = "\n".join(
        f"  [{rid}]  {title}  (severity: {sev})"
        for rid, title, sev in rule_lines
    )

    # Locate the OUTPUT FORMAT block — keep it verbatim
    output_fmt_marker = "OUTPUT FORMAT"
    output_fmt_start = system_prompt.find(output_fmt_marker)
    output_format_block = (
        system_prompt[output_fmt_start:].strip()
        if output_fmt_start != -1
        else ""
    )

    # Locate the regulation metadata block
    reg_marker = "ACTIVE REGULATION:"
    reg_start = system_prompt.find(reg_marker)
    role_marker = "ACTIVE RULE PACK"
    role_end = system_prompt.find(role_marker)
    regulation_block = (
        system_prompt[reg_start:role_end].strip()
        if reg_start != -1 and role_end != -1
        else ""
    )

    condensed = (
        "You are a compliance code analyser. "
        "Find violations and return ONLY a JSON array — no prose, no fences.\n\n"
        f"{regulation_block}\n\n"
        f"RULES (ID + title only — cite these IDs in your findings):\n{compact_rules}\n\n"
        f"{output_format_block}"
    )
    return condensed


# Instruction prepended to every Ollama prompt to suppress prose wrapping.
_OLLAMA_JSON_PREAMBLE = (
    "IMPORTANT: You must respond with ONLY a valid JSON array. "
    "No explanation, no markdown, no code fences, no text before or after the JSON. "
    "Start your response with [ and end with ]. "
    "Each element in the array must be a JSON object matching the schema in your instructions.\n\n"
)


def _call_ollama(system_prompt: str, user_turn: str) -> str:
    """POST to the Ollama /api/generate endpoint and return cleaned JSON text.

    Combines system_prompt and user_turn into a single "prompt" field.
    Sets stream=false for a single JSON response object.

    Returns:
        Cleaned string ready for json.loads() — fences stripped, array extracted.

    Raises:
        RuntimeError — on HTTP/connection error, missing response field, or
                       when no valid JSON array can be extracted after cleaning.
    """
    base_url = _ollama_base_url()
    model = _ollama_model()
    condensed_system = _condense_system_prompt(system_prompt)
    full_prompt = _OLLAMA_JSON_PREAMBLE + condensed_system + "\n\n" + user_turn

    logger.debug(
        "Ollama request: model=%s prompt_chars=%d\n%s",
        model,
        len(full_prompt),
        full_prompt[:800],
    )

    try:
        resp = httpx.post(
            f"{base_url}/api/generate",
            json={
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 400,
                },
            },
            timeout=180.0,
        )
        resp.raise_for_status()
    except httpx.TimeoutException as exc:
        raise OllamaTimeoutError(f"Ollama request timed out after 180s: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"Ollama HTTP {exc.response.status_code}: {exc.response.text[:200]}"
        ) from exc
    except httpx.RequestError as exc:
        raise RuntimeError(f"Ollama connection error: {exc}") from exc

    try:
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Ollama returned non-JSON body: {resp.text[:200]}") from exc

    raw = data.get("response")
    if raw is None:
        raise RuntimeError(f"Ollama response missing 'response' field: {list(data.keys())}")

    # Log the raw response before cleaning so the exact model output is visible.
    logger.debug("Ollama raw response (chars=%d):\n%s", len(raw), raw[:500])

    cleaned = _strip_fences(raw)
    cleaned = _extract_json_array(cleaned)

    logger.debug("Ollama cleaned response: %r", cleaned[:300])

    # Validate we can parse it before handing back to _parse_findings
    try:
        json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning("Ollama response not parseable as JSON: %r", cleaned[:500])
        raise RuntimeError(
            f"Ollama response could not be parsed as JSON after cleaning: {exc}"
        ) from exc

    return cleaned


# ---------------------------------------------------------------------------
# Provider: Anthropic
# ---------------------------------------------------------------------------

def _call_anthropic(system_prompt: str, user_turn: str) -> str:
    """Stream a request to claude-opus-4-6 and return the full text response.

    Raises:
        anthropic.AuthenticationError / PermissionDeniedError — propagated as-is.
        RuntimeError — when the API returns a non-text or empty response, or
                       when the message contains "credit" (quota exhausted).
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")

    client = anthropic.Anthropic(api_key=api_key)

    try:
        with client.messages.stream(
            model="claude-opus-4-6",
            max_tokens=4096,
            thinking={"type": "adaptive"},
            system=system_prompt,
            messages=[{"role": "user", "content": user_turn}],
        ) as stream:
            message = stream.get_final_message()
    except _LLM_UNAVAILABLE_EXCEPTIONS:
        raise
    except Exception as exc:
        if "credit" in str(exc).lower():
            raise RuntimeError(str(exc)) from exc
        raise

    for block in message.content:
        if block.type == "text":
            return _strip_fences(block.text)

    raise RuntimeError("Anthropic returned no text content block.")


# ---------------------------------------------------------------------------
# Dispatcher: call_llm
# ---------------------------------------------------------------------------

def call_llm(system_prompt: str, user_turn: str) -> Tuple[str, str]:
    """Route to the configured LLM provider and return (raw_text, provider_name).

    Provider is selected via the LLM_PROVIDER environment variable:
        "ollama"     → _call_ollama()   (default)
        "anthropic"  → _call_anthropic()

    Returns:
        Tuple of (raw response text, provider label string).

    Raises:
        Any exception from the underlying provider — callers must handle.
    """
    provider = _llm_provider()
    if provider == "anthropic":
        return _call_anthropic(system_prompt, user_turn), "anthropic"
    # Default to Ollama for any other value (including "ollama")
    return _call_ollama(system_prompt, user_turn), "ollama"


# ---------------------------------------------------------------------------
# Helper: parse LLM JSON output
# ---------------------------------------------------------------------------

def _parse_findings(
    raw_text: str,
    file_path: str,
) -> List[ComplianceFinding]:
    """Parse the JSON array returned by the LLM into ComplianceFinding objects.

    Applies fence stripping and array extraction as a final safety net before
    parsing, even though _call_ollama already does this — _call_anthropic
    feeds text through here too.
    """
    text = _strip_fences(raw_text)
    text = _extract_json_array(text)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM response is not valid JSON: {exc}\n\nRaw:\n{raw_text[:500]}") from exc

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array from LLM, got {type(data).__name__}")

    _sev_order = {"high": 0, "medium": 1, "low": 2}
    findings: List[ComplianceFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # Inject file_path if the model omitted it
        item.setdefault("file", file_path)
        try:
            findings.append(ComplianceFinding(**item))
        except (ValidationError, TypeError):
            # Skip malformed findings rather than failing the whole response
            continue

    # Sort defensively — the LLM is instructed to order findings but may not
    findings.sort(key=lambda f: _sev_order.get(f.severity, 99))
    return findings


# ---------------------------------------------------------------------------
# Helper: deduplicate merged findings
# ---------------------------------------------------------------------------

_TITLE_SIMILARITY_THRESHOLD = 0.80


def _deduplicate_findings(findings: List[ComplianceFinding]) -> List[ComplianceFinding]:
    """Remove near-duplicate findings from a merged LLM + static-scanner list.

    Two findings are considered duplicates when:
      1. They share the same rule_id  (exact match), AND
      2. Their titles have SequenceMatcher similarity >= 0.80

    When a duplicate pair is found, the finding with higher confidence is kept.
    If confidence is equal, the earlier finding (lower index) wins.

    The input list order is otherwise preserved; severity sort is re-applied
    after deduplication.
    """
    kept: List[ComplianceFinding] = []

    for candidate in findings:
        duplicate_index: int = -1

        for i, existing in enumerate(kept):
            if existing.rule_id != candidate.rule_id:
                continue
            similarity = difflib.SequenceMatcher(
                None, existing.title.lower(), candidate.title.lower()
            ).ratio()
            if similarity >= _TITLE_SIMILARITY_THRESHOLD:
                duplicate_index = i
                break

        if duplicate_index == -1:
            kept.append(candidate)
        else:
            # Replace the existing entry only if the candidate has strictly
            # higher confidence (LLM findings win over static-scanner ones).
            if candidate.confidence > kept[duplicate_index].confidence:
                kept[duplicate_index] = candidate

    _sev_order = {"high": 0, "medium": 1, "low": 2}
    kept.sort(key=lambda f: _sev_order.get(f.severity, 99))
    return kept


# ---------------------------------------------------------------------------
# POST /analyze
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyse source code for compliance violations.

    1. Run the static pre-scanner.
    2. Resolve the regulation's rule pack.
    3. Build system + user prompts.
    4. Dispatch to the configured LLM provider (Ollama or Anthropic).
    5. Parse JSON findings.
    6. On any LLM failure, fall back to static-scanner-derived findings.
    """
    t0 = time.perf_counter()

    # Step 1 — static pre-scan (always runs)
    hint_dict = scan(request.code, file_path=request.file_path)

    # Step 2 — resolve rule pack
    rule_pack_path = _resolve_rule_pack(request.regulation)

    # Step 3 — build prompts
    system_prompt = _system_prompt_for(request.regulation, rule_pack_path)
    user_turn = build_user_turn(
        code=request.code,
        file_path=request.file_path,
        context_hint=hint_dict,
        regulation_name=request.regulation,
        extra_context=request.extra_context,
    )

    # Step 4 — static scanner findings (always generated; used for merge + fallback)
    static_findings = build_fallback_findings(hint_dict, file_path=request.file_path)

    # Step 5 — call LLM and parse response
    llm_unavailable = False
    llm_provider = "none"
    llm_findings: List[ComplianceFinding] = []

    try:
        raw_text, llm_provider = call_llm(system_prompt, user_turn)
        llm_findings = _parse_findings(raw_text, request.file_path)
    except OllamaTimeoutError as exc:
        llm_unavailable = True
        llm_provider = "ollama-timeout"
        logger.warning("LLM timed out; falling back to static findings: %s", exc)
    except _LLM_UNAVAILABLE_EXCEPTIONS as exc:
        llm_unavailable = True
        logger.warning(
            "LLM rejected our credentials; falling back to static findings: %s", exc
        )
    except ValueError as exc:
        llm_unavailable = True
        logger.warning(
            "LLM returned an unparseable response; falling back to static findings: %s",
            exc,
        )
    except Exception:
        llm_unavailable = True
        # Still degrade gracefully — a broken LLM must never fail the request —
        # but record the traceback so genuine bugs are not hidden.
        logger.exception("Unexpected LLM error; falling back to static findings")

    # Step 6 — merge and deduplicate
    # Preserve specific failure labels (e.g. "ollama-timeout"); reset everything
    # else to "none" so the response always reflects the true outcome.
    if llm_unavailable and llm_provider not in ("ollama-timeout",):
        llm_provider = "none"
        # LLM failed: static findings only, still deduplicate within them
        findings = _deduplicate_findings(static_findings)
    else:
        # LLM succeeded: merge LLM findings (confidence=1.0) with static findings
        # (confidence=0.6).  Deduplication keeps the higher-confidence version of
        # any pair that shares rule_id and a similar title.
        findings = _deduplicate_findings(llm_findings + static_findings)

    duration_ms = (time.perf_counter() - t0) * 1000.0

    return AnalyzeResponse(
        findings=findings,
        llm_unavailable=llm_unavailable,
        scanner_hint=hint_dict,
        duration_ms=round(duration_ms, 2),
        regulation=request.regulation,
        file_path=request.file_path,
        llm_provider=llm_provider,
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Dev server entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api.main:app", host="0.0.0.0", port=8001, reload=True)
