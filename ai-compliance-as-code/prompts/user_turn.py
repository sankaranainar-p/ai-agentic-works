"""
user_turn.py — Assembles the user-turn message for the AI Compliance-as-Code
VS Code plugin.

Takes the raw code + the context_hint dict produced by static_scanner.scan()
and renders a structured message that:
  1. Orients the model with pre-detected facts so it spends tokens on reasoning
     rather than re-deriving obvious structural information.
  2. Directs the model's attention toward the highest-risk areas flagged by the
     scanner.
  3. Requests the JSON finding array defined in system_prompt.py's output schema.

Usage:
    from scanner.static_scanner import scan
    from prompts.user_turn import build_user_turn

    hint     = scan(code, file_path="src/PaymentService.java")
    message  = build_user_turn(code, "src/PaymentService.java", hint, "PCI DSS")
    # → pass as messages=[{"role": "user", "content": message}] to the API
"""

from __future__ import annotations

from typing import Optional

# Maximum lines of code to inline verbatim in the prompt.
# Files above this limit are sent in full — the VS Code plugin is expected
# to chunk large files before calling this function.
_MAX_INLINE_LINES = 600

# Risk indicator → human-readable directive injected into the "focus areas" block
_RISK_DIRECTIVE: dict[str, str] = {
    "unencrypted_http_outbound":          "One or more outbound calls use plain HTTP — check for PAN or PII in transit (REQ-4 / Art.32).",
    "cardholder_data_in_scope":           "Cardholder data fields detected — verify storage, masking, and tokenisation compliance (REQ-3).",
    "sad_cvv_present":                    "CVV/CVC field detected — this Sensitive Authentication Data must NEVER be stored post-authorisation (REQ-3).",
    "auth_credentials_in_scope":          "Authentication credentials or tokens detected — check for plaintext storage, logging, and key hygiene (REQ-8 / Art.32).",
    "personal_data_in_scope":             "PII fields detected — verify lawful basis, minimisation, and retention controls (Art.5, Art.6, Art.25).",
    "sensitive_fields_on_public_endpoint":"Sensitive fields appear on a public (unauthenticated) endpoint — verify access control (REQ-7 / Art.25).",
    "sensitive_data_in_log_call":         "Sensitive field passed to a logging call — this likely logs PII or cardholder data in plaintext (Art.5 / REQ-3).",
    "mixed_http_https_outbound":          "Both HTTP and HTTPS outbound calls in the same file — verify no sensitive data travels over the HTTP path.",
    "password_field_present":             "Password field detected — verify hashing algorithm (bcrypt/Argon2/scrypt) and ensure it is never logged (REQ-8 / Art.32).",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_user_turn(
    code: str,
    file_path: str,
    context_hint: dict,
    regulation_name: str,
    extra_context: Optional[str] = None,
) -> str:
    """Return the complete user-turn message string ready for the LLM.

    Args:
        code:           Raw source code of the file under analysis.
        file_path:      Path of the file (shown in the prompt for reference).
        context_hint:   Dict returned by ``static_scanner.scan()``.
        regulation_name: Active regulation, e.g. "GDPR" or "PCI DSS v4.0".
        extra_context:  Optional free-text the VS Code plugin can inject
                        (e.g. git diff, PR description, related file names).

    Returns:
        A single string to use as the ``content`` of the user turn.
    """
    sections: list[str] = []

    sections.append(_header_block(file_path, regulation_name, context_hint))
    sections.append(_pre_scan_block(context_hint))

    focus = _focus_areas_block(context_hint)
    if focus:
        sections.append(focus)

    if extra_context:
        sections.append(_extra_context_block(extra_context))

    sections.append(_code_block(code, file_path))
    sections.append(_instruction_block(regulation_name))

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _header_block(file_path: str, regulation_name: str, hint: dict) -> str:
    lang = hint.get("language") or "unknown"
    fw = hint.get("framework")
    fw_conf = hint.get("framework_confidence", 0.0)
    fw_str = f"{fw} (confidence: {fw_conf:.0%})" if fw else "not detected"
    line_count = hint.get("line_count", "?")

    return (
        f"Analyse the following file for {regulation_name} compliance violations.\n"
        f"\n"
        f"File      : {file_path or 'untitled'}\n"
        f"Language  : {lang}\n"
        f"Framework : {fw_str}\n"
        f"Lines     : {line_count}"
    )


def _pre_scan_block(hint: dict) -> str:
    """Summarise what the static pre-scanner already found."""
    lines: list[str] = [
        "────────────────────────────────────────────────────────────────",
        "PRE-SCAN FINDINGS  (static analysis — use as a starting point)",
        "────────────────────────────────────────────────────────────────",
    ]

    # Sensitive fields
    fields: list[dict] = hint.get("sensitive_fields", [])
    if fields:
        lines.append(f"\nSensitive fields detected ({len(fields)}):")
        # Group by category for readability
        by_cat: dict[str, list[dict]] = {}
        for f in fields:
            by_cat.setdefault(f["category"], []).append(f)
        for cat, cat_fields in sorted(by_cat.items()):
            names = ", ".join(
                f"{f['raw_token']} (line {f['line']}, {f['context']})"
                for f in cat_fields
            )
            lines.append(f"  [{cat.upper()}]  {names}")
    else:
        lines.append("\nSensitive fields detected: none")

    # Endpoints
    endpoints: list[dict] = hint.get("endpoints", [])
    if endpoints:
        lines.append(f"\nEndpoints detected ({len(endpoints)}):")
        for ep in endpoints:
            auth_note = (
                f"auth={ep['auth_mechanism']}"
                if ep["auth_mechanism"] not in ("none", "unknown")
                else f"⚠ NO AUTH DETECTED"
            )
            lines.append(
                f"  {ep['method']:7s} {ep['path']:<40s}  "
                f"visibility={ep['visibility']}  {auth_note}  line={ep['line']}"
            )
    else:
        lines.append("\nEndpoints detected: none")

    # Outbound calls
    outbound: list[dict] = hint.get("outbound_calls", [])
    if outbound:
        lines.append(f"\nOutbound HTTP calls ({len(outbound)}):")
        for call in outbound:
            flag = "⚠ UNENCRYPTED" if call["protocol"] == "http" else "✓ encrypted"
            lines.append(
                f"  [{call['protocol'].upper()}]  {call['url'][:80]:<80s}  "
                f"{flag}  via={call['call_site']}  line={call['line']}"
            )
    else:
        lines.append("\nOutbound HTTP calls: none detected")

    return "\n".join(lines)


def _focus_areas_block(hint: dict) -> str:
    """Translate risk indicators into explicit analysis directives."""
    indicators: list[str] = hint.get("risk_indicators", [])
    if not indicators:
        return ""

    lines = [
        "────────────────────────────────────────────────────────────────",
        "FOCUS AREAS  (scanner-flagged risk indicators — prioritise these)",
        "────────────────────────────────────────────────────────────────",
    ]
    for ind in indicators:
        directive = _RISK_DIRECTIVE.get(ind, ind.replace("_", " ").capitalize() + ".")
        lines.append(f"  ▶  {directive}")

    return "\n".join(lines)


def _extra_context_block(extra: str) -> str:
    return (
        "────────────────────────────────────────────────────────────────\n"
        "ADDITIONAL CONTEXT (provided by developer / plugin)\n"
        "────────────────────────────────────────────────────────────────\n"
        + extra.strip()
    )


def _code_block(code: str, file_path: str) -> str:
    lines = code.splitlines()
    truncated = False

    if len(lines) > _MAX_INLINE_LINES:
        lines = lines[:_MAX_INLINE_LINES]
        truncated = True

    # Detect language for fence tag
    ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
    fence_lang = {
        "py": "python", "java": "java", "kt": "kotlin",
        "js": "javascript", "ts": "typescript", "rb": "ruby",
        "go": "go", "cs": "csharp", "php": "php",
    }.get(ext, "")

    body = "\n".join(lines)
    truncation_note = (
        f"\n[... file truncated at {_MAX_INLINE_LINES} lines for prompt length ...]"
        if truncated else ""
    )

    return (
        "────────────────────────────────────────────────────────────────\n"
        f"SOURCE CODE  ({file_path})\n"
        "────────────────────────────────────────────────────────────────\n"
        f"```{fence_lang}\n"
        f"{body}"
        f"{truncation_note}\n"
        "```"
    )


def _instruction_block(regulation_name: str) -> str:
    return (
        "────────────────────────────────────────────────────────────────\n"
        "INSTRUCTIONS\n"
        "────────────────────────────────────────────────────────────────\n"
        f"1. Review the code above for {regulation_name} compliance violations.\n"
        "2. Use the pre-scan findings and focus areas above as your starting point,\n"
        "   but do NOT limit your analysis to them — scan the full file.\n"
        "3. For each violation found, produce one JSON object matching the schema\n"
        "   defined in your system prompt. Include line_start and line_end wherever\n"
        "   possible; set them to null only when the violation is structural.\n"
        "4. If a pre-scan finding turns out NOT to be a violation in context,\n"
        "   you may omit it — do not force a finding.\n"
        "5. Order findings by severity descending: high → medium → low.\n"
        "6. Return ONLY the JSON array. No markdown fences, no explanation text."
    )


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys, textwrap
    from scanner.static_scanner import scan  # type: ignore

    _SAMPLE = textwrap.dedent("""\
        from fastapi import FastAPI
        import requests

        app = FastAPI()

        @app.post("/api/v1/payments")
        def create_payment(card_number: str, cvv: str, email: str):
            response = requests.post("http://payment-processor.internal/charge",
                                     json={"pan": card_number, "cvv": cvv})
            print(f"Payment for {email}, card: {card_number}")
            return {"status": "ok"}
    """)

    code = sys.stdin.read() if not sys.stdin.isatty() else _SAMPLE
    file_path = sys.argv[1] if len(sys.argv) > 1 else "payments.py"
    regulation = sys.argv[2] if len(sys.argv) > 2 else "PCI DSS"

    hint = scan(code, file_path=file_path)
    message = build_user_turn(code, file_path, hint, regulation)
    print(message)
