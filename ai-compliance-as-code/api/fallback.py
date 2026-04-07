"""
api/fallback.py — Static-analysis-only fallback for the /analyze endpoint.

Called when the Anthropic API is unreachable (auth failure, quota exhaustion,
network error). Converts the context_hint produced by static_scanner.scan()
into a best-effort list of ComplianceFinding objects so the VS Code plugin
always receives actionable output.

Findings generated here carry confidence < 1 and the outer AnalyzeResponse
sets llm_unavailable=True so the UI can surface an appropriate warning.
"""

from __future__ import annotations

import uuid
from typing import Dict, List

from api.schemas import ComplianceFinding

# ---------------------------------------------------------------------------
# Risk indicator → partial ComplianceFinding template
#
# Each entry supplies rule_id, title, severity, violation, and remediation.
# line_start / line_end / snippet are filled in where the hint has line numbers.
# References are the canonical article / requirement URLs.
# ---------------------------------------------------------------------------

_INDICATOR_TEMPLATES: Dict[str, Dict] = {
    "unencrypted_http_outbound": {
        "rule_id": "PCI-REQ-4 / GDPR-Art.32",
        "title": "Unencrypted HTTP outbound call",
        "severity": "high",
        "violation": "An outbound HTTP (non-TLS) call was detected; sensitive data in transit is not protected.",
        "remediation": "Replace http:// with https:// and validate TLS certificates (do not disable verify).",
        "references": [
            "https://www.pcisecuritystandards.org/document_library/",
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3383-1-1",
        ],
    },
    "cardholder_data_in_scope": {
        "rule_id": "PCI-REQ-3",
        "title": "Cardholder data field in scope",
        "severity": "high",
        "violation": "Cardholder data (PAN or card number) field detected; storage, masking, and tokenisation must be verified.",
        "remediation": "Tokenise PANs before storage; never persist full card numbers — store only masked last-4 digits.",
        "references": ["https://www.pcisecuritystandards.org/document_library/"],
    },
    "sad_cvv_present": {
        "rule_id": "PCI-REQ-3",
        "title": "CVV/CVC Sensitive Authentication Data present",
        "severity": "high",
        "violation": "A CVV/CVC field was found; Sensitive Authentication Data must never be stored post-authorisation.",
        "remediation": "Remove all CVV/CVC persistence; purge any existing stored values immediately.",
        "references": ["https://www.pcisecuritystandards.org/document_library/"],
    },
    "auth_credentials_in_scope": {
        "rule_id": "PCI-REQ-8 / GDPR-Art.32",
        "title": "Authentication credentials or tokens in scope",
        "severity": "high",
        "violation": "Authentication credential or token field detected; plaintext storage or logging risk.",
        "remediation": "Hash passwords with bcrypt/Argon2. Store tokens in secure vaults; never log credentials.",
        "references": [
            "https://www.pcisecuritystandards.org/document_library/",
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3383-1-1",
        ],
    },
    "personal_data_in_scope": {
        "rule_id": "GDPR-Art.5 / GDPR-Art.25",
        "title": "PII fields detected",
        "severity": "medium",
        "violation": "Personal data fields were found; lawful basis, minimisation, and retention controls must be verified.",
        "remediation": "Apply data minimisation — collect only fields required for the declared purpose; add retention TTL.",
        "references": [
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e1797-1-1",
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3150-1-1",
        ],
    },
    "sensitive_fields_on_public_endpoint": {
        "rule_id": "PCI-REQ-7 / GDPR-Art.25",
        "title": "Sensitive fields on unauthenticated endpoint",
        "severity": "high",
        "violation": "A sensitive data field appears on an endpoint with no detected authentication mechanism.",
        "remediation": "Add authentication guard (JWT, session, API key) before any handler that processes sensitive data.",
        "references": [
            "https://www.pcisecuritystandards.org/document_library/",
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3150-1-1",
        ],
    },
    "sensitive_data_in_log_call": {
        "rule_id": "GDPR-Art.5 / PCI-REQ-3",
        "title": "Sensitive data passed to logging call",
        "severity": "high",
        "violation": "A sensitive field was passed to a logging function; PII or cardholder data is likely logged in plaintext.",
        "remediation": "Remove the sensitive field from the log call or pseudonymise it before logging.",
        "references": [
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e1797-1-1",
            "https://www.pcisecuritystandards.org/document_library/",
        ],
    },
    "mixed_http_https_outbound": {
        "rule_id": "PCI-REQ-4 / GDPR-Art.32",
        "title": "Mixed HTTP and HTTPS outbound calls",
        "severity": "medium",
        "violation": "Both HTTP and HTTPS outbound calls exist in the same file; sensitive data may travel over the HTTP path.",
        "remediation": "Audit every HTTP call to confirm no sensitive data is sent on that path; migrate all calls to HTTPS.",
        "references": [
            "https://www.pcisecuritystandards.org/document_library/",
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3383-1-1",
        ],
    },
    "password_field_present": {
        "rule_id": "PCI-REQ-8 / GDPR-Art.32",
        "title": "Password field detected",
        "severity": "medium",
        "violation": "A password field was detected; the hashing algorithm and logging controls must be verified.",
        "remediation": "Use bcrypt, Argon2id, or scrypt for hashing; ensure the password value is never passed to any logger.",
        "references": [
            "https://www.pcisecuritystandards.org/document_library/",
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3383-1-1",
        ],
    },
}

# Severity sort order for deterministic output
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def build_fallback_findings(
    context_hint: dict,
    file_path: str = "N/A",
) -> List[ComplianceFinding]:
    """Convert a static_scanner context_hint into ComplianceFinding objects.

    Only risk indicators with a known template produce findings.  Each finding
    carries confidence=0.6 to signal that it was derived from pattern matching
    rather than LLM reasoning.

    Args:
        context_hint: Dict returned by ``static_scanner.scan()``.
        file_path:    Path of the analysed file (for display).

    Returns:
        List of ComplianceFinding, sorted high → medium → low.
    """
    indicators: List[str] = context_hint.get("risk_indicators", [])
    sensitive_fields: List[dict] = context_hint.get("sensitive_fields", [])
    outbound_calls: List[dict] = context_hint.get("outbound_calls", [])

    # Build a quick lookup: indicator → first relevant line number from the hint
    _indicator_lines = _extract_indicator_lines(
        indicators, sensitive_fields, outbound_calls
    )

    findings: List[ComplianceFinding] = []

    for indicator in indicators:
        template = _INDICATOR_TEMPLATES.get(indicator)
        if template is None:
            # Unknown indicator — emit a generic low-confidence low-severity finding
            findings.append(
                ComplianceFinding(
                    violation_id=str(uuid.uuid4()),
                    rule_id="UNKNOWN",
                    title=indicator.replace("_", " ").capitalize(),
                    severity="low",
                    severity_override=False,
                    file=file_path,
                    line_start=None,
                    line_end=None,
                    snippet=None,
                    violation=f"Static scanner flagged '{indicator}' — manual review recommended.",
                    remediation="Review the flagged code pattern against the active regulation's requirements.",
                    references=[],
                    confidence=0.4,
                )
            )
            continue

        line = _indicator_lines.get(indicator)
        findings.append(
            ComplianceFinding(
                violation_id=str(uuid.uuid4()),
                rule_id=template["rule_id"],
                title=template["title"],
                severity=template["severity"],
                severity_override=False,
                file=file_path,
                line_start=line,
                line_end=line,
                snippet=None,  # no snippet in fallback — we have no rendered code
                violation=template["violation"],
                remediation=template["remediation"],
                references=template["references"],
                confidence=0.6,
            )
        )

    # Sort high → medium → low
    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))
    return findings


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _extract_indicator_lines(
    indicators: List[str],
    sensitive_fields: List[dict],
    outbound_calls: List[dict],
) -> Dict[str, int]:
    """Best-effort mapping of indicator name → first relevant source line."""
    lines: Dict[str, int] = {}

    # Sensitive-field indicators → use the line of the first matching field
    _field_indicator_map = {
        "cardholder_data_in_scope": {"financial"},
        "sad_cvv_present": {"financial"},
        "auth_credentials_in_scope": {"auth"},
        "personal_data_in_scope": {"pii", "health"},
        "password_field_present": {"auth"},
    }
    for indicator, categories in _field_indicator_map.items():
        if indicator in indicators:
            for field in sensitive_fields:
                if field.get("category") in categories:
                    lines[indicator] = field["line"]
                    break

    # Outbound call indicators → use line of first matching call
    for call in outbound_calls:
        protocol = call.get("protocol", "")
        if protocol == "http" and "unencrypted_http_outbound" in indicators:
            lines.setdefault("unencrypted_http_outbound", call["line"])
        if "mixed_http_https_outbound" in indicators:
            lines.setdefault("mixed_http_https_outbound", call["line"])

    return lines
