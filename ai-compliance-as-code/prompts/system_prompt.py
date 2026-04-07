"""
system_prompt.py — Builds the LLM system prompt dynamically for the
AI Compliance-as-Code VS Code plugin.

Usage:
    prompt = build_system_prompt("GDPR", "rules/gdpr.json")
    prompt = build_system_prompt("PCI DSS", "rules/pci_dss.json")
"""

import json
from pathlib import Path
from typing import Union

# ---------------------------------------------------------------------------
# Severity rubric — referenced in the system prompt and by the VS Code plugin
# UI to colour-code findings.
# ---------------------------------------------------------------------------

SEVERITY_RUBRIC: dict[str, dict] = {
    "high": {
        "label": "HIGH",
        "description": (
            "Critical violation that directly exposes personal data or cardholder "
            "data, bypasses authentication/authorisation, or stores/transmits "
            "sensitive data without encryption."
        ),
        "examples": [
            "Storing unencrypted credit card numbers or PAN in a database column",
            "Logging raw passwords or authentication tokens to stdout/files",
            "No consent check before processing personal data (GDPR Art. 6)",
            "Missing TLS/HTTPS on any endpoint that transmits cardholder data",
            "Hardcoded API keys or secrets committed to source control",
            "User PII written to an unprotected S3 bucket or public storage",
        ],
        "slo": "Must be remediated before the code is merged / deployed.",
    },
    "medium": {
        "label": "MEDIUM",
        "description": (
            "Violation that materially increases compliance risk or weakens the "
            "security posture but does not immediately expose sensitive data."
        ),
        "examples": [
            "Audit log entries missing required fields (user, timestamp, action)",
            "Data retention policy not enforced — records kept beyond declared purpose",
            "Weak or missing password-complexity / key-length requirements",
            "Right-to-erasure (GDPR Art. 17) handler exists but does not cascade to backups",
            "Access control implemented but not enforced on all code paths",
            "Encryption at rest present but using a deprecated algorithm (e.g. 3DES, RC4)",
        ],
        "slo": "Must be remediated within the current sprint / release cycle.",
    },
    "low": {
        "label": "LOW",
        "description": (
            "Best-practice gap, documentation deficiency, or minor policy deviation "
            "that does not immediately affect data security or user rights."
        ),
        "examples": [
            "Data Processing Register (ROPA) entry missing for a new processing activity",
            "Privacy notice not updated to reflect a new data field being collected",
            "DPO contact details not surfaced in the application's privacy page",
            "Cookie consent banner present but preference is not persisted across sessions",
            "Vulnerability scan scheduled but result is not linked back to a ticket",
            "PCI DSS network diagram not updated after infrastructure change",
        ],
        "slo": "Must be remediated within 30 days or accepted with documented risk owner.",
    },
}


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def build_system_prompt(
    regulation_name: str,
    rule_pack_path: Union[str, Path],
) -> str:
    """Return the full system prompt string for the given regulation and rule pack.

    Args:
        regulation_name: Human-readable name shown in findings, e.g. "GDPR" or "PCI DSS v4.0".
        rule_pack_path:  Path to the JSON rule pack file (rules/gdpr.json, etc.).

    Returns:
        A multi-section system prompt ready to be passed as the ``system``
        parameter to the Anthropic Messages API.
    """
    rule_pack_path = Path(rule_pack_path)
    if not rule_pack_path.exists():
        raise FileNotFoundError(f"Rule pack not found: {rule_pack_path}")

    with open(rule_pack_path) as fh:
        rule_pack: dict = json.load(fh)

    regulation_meta = rule_pack.get("regulation", {})
    rules: list[dict] = rule_pack.get("rules", [])

    rules_block = _format_rules_block(rules)
    severity_block = _format_severity_block()

    prompt = f"""\
You are an AI Compliance-as-Code engine embedded in a VS Code plugin.
Your sole purpose is to analyse source code, configuration files, and
infrastructure-as-code for violations of {regulation_name}
({regulation_meta.get("full_name", regulation_name)}, version {regulation_meta.get("version", "current")}).

────────────────────────────────────────────────────────────────
ROLE AND CONSTRAINTS
────────────────────────────────────────────────────────────────
• You are a read-only static analyser — you NEVER modify code.
• You report findings only; you do not infer intent or business context
  beyond what is present in the supplied code.
• Every finding MUST cite the specific article / requirement ID from the
  rule pack below.
• If you are unsure whether a pattern constitutes a violation, report it
  as LOW severity with a note that manual review is recommended.
• Do NOT hallucinate regulations, article numbers, or requirement IDs
  that are not listed in the active rule pack.

────────────────────────────────────────────────────────────────
ACTIVE REGULATION: {regulation_name}
────────────────────────────────────────────────────────────────
Full name  : {regulation_meta.get("full_name", regulation_name)}
Version    : {regulation_meta.get("version", "current")}
Jurisdiction: {regulation_meta.get("jurisdiction", "N/A")}
Scope      : {regulation_meta.get("scope", "N/A")}

────────────────────────────────────────────────────────────────
ACTIVE RULE PACK  ({len(rules)} rules)
────────────────────────────────────────────────────────────────
{rules_block}

────────────────────────────────────────────────────────────────
SEVERITY RUBRIC
────────────────────────────────────────────────────────────────
{severity_block}

────────────────────────────────────────────────────────────────
OUTPUT FORMAT
────────────────────────────────────────────────────────────────
Return a JSON array. Each element is one finding with these fields:

{{
  "rule_id":            "<article or requirement ID, e.g. GDPR-Art.32 or PCI-REQ-3>",
  "title":              "<short human-readable title>",
  "severity":           "high" | "medium" | "low",
  "severity_override":  false,          // set true if you escalate beyond default
  "file":               "<file path or 'N/A'>",
  "line_start":         <integer or null>,
  "line_end":           <integer or null>,
  "snippet":            "<offending code snippet, max 10 lines>",
  "violation":          "<one-sentence description of what is wrong>",
  "remediation":        "<one-sentence actionable fix>",
  "references":         ["<regulation article URL or official guidance link>"]
}}

If no violations are found, return an empty array: []
Do NOT wrap the JSON in markdown fences.
Do NOT include any text outside the JSON array.
"""
    return prompt


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _format_rules_block(rules: list[dict]) -> str:
    lines: list[str] = []
    for rule in rules:
        default_sev = rule.get("default_severity", "medium").upper()
        lines.append(
            f"  [{rule['id']}]  {rule['title']}  (default severity: {default_sev})"
        )
        lines.append(f"    {rule['description']}")
        check_hints = rule.get("check_hints", [])
        if check_hints:
            lines.append("    Check for:")
            for hint in check_hints:
                lines.append(f"      • {hint}")
        lines.append("")
    return "\n".join(lines)


def _format_severity_block() -> str:
    lines: list[str] = []
    for level, meta in SEVERITY_RUBRIC.items():
        lines.append(f"  {meta['label']}")
        lines.append(f"    {meta['description']}")
        lines.append(f"    SLO : {meta['slo']}")
        lines.append("    Examples:")
        for ex in meta["examples"]:
            lines.append(f"      • {ex}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    reg = sys.argv[1] if len(sys.argv) > 1 else "GDPR"
    pack = sys.argv[2] if len(sys.argv) > 2 else "rules/gdpr.json"

    print(build_system_prompt(reg, pack))
