"""
triage.py — Module 1: Literature Triage
---------------------------------------
Takes raw paper text or an abstract and returns a structured breakdown:
problem, method, key findings, limitations, and candidate research gaps.

This is where an LLM genuinely saves a researcher time — converting dense
prose into a scannable, comparable structure across many papers.
"""

from __future__ import annotations
from .llm_client import generate_json

SYSTEM = (
    "You are a meticulous research assistant for academic faculty. "
    "You extract structure from papers. You never invent findings that are "
    "not present in the text. If something is absent, say 'not stated'."
)

PROMPT = """Analyse the following academic text and return ONLY a JSON object
with these exact keys:

- "problem": one sentence on the problem addressed
- "method": one sentence on the approach/methodology
- "findings": a list of 2-4 short strings, key results
- "limitations": a list of 1-3 short strings (use ["not stated"] if absent)
- "gaps": a list of 2-3 concrete research-gap statements a follow-up study
  could pursue

Do not include any prose outside the JSON.

TEXT:
\"\"\"{text}\"\"\"
"""


def triage(text: str) -> dict:
    """Return structured triage of a paper/abstract."""
    return generate_json(PROMPT.format(text=text.strip()), system=SYSTEM)
