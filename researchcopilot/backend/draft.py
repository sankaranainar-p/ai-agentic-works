"""
draft.py — Module 3: Draft Assistant
-------------------------------------
Generates a related-work paragraph or abstract draft from selected inputs.

IMPORTANT framing for the FDP: this produces a *starting draft*, not a final
text. Any factual claim still needs the author's verification, and any citation
it emits is treated as UNVERIFIED until the Citation Verifier (Module 4)
confirms it. We make that explicit by tagging citations as [CITE: ...].
"""

from __future__ import annotations
from .llm_client import generate

SYSTEM = (
    "You are an academic writing assistant. You write in a formal, neutral "
    "scholarly register. Whenever you reference prior work, mark it inline as "
    "[CITE: author, year, title] so it can be verified later. Never present a "
    "citation as confirmed."
)

PROMPT = """Write a single {kind} (~150-200 words) for the topic below.
Use formal academic prose. Mark every reference to prior work as
[CITE: author, year, title]. Do not fabricate specific statistics.

TOPIC / NOTES:
\"\"\"{notes}\"\"\"
"""


def draft(notes: str, kind: str = "related-work paragraph") -> str:
    """Return a draft paragraph with citations tagged for downstream checking."""
    return generate(PROMPT.format(kind=kind, notes=notes.strip()), system=SYSTEM)
