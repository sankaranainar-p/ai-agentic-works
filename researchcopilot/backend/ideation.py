"""
ideation.py — Module 2: Ideation / Gap Analysis
------------------------------------------------
Given one or more triaged papers (or a free-text research interest), propose
candidate research questions and project ideas, each scored on novelty and
feasibility so faculty can prioritise.
"""

from __future__ import annotations
from .llm_client import generate_json

SYSTEM = (
    "You are a research strategist helping faculty find publishable, feasible "
    "research directions. You favour specific, testable ideas over vague themes."
)

PROMPT = """Based on the research context below, propose 3 candidate research
directions. Return ONLY a JSON object with key "ideas" whose value is a list of
objects, each with:

- "title": a crisp working title
- "question": the central research question
- "novelty": integer 1-5 (5 = highly novel)
- "feasibility": integer 1-5 (5 = easily feasible for a small team)
- "rationale": one sentence on why it matters

No prose outside the JSON.

RESEARCH CONTEXT:
\"\"\"{context}\"\"\"
"""


def ideate(context: str) -> dict:
    """Return candidate research directions with novelty/feasibility scores."""
    return generate_json(PROMPT.format(context=context.strip()), system=SYSTEM)
