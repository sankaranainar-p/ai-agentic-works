"""
contradict.py — Cross-corpus contradiction & consensus detection
-----------------------------------------------------------------
Given a claim or topic, this pulls the most relevant passages from ACROSS the
whole corpus and asks the model to classify each as SUPPORTS, CONTRADICTS, or
QUALIFIES the claim — with the supporting quote and source.

Why this is more than a chat wrapper: no single LLM prompt does reliable
multi-document synthesis, and a chat window can't hold a 10-paper corpus with
per-source provenance. Surfacing *disagreement* between papers is exactly the
literature-synthesis work a grad student spends days on by hand.
"""

from __future__ import annotations

from .llm_client import generate_json
from . import retrieve

SYSTEM = (
    "You are a careful evidence analyst. For a given claim, you classify each "
    "source passage's stance strictly by what the passage itself says. You do "
    "not use outside knowledge. Valid stances: SUPPORTS, CONTRADICTS, QUALIFIES, "
    "UNRELATED."
)

PROMPT = """Claim under examination:
"{claim}"

Assess each numbered passage's stance toward the claim. Return ONLY a JSON
object with key "findings": a list of objects, each with:
- "source": the source label given
- "stance": one of SUPPORTS / CONTRADICTS / QUALIFIES / UNRELATED
- "evidence": a short (<25 word) paraphrase of the relevant point
- "confidence": integer 1-5

Passages:
{passages}
"""


def analyze_claim(claim: str, k: int = 6) -> dict:
    """Classify corpus passages as supporting/contradicting a claim.

    Returns per-passage stances plus a consensus tally the UI can chart.
    """
    hits = retrieve.search(claim, k=k)
    if not hits:
        return {"findings": [], "consensus": {}, "passages": []}

    passages_block = "\n\n".join(
        f"[{i+1}] (source: {h['source']}, p.{h['page']})\n{h['text']}"
        for i, h in enumerate(hits)
    )
    result = generate_json(
        PROMPT.format(claim=claim, passages=passages_block), system=SYSTEM
    )

    findings = result.get("findings", [])
    consensus = {"SUPPORTS": 0, "CONTRADICTS": 0, "QUALIFIES": 0, "UNRELATED": 0}
    for f in findings:
        consensus[f.get("stance", "UNRELATED")] = \
            consensus.get(f.get("stance", "UNRELATED"), 0) + 1

    return {"findings": findings, "consensus": consensus, "passages": hits}
