"""
grounded.py — Grounded extraction over the retrieved corpus
-----------------------------------------------------------
Instead of summarising whatever you paste, this asks a question against the
ingested PDF corpus, retrieves the most relevant chunks, and instructs the
model to answer USING ONLY those chunks — tagging each claim with the chunk id
it came from. The UI then resolves [S:chunkid] back to source + page + text.

When web_enrich=True the local corpus hits are blended with real-time
Semantic Scholar abstracts. Local passages are tagged [LOCAL] and web
passages are tagged [WEB] so the LLM and the UI can distinguish them.
"""

from __future__ import annotations

from .llm_client import generate
from . import retrieve
from . import web_retriever

SYSTEM = (
    "You are a grounded research assistant. You answer ONLY using the numbered "
    "source passages provided. Every sentence you write must end with the tag "
    "of the passage(s) it draws from, like [S:ab12cd34]. If the passages do not "
    "support an answer, say exactly: 'The provided sources do not address this.' "
    "You never use outside knowledge and never invent passage tags."
)

PROMPT = """Question: {question}

Source passages (use ONLY these, cite each by its tag):
{passages}

Write a grounded answer of 3-6 sentences. End every sentence with the
tag(s) of the source passage(s) it relies on, e.g. [S:ab12cd34].
"""


def grounded_answer(question: str, k: int = 4, web_enrich: bool = False) -> dict:
    """Retrieve, then answer with per-sentence source attribution.

    When web_enrich is True, Semantic Scholar is queried in real-time and its
    results are appended after the local corpus hits. The LLM sees both; the UI
    renders LOCAL vs WEB badges per passage.

    Returns the answer text, local passages, and (if requested) web passages.
    """
    local_hits = retrieve.search(question, k=k)
    web_hits: list[dict] = []

    if web_enrich:
        raw_web = web_retriever.search_web(query=question, k=k)
        web_hits = [h for h in raw_web if h.get("origin") == "WEB"]
        web_errors = [h for h in raw_web if h.get("origin") == "WEB_ERROR"]
    else:
        web_errors = []

    all_hits = (
        [{**h, "origin": "LOCAL"} for h in local_hits] +
        web_hits
    )

    if not all_hits:
        return {
            "answer": "No documents have been ingested yet and no web results found. Add PDFs first.",
            "passages": [],
            "web_passages": [],
            "web_errors": web_errors,
        }

    passages_block = "\n\n".join(
        f"[S:{h['id']}] ({h.get('origin','LOCAL')} — source: {h['source']}"
        + (f", p.{h['page']}" if h.get("page") else "")
        + (f", relevance {h['score']}" if h.get("score") is not None else "")
        + f")\n{h['text']}"
        for h in all_hits
    )

    answer = generate(
        PROMPT.format(question=question, passages=passages_block),
        system=SYSTEM, temperature=0.1,
    )
    return {
        "answer": answer,
        "passages": [{**h, "origin": "LOCAL"} for h in local_hits],
        "web_passages": web_hits,
        "web_errors": web_errors,
    }
