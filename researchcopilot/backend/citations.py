"""
citations.py — Citation Trail: extract and validate a PDF's bibliography
------------------------------------------------------------------------
Reads the reference section from an ingested PDF (last 15% of pages),
parses each reference via the local LLM, then validates against Semantic
Scholar (primary) with CrossRef as fallback. Returns structured results
the UI renders as per-reference status badges.

Only reference strings leave the machine — no full PDF text goes outbound.
"""
from __future__ import annotations

import os
import requests
from difflib import SequenceMatcher
from pypdf import PdfReader

from .llm_client import generate_json
from .verify import verify_one

_SS_SEARCH_URL = "https://api.semanticscholar.org/graph/v1/paper/search"
_SS_FIELDS = "title,authors,year,externalIds,abstract"
_USER_AGENT = "ResearchCopilot/1.0 (mailto:demo@researchcopilot.local)"
_TITLE_THRESHOLD = 0.6

_EXTRACT_SYSTEM = (
    "You are a reference parser. Extract bibliography entries from raw PDF text. "
    "Return only valid JSON. Never invent references not present in the text."
)

_EXTRACT_PROMPT = """Parse the following bibliography text into structured references.
Return ONLY a JSON object with key "references" containing a list of objects, each with:
- "raw": the full original reference string (required)
- "title": paper title string, or null if unclear
- "authors": author string, or null if unclear
- "year": publication year as string, or null if unclear

TEXT:
\"\"\"{text}\"\"\"
"""

_NOT_FOUND: dict = {
    "status": "NOT_FOUND", "source": None, "matched_title": None,
    "authors": None, "year": None, "doi": None,
    "abstract": None, "url": None, "similarity": None,
}


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def extract_references(pdf_path: str) -> list[dict]:
    """Extract bibliography entries from the last 15% of PDF pages via local LLM."""
    reader = PdfReader(pdf_path)
    total = len(reader.pages)
    start = max(0, int(total * 0.85))

    ref_text = "\n".join(
        page.extract_text() or "" for page in reader.pages[start:]
    ).strip()

    if not ref_text:
        return []

    result = generate_json(
        _EXTRACT_PROMPT.format(text=ref_text[:4000]),
        system=_EXTRACT_SYSTEM,
    )
    return [
        {
            "raw": r.get("raw", ""),
            "title": r.get("title"),
            "authors": r.get("authors"),
            "year": r.get("year"),
        }
        for r in result.get("references", [])
        if r.get("raw")
    ]


def lookup_reference(ref: dict) -> dict:
    """Validate one reference: Semantic Scholar first, CrossRef as fallback."""
    query = ref.get("title") or ref.get("raw", "")
    if not query.strip():
        return {**_NOT_FOUND, "status": "ERROR"}

    try:
        resp = requests.get(
            _SS_SEARCH_URL,
            params={"query": query, "fields": _SS_FIELDS, "limit": 1},
            headers={"User-Agent": _USER_AGENT},
            timeout=12,
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if data:
            p = data[0]
            matched = p.get("title") or ""
            sim = _similarity(query, matched)
            if sim >= _TITLE_THRESHOLD:
                ext = p.get("externalIds") or {}
                doi = ext.get("DOI", "")
                authors = ", ".join(
                    a.get("name", "") for a in (p.get("authors") or [])[:3]
                )
                return {
                    "status": "FOUND",
                    "source": "SEMANTIC_SCHOLAR",
                    "matched_title": matched,
                    "authors": authors or None,
                    "year": str(p.get("year") or "") or None,
                    "doi": doi or None,
                    "abstract": (p.get("abstract") or "")[:300] or None,
                    "url": f"https://doi.org/{doi}" if doi else None,
                    "similarity": round(sim, 2),
                }
    except requests.RequestException:
        pass

    cr = verify_one(query)
    if cr.get("status") == "VERIFIED":
        doi = cr.get("doi", "")
        return {
            "status": "FOUND",
            "source": "CROSSREF",
            "matched_title": cr.get("matched_title"),
            "authors": None,
            "year": None,
            "doi": doi or None,
            "abstract": None,
            "url": f"https://doi.org/{doi}" if doi else None,
            "similarity": cr.get("score"),
        }

    return dict(_NOT_FOUND)


def build_citation_trail(pdf_path: str) -> dict:
    """Extract all references from a PDF and validate each one online."""
    refs = extract_references(pdf_path)
    results = [{**ref, **lookup_reference(ref)} for ref in refs]
    found = sum(1 for r in results if r.get("status") == "FOUND")
    not_found = sum(1 for r in results if r.get("status") == "NOT_FOUND")
    errors = sum(1 for r in results if r.get("status") == "ERROR")
    return {
        "pdf": os.path.basename(pdf_path),
        "total": len(results),
        "found": found,
        "not_found": not_found,
        "errors": errors,
        "references": results,
    }
