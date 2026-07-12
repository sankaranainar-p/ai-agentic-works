"""
web_retriever.py — Real-time internet enrichment via OpenAlex and Semantic Scholar
----------------------------------------------------------------------------------
search_web() queries both sources, deduplicates by DOI (Semantic Scholar wins on
collision), and returns results in retrieve.search() format so grounded.py can
blend them with local corpus hits transparently.

Privacy boundary: local PDFs never leave the machine. Only the query string goes
outbound; what comes back is title + abstract metadata.
"""
from __future__ import annotations
import requests

OPENALEX_URL = "https://api.openalex.org/works"
SEMANTIC_SCHOLAR_URL = "https://api.semanticscholar.org/graph/v1/paper/search"
USER_AGENT = "ResearchCopilot/1.0 (mailto:demo@researchcopilot.local)"
_OA_FIELDS = "title,abstract_inverted_index,authorships,publication_year,doi"
_SS_FIELDS = "title,authors,year,externalIds,abstract"


def _reconstruct_abstract(inverted_index: dict | None) -> str:
    if not inverted_index:
        return ""
    positions: dict[int, str] = {}
    for word, pos_list in inverted_index.items():
        for pos in pos_list:
            positions[pos] = word
    return " ".join(positions[i] for i in sorted(positions))


def _search_openalex(query: str, k: int) -> list[dict]:
    try:
        resp = requests.get(
            OPENALEX_URL,
            params={"search": query, "per_page": k, "select": _OA_FIELDS},
            headers={"User-Agent": USER_AGENT},
            timeout=12,
        )
        resp.raise_for_status()
        items = resp.json().get("results", [])
    except requests.RequestException as exc:
        return [{"origin": "WEB_ERROR", "detail": str(exc)}]

    results = []
    for i, p in enumerate(items):
        abstract = _reconstruct_abstract(p.get("abstract_inverted_index"))
        if not abstract:
            continue
        authors = ", ".join(
            a.get("author", {}).get("display_name", "")
            for a in (p.get("authorships") or [])[:3]
        )
        year = str(p.get("publication_year") or "")
        title = p.get("title") or "(untitled)"
        doi = p.get("doi") or ""
        url = doi if doi.startswith("http") else (f"https://doi.org/{doi}" if doi else "")
        results.append({
            "id": f"oa_{i}",
            "source": f"{title} — {authors} ({year})" if authors else f"{title} ({year})",
            "page": 0, "text": abstract, "score": None,
            "url": url, "doi": doi, "origin": "OPENALEX",
        })
    return results


def search_semantic_scholar(query: str, k: int = 4) -> list[dict]:
    """Query Semantic Scholar and return up to k results in retrieve.search() format."""
    try:
        resp = requests.get(
            SEMANTIC_SCHOLAR_URL,
            params={"query": query, "fields": _SS_FIELDS, "limit": k},
            headers={"User-Agent": USER_AGENT},
            timeout=12,
        )
        resp.raise_for_status()
        items = resp.json().get("data", [])
    except requests.RequestException as exc:
        return [{"origin": "WEB_ERROR", "detail": str(exc)}]

    results = []
    for i, p in enumerate(items):
        abstract = p.get("abstract") or ""
        if not abstract:
            continue
        authors = ", ".join(a.get("name", "") for a in (p.get("authors") or [])[:3])
        year = str(p.get("year") or "")
        title = p.get("title") or "(untitled)"
        ext_ids = p.get("externalIds") or {}
        doi = ext_ids.get("DOI", "")
        url = f"https://doi.org/{doi}" if doi else ""
        results.append({
            "id": f"ss_{i}",
            "source": f"{title} — {authors} ({year})" if authors else f"{title} ({year})",
            "page": 0, "text": abstract, "score": None,
            "url": url, "doi": doi, "origin": "SEMANTIC_SCHOLAR",
        })
    return results


def search_web(query: str, k: int = 4) -> list[dict]:
    """Query OpenAlex + Semantic Scholar; merge, deduplicate by DOI, return up to k results."""
    oa = _search_openalex(query, k)
    ss = search_semantic_scholar(query, k)

    errors = [r for r in oa + ss if r.get("origin") == "WEB_ERROR"]
    valid_ss = [r for r in ss if r.get("origin") == "SEMANTIC_SCHOLAR"]
    valid_oa = [r for r in oa if r.get("origin") == "OPENALEX"]

    seen_dois: set[str] = set()
    combined: list[dict] = []
    for result in valid_ss + valid_oa:  # SS wins on DOI collision
        doi = result.get("doi") or ""
        if doi and doi in seen_dois:
            continue
        if doi:
            seen_dois.add(doi)
        combined.append(result)

    return combined[:k] + errors
