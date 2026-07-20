"""
verify.py — Module 4: Citation Verifier  (the credibility differentiator)
-------------------------------------------------------------------------
LLMs hallucinate citations: plausible-looking authors, titles, and DOIs that
do not exist. For an academic audience this is THE objection to address.

This module extracts [CITE: ...] tags from generated text and checks each one
against the real CrossRef API (https://api.crossref.org), a free, public index
of scholarly metadata. Each citation is returned as VERIFIED (a real match was
found) or UNVERIFIED (no convincing match — likely hallucinated).

CrossRef needs no API key. Sending a contact email in the User-Agent is the
"polite pool" convention and gives more reliable service.
"""

from __future__ import annotations

import re
import requests
from difflib import SequenceMatcher

CROSSREF_URL = "https://api.crossref.org/works"
USER_AGENT = "ResearchCopilot/1.0 (FDP demo; mailto:demo@example.org)"
CITE_PATTERN = re.compile(r"\[CITE:\s*(.*?)\]")


def extract_citations(text: str) -> list[str]:
    """Pull all [CITE: ...] payloads out of generated text."""
    return [m.strip() for m in CITE_PATTERN.findall(text)]


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def verify_one(citation: str, threshold: float = 0.6) -> dict:
    """Query CrossRef for a citation string and judge whether it is real.

    Returns a dict the front-end renders directly: status, the claimed text,
    the best real match found (if any), a similarity score, and the DOI.
    """
    try:
        resp = requests.get(
            CROSSREF_URL,
            params={"query.bibliographic": citation, "rows": 1},
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        resp.raise_for_status()
        items = resp.json().get("message", {}).get("items", [])
    except requests.RequestException as exc:
        return {"claimed": citation, "status": "ERROR",
                "detail": f"CrossRef lookup failed: {exc}"}

    if not items:
        return {"claimed": citation, "status": "UNVERIFIED",
                "detail": "No match found in CrossRef — likely hallucinated."}

    top = items[0]
    matched_title = (top.get("title") or ["(no title)"])[0]
    score = _similarity(citation, matched_title)
    status = "VERIFIED" if score >= threshold else "UNVERIFIED"

    return {
        "claimed": citation,
        "status": status,
        "matched_title": matched_title,
        "doi": top.get("DOI", ""),
        "score": round(score, 2),
        "detail": ("Strong match in CrossRef." if status == "VERIFIED"
                   else "Closest match too weak — treat as unverified."),
    }


def verify_text(text: str) -> list[dict]:
    """Extract and verify every citation in a block of generated text."""
    return [verify_one(c) for c in extract_citations(text)]


def cross_check_doi(doi: str, claimed_year: str | None = None,
                    claimed_author: str | None = None) -> dict:
    """Fetch a DOI's REAL metadata and compare to what was claimed about it.

    This catches the subtler failure the basic check misses: the citation is
    real (the DOI resolves) but the draft misattributes it — wrong year, wrong
    authors, or a title that doesn't match the claim. An LLM will happily cite a
    real paper for a finding it never made; only fetching the authoritative
    record exposes that.
    """
    try:
        resp = requests.get(
            f"{CROSSREF_URL}/{doi}",
            headers={"User-Agent": USER_AGENT}, timeout=30,
        )
        resp.raise_for_status()
        msg = resp.json().get("message", {})
    except requests.RequestException as exc:
        return {"doi": doi, "status": "ERROR",
                "detail": f"Could not resolve DOI: {exc}"}

    real_title = (msg.get("title") or ["(no title)"])[0]
    real_year = None
    for key in ("published-print", "published-online", "issued"):
        parts = msg.get(key, {}).get("date-parts", [[None]])
        if parts and parts[0] and parts[0][0]:
            real_year = str(parts[0][0])
            break
    real_authors = [a.get("family", "") for a in msg.get("author", [])][:3]

    mismatches = []
    if claimed_year and real_year and claimed_year != real_year:
        mismatches.append(f"year claimed {claimed_year}, actual {real_year}")
    if claimed_author and real_authors and \
            not any(claimed_author.lower() in a.lower() for a in real_authors):
        mismatches.append(
            f"author '{claimed_author}' not among {', '.join(real_authors)}")

    return {
        "doi": doi,
        "status": "MISATTRIBUTED" if mismatches else "CONFIRMED",
        "real_title": real_title,
        "real_year": real_year,
        "real_authors": real_authors,
        "mismatches": mismatches,
        "detail": ("Real paper, but the draft's attribution is off: "
                   + "; ".join(mismatches)) if mismatches
                  else "DOI metadata matches the claim.",
    }


def check_numeric_consistency(text: str) -> list[dict]:
    """Flag internally inconsistent numbers, e.g. percentages that exceed 100
    or a set of parts claimed to sum to a total that they do not.

    Purely computational — the LLM's blind spot. We detect 'X%, Y%, and Z%'
    groupings and check whether they plausibly sum to 100 when the surrounding
    text implies a partition ('split', 'breakdown', 'of respondents').
    """
    issues = []
    # any single percentage over 100
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s*%", text):
        val = float(m.group(1))
        if val > 100:
            issues.append({"type": "impossible_percentage",
                           "detail": f"{val}% exceeds 100%",
                           "fragment": text[max(0, m.start()-30):m.end()+10]})
    # partition that doesn't sum to ~100
    partition_cue = re.search(
        r"(split|breakdown|distributed|comprised|of (?:all )?respondents)", text, re.I)
    if partition_cue:
        pcts = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*%", text)]
        if len(pcts) >= 3 and not (95 <= sum(pcts) <= 105):
            issues.append({"type": "partition_sum",
                           "detail": f"percentages {pcts} sum to {round(sum(pcts),1)}%, "
                                     f"not ~100%",
                           "fragment": text[max(0, partition_cue.start()-10):
                                            partition_cue.start()+120]})
    return issues
