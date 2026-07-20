# LexiQ Citation Trail + Internet Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix model/embed config, auto-ingest the new LLM-security PDF, enrich web retrieval with Semantic Scholar, add a Citation Trail backend module + UI panel, and serve live at `http://127.0.0.1:9090/`.

**Architecture:** All seven existing pipeline stages remain untouched. `citations.py` (new) handles bibliography extraction + per-reference online lookup. `web_retriever.py` gains a Semantic Scholar source alongside OpenAlex. `app.py` gains auto-ingest on `/api/corpus` and a new `/api/citations` endpoint. The frontend gains `LIVE=true`, updated demo strings, and a Citation Trail panel.

**Tech Stack:** Python 3.x, Flask 3.x, pypdf 4.x, requests 2.x, numpy 1.x, Ollama (`llama3.1:latest` for generation AND embedding), Semantic Scholar public API (no key), CrossRef API, OpenAlex API, pytest 8.x

## Global Constraints

- Ollama must be running at `http://localhost:11434` with `llama3.1:latest` loaded — no other model assumed present
- `nomic-embed-text` is NOT available; use `llama3.1:latest` for both generation (`/api/generate`) and embedding (`/api/embeddings`)
- All inference is local-only; only query strings leave the machine (Semantic Scholar, OpenAlex, CrossRef)
- No breaking changes to any existing `/api/*` endpoint interface
- Run with `python -m backend.app` — must bind to `127.0.0.1:9090`
- Frontend panel IDs follow pattern `p-{name}`; sidebar nav items use `data-p="{name}"` attributes
- All tests live in `tests/` at the project root; run with `pytest tests/ -v` from project root

---

### Task 1: Fix model config + set up test infrastructure

**Files:**
- Modify: `backend/llm_client.py` (line 12 — `DEFAULT_MODEL`)
- Modify: `backend/retrieve.py` (line 16 — `EMBED_MODEL`)
- Modify: `requirements.txt`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

**Interfaces:**
- Produces: `DEFAULT_MODEL = "llama3.1:latest"` consumed by all `generate()` / `generate_json()` calls
- Produces: `EMBED_MODEL = "llama3.1:latest"` consumed by `_embed()` in `retrieve.py`
- Produces: `pytest` runnable from project root

- [ ] **Step 1: Update `DEFAULT_MODEL` in `backend/llm_client.py`**

Change line 12 from:
```python
DEFAULT_MODEL = "llama3.1:8b"
```
to:
```python
DEFAULT_MODEL = "llama3.1:latest"
```

- [ ] **Step 2: Update `EMBED_MODEL` in `backend/retrieve.py`**

Change line 16 from:
```python
EMBED_MODEL = "nomic-embed-text"
```
to:
```python
EMBED_MODEL = "llama3.1:latest"
```

- [ ] **Step 3: Add pytest to `requirements.txt`**

Append to the file:
```
pytest>=8.0
```

- [ ] **Step 4: Create `tests/__init__.py`** (empty file)

- [ ] **Step 5: Create `tests/conftest.py`**

```python
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
```

- [ ] **Step 6: Smoke-test the config values**

```bash
python -c "from backend.llm_client import DEFAULT_MODEL; from backend.retrieve import EMBED_MODEL; assert DEFAULT_MODEL=='llama3.1:latest'; assert EMBED_MODEL=='llama3.1:latest'; print('OK')"
```
Expected output: `OK`

- [ ] **Step 7: Commit**

```bash
git add backend/llm_client.py backend/retrieve.py requirements.txt tests/__init__.py tests/conftest.py
git commit -m "fix: use llama3.1:latest for generation and embedding; add test infrastructure"
```

---

### Task 2: Add `already_ingested()` + auto-ingest on `/api/corpus`

**Files:**
- Modify: `backend/retrieve.py` (add `already_ingested` after `corpus_summary`)
- Modify: `backend/app.py` (replace `api_corpus` body)
- Create: `tests/test_retrieve.py`

**Interfaces:**
- Produces: `already_ingested(filename: str) -> bool` — used by `app.py`
- Consumes: `_load_index()` from `retrieve.py` (already exists)

- [ ] **Step 1: Write failing tests in `tests/test_retrieve.py`**

```python
import json

def test_already_ingested_true_when_in_index(tmp_path, monkeypatch):
    idx = {"chunks": [{"source": "paper.pdf", "page": 1, "text": "x", "embedding": [], "id": "abc"}]}
    p = tmp_path / "index.json"
    p.write_text(json.dumps(idx))
    import backend.retrieve as r
    monkeypatch.setattr(r, "INDEX_PATH", str(p))
    assert r.already_ingested("paper.pdf") is True

def test_already_ingested_false_when_not_in_index(tmp_path, monkeypatch):
    idx = {"chunks": []}
    p = tmp_path / "index.json"
    p.write_text(json.dumps(idx))
    import backend.retrieve as r
    monkeypatch.setattr(r, "INDEX_PATH", str(p))
    assert r.already_ingested("missing.pdf") is False

def test_already_ingested_false_when_no_index_file(tmp_path, monkeypatch):
    import backend.retrieve as r
    monkeypatch.setattr(r, "INDEX_PATH", str(tmp_path / "nonexistent.json"))
    assert r.already_ingested("any.pdf") is False
```

- [ ] **Step 2: Run tests — expect failure**

```bash
pytest tests/test_retrieve.py -v
```
Expected: `AttributeError: module 'backend.retrieve' has no attribute 'already_ingested'`

- [ ] **Step 3: Add `already_ingested` to `backend/retrieve.py`**

After the `corpus_summary` function and before `# ---- index persistence ---`, add:

```python
def already_ingested(filename: str) -> bool:
    """Return True if any chunk in the index came from this filename."""
    index = _load_index()
    return any(ch["source"] == filename for ch in index["chunks"])
```

- [ ] **Step 4: Run tests — expect pass**

```bash
pytest tests/test_retrieve.py -v
```
Expected: 3 passed

- [ ] **Step 5: Replace `api_corpus` in `backend/app.py`**

Replace the existing:
```python
@app.get("/api/corpus")
def api_corpus():
    return jsonify(retrieve.corpus_summary())
```
With:
```python
@app.get("/api/corpus")
def api_corpus():
    pdf_dir = os.path.join(os.path.dirname(__file__), "corpus", "pdfs")
    if os.path.isdir(pdf_dir):
        for fn in sorted(os.listdir(pdf_dir)):
            if fn.lower().endswith(".pdf") and not retrieve.already_ingested(fn):
                try:
                    retrieve.ingest_pdf(os.path.join(pdf_dir, fn))
                except Exception:
                    pass
    return jsonify(retrieve.corpus_summary())
```

- [ ] **Step 6: Commit**

```bash
git add backend/retrieve.py backend/app.py tests/test_retrieve.py
git commit -m "feat: add already_ingested helper and auto-ingest new PDFs on corpus endpoint"
```

---

### Task 3: Enhance `web_retriever.py` with Semantic Scholar

**Files:**
- Modify: `backend/web_retriever.py` (full rewrite — extract OpenAlex to private fn, add Semantic Scholar, update `search_web`)
- Create: `tests/test_web_retriever.py`

**Interfaces:**
- Produces: `search_semantic_scholar(query: str, k: int = 4) -> list[dict]` — used by `citations.py` (Task 4)
- Produces: `search_web(query: str, k: int = 4) -> list[dict]` — updated signature-compatible with existing callers in `grounded.py`
- Result shape: `{"id": str, "source": str, "page": int, "text": str, "score": None, "url": str, "doi": str, "origin": "SEMANTIC_SCHOLAR"|"OPENALEX"|"WEB_ERROR"}`

- [ ] **Step 1: Write failing tests in `tests/test_web_retriever.py`**

```python
from unittest.mock import patch, MagicMock

def _ss_resp(items):
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {"data": items}
    return m

def _oa_resp(items):
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {"results": items}
    return m

_SS_ITEM = {
    "title": "Attention Is All You Need",
    "authors": [{"name": "Vaswani"}, {"name": "Shazeer"}],
    "year": 2017,
    "externalIds": {"DOI": "10.48550/arXiv.1706.03762"},
    "abstract": "We propose the Transformer.",
}

_OA_ITEM = {
    "title": "BERT",
    "abstract_inverted_index": {"BERT": [0], "model": [1]},
    "authorships": [{"author": {"display_name": "Devlin"}}],
    "publication_year": 2019,
    "doi": "10.1234/bert",
    "open_access": {},
}

def test_search_semantic_scholar_returns_results():
    with patch("backend.web_retriever.requests.get", return_value=_ss_resp([_SS_ITEM])):
        from backend import web_retriever
        results = web_retriever.search_semantic_scholar("transformer", k=1)
    assert len(results) == 1
    assert results[0]["origin"] == "SEMANTIC_SCHOLAR"
    assert results[0]["doi"] == "10.48550/arXiv.1706.03762"
    assert "Vaswani" in results[0]["source"]

def test_search_semantic_scholar_web_error_on_failure():
    with patch("backend.web_retriever.requests.get", side_effect=Exception("timeout")):
        from backend import web_retriever
        results = web_retriever.search_semantic_scholar("q", k=1)
    assert results[0]["origin"] == "WEB_ERROR"

def test_search_web_deduplicates_by_doi():
    # SS and OA both return the same DOI — SS entry wins, only one result
    oa_same_doi = dict(_OA_ITEM, doi="10.48550/arXiv.1706.03762",
                       abstract_inverted_index={"same": [0]})
    with patch("backend.web_retriever.requests.get") as mock_get:
        mock_get.side_effect = [_oa_resp([oa_same_doi]), _ss_resp([_SS_ITEM])]
        from backend import web_retriever
        results = web_retriever.search_web("q", k=4)
    valid = [r for r in results if r.get("origin") in ("SEMANTIC_SCHOLAR", "OPENALEX")]
    dois = [r["doi"] for r in valid if r.get("doi")]
    assert len(dois) == len(set(dois))  # no duplicate DOIs

def test_search_web_skips_items_without_abstract():
    no_abstract = dict(_SS_ITEM, abstract=None)
    with patch("backend.web_retriever.requests.get") as mock_get:
        mock_get.side_effect = [_oa_resp([]), _ss_resp([no_abstract])]
        from backend import web_retriever
        results = web_retriever.search_web("q", k=4)
    valid = [r for r in results if r.get("origin") in ("SEMANTIC_SCHOLAR", "OPENALEX")]
    assert len(valid) == 0
```

- [ ] **Step 2: Run tests — expect failure**

```bash
pytest tests/test_web_retriever.py -v
```
Expected: `AttributeError: module 'backend.web_retriever' has no attribute 'search_semantic_scholar'`

- [ ] **Step 3: Replace the full content of `backend/web_retriever.py`**

```python
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
_OA_FIELDS = "title,abstract_inverted_index,authorships,publication_year,doi,open_access"
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
```

- [ ] **Step 4: Run tests — expect pass**

```bash
pytest tests/test_web_retriever.py -v
```
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add backend/web_retriever.py tests/test_web_retriever.py
git commit -m "feat: add Semantic Scholar source to web_retriever; deduplicate results by DOI"
```

---

### Task 4: Create `backend/citations.py`

**Files:**
- Create: `backend/citations.py`
- Create: `tests/test_citations.py`

**Interfaces:**
- Produces:
  - `extract_references(pdf_path: str) -> list[dict]` — each item: `{"raw": str, "title": str|None, "authors": str|None, "year": str|None}`
  - `lookup_reference(ref: dict) -> dict` — item: `{"status": "FOUND"|"NOT_FOUND"|"ERROR", "source": "SEMANTIC_SCHOLAR"|"CROSSREF"|None, "matched_title": str|None, "authors": str|None, "year": str|None, "doi": str|None, "abstract": str|None, "url": str|None, "similarity": float|None}`
  - `build_citation_trail(pdf_path: str) -> dict` — `{"pdf": str, "total": int, "found": int, "not_found": int, "errors": int, "references": list[dict]}`
- Consumes: `generate_json` from `backend.llm_client`, `verify_one` from `backend.verify`, `search_semantic_scholar` from `backend.web_retriever` (NOT used directly — `citations.py` does its own single-ref SS lookup to get the `limit=1` result with similarity check)

- [ ] **Step 1: Write failing tests in `tests/test_citations.py`**

```python
from unittest.mock import patch, MagicMock


def _mock_pdf(pages_text):
    page = lambda t: MagicMock(extract_text=MagicMock(return_value=t))
    reader = MagicMock()
    reader.pages = [page(t) for t in pages_text]
    return reader


# ── extract_references ───────────────────────────────────────────────────────

def test_extract_references_parses_reference_list():
    pages = ["intro"] * 8 + [
        "[1] Greshake et al. (2023). Not what you've signed up for.",
        "[2] Perez & Ribeiro (2022). Ignore Previous Prompt.",
    ]
    llm_refs = [
        {"raw": "[1] Greshake et al. (2023). Not what you've signed up for.",
         "title": "Not what you've signed up for", "authors": "Greshake et al.", "year": "2023"},
        {"raw": "[2] Perez & Ribeiro (2022). Ignore Previous Prompt.",
         "title": "Ignore Previous Prompt", "authors": "Perez & Ribeiro", "year": "2022"},
    ]
    with patch("pypdf.PdfReader", return_value=_mock_pdf(pages)), \
         patch("backend.citations.generate_json", return_value={"references": llm_refs}):
        from backend.citations import extract_references
        result = extract_references("/fake/path.pdf")
    assert len(result) == 2
    assert result[0]["year"] == "2023"
    assert result[1]["title"] == "Ignore Previous Prompt"

def test_extract_references_returns_empty_when_no_text():
    pages = [""] * 10
    with patch("pypdf.PdfReader", return_value=_mock_pdf(pages)), \
         patch("backend.citations.generate_json", return_value={"references": []}):
        from backend.citations import extract_references
        assert extract_references("/fake/path.pdf") == []


# ── lookup_reference ─────────────────────────────────────────────────────────

def _ss_found():
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {"data": [{
        "title": "Not What You've Signed Up For",
        "authors": [{"name": "Greshake"}, {"name": "Abdelnabi"}],
        "year": 2023,
        "externalIds": {"DOI": "10.48550/arXiv.2302.12173"},
        "abstract": "We analyze indirect prompt injection threats.",
    }]}
    return m

def _ss_miss():
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {"data": []}
    return m

def test_lookup_reference_found_on_semantic_scholar():
    ref = {"raw": "Greshake 2023 Not What Signed Up For", "title": "Not What You've Signed Up For",
           "authors": "Greshake", "year": "2023"}
    with patch("backend.citations.requests.get", return_value=_ss_found()):
        from backend.citations import lookup_reference
        result = lookup_reference(ref)
    assert result["status"] == "FOUND"
    assert result["source"] == "SEMANTIC_SCHOLAR"
    assert result["doi"] == "10.48550/arXiv.2302.12173"

def test_lookup_reference_falls_back_to_crossref():
    cr = {"status": "VERIFIED", "matched_title": "Some Paper", "doi": "10.1000/xyz", "score": 0.85}
    ref = {"raw": "Some Paper 2020", "title": "Some Paper", "authors": None, "year": None}
    with patch("backend.citations.requests.get", return_value=_ss_miss()), \
         patch("backend.citations.verify_one", return_value=cr):
        from backend.citations import lookup_reference
        result = lookup_reference(ref)
    assert result["status"] == "FOUND"
    assert result["source"] == "CROSSREF"

def test_lookup_reference_not_found_when_both_miss():
    cr = {"status": "UNVERIFIED", "matched_title": "wrong", "doi": "", "score": 0.1}
    ref = {"raw": "Nonexistent 2099", "title": "Nonexistent Paper", "authors": None, "year": None}
    with patch("backend.citations.requests.get", return_value=_ss_miss()), \
         patch("backend.citations.verify_one", return_value=cr):
        from backend.citations import lookup_reference
        result = lookup_reference(ref)
    assert result["status"] == "NOT_FOUND"
    assert result["source"] is None


# ── build_citation_trail ─────────────────────────────────────────────────────

def test_build_citation_trail_counts_correctly():
    refs = [
        {"raw": "r1", "title": "A", "authors": None, "year": None},
        {"raw": "r2", "title": "B", "authors": None, "year": None},
    ]
    lookups = [
        {"status": "FOUND", "source": "SEMANTIC_SCHOLAR", "matched_title": "A",
         "authors": None, "year": None, "doi": None, "abstract": None, "url": None, "similarity": 0.9},
        {"status": "NOT_FOUND", "source": None, "matched_title": None,
         "authors": None, "year": None, "doi": None, "abstract": None, "url": None, "similarity": None},
    ]
    with patch("backend.citations.extract_references", return_value=refs), \
         patch("backend.citations.lookup_reference", side_effect=lookups):
        from backend.citations import build_citation_trail
        result = build_citation_trail("/fake/path.pdf")
    assert result["total"] == 2
    assert result["found"] == 1
    assert result["not_found"] == 1
    assert result["errors"] == 0
    assert result["pdf"] == "path.pdf"
```

- [ ] **Step 2: Run tests — expect failure**

```bash
pytest tests/test_citations.py -v
```
Expected: `ModuleNotFoundError: No module named 'backend.citations'`

- [ ] **Step 3: Create `backend/citations.py`**

```python
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
```

- [ ] **Step 4: Run tests — expect pass**

```bash
pytest tests/test_citations.py -v
```
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add backend/citations.py tests/test_citations.py
git commit -m "feat: add citations module for PDF bibliography extraction and online validation"
```

---

### Task 5: Add `/api/citations` endpoint

**Files:**
- Modify: `backend/app.py` (add `citations` import + endpoint)
- Create: `tests/test_app_citations.py`

**Interfaces:**
- Endpoint: `POST /api/citations` body `{"pdf": "filename.pdf"}` → `build_citation_trail(path)` result JSON or `{"error": str}` with 404/500
- Consumes: `citations.build_citation_trail(pdf_path: str) -> dict`

- [ ] **Step 1: Write failing test in `tests/test_app_citations.py`**

```python
import pytest
from unittest.mock import patch

@pytest.fixture
def client():
    from backend.app import app
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def test_citations_endpoint_returns_trail(client):
    trail = {"pdf": "paper.pdf", "total": 2, "found": 1,
             "not_found": 1, "errors": 0, "references": []}
    with patch("backend.citations.build_citation_trail", return_value=trail):
        resp = client.post("/api/citations", json={"pdf": "paper.pdf"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 2

def test_citations_endpoint_404_for_missing_file(client):
    resp = client.post("/api/citations", json={"pdf": "nonexistent.pdf"})
    assert resp.status_code == 404
    assert "error" in resp.get_json()
```

- [ ] **Step 2: Run tests — expect failure**

```bash
pytest tests/test_app_citations.py -v
```
Expected: `404` test passes (no route), `200` test fails

- [ ] **Step 3: Update imports and add endpoint in `backend/app.py`**

Change the existing import line:
```python
from . import triage, ideation, draft, verify, grounded, contradict, provenance, retrieve, web_retriever
```
to:
```python
from . import triage, ideation, draft, verify, grounded, contradict, provenance, retrieve, web_retriever, citations
```

After the `api_web_search` function, add:
```python
@app.post("/api/citations")
def api_citations():
    pdf_name = request.json.get("pdf", "")
    pdf_path = os.path.join(os.path.dirname(__file__), "corpus", "pdfs", pdf_name)
    if not os.path.isfile(pdf_path):
        return jsonify({"error": f"PDF not found: {pdf_name}"}), 404
    try:
        return jsonify(citations.build_citation_trail(pdf_path))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

- [ ] **Step 4: Run all tests — expect pass**

```bash
pytest tests/ -v
```
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add backend/app.py tests/test_app_citations.py
git commit -m "feat: add /api/citations endpoint wired to citation trail module"
```

---

### Task 6: Frontend — LIVE mode, updated demo strings, corrected topbar

**Files:**
- Modify: `frontend/index.html`

Specific line targets (verify with `grep -n` if needed):
- Line 494: `const LIVE=false`
- Lines 216–219: topbar status pills
- Line 269: overview sub-heading
- Lines 281–282: system health card model rows
- Lines 496–503: `const S={...}` demo strings

- [ ] **Step 1: Set `LIVE=true` (line 494)**

Change:
```javascript
const LIVE=false;
```
to:
```javascript
const LIVE=true;
```

- [ ] **Step 2: Update topbar status pills (lines 216–219)**

Replace:
```html
    <div class="status-pill"><div class="dot ok"></div>Ollama</div>
    <div class="status-pill"><div class="dot ok"></div>llama3.1:8b</div>
    <div class="status-pill"><div class="dot ok"></div>nomic-embed-text</div>
    <div class="status-pill"><div class="dot ok"></div>CrossRef</div>
```
With:
```html
    <div class="status-pill"><div class="dot ok"></div>Ollama</div>
    <div class="status-pill"><div class="dot ok"></div>llama3.1:latest</div>
    <div class="status-pill"><div class="dot ok"></div>embed:llama3.1</div>
    <div class="status-pill"><div class="dot ok"></div>CrossRef</div>
```

- [ ] **Step 3: Update overview sub-heading (line 269)**

Replace:
```html
        <div class="ov-sub">lxq_4a91d8c7 · 09:12:03 UTC · Demo mode · 6-document corpus on federated learning &amp; privacy</div>
```
With:
```html
        <div class="ov-sub">lxq_4a91d8c7 · Live mode · LLM agent security corpus</div>
```

- [ ] **Step 4: Update system health rows (lines 281–282)**

Replace:
```html
          <div class="status-row"><span class="status-label">llama3.1:8b</span><span class="status-val"><div class="dot ok"></div>LOADED · 4.7 GB</span></div>
          <div class="status-row"><span class="status-label">nomic-embed-text</span><span class="status-val"><div class="dot ok"></div>LOADED · 274 MB</span></div>
```
With:
```html
          <div class="status-row"><span class="status-label">llama3.1:latest</span><span class="status-val"><div class="dot ok"></div>LOADED · generation + embed</span></div>
          <div class="status-row"><span class="status-label">Semantic Scholar</span><span class="status-val"><div class="dot ok"></div>PUBLIC API · no key required</span></div>
```

- [ ] **Step 5: Replace the entire `const S={...}` block (lines 496–503)**

Replace:
```javascript
const S={
  grounded:"Does jurisdiction-aware aggregation improve fraud-detection recall under a fixed privacy budget, and what do contradicting studies report?",
  divergence:"Differential privacy preserves fraud-detection recall with no meaningful degradation in federated cross-border payment settings.",
  analysis:"Federated learning enables collaborative model training across institutions without centralising raw data — attractive for cross-border fraud detection where data-sharing is legally restricted. However, existing approaches struggle to balance detection recall against differential-privacy guarantees, and the resulting models are difficult to explain to regulators. This paper proposes a jurisdiction-aware aggregation scheme evaluated on a synthetic cross-border payments dataset, reporting a 4.1% recall improvement at a fixed privacy budget over a FedAvg baseline.",
  vectors:"Research interest: privacy-preserving fraud detection for cross-border payments. Known gap: the tension between recall, differential privacy, and regulatory explainability in federated settings. ISO 20022 migration opens richer transaction semantics.",
  synthesis:"Topic: why post-hoc explainability is degraded in federated fraud-detection models operating under differential privacy constraints, and what the ISO 20022 enrichment may or may not solve.",
  integrity:`Federated learning avoids centralising sensitive data [CITE: McMahan et al., 2017, Communication-Efficient Learning of Deep Networks from Decentralized Data]. Differential privacy provides formal guarantees for such systems [CITE: Dwork & Roth, 2014, The Algorithmic Foundations of Differential Privacy]. One study claims the recall-privacy trilemma is fully resolved [CITE: Nainar & Kumar, 2023, A Unified Solution to Federated Privacy Tradeoffs in Payments]. In the evaluated cohort, the institution breakdown was 55%, 30%, and 40% respectively.`
};
```
With:
```javascript
const S={
  grounded:"What attack vectors does the paper identify for web-capable LLM agents, and how does the defense framework address prompt injection?",
  divergence:"Web-capable LLM agents are vulnerable to indirect prompt injection attacks via malicious web content.",
  analysis:"We present a threat model, attack taxonomy, and defense framework for web-capable LLM agents. Our taxonomy classifies attacks across seven dimensions including injection source, attacker goal, and required access level. We demonstrate that existing defenses are insufficient against multi-step indirect prompt injection chains and propose a layered mitigation strategy combining input sanitisation, privilege separation, and output monitoring.",
  vectors:"Research interest: security of web-capable LLM agents. Known gaps: multi-step attack chains are poorly understood, existing defenses do not compose well, and there is no standardised evaluation benchmark for LLM agent security.",
  synthesis:"Topic: why privilege separation is a necessary but not sufficient defense against indirect prompt injection in web-capable LLM agents, and what the current defense framework leaves unresolved.",
  integrity:`Web-capable LLM agents face novel prompt injection risks not present in static deployments [CITE: Greshake et al., 2023, Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection]. Sandboxing techniques offer partial mitigation [CITE: Anthropic, 2024, Constitutional AI: Harmlessness from AI Feedback]. Some authors claim the attack surface is fully enumerated [CITE: Smith & Jones, 2024, Complete Survey of LLM Security Attacks]. In the evaluated threat model, 85%, 90%, and 45% of attack chains were blocked by each defense layer respectively.`
};
```

- [ ] **Step 6: Commit**

```bash
git add frontend/index.html
git commit -m "feat: enable LIVE mode; update model labels and demo strings for LLM agent security paper"
```

---

### Task 7: Frontend — Citation Trail panel + PDF dropdown init

**Files:**
- Modify: `frontend/index.html` (sidebar entry, panel HTML, CANNED data, JS)

- [ ] **Step 1: Add Citation Trail sidebar item**

Find the block (around line 252–255):
```html
      <div class="sb-divider"></div>
      <div class="sb-group">
        <div class="sb-item" data-p="audit"><span class="sb-lbl">Audit Ledger</span></div>
      </div>
```
Replace with:
```html
      <div class="sb-divider"></div>
      <div class="sb-group">
        <div class="sb-item" data-p="citations"><span class="sb-lbl">Citation Trail</span><span class="sb-badge">NEW</span></div>
      </div>
      <div class="sb-divider"></div>
      <div class="sb-group">
        <div class="sb-item" data-p="audit"><span class="sb-lbl">Audit Ledger</span></div>
      </div>
```

- [ ] **Step 2: Add `CANNED.citations` entry**

In the `const CANNED={...}` block, find the closing `};` (after the `integrity` entry, around line 555). Insert before the `};`:
```javascript
  ,citations:{
    pdf:"Securing Web-Capable LLM Agents - Threat Model, Attack Taxonomy, and Defense Framework.pdf",
    total:3,found:2,not_found:1,errors:0,
    references:[
      {raw:"[1] Greshake et al. (2023). Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.",title:"Not What You've Signed Up For",authors:"Greshake et al.",year:"2023",status:"FOUND",source:"SEMANTIC_SCHOLAR",matched_title:"Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection",doi:"10.48550/arXiv.2302.12173",abstract:"We analyze indirect prompt injection threats to LLM-integrated applications, showing attackers can exfiltrate data or trigger actions via injected web content.",url:"https://doi.org/10.48550/arXiv.2302.12173",similarity:0.95},
      {raw:"[2] Perez & Ribeiro (2022). Ignore Previous Prompt: Attack Techniques For Language Models.",title:"Ignore Previous Prompt",authors:"Perez, Ribeiro",year:"2022",status:"FOUND",source:"CROSSREF",matched_title:"Ignore Previous Prompt: Attack Techniques For Language Models",doi:"10.48550/arXiv.2211.09527",abstract:null,url:"https://doi.org/10.48550/arXiv.2211.09527",similarity:0.82},
      {raw:"[3] Smith & Jones (2024). Complete Enumeration of LLM Attack Surfaces.",title:"Complete Enumeration of LLM Attack Surfaces",authors:"Smith, Jones",year:"2024",status:"NOT_FOUND",source:null,matched_title:null,doi:null,abstract:null,url:null,similarity:null}
    ]
  }
```

- [ ] **Step 3: Add the Citation Trail panel HTML**

Find the comment `<!-- /main -->` (line 490) just before `</div><!-- /workspace -->`. Insert the new panel immediately before that comment, after the closing `</div>` of `p-audit`:

```html
    <!-- ══ 7. CITATION TRAIL ════════════════════════════════════════ -->
    <div class="panel" id="p-citations">
      <div class="mod-header">
        <div class="mod-title">Citation Trail</div>
        <div class="mod-badges">
          <span class="mbadge multi">SEMANTIC SCHOLAR</span>
          <span class="mbadge deterministic">CROSSREF</span>
        </div>
        <div class="mod-desc">Extract the reference list from an ingested PDF and validate each citation against Semantic Scholar and CrossRef. Status badges show whether each reference resolves to a real paper in the scholarly index.</div>
      </div>
      <div class="io">
        <div>
          <div class="col-label">Source document</div>
          <select id="ct-pdf" style="width:100%;padding:10px;border:1px solid var(--b);border-radius:8px;font-family:var(--mono);font-size:12px;background:var(--card);color:var(--t1)"><option value="">Loading…</option></select>
          <div class="controls" style="margin-top:10px">
            <button class="run" onclick="runCitations()">Run Citation Trail</button>
          </div>
        </div>
        <div>
          <div class="col-label">Citation trail</div>
          <div class="out-wrap">
            <div class="output" id="ct-out">
              <div class="out-body"><span class="placeholder">Select a document and run to see its citation trail.</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
```

- [ ] **Step 4: Add `runCitations()` and corpus init JS**

Immediately before the closing `</script>` tag, add:

```javascript
/* ─── citation trail ─────────────────────── */
async function runCitations(){
  const pdf=document.getElementById('ct-pdf').value;
  if(!pdf) return;
  busy('ct-out');
  const t0=Date.now();
  const d=LIVE?await callApi('citations',{pdf}):await fake(CANNED.citations);
  if(d.error){
    document.getElementById('ct-out').innerHTML=
      `<div class="out-body"><span class="placeholder" style="color:var(--red)">${d.error}</span></div>`;
    return;
  }
  const refs=d.references||[];
  const banner=
    `<div style="font-family:var(--mono);font-size:11px;color:var(--t2);margin-bottom:12px">`+
    `${d.total} references · <span style="color:var(--green)">${d.found} verified</span> · `+
    `<span style="color:var(--red)">${d.not_found} not found</span>`+
    (d.errors?` · <span style="color:var(--amber)">${d.errors} errors</span>`:'')+
    `</div>`;
  const cards=refs.map((r)=>{
    const badge=r.status==='FOUND'
      ?`<span class="v-badge VERIFIED">FOUND</span>`
      :r.status==='NOT_FOUND'
      ?`<span class="v-badge UNRESOLVED">NOT FOUND</span>`
      :`<span class="v-badge MISATTRIBUTED">ERROR</span>`;
    const srcBadge=r.source
      ?`<span class="mbadge ${r.source==='SEMANTIC_SCHOLAR'?'multi':'deterministic'}" style="font-size:9px;margin-left:4px">${r.source.replace('_',' ')}</span>`:'';
    const raw=(r.raw||'').slice(0,120)+((r.raw||'').length>120?'…':'');
    const meta=r.matched_title
      ?`<div style="font-size:12px;font-weight:600;color:var(--t1);margin-top:5px">${r.matched_title}</div>`+
       `<div style="font-size:11px;color:var(--t2);margin-top:2px">${[r.authors,r.year?'('+r.year+')':null].filter(Boolean).join(' ')}</div>`+
       (r.doi?`<div class="cite-doi"><a href="${r.url||'https://doi.org/'+r.doi}" target="_blank" style="color:var(--blue)">${r.doi}</a></div>`:``) +
       (r.abstract?`<div style="font-size:11px;color:var(--t3);margin-top:4px;font-style:italic">${r.abstract.slice(0,180)}…</div>`:``)
      :'';
    return `<div class="cite-card"><div>${badge}${srcBadge}</div><div><div class="cite-claimed">${raw}</div>${meta}</div></div>`;
  }).join('');
  const ms=Date.now()-t0;
  document.getElementById('ct-out').innerHTML=
    `<div class="out-body">${banner}${cards||'<span class="placeholder">No references extracted.</span>'}</div>`+
    tele(`${d.total} refs extracted · ${d.found} verified · ${ms.toLocaleString()}ms`);
}

/* populate PDF dropdown from /api/corpus on load */
(async function initCorpusPicker(){
  const sel=document.getElementById('ct-pdf');
  if(!sel) return;
  if(!LIVE){
    sel.innerHTML=`<option value="${CANNED.citations.pdf}">${CANNED.citations.pdf}</option>`;
    return;
  }
  try{
    const data=await fetch('/api/corpus').then(r=>r.json());
    const sources=Object.keys(data.by_source||{});
    sel.innerHTML=sources.length
      ?sources.map(k=>`<option value="${k}">${k}</option>`).join('')
      :`<option value="">No documents ingested yet</option>`;
  }catch(e){
    sel.innerHTML=`<option value="">Could not load corpus</option>`;
  }
})();
```

- [ ] **Step 5: Verify manually**

```bash
python -m backend.app
```
Open `http://127.0.0.1:9090/` and verify:
1. Topbar shows `llama3.1:latest` and `embed:llama3.1`
2. Overview shows "Live mode · LLM agent security corpus"
3. Session Overview → `/api/corpus` is called on page load; after auto-ingest completes the sidebar footer should reflect actual chunk count
4. "Citation Trail" sidebar item appears; clicking it shows the panel
5. PDF dropdown auto-populates with the ingested filename
6. "Run Citation Trail" calls `/api/citations`, renders reference cards with FOUND/NOT FOUND badges and DOI links
7. "Grounded Query" with Web Enrich on returns both LOCAL and SEMANTIC_SCHOLAR/OPENALEX passages
8. All other panels (Divergence, Analysis, Vectors, Synthesis, Reference Integrity, Audit Ledger) still load and execute without errors

- [ ] **Step 6: Commit**

```bash
git add frontend/index.html
git commit -m "feat: add Citation Trail panel with Semantic Scholar validation and live PDF dropdown"
```

---

## Final check: run the server

```bash
python -m backend.app
```

Open `http://127.0.0.1:9090/`

**Note on first run:** The page load triggers `/api/corpus` which auto-ingests the PDF. Embedding each ~900-char chunk via `llama3.1:latest` through Ollama is slower than a dedicated embedding model — expect 5–15 minutes for a 20-page paper. The endpoint returns immediately with `{"documents": 0, "chunks": 0}` on the first call while ingestion runs; refresh the corpus status after ingestion completes to see the chunk count update.
