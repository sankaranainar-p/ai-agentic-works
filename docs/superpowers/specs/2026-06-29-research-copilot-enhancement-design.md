# LexiQ Enhancement: Citation Trail + Internet Validation

**Date:** 2026-06-29  
**Status:** Approved  
**Scope:** Fix model/embed config, auto-ingest new PDF, add Semantic Scholar enrichment, add Citation Trail module and UI panel, run on port 9090

---

## Context

A new PDF — *Securing Web-Capable LLM Agents: Threat Model, Attack Taxonomy, and Defense Framework* — has been uploaded to `backend/corpus/pdfs/` but has never been ingested (no `index.json` exists). The frontend is in demo mode (`LIVE=false`) showing canned federated-learning data. Ollama is running with `llama3.1:latest` and `llama3.2:latest`; `nomic-embed-text` is not installed.

The goal is to make the project pick up the new paper, search the internet to validate and explore its citations, and run live at `http://127.0.0.1:9090/`.

---

## What Is Not Changing

- All 7 existing pipeline stages and their `/api/*` endpoints remain intact with no interface changes.
- Flask server, provenance logging, JSONL audit trail, CrossRef verification flow — all unchanged.
- Local-only inference guarantee: PDFs never leave the machine; only query strings go outbound.

---

## Section 1: Configuration Fixes

### 1.1 Model tags
`llm_client.py` `DEFAULT_MODEL`: `"llama3.1:8b"` → `"llama3.1:latest"` (matches installed Ollama tag).

### 1.2 Embedding model
`retrieve.py` `EMBED_MODEL`: `"nomic-embed-text"` → `"llama3.1:latest"`.  
Ollama's `/api/embeddings` endpoint accepts any loaded model. Cosine similarity, chunk size (900 chars), overlap (150 chars), and index format are unchanged.

### 1.3 Frontend live mode
`frontend/index.html` line 494: `const LIVE=false` → `const LIVE=true`.

### 1.4 Demo queries
Replace the existing federated-learning canned data with content relevant to the new paper:
- **Grounded query:** *"What attack vectors does the paper identify for web-capable LLM agents, and how does the defense framework address prompt injection?"*
- **Analysis paste:** The paper's abstract/opening paragraph
- **Divergence claim:** *"Web-capable LLM agents are vulnerable to indirect prompt injection attacks via malicious web content"*

---

## Section 2: Auto-Ingest on Startup

### 2.1 Helper in `retrieve.py`
Add `already_ingested(filename: str) -> bool` — checks whether any chunk in the current index has `source == filename`. O(n) scan of in-memory index; acceptable for a local corpus.

### 2.2 Startup ingest trigger in `app.py`
On the first call to `GET /api/corpus`, after loading the summary:
1. List all `.pdf` files in `backend/corpus/pdfs/`
2. For each file not already in the index (via `already_ingested`), call `retrieve.ingest_pdf(path)`
3. Return the updated summary

This ensures any newly dropped PDF is indexed transparently without requiring a manual "Ingest" button click. Subsequent calls to `/api/corpus` skip ingestion (files already indexed).

---

## Section 3: Web Retriever Enhancement (Semantic Scholar)

### 3.1 New function `search_semantic_scholar(query, k)` in `web_retriever.py`
- Endpoint: `https://api.semanticscholar.org/graph/v1/paper/search`
- Fields: `title,authors,year,externalIds,abstract`
- No API key required for standard use (Semantic Scholar public API)
- Returns results in the same shape as `search_openalex` with `origin="SEMANTIC_SCHOLAR"`

### 3.2 Updated `search_web(query, k)` 
- Calls both `search_openalex` and `search_semantic_scholar` with `k` each
- Deduplicates by DOI (prefers Semantic Scholar entry on collision)
- Returns at most `k` total results, alternating sources if both have hits
- `WEB_ERROR` entries from either source are preserved and surfaced separately

### 3.3 Result shape (unchanged from current)
```
{
  "id": str,
  "source": str,        # "Title — Authors (Year)"
  "page": 0,
  "text": str,          # abstract
  "score": None,
  "url": str,
  "doi": str,
  "origin": "SEMANTIC_SCHOLAR" | "OPENALEX" | "WEB_ERROR"
}
```
The frontend already renders `WEB` origin with a purple badge; `SEMANTIC_SCHOLAR` and `OPENALEX` will both display under that badge. No UI change needed for grounded-query web passages.

---

## Section 4: Citation Trail Module (New)

### 4.1 `citations.py` — three public functions

**`extract_references(pdf_path: str) -> list[dict]`**  
- Reads the last 15% of PDF pages (where reference sections live)
- Combines extracted text, then uses a regex pre-pass to detect numbered/bracketed reference lines (`[1]`, `1.`, etc.)
- Passes the block to `llm_client.generate_json` with a prompt asking for structured parsing into `{raw, title, authors, year}` objects
- Returns a list of reference dicts; malformed entries are kept with `title=None`

**`lookup_reference(ref: dict) -> dict`**  
- Queries Semantic Scholar first using `ref["raw"]` as the search string
- If no confident match (no result or title similarity < 0.6), falls back to CrossRef via `verify.verify_one(ref["raw"])`
- Returns:
  ```
  {
    "status": "FOUND" | "NOT_FOUND" | "ERROR",
    "source": "SEMANTIC_SCHOLAR" | "CROSSREF",
    "matched_title": str | None,
    "authors": str | None,
    "year": str | None,
    "doi": str | None,
    "abstract": str | None,
    "url": str | None,
    "similarity": float | None
  }
  ```

**`build_citation_trail(pdf_path: str) -> dict`**  
- Calls `extract_references`, then `lookup_reference` for each reference
- Returns:
  ```
  {
    "pdf": str,
    "total": int,
    "found": int,
    "not_found": int,
    "errors": int,
    "references": [{ ...ref dict..., ...lookup result... }]
  }
  ```

### 4.2 `/api/citations` endpoint in `app.py`
```
POST /api/citations
Body: { "pdf": "filename.pdf" }
Response: build_citation_trail result (or {"error": ...} on failure)
```
Path is resolved to `backend/corpus/pdfs/<pdf>`. Returns 404 if file not found.

---

## Section 5: Frontend — Citation Trail Panel

### 5.1 Sidebar
New item inserted between "Reference Integrity" (6) and "Audit Ledger":
```
Label: Citation Trail
Badge: NEW
```
"Audit Ledger" renumbered from 7 → 8 in the sidebar display only (JS panel IDs unchanged to avoid regressions).

### 5.2 Panel layout

**Input column:**
- Dropdown `<select>` pre-populated with the filenames of ingested PDFs (fetched from `/api/corpus` `by_source` keys on page load)
- "Run Citation Trail" button

**Output column:**
- Count banner: `{total} references extracted · {found} verified online · {not_found} not found`
- Scrollable list of reference cards, one per reference:
  - Reference number (left-aligned, monospace)
  - Raw reference text (truncated to 120 chars)
  - Status badge: `FOUND` (green) / `NOT_FOUND` (red) / `ERROR` (amber)
  - If FOUND: matched title (bold), authors + year, DOI as a clickable link, one-line abstract snippet (italic, truncated to 180 chars)
  - Source badge: `SEMANTIC SCHOLAR` or `CROSSREF` (monospace, small)
- Telemetry strip: `refs extracted · verified · elapsed`

### 5.3 Existing panel IDs
All existing JS `show('panel-N')` calls and panel `id` attributes are unchanged. The new panel uses id `panel-citations`.

---

## Section 6: Run Configuration

`app.py` already contains:
```python
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9090, debug=True)
```
No change needed. Run with: `python -m backend.app`

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Ollama not running | Existing `OllamaError` propagates; frontend shows error pill |
| PDF has no reference section | `extract_references` returns `[]`; citation trail shows "0 references found" |
| Semantic Scholar rate-limited | Falls back to CrossRef; result tagged `CROSSREF` |
| Network offline | Both web enrichment and citation lookup return `WEB_ERROR`; local RAG continues |
| PDF not ingested yet | `/api/citations` triggers ingest first, then runs trail |

---

## Testing Approach

1. Start Ollama (`ollama serve`) — confirm `llama3.1:latest` responds
2. Start server (`python -m backend.app`) — confirm port 9090
3. Load `http://127.0.0.1:9090/` — verify `LIVE` mode indicator shows
4. Navigate to Session Overview → click "Refresh" → confirm corpus shows 1 document, N chunks (auto-ingest)
5. Run a Grounded Query with Web Enrich ON — verify LOCAL and SEMANTIC_SCHOLAR/OPENALEX passages appear
6. Run Citation Trail on the LLM agents PDF — verify reference cards render with FOUND/NOT_FOUND badges
7. Confirm all existing panels (Divergence, Analysis, Vectors, Synthesis, Reference Integrity, Audit) still work
