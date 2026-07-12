# LexiQ — Research Intelligence Platform

**Applying distributed systems engineering to the knowledge latency problem in academic R&D.**

When you build distributed systems at scale you learn to reason about three properties: data freshness, propagation latency, and consistency guarantees. Research organisations fail on all three dimensions of their knowledge pipelines. Literature goes stale. Insights don't propagate across labs. There are no consistency guarantees on what gets synthesised or cited.

LexiQ treats this as an engineering problem. The retrieval layer is your consistency model. The grounded query pipeline is your replication mechanism. The Reference Integrity layer is your checksum. The Audit Ledger is your write-ahead log.

Built as a demonstration for a Faculty Development Programme session on *Generative LLMs for Research & Development*.

---

## The engineering framing

A chat window is a single ungrounded LLM call. Every failure mode in research AI — hallucinated citations, unsourced claims, non-reproducible outputs — traces back to that single missing property: **the model has no corpus, no checksum, and no audit trail.** LexiQ adds all three as independent layers that the LLM does not touch.

| Layer | What it does | Why the LLM alone cannot do it |
|-------|-------------|--------------------------------|
| **Retrieval (RAG)** | Grounds every answer to specific corpus chunks with page-level provenance | A language model generates plausible text; it has no corpus and no memory of what was ingested |
| **Evidence Divergence** | Classifies each corpus passage as SUPPORTS / CONTRADICTS / QUALIFIES a claim | No single prompt does reliable multi-document synthesis with per-source attribution |
| **Reference Integrity** | Three-pass check: existence (CrossRef), attribution (DOI metadata vs claim), arithmetic | Existence checks, metadata lookups, and sums are computational — not generative |
| **Audit Ledger** | Append-only log: model, temperature, prompt SHA-256, output SHA-256 | A language model keeps no auditable record of what it produced or under which conditions |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Single-page UI (index.html) — dark sidebar, session    │
│  dashboard, telemetry strip on every operation          │
└────────────────────────┬────────────────────────────────┘
                         │ HTTP/JSON
┌────────────────────────▼────────────────────────────────┐
│  Flask API (app.py) — 9 typed endpoints                 │
└──┬──────────────┬──────────────┬────────────────────────┘
   │              │              │
   ▼              ▼              ▼
Ollama        nomic-embed-text  CrossRef API
llama3.1:8b   (local)          (citation only)
(local)
```

**All inference and all embedding run locally.** The only external call is CrossRef — and only the short citation string is sent, never the manuscript.

---

## Seven pipeline stages

| # | Module | Backend | Core capability |
|---|--------|---------|----------------|
| 0 | Session Overview | — | Corpus health, system status, activity log |
| 1 | Grounded Query | `grounded.py` + `retrieve.py` | RAG with per-sentence source attribution |
| 2 | Evidence Divergence | `contradict.py` | Multi-document stance classification |
| 3 | Document Analysis | `triage.py` | Structured extraction from source text |
| 4 | Research Vectors | `ideation.py` | Candidate directions, novelty/feasibility scored |
| 5 | Synthesis | `draft.py` | Draft with `[CITE:]` markers — explicitly unverified |
| 6 | Reference Integrity | `verify.py` | Three-layer deterministic verification |
| 7 | Audit Ledger | `provenance.py` | Append-only reproducibility log |

---

## Running it

```bash
# Models
ollama pull llama3.1:8b
ollama pull nomic-embed-text
ollama serve

# Dependencies
pip install -r requirements.txt      # flask, requests, pypdf, numpy

# Ingest a corpus
mkdir -p backend/corpus/pdfs
cp your-papers/*.pdf backend/corpus/pdfs/

# Start
python -m backend.app
# open http://localhost:5000
```

**Demo mode** — `LIVE_MODE = false` in `index.html` uses pre-recorded outputs with realistic telemetry. Safe for projectors. Set to `true` once Ollama is confirmed running with the corpus ingested.

---

## Design decisions and explicit tradeoffs

**Why local Ollama, not an API?** Data residency: unpublished manuscripts and grant data should not transit a third-party network. Local inference also enables honest latency reporting in the telemetry strip — the numbers are real.

**Why cosine similarity over BM25?** Semantic queries ("what do papers say about the recall-privacy tradeoff") map better to embedding space than keyword matching. The tradeoff: BM25 handles exact-match terminology better; this system is tuned for conceptual synthesis.

**Why CrossRef for verification?** It is the authoritative scholarly index, not scraped data. Coverage is strong for journals and IEEE/ACM conferences; weaker for grey literature and preprints.

**Why chunk at 900 characters?** Preserves paragraph-level context while keeping chunks small enough for precise attribution. The tradeoff: long methodological sections may span multiple chunks and surface in separate retrievals.

**Known constraints** (stated as engineering constraints, not disclaimers):
- Retrieval precision degrades for highly domain-specific jargon not in the embedding model's vocabulary
- Contradiction classification reflects the retrieved passages only — it is evidence for human review, not a verdict
- Numeric consistency checks catch common anomalies; they do not validate statistical methodology

---

## License

MIT — see `LICENSE`.
