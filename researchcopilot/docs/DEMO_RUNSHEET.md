# LexiQ — 60-Minute FDP Demo Script

**Opening line (say this first):**
"When you build distributed systems at scale, you learn to reason about three properties: data freshness, propagation latency, and consistency guarantees. Research organisations fail on all three in their knowledge pipelines. This is an engineering approach to that problem."

---

## Timing

| Min | What you show | What you say |
|-----|--------------|--------------|
| 0–5 | **Framing** — the three failure modes | "A chat window is one ungrounded LLM call. Every problem — hallucinated citations, unsourced claims, non-reproducible outputs — traces back to that. We add a corpus, a checksum, and an audit trail." |
| 5–8 | **Session Overview** | Point out: session ID, four system health indicators, pipeline config (chunk size, similarity threshold, verification layers). "This is what a production deployment dashboard looks like." |
| 8–20 | **Grounded Query** ⭐ | Execute the sample. Point out: every sentence has a source tag, each resolves to `filename · page · similarity score`. "This is sourced text. Not plausible text. That's the entire difference." |
| 20–30 | **Evidence Divergence** ⭐ | Execute. Show 1 support, 2 contradict, 2 qualify. "Surfacing disagreement between papers is what a PhD student spends a week doing by hand. This is the synthesis work a chat window structurally cannot do — it has no corpus." |
| 30–36 | **Document Analysis + Research Vectors** | Move briskly. Show structured extraction, then scored directions. "It helps you prioritise. The novelty and feasibility scores force explicit tradeoffs." |
| 36–42 | **Synthesis** | Show the draft with amber `[CITE:]` markers. "Notice the system does NOT claim these are real. They are hypotheses. That's by design." |
| 42–52 | **Reference Integrity** ⭐ | The payoff. Summary bar: 2 verified, 1 unresolved, 1 anomaly. The PARTITION_SUM_ANOMALY: 55+30+40=125%. "Three layers the model cannot run on itself: existence, attribution, arithmetic. Computational checks over a generative output." |
| 52–57 | **Audit Ledger + Code walkthrough** | Show the telemetry strip on any panel. Open `verify.py` — point to `cross_check_doi` and `check_numeric_consistency`. Open `retrieve.py` — show chunk sizes and cosine similarity. "These are engineering decisions with explicit tradeoffs, not magic." |
| 57–60 | **Close** | "The LLM is one node in this pipeline. The engineering that matters is everything we built around it — the retrieval layer, the verification layer, the audit trail. That's the blueprint." |

---

## Questions to expect

| Question | Answer |
|----------|--------|
| "Does it need internet?" | Only Reference Integrity sends to CrossRef — and only the short citation string, never the manuscript. Everything else is local. |
| "What model is this?" | llama3.1:8b + nomic-embed-text via Ollama. Both are swappable — one line change in `llm_client.py` and `retrieve.py`. |
| "Can it replace a literature review?" | No — and we don't claim it does. It surfaces candidates and conflicts for a human to confirm. The system tells you where to look, not what to conclude. |
| "How big a corpus can it handle?" | The on-disk index scales to hundreds of papers before you'd want a production vector DB like Chroma or Qdrant. The architecture is the same. |
| "Is this safe for unpublished work?" | Stages 1–5 are 100% local. Reference Integrity sends only the short citation string to CrossRef — never the manuscript body. |
