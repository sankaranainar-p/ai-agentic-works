"""
app.py — Flask server wiring all modules to the web UI
------------------------------------------------------
Run:  python -m backend.app   then open http://localhost:5000
"""

from __future__ import annotations

import os
from flask import Flask, request, jsonify, send_from_directory
from . import triage, ideation, draft, verify, grounded, contradict, provenance, retrieve, web_retriever, citations
from .llm_client import OllamaError, DEFAULT_MODEL

app = Flask(__name__, static_folder="../frontend", static_url_path="")


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---- original modules ----------------------------------------------------
@app.post("/api/triage")
def api_triage():
    try:
        return jsonify(triage.triage(request.json.get("text", "")))
    except OllamaError as e:
        return jsonify({"error": str(e)}), 503


@app.post("/api/ideate")
def api_ideate():
    try:
        return jsonify(ideation.ideate(request.json.get("context", "")))
    except OllamaError as e:
        return jsonify({"error": str(e)}), 503


@app.post("/api/draft")
def api_draft():
    try:
        text = draft.draft(request.json.get("notes", ""),
                           request.json.get("kind", "related-work paragraph"))
        provenance.record("draft", DEFAULT_MODEL,
                          request.json.get("notes", ""), text, 0.2)
        return jsonify({"draft": text})
    except OllamaError as e:
        return jsonify({"error": str(e)}), 503


@app.post("/api/verify")
def api_verify():
    text = request.json.get("text", "")
    return jsonify({
        "results": verify.verify_text(text),
        "numeric": verify.check_numeric_consistency(text),
    })


@app.post("/api/crosscheck")
def api_crosscheck():
    d = request.json
    return jsonify(verify.cross_check_doi(
        d.get("doi", ""), d.get("year"), d.get("author")))


# ---- new modules ---------------------------------------------------------
@app.post("/api/ingest")
def api_ingest():
    pdf_dir = os.path.join(os.path.dirname(__file__), "corpus", "pdfs")
    os.makedirs(pdf_dir, exist_ok=True)
    total = 0
    try:
        for fn in sorted(os.listdir(pdf_dir)):
            if fn.lower().endswith(".pdf"):
                total += retrieve.ingest_pdf(os.path.join(pdf_dir, fn))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(retrieve.corpus_summary())


@app.get("/api/corpus")
def api_corpus():
    summary = retrieve.corpus_summary()
    pdf_dir = os.path.join(os.path.dirname(__file__), "corpus", "pdfs")
    if os.path.isdir(pdf_dir):
        summary["available_pdfs"] = sorted(
            fn for fn in os.listdir(pdf_dir) if fn.lower().endswith(".pdf")
        )
    else:
        summary["available_pdfs"] = []
    return jsonify(summary)


@app.post("/api/grounded")
def api_grounded():
    try:
        d = request.json
        return jsonify(grounded.grounded_answer(
            question=d.get("question", ""),
            web_enrich=bool(d.get("web_enrich", False)),
        ))
    except OllamaError as e:
        return jsonify({"error": str(e)}), 503


@app.post("/api/web-search")
def api_web_search():
    """Direct real-time Semantic Scholar search — no local corpus involved."""
    query = request.json.get("query", "")
    k = int(request.json.get("k", 6))
    results = web_retriever.search_web(query=query, k=k)
    return jsonify({"results": results})


@app.post("/api/citations")
def api_citations():
    pdf_name = request.json.get("pdf", "")
    pdf_name = os.path.basename(pdf_name)
    pdf_path = os.path.join(os.path.dirname(__file__), "corpus", "pdfs", pdf_name)
    if not os.path.isfile(pdf_path):
        return jsonify({"error": f"PDF not found: {pdf_name}"}), 404
    try:
        return jsonify(citations.build_citation_trail(pdf_path))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/contradict")
def api_contradict():
    try:
        return jsonify(contradict.analyze_claim(request.json.get("claim", "")))
    except OllamaError as e:
        return jsonify({"error": str(e)}), 503


@app.get("/api/provenance")
def api_provenance():
    return jsonify({"entries": provenance.recent(15)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9090, debug=True)
