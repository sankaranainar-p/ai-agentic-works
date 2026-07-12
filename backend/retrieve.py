"""
retrieve.py — Grounded retrieval via TF-IDF
--------------------------------------------
Ingests PDFs, chunks them, and stores text in a simple on-disk index.
At query time, TF-IDF cosine similarity finds the nearest chunks.

Every returned chunk carries source file and page number so every downstream
claim can be traced to "PDF X, page N, this exact text."

No cloud calls. No Ollama dependency for retrieval.
Requires: pypdf numpy scikit-learn
"""

from __future__ import annotations

import os
import re
import json
import hashlib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from pypdf import PdfReader

INDEX_PATH = os.path.join(os.path.dirname(__file__), "corpus", "index.json")

CHUNK_CHARS = 900
CHUNK_OVERLAP = 150


def _chunk_page(text: str) -> list[str]:
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    chunks, start = [], 0
    while start < len(text):
        end = start + CHUNK_CHARS
        window = text[start:end]
        last_stop = max(window.rfind(". "), window.rfind("? "), window.rfind("! "))
        if last_stop > CHUNK_CHARS * 0.5 and end < len(text):
            end = start + last_stop + 1
        chunks.append(text[start:end].strip())
        start = end - CHUNK_OVERLAP
    return [c for c in chunks if c]


def ingest_pdf(path: str) -> int:
    """Read a PDF, chunk per page, append to on-disk index. Returns chunks added."""
    reader = PdfReader(path)
    fname = os.path.basename(path)
    index = _load_index()

    added = 0
    for page_no, page in enumerate(reader.pages, start=1):
        page_text = page.extract_text() or ""
        for chunk in _chunk_page(page_text):
            cid = hashlib.sha1(f"{fname}:{page_no}:{chunk[:60]}".encode()).hexdigest()[:12]
            index["chunks"].append({
                "id": cid,
                "source": fname,
                "page": page_no,
                "text": chunk,
            })
            added += 1

    _save_index(index)
    return added


def search(query: str, k: int = 4) -> list[dict]:
    """Return the k most relevant chunks to a query using TF-IDF cosine similarity."""
    index = _load_index()
    if not index["chunks"]:
        return []

    texts = [ch["text"] for ch in index["chunks"]]
    vectorizer = TfidfVectorizer(stop_words="english", max_features=10000)
    tfidf_matrix = vectorizer.fit_transform(texts)
    query_vec = vectorizer.transform([query])

    scores = (tfidf_matrix @ query_vec.T).toarray().flatten()
    top_indices = np.argsort(scores)[::-1][:k]

    out = []
    for idx in top_indices:
        ch = index["chunks"][idx]
        score = float(scores[idx])
        if score == 0.0:
            continue
        out.append({
            "id": ch["id"], "source": ch["source"], "page": ch["page"],
            "text": ch["text"], "score": round(score, 3),
        })
    return out


def corpus_summary() -> dict:
    index = _load_index()
    sources = {}
    for ch in index["chunks"]:
        sources.setdefault(ch["source"], 0)
        sources[ch["source"]] += 1
    return {"documents": len(sources), "chunks": len(index["chunks"]),
            "by_source": sources}


def already_ingested(filename: str) -> bool:
    """Return True if any chunk in the index came from this filename."""
    index = _load_index()
    return any(ch["source"] == filename for ch in index["chunks"])


def _load_index() -> dict:
    if os.path.exists(INDEX_PATH):
        with open(INDEX_PATH) as f:
            return json.load(f)
    return {"chunks": []}


def _save_index(index: dict) -> None:
    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    with open(INDEX_PATH, "w") as f:
        json.dump(index, f)
