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
    with patch("backend.citations.PdfReader", return_value=_mock_pdf(pages)), \
         patch("backend.citations.generate_json", return_value={"references": llm_refs}):
        from backend.citations import extract_references
        result = extract_references("/fake/path.pdf")
    assert len(result) == 2
    assert result[0]["year"] == "2023"
    assert result[1]["title"] == "Ignore Previous Prompt"

def test_extract_references_returns_empty_when_no_text():
    pages = [""] * 10
    with patch("backend.citations.PdfReader", return_value=_mock_pdf(pages)), \
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
