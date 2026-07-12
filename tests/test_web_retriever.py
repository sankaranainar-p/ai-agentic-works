from unittest.mock import patch, MagicMock
import requests

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
    with patch("backend.web_retriever.requests.get", side_effect=requests.exceptions.Timeout("timeout")):
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
