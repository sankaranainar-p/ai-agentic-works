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
    with patch("backend.citations.build_citation_trail", return_value=trail), \
         patch("backend.app.os.path.isfile", return_value=True):
        resp = client.post("/api/citations", json={"pdf": "paper.pdf"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 2

def test_citations_endpoint_404_for_missing_file(client):
    resp = client.post("/api/citations", json={"pdf": "nonexistent.pdf"})
    assert resp.status_code == 404
    assert "error" in resp.get_json()
