import json

def test_already_ingested_true_when_in_index(tmp_path, monkeypatch):
    idx = {"chunks": [{"source": "paper.pdf", "page": 1, "text": "x", "id": "abc"}]}
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
