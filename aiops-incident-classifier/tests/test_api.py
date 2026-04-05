"""
Integration tests for all 4 FastAPI endpoints.
The ensemble classifier is mocked — no real Anthropic/ML calls.
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.models.schemas import (
    Category, ClassificationOutput, EnsembleOutput, IncidentInput, Severity
)
from backend.main import app

client = TestClient(app)


def _ensemble_output(
    category: Category = Category.APPLICATION,
    severity: Severity = Severity.SEV2,
    confidence: float = 0.85,
    agreement: bool = True,
    incident_id: str = "test-id-001",
) -> EnsembleOutput:
    result = ClassificationOutput(
        category=category,
        severity=severity,
        confidence=confidence,
        recommended_action="Check APM traces",
        runbook=["Step 1", "Step 2"],
        route_to="App Engineering On-Call",
        auto_remediation=False,
        escalation_required=severity == Severity.SEV1,
    )
    return EnsembleOutput(
        ml_result=result,
        llm_result=result,
        final_decision=result,
        agreement=agreement,
        incident_id=incident_id,
    )


# --- GET /health ---

def test_health_returns_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "service" in body


# --- POST /classify ---

def test_classify_returns_ensemble_output():
    mock_result = _ensemble_output()
    with patch("backend.main.ensemble.classify", return_value=mock_result), \
         patch("backend.main.slack.notify", return_value=False), \
         patch("backend.main.pagerduty.trigger", return_value=False):
        resp = client.post("/classify", json={"alert_text": "Payment service error rate spike"})

    assert resp.status_code == 200
    body = resp.json()
    assert "final_decision" in body
    assert "ml_result" in body
    assert "llm_result" in body
    assert "agreement" in body
    assert body["final_decision"]["category"] == Category.APPLICATION.value


def test_classify_sev1_triggers_slack():
    """SEV-1 incident should trigger Slack notification."""
    mock_result = _ensemble_output(category=Category.DDOS_ATTACK, severity=Severity.SEV1)
    with patch("backend.main.ensemble.classify", return_value=mock_result) as _mock_ens, \
         patch("backend.main.slack.notify", return_value=True) as mock_slack, \
         patch("backend.main.pagerduty.trigger", return_value=True):
        resp = client.post("/classify", json={"alert_text": "DDoS attack detected", "source": "Datadog"})

    assert resp.status_code == 200
    mock_slack.assert_called_once()


def test_classify_non_sev1_does_not_trigger_slack():
    """SEV-2/3 incidents should not trigger Slack."""
    mock_result = _ensemble_output(category=Category.APPLICATION, severity=Severity.SEV2)
    with patch("backend.main.ensemble.classify", return_value=mock_result), \
         patch("backend.main.slack.notify", return_value=False) as mock_slack, \
         patch("backend.main.pagerduty.trigger", return_value=False):
        resp = client.post("/classify", json={"alert_text": "App error rate at 5%"})

    assert resp.status_code == 200
    mock_slack.assert_not_called()


def test_classify_with_source_and_timestamp():
    """Classify endpoint accepts optional source and timestamp fields."""
    mock_result = _ensemble_output()
    with patch("backend.main.ensemble.classify", return_value=mock_result), \
         patch("backend.main.slack.notify", return_value=False), \
         patch("backend.main.pagerduty.trigger", return_value=False):
        resp = client.post("/classify", json={
            "alert_text": "Database replication lag",
            "source": "Dynatrace",
            "timestamp": "2024-01-15T14:32:00Z",
        })

    assert resp.status_code == 200


def test_classify_propagates_server_error():
    """Returns 500 when ensemble raises an exception."""
    with patch("backend.main.ensemble.classify", side_effect=RuntimeError("model failed")):
        resp = client.post("/classify", json={"alert_text": "bad input"})
    assert resp.status_code == 500


# --- GET /incidents ---

def test_list_incidents_returns_empty_when_no_dataset(tmp_path, monkeypatch):
    """Returns empty list when incidents.json does not exist."""
    import backend.main as main_module
    monkeypatch.setattr(main_module, "INCIDENTS_PATH", tmp_path / "nonexistent.json")
    resp = client.get("/incidents")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_incidents_with_dataset(tmp_path, monkeypatch):
    """Returns paginated list of incidents from the dataset."""
    import backend.main as main_module
    dataset = [
        {"id": f"id-{i}", "title": f"Alert {i}", "description": "desc", "category": "application", "severity": "SEV-2", "source": "Datadog"}
        for i in range(10)
    ]
    incidents_file = tmp_path / "incidents.json"
    incidents_file.write_text(json.dumps(dataset))
    monkeypatch.setattr(main_module, "INCIDENTS_PATH", incidents_file)

    resp = client.get("/incidents?limit=5&offset=0")
    assert resp.status_code == 200
    assert len(resp.json()) == 5

    resp2 = client.get("/incidents?limit=5&offset=5")
    assert resp2.status_code == 200
    assert len(resp2.json()) == 5


def test_get_incident_by_id(tmp_path, monkeypatch):
    """Returns a single incident by ID."""
    import backend.main as main_module
    dataset = [
        {"id": "abc-123", "title": "Test alert", "description": "desc", "category": "network", "severity": "SEV-3", "source": "Splunk"}
    ]
    incidents_file = tmp_path / "incidents.json"
    incidents_file.write_text(json.dumps(dataset))
    monkeypatch.setattr(main_module, "INCIDENTS_PATH", incidents_file)

    resp = client.get("/incidents/abc-123")
    assert resp.status_code == 200
    assert resp.json()["id"] == "abc-123"


def test_get_incident_not_found(tmp_path, monkeypatch):
    """Returns 404 for unknown incident ID."""
    import backend.main as main_module
    incidents_file = tmp_path / "incidents.json"
    incidents_file.write_text(json.dumps([]))
    monkeypatch.setattr(main_module, "INCIDENTS_PATH", incidents_file)

    resp = client.get("/incidents/nonexistent-id")
    assert resp.status_code == 404


# --- GET /stats ---

def test_stats_returns_empty_when_no_dataset(tmp_path, monkeypatch):
    """Returns zero counts when incidents.json does not exist."""
    import backend.main as main_module
    monkeypatch.setattr(main_module, "INCIDENTS_PATH", tmp_path / "nonexistent.json")
    resp = client.get("/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_incidents"] == 0
    assert body["by_category"] == {}
    assert body["by_severity"] == {}


def test_stats_counts_correctly(tmp_path, monkeypatch):
    """Stats endpoint returns correct counts by category, severity, and source."""
    import backend.main as main_module
    dataset = [
        {"id": "1", "title": "a", "description": "d", "category": "application", "severity": "SEV-1", "source": "Datadog"},
        {"id": "2", "title": "b", "description": "d", "category": "application", "severity": "SEV-2", "source": "Splunk"},
        {"id": "3", "title": "c", "description": "d", "category": "database", "severity": "SEV-1", "source": "Dynatrace"},
    ]
    incidents_file = tmp_path / "incidents.json"
    incidents_file.write_text(json.dumps(dataset))
    monkeypatch.setattr(main_module, "INCIDENTS_PATH", incidents_file)

    resp = client.get("/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_incidents"] == 3
    assert body["by_category"]["application"] == 2
    assert body["by_category"]["database"] == 1
    assert body["by_severity"]["SEV-1"] == 2
    assert body["by_source"]["Datadog"] == 1
    assert body["by_source"]["Splunk"] == 1
    assert body["by_source"]["Dynatrace"] == 1
