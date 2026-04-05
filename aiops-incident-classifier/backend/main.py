"""
AIOps Incident Classifier — FastAPI entry point.
Start: uvicorn backend.main:app --reload
"""
import json
import uuid
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from backend.classifier import ensemble
from backend.classifier.llm_classifier import LLMUnavailableError
from backend.integrations import slack, pagerduty
from backend.models.schemas import EnsembleOutput, IncidentInput, IncidentRecord, Severity

app = FastAPI(
    title="AIOps Incident Classifier",
    description="ML + LLM ensemble for fintech incident classification and routing",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:4173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

INCIDENTS_PATH = Path("backend/data/incidents.json")


@app.get("/health")
def health():
    return {"status": "ok", "service": "aiops-incident-classifier", "version": "2.0.0"}


@app.post("/classify", response_model=EnsembleOutput)
def classify_incident(incident: IncidentInput):
    """Classify an incident using the ML + LLM ensemble.

    Always returns 200. When the LLM is unavailable, falls back to ML-only
    classification and sets llm_status='unavailable' in the response.
    """
    incident_id = str(uuid.uuid4())
    try:
        result = ensemble.classify(incident, incident_id=incident_id)
    except LLMUnavailableError:
        # Should not reach here — ensemble handles it — but guard defensively
        from backend.classifier import ml_classifier
        ml_out = ml_classifier.classify(incident)
        from backend.classifier.ensemble import _ml_only_result
        result = _ml_only_result(ml_out, incident, incident_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Notify Slack only for SEV-1
    if result.final_decision.severity == Severity.SEV1:
        slack.notify(incident.alert_text, result)

    # Trigger PagerDuty for SEV-1 and SEV-2
    pagerduty.trigger(incident.alert_text, result)

    return result


@app.get("/incidents", response_model=list[IncidentRecord])
def list_incidents(limit: int = 50, offset: int = 0):
    """Return incidents from the training dataset (for dashboard)."""
    if not INCIDENTS_PATH.exists():
        return []
    with open(INCIDENTS_PATH) as f:
        records = json.load(f)
    return records[offset: offset + limit]


@app.get("/incidents/{incident_id}", response_model=IncidentRecord)
def get_incident(incident_id: str):
    if not INCIDENTS_PATH.exists():
        raise HTTPException(status_code=404, detail="Dataset not found")
    with open(INCIDENTS_PATH) as f:
        records = json.load(f)
    match = next((r for r in records if r["id"] == incident_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Incident not found")
    return match


@app.get("/stats")
def get_stats():
    """Return aggregate statistics from the incident dataset."""
    if not INCIDENTS_PATH.exists():
        return {
            "total_incidents": 0,
            "by_category": {},
            "by_severity": {},
            "by_source": {},
        }

    with open(INCIDENTS_PATH) as f:
        records = json.load(f)

    by_category = dict(Counter(r["category"] for r in records))
    by_severity = dict(Counter(r["severity"] for r in records))
    by_source = dict(Counter(r.get("source", "unknown") for r in records))

    return {
        "total_incidents": len(records),
        "by_category": dict(sorted(by_category.items(), key=lambda x: x[1], reverse=True)),
        "by_severity": dict(sorted(by_severity.items())),
        "by_source": dict(sorted(by_source.items(), key=lambda x: x[1], reverse=True)),
    }
