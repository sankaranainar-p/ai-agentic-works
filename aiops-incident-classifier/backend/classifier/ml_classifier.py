"""
ML-based incident classifier using TF-IDF + LinearSVC (scikit-learn).
CalibratedClassifierCV wraps LinearSVC to produce probability estimates.
Train with: python -m backend.classifier.ml_classifier
"""
import json
import os
import pickle
from pathlib import Path

from typing import Optional, Tuple

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import LinearSVC

from backend.models.schemas import (
    Category, ClassificationOutput, IncidentInput, Severity
)
from backend.classifier.maps import ROUTING_MAP, RUNBOOK_MAP

MODEL_PATH = Path(os.getenv("ML_MODEL_PATH", "backend/models/ml_model.pkl"))

SEVERITY_MAP: dict[str, Severity] = {
    "infrastructure":          Severity.SEV2,
    "application":             Severity.SEV2,
    "database":                Severity.SEV1,
    "network":                 Severity.SEV2,
    "security":                Severity.SEV1,
    "data_pipeline":           Severity.SEV3,
    "performance_degradation": Severity.SEV3,
    "availability":            Severity.SEV1,
    "ddos_attack":             Severity.SEV1,
    "availability_drop":       Severity.SEV2,
    "http_500_spike":          Severity.SEV2,
}

# Categories that require immediate escalation
ESCALATION_CATEGORIES = {
    Category.DDOS_ATTACK, Category.SECURITY, Category.AVAILABILITY, Category.DATABASE
}

# Categories eligible for auto-remediation
AUTO_REMEDIATION_CATEGORIES = {
    Category.HTTP_500_SPIKE, Category.AVAILABILITY_DROP, Category.PERFORMANCE_DEGRADATION
}

_pipeline: Optional[Pipeline] = None
_label_encoder: Optional[LabelEncoder] = None


def _load_model() -> Tuple[Pipeline, LabelEncoder]:
    global _pipeline, _label_encoder
    if _pipeline is None:
        if not MODEL_PATH.exists():
            train()
        with open(MODEL_PATH, "rb") as f:
            _pipeline, _label_encoder = pickle.load(f)
    return _pipeline, _label_encoder


def train() -> None:
    """Train the classifier from incidents.json and save the model."""
    data_path = Path("backend/data/incidents.json")
    if not data_path.exists():
        raise FileNotFoundError(
            "incidents.json not found. Run: python backend/data/generate_dataset.py"
        )

    with open(data_path) as f:
        records = json.load(f)

    # Use alert_text if present, else combine title + description
    texts = [
        r.get("alert_text") or f"{r.get('title', '')} {r.get('description', '')}"
        for r in records
    ]
    labels = [r["category"] for r in records]

    le = LabelEncoder()
    y = le.fit_transform(labels)

    # LinearSVC wrapped with CalibratedClassifierCV for probability estimates
    svc = CalibratedClassifierCV(LinearSVC(C=1.0, max_iter=2000, random_state=42))
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=8000, sublinear_tf=True)),
        ("clf", svc),
    ])
    pipeline.fit(texts, y)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump((pipeline, le), f)
    print(f"Model saved to {MODEL_PATH}")


def classify(incident: IncidentInput) -> ClassificationOutput:
    """Classify an incident using the trained ML pipeline."""
    pipeline, le = _load_model()

    text = incident.alert_text
    proba = pipeline.predict_proba([text])[0]
    pred_idx = int(np.argmax(proba))
    confidence = float(proba[pred_idx])
    category_str = le.inverse_transform([pred_idx])[0]
    category = Category(category_str)
    severity = SEVERITY_MAP.get(category_str, Severity.SEV3)

    # Force SEV-1 for DDoS
    if category == Category.DDOS_ATTACK:
        severity = Severity.SEV1

    escalation = category in ESCALATION_CATEGORIES or severity == Severity.SEV1
    auto_rem = category in AUTO_REMEDIATION_CATEGORIES and severity != Severity.SEV1

    return ClassificationOutput(
        category=category,
        severity=severity,
        confidence=confidence,
        recommended_action=RUNBOOK_MAP[category][0],
        runbook=RUNBOOK_MAP[category],
        route_to=ROUTING_MAP[category],
        auto_remediation=auto_rem,
        escalation_required=escalation,
    )


if __name__ == "__main__":
    train()
