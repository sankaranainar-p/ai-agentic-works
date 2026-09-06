"""
tests/test_scenarios_alignment.py — Every demo scenario returned by
GET /scenarios, and every seed scenario processed at startup, must
classify into a real fault_class (data/taxonomy.yaml) with reasonable
confidence — not "unknown" and not near-zero confidence, which would
indicate the demo content still describes a category the taxonomy no
longer supports (e.g. leftover ddos_attack/security wording).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from pre.agent_loop import SEED_SCENARIOS
from pre.classifier.model import get_classifier
from pre.classifier.taxonomy import UNKNOWN_CATEGORY
from pre.main import app

_MIN_CONFIDENCE = 0.3


@pytest.mark.asyncio
async def test_scenarios_endpoint_all_classify_confidently() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            response = await client.get("/scenarios")

    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) >= 10

    clf = get_classifier()
    low_confidence = []
    for scenario in scenarios:
        if scenario["name"] == "Unknown":
            continue
        result = clf.classify(scenario["alert_text"])
        if result.category == UNKNOWN_CATEGORY or result.confidence < _MIN_CONFIDENCE:
            low_confidence.append((scenario["name"], result.category, result.confidence))

    assert not low_confidence, f"Scenarios classify poorly: {low_confidence}"


def test_seed_scenarios_all_classify_confidently() -> None:
    clf = get_classifier()
    low_confidence = []
    for alert_text, _source in SEED_SCENARIOS:
        result = clf.classify(alert_text)
        if result.category == UNKNOWN_CATEGORY or result.confidence < _MIN_CONFIDENCE:
            low_confidence.append((alert_text, result.category, result.confidence))

    assert not low_confidence, f"Seed scenarios classify poorly: {low_confidence}"
