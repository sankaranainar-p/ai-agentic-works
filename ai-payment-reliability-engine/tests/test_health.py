"""
tests/test_health.py — Smoke test: the FastAPI app starts (full lifespan,
including classifier load and monitor startup) and GET /health succeeds.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from pre.main import app


@pytest.mark.asyncio
async def test_health_endpoint_after_startup() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # LifespanManager equivalent: httpx's ASGITransport doesn't run
        # lifespan by default, so run it explicitly via the app's router.
        async with app.router.lifespan_context(app):
            response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "incidents_processed" in body
    assert "log_entries" in body
