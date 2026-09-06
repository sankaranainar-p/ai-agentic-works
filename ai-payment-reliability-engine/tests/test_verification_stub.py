"""
tests/test_verification_stub.py — Documents and locks in the intended
behaviour of the verification.py / monitor.py NotImplementedError stubs
introduced to replace `random.random()`-based simulation.

Design intent:
  - Background paths (monitor polling, startup seeding) catch exceptions
    per-iteration and log them, so a stubbed-out verify()/monitor check
    does not crash the whole app or the monitor loop.
  - The direct API path (POST /trigger) does NOT swallow the exception:
    calling /trigger surfaces the stub loudly as a 500, so a developer
    exercising the API directly cannot mistake the stub for a working
    verification step.
"""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

from pre.main import app

# Skip verify()'s wait so this test suite runs fast; VERIFY_WAIT_SECONDS
# defaults to 10s which would otherwise make this test slow for no benefit.
os.environ.setdefault("VERIFY_WAIT_SECONDS", "0")


@pytest.mark.asyncio
async def test_verify_stub_raises_not_implemented_directly() -> None:
    from pre.verification import verify

    with pytest.raises(NotImplementedError, match="pre.telemetry.metrics_client"):
        await verify(category="cpu", severity="SEV-2", alert_text="cpu high")


@pytest.mark.asyncio
async def test_monitor_probabilistic_breach_stub_raises() -> None:
    from pre.monitor import _probabilistic_breach

    with pytest.raises(NotImplementedError, match="pre.telemetry.metrics_client"):
        _probabilistic_breach({"name": "test_check", "threshold": 1.0})


@pytest.mark.asyncio
async def test_trigger_endpoint_surfaces_verification_stub_as_500() -> None:
    """POST /trigger exercises the full 5-layer loop; the verification
    stub raising NotImplementedError should surface as an HTTP 500,
    not be silently swallowed into a fake "resolved"/"unresolved" status.
    """
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            response = await client.post(
                "/trigger",
                json={"alert_text": "cpu utilization 99% payment nodes", "source": "test"},
            )

    assert response.status_code == 500
