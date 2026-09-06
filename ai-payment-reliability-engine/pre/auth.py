"""
app/auth.py — API key authentication dependency.

Accepts the key via:
  - X-API-Key request header  (all endpoints)
  - ?api_key= query parameter (SSE endpoint — browsers can't set headers on EventSource)

Behaviour:
  - API_KEY env var not set  → allow all requests (local dev mode)
  - API_KEY set, key matches → allow
  - API_KEY set, key missing or wrong → HTTP 401
"""

from __future__ import annotations

import os

from fastapi import Header, HTTPException, Query


async def verify_api_key(
    x_api_key: str = Header(None),
    api_key: str = Query(None),
) -> None:
    """FastAPI dependency that enforces API key authentication."""
    required = os.getenv("API_KEY")

    if not required:
        return  # Dev mode — no key configured, allow everything

    provided = x_api_key or api_key

    if provided != required:
        print(
            "[auth] Unauthorized request — "
            + ("missing API key" if provided is None else "invalid API key"),
            flush=True,
        )
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
