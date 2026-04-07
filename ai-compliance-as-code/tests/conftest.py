"""
tests/conftest.py — Shared pytest fixtures for the AI Compliance-as-Code test suite.

All tests that POST to /analyze use the TestClient fixture defined here.
api.main.call_llm is patched at the dispatcher level so tests are provider-agnostic:
they never touch a real Anthropic client or Ollama server.
"""

from __future__ import annotations

import json
import os
import textwrap
from typing import Generator, List, Tuple
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure a dummy API key exists before importing the app (used by _call_anthropic
# if the provider were switched to "anthropic" in a test).
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-for-pytest")

from api.main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Patch target — patch the public dispatcher so tests are provider-agnostic
# ---------------------------------------------------------------------------
CALL_LLM_PATH = "api.main.call_llm"


# ---------------------------------------------------------------------------
# Sample source files
# ---------------------------------------------------------------------------

# Django-style UserController with multiple GDPR violations:
#   • plaintext password written to logger (Art.32 — HIGH, line 11)
#   • weak MD5 hash for passwords       (Art.32 — HIGH, line 14)
#   • full user object logged            (Art.5  — HIGH, line 22)
#   • PAN stored in analytics            (Art.5 / PCI-REQ-3 — HIGH)
USER_CONTROLLER_CODE = textwrap.dedent("""\
    import hashlib
    import logging

    from django.db import models

    logger = logging.getLogger(__name__)


    class UserController:
        def register(self, username: str, password: str, email: str, pan: str):
            # VIOLATION: plaintext password written to log
            logger.info(f"Registering user {username}, password={password}")

            # VIOLATION: weak MD5 hash — never use for passwords
            password_hash = hashlib.md5(password.encode()).hexdigest()

            user = models.User.objects.create(
                username=username,
                password_hash=password_hash,
                email=email,
            )

            # VIOLATION: full user object (contains PII) logged without masking
            logger.debug(f"Created user: {user.__dict__}")

            # VIOLATION: PAN stored in plain analytics table
            AnalyticsEvent.objects.create(
                event="registration",
                user_email=email,
                card_number=pan,
            )
            return user

        def get_profile(self, user_id: int):
            # VIOLATION: no auth check on sensitive data read
            user = models.User.objects.get(pk=user_id)
            return {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "password_hash": user.password_hash,
            }
""")

# Clean FastAPI handler — zero violations expected
CLEAN_HANDLER_CODE = textwrap.dedent("""\
    from fastapi import APIRouter, Depends
    from .auth import require_auth
    from .models import UserProfile

    router = APIRouter()


    @router.get("/profile/{user_id}", dependencies=[Depends(require_auth)])
    def get_profile(user_id: int) -> UserProfile:
        profile = UserProfile.get_by_id(user_id)
        return UserProfile(id=profile.id, display_name=profile.display_name)
""")


# ---------------------------------------------------------------------------
# call_llm mock factory
#
# call_llm() now returns Tuple[str, str] = (raw_text, provider_label).
# These helpers produce a side_effect callable or a return_value tuple.
# ---------------------------------------------------------------------------

def make_call_llm_return(findings: List[dict], provider: str = "ollama") -> Tuple[str, str]:
    """Return the (raw_json, provider) tuple that call_llm would produce."""
    return json.dumps(findings), provider


def gdpr_art32_password_log_finding(file_path: str = "user_controller.py") -> dict:
    """Canonical Art.32 finding for plaintext password in logger call."""
    return {
        "rule_id": "GDPR-Art.32",
        "title": "Plaintext password written to application log",
        "severity": "high",
        "severity_override": False,
        "file": file_path,
        "line_start": 11,
        "line_end": 11,
        "snippet": 'logger.info(f"Registering user {username}, password={password}")',
        "violation": (
            "The raw password is interpolated into a log message; "
            "any log aggregator will store it in plaintext, violating Art.32(1)(a)."
        ),
        "remediation": (
            "Remove the password from the log call entirely; "
            "log only non-sensitive identifiers such as username or user_id."
        ),
        "references": [
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3383-1-1"
        ],
    }


def gdpr_art32_md5_finding(file_path: str = "user_controller.py") -> dict:
    """Art.32 finding for MD5 password hashing."""
    return {
        "rule_id": "GDPR-Art.32",
        "title": "Weak MD5 algorithm used for password hashing",
        "severity": "high",
        "severity_override": False,
        "file": file_path,
        "line_start": 14,
        "line_end": 14,
        "snippet": "password_hash = hashlib.md5(password.encode()).hexdigest()",
        "violation": "MD5 is a broken cryptographic hash; it must not be used for password storage per Art.32(1)(a).",
        "remediation": "Replace with bcrypt, Argon2id, or scrypt using a well-vetted library such as passlib.",
        "references": [
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e3383-1-1"
        ],
    }


def gdpr_art5_pii_log_finding(file_path: str = "user_controller.py") -> dict:
    """Art.5 finding for full user object (PII) in log."""
    return {
        "rule_id": "GDPR-Art.5",
        "title": "Full user object with PII written to log",
        "severity": "high",
        "severity_override": False,
        "file": file_path,
        "line_start": 22,
        "line_end": 22,
        "snippet": 'logger.debug(f"Created user: {user.__dict__}")',
        "violation": "Logging the full user dict exposes PII (email, password_hash) in plaintext logs, violating Art.5(1)(f).",
        "remediation": "Log only non-sensitive fields (e.g. user.id) or use a structured log sanitiser.",
        "references": [
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679#d1e1797-1-1"
        ],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as tc:
        yield tc


@pytest.fixture()
def mock_call_llm_user_controller():
    """Patches call_llm to return realistic findings for USER_CONTROLLER_CODE."""
    return_value = make_call_llm_return([
        gdpr_art32_password_log_finding(),
        gdpr_art32_md5_finding(),
        gdpr_art5_pii_log_finding(),
    ])
    with patch(CALL_LLM_PATH, return_value=return_value) as m:
        yield m


@pytest.fixture()
def mock_call_llm_empty():
    """Patches call_llm to return an empty findings array (clean file)."""
    return_value = make_call_llm_return([])
    with patch(CALL_LLM_PATH, return_value=return_value) as m:
        yield m


@pytest.fixture()
def mock_call_llm_error():
    """Patches call_llm to raise RuntimeError (simulates any LLM failure)."""
    with patch(CALL_LLM_PATH, side_effect=RuntimeError("LLM unavailable")) as m:
        yield m


@pytest.fixture()
def mock_call_llm_auth_error():
    """Patches call_llm to raise AuthenticationError (Anthropic-specific path)."""
    import anthropic
    import httpx
    mock_request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    mock_response = httpx.Response(401, request=mock_request)
    err = anthropic.AuthenticationError(
        message="Invalid API key",
        response=mock_response,
        body={"error": {"type": "authentication_error"}},
    )
    with patch(CALL_LLM_PATH, side_effect=err) as m:
        yield m
