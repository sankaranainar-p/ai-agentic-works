"""
pre/signals/log_template.py — Minimal Drain-style log template extraction.

This is a simplified, dependency-free version of the Drain log parsing
algorithm (He et al., 2017): tokens are masked when they look like
variable data (numbers, hex/UUID-like tokens, IPs, timestamps, paths with
digits), producing a stable "template" string per log line, plus a short
hash of that template usable as a cluster id. It does not build Drain's
prefix tree; for adapter purposes (grouping RCAEval log lines into
recurring templates) direct masking + hashing is sufficient and easier to
audit than a full streaming implementation.
"""

from __future__ import annotations

import hashlib
import re

_NUMBER_RE = re.compile(r"\b\d+(\.\d+)?\b")
_HEX_ID_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MASK = "<*>"


def mask_variables(message: str) -> str:
    """Replace variable-looking tokens in *message* with a mask token.

    Order matters: UUIDs and IPs before the generic hex/number masks, since
    a UUID also matches the hex-id pattern once dashes are considered word
    boundaries.
    """
    text = message
    text = _UUID_RE.sub(_MASK, text)
    text = _IP_RE.sub(_MASK, text)
    text = _HEX_ID_RE.sub(_MASK, text)
    text = _NUMBER_RE.sub(_MASK, text)
    return text


def template_hash(template: str) -> str:
    """Short stable hash of a template string, usable as a cluster id."""
    return hashlib.sha1(template.encode("utf-8")).hexdigest()[:12]


def extract_template(message: str) -> tuple[str, str]:
    """Return (template, template_hash) for a raw log message."""
    template = mask_variables(str(message))
    return template, template_hash(template)
