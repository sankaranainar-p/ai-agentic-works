"""
audit/sink.py — Audit sink interface and implementations for arbitration events.
"""

from __future__ import annotations

from typing import Any, List, Protocol, runtime_checkable


@runtime_checkable
class AuditSink(Protocol):
    """Interface for receiving structured audit events during arbitration."""

    def emit(self, event: Any) -> None:
        """Emit a single structured audit event."""
        ...


class NullAuditSink:
    """Default no-op audit sink."""

    def emit(self, event: Any) -> None:
        pass


class InMemoryAuditSink:
    """In-memory sink useful for testing, debugging, and verification."""

    def __init__(self) -> None:
        self.events: List[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()
