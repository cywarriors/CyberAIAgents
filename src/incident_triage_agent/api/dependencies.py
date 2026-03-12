"""Shared dependencies for the Incident Triage BFF API (in-memory store)."""

from __future__ import annotations

import time
from typing import Any


class InMemoryStore:
    """In-memory data store for BFF MVP."""

    def __init__(self) -> None:
        self.incidents: dict[str, dict[str, Any]] = {}
        self.feedback: list[dict[str, Any]] = []
        self.analysts: dict[str, dict[str, Any]] = {}
        self._start_time = time.time()

    @property
    def uptime(self) -> float:
        return time.time() - self._start_time


_store_instance: InMemoryStore | None = None


def get_store() -> InMemoryStore:
    global _store_instance
    if _store_instance is None:
        _store_instance = InMemoryStore()
    return _store_instance
