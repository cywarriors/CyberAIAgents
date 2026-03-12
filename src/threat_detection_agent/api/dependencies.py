"""Shared dependencies for the Threat Detection BFF API (in-memory store)."""

from __future__ import annotations

import time
from typing import Any


class InMemoryStore:
    """In-memory data store for BFF MVP."""

    def __init__(self) -> None:
        self.alerts: dict[str, dict[str, Any]] = {}
        self.rules: dict[str, dict[str, Any]] = {}
        self.anomalies: dict[str, dict[str, Any]] = {}
        self.feedback: list[dict[str, Any]] = []
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
