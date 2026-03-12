"""Shared dependencies for the VAPT BFF API (in-memory stores for MVP)."""

from __future__ import annotations

import time
from typing import Any


class InMemoryStore:
    """Thread-safe in-memory data store for BFF MVP.

    In production this would be backed by PostgreSQL / Redis.
    """

    def __init__(self) -> None:
        self.engagements: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, dict[str, Any]] = {}
        self.scans: dict[str, dict[str, Any]] = {}
        self.attack_paths: dict[str, dict[str, Any]] = {}
        self.exploits: dict[str, dict[str, Any]] = {}
        self.reports: dict[str, dict[str, Any]] = {}
        self.compliance_schedules: dict[str, dict[str, Any]] = {}
        self._start_time = time.time()

    @property
    def uptime(self) -> float:
        return time.time() - self._start_time


# Singleton
_store_instance: InMemoryStore | None = None


def get_store() -> InMemoryStore:
    global _store_instance
    if _store_instance is None:
        _store_instance = InMemoryStore()
    return _store_instance
