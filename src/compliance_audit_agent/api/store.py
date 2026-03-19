"""Shared in-memory data store for API endpoints."""
from __future__ import annotations
import threading
from functools import lru_cache
from typing import Any


class InMemoryStore:
    """Thread-safe in-memory store for API data."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._evidence: list[dict[str, Any]] = []
        self._audit_packs: list[dict[str, Any]] = []
        self._gaps: list[dict[str, Any]] = []
        self._framework_scores: dict[str, Any] = {}
        self._feeds: list[dict[str, Any]] = []

    # ── Evidence ─────────────────────────────────────────────────────────
    def add_evidence(self, items: list[dict[str, Any]]) -> None:
        with self._lock:
            self._evidence.extend(items)

    def get_evidence(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._evidence)

    # ── Audit Packs ──────────────────────────────────────────────────────
    def add_audit_packs(self, packs: list[dict[str, Any]]) -> None:
        with self._lock:
            self._audit_packs.extend(packs)

    def get_audit_packs(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._audit_packs)

    # ── Gaps ─────────────────────────────────────────────────────────────
    def add_gaps(self, gaps: list[dict[str, Any]]) -> None:
        with self._lock:
            self._gaps.extend(gaps)

    def get_gaps(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._gaps)

    # ── Framework Scores ─────────────────────────────────────────────────
    def set_framework_scores(self, scores: dict[str, Any]) -> None:
        with self._lock:
            self._framework_scores.update(scores)

    def get_framework_scores(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._framework_scores)

    # ── Evidence Sources ─────────────────────────────────────────────────
    def add_feed(self, feed: dict[str, Any]) -> None:
        with self._lock:
            self._feeds.append(feed)

    def get_feeds(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._feeds)

    def delete_feed(self, feed_id: str) -> bool:
        with self._lock:
            before = len(self._feeds)
            self._feeds = [f for f in self._feeds if f.get("feed_id") != feed_id]
            return len(self._feeds) < before

    def reset(self) -> None:
        with self._lock:
            self._evidence.clear()
            self._audit_packs.clear()
            self._gaps.clear()
            self._framework_scores.clear()
            self._feeds.clear()


@lru_cache()
def get_data_store() -> InMemoryStore:
    return InMemoryStore()
