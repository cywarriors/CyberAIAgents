"""In-memory store for compliance score history (drift tracking)."""

from __future__ import annotations

import threading
from functools import lru_cache


class ScoreHistoryStore:
    """Thread-safe in-memory store for compliance score history."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scores: dict[str, float] = {}

    def get_previous_score(self, framework: str) -> float | None:
        with self._lock:
            return self._scores.get(framework)

    def save_score(self, framework: str, score: float) -> None:
        with self._lock:
            self._scores[framework] = score

    def get_all_scores(self) -> dict[str, float]:
        with self._lock:
            return dict(self._scores)

    def reset(self) -> None:
        with self._lock:
            self._scores.clear()


@lru_cache()
def get_store() -> ScoreHistoryStore:
    return ScoreHistoryStore()
