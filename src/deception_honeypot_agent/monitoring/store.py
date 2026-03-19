"""In-memory interaction and profile store for deception agent."""
from __future__ import annotations
import threading
from functools import lru_cache


class InteractionStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._profiles: dict[str, dict] = {}

    def get_profile(self, source_ip: str) -> dict | None:
        with self._lock:
            return self._profiles.get(source_ip)

    def save_profile(self, source_ip: str, profile: dict) -> None:
        with self._lock:
            self._profiles[source_ip] = profile

    def get_all_profiles(self) -> list[dict]:
        with self._lock:
            return list(self._profiles.values())

    def clear(self) -> None:
        with self._lock:
            self._profiles.clear()


@lru_cache()
def get_interaction_store() -> InteractionStore:
    return InteractionStore()
