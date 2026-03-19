"""In-memory data store for the Deception Honeypot Agent BFF API."""
from __future__ import annotations

import threading
from functools import lru_cache
from typing import Any


class InMemoryStore:
    """Thread-safe in-memory store for honeypot data."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._decoys: list[dict] = []
        self._interactions: list[dict] = []
        self._alerts: list[dict] = []
        self._profiles: list[dict] = []
        self._coverage: dict = {}

    # ------------------------------------------------------------------
    # Decoys
    # ------------------------------------------------------------------
    def add_decoys(self, decoys: list[dict]) -> None:
        with self._lock:
            existing_ids = {d.get("decoy_id") for d in self._decoys}
            for d in decoys:
                if d.get("decoy_id") not in existing_ids:
                    self._decoys.append(d)
                    existing_ids.add(d.get("decoy_id"))

    def get_decoys(self) -> list[dict]:
        with self._lock:
            return list(self._decoys)

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------
    def add_interactions(self, interactions: list[dict]) -> None:
        with self._lock:
            existing_ids = {i.get("interaction_id") for i in self._interactions}
            for i in interactions:
                if i.get("interaction_id") not in existing_ids:
                    self._interactions.append(i)
                    existing_ids.add(i.get("interaction_id"))

    def get_interactions(self, limit: int = 100, offset: int = 0) -> list[dict]:
        with self._lock:
            return list(self._interactions)[offset : offset + limit]

    def count_interactions(self) -> int:
        with self._lock:
            return len(self._interactions)

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def add_alerts(self, alerts: list[dict]) -> None:
        with self._lock:
            existing_ids = {a.get("alert_id") for a in self._alerts}
            for a in alerts:
                if a.get("alert_id") not in existing_ids:
                    self._alerts.append(a)
                    existing_ids.add(a.get("alert_id"))

    def get_alerts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        with self._lock:
            return list(self._alerts)[offset : offset + limit]

    def count_alerts(self) -> int:
        with self._lock:
            return len(self._alerts)

    # ------------------------------------------------------------------
    # Attacker profiles
    # ------------------------------------------------------------------
    def add_profile(self, profile: dict) -> None:
        with self._lock:
            existing_ips = {p.get("source_ip") for p in self._profiles}
            if profile.get("source_ip") not in existing_ips:
                self._profiles.append(profile)

    def get_profiles(self) -> list[dict]:
        with self._lock:
            return list(self._profiles)

    # ------------------------------------------------------------------
    # Coverage
    # ------------------------------------------------------------------
    def set_coverage(self, assessment: dict) -> None:
        with self._lock:
            self._coverage = dict(assessment)

    def get_coverage(self) -> dict:
        with self._lock:
            return dict(self._coverage)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "decoy_count": len(self._decoys),
                "interaction_count": len(self._interactions),
                "alert_count": len(self._alerts),
                "profile_count": len(self._profiles),
                "coverage_percent": self._coverage.get("coverage_percent", 0.0),
            }


@lru_cache(maxsize=1)
def get_data_store() -> InMemoryStore:
    return InMemoryStore()
