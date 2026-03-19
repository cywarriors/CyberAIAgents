from __future__ import annotations
import threading
from functools import lru_cache


class FindingsStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._findings: dict[str, dict] = {}

    def get_finding(self, finding_id: str) -> dict | None:
        with self._lock:
            return self._findings.get(finding_id)

    def save_finding(self, finding_id: str, data: dict) -> None:
        with self._lock:
            self._findings[finding_id] = data

    def get_all(self) -> list[dict]:
        with self._lock:
            return list(self._findings.values())


@lru_cache()
def get_findings_store() -> FindingsStore:
    return FindingsStore()
