from __future__ import annotations
import threading
from functools import lru_cache
from typing import Any


class InMemoryStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._sast: list[dict] = []
        self._secrets: list[dict] = []
        self._sca: list[dict] = []
        self._sboms: list[dict] = []
        self._policy_verdicts: list[dict] = []
        self._scans: list[dict] = []

    def add_sast_findings(self, items: list[dict]) -> None:
        with self._lock:
            self._sast.extend(items)

    def get_sast_findings(self) -> list[dict]:
        with self._lock:
            return list(self._sast)

    def add_secrets_findings(self, items: list[dict]) -> None:
        with self._lock:
            self._secrets.extend(items)

    def get_secrets_findings(self) -> list[dict]:
        with self._lock:
            return list(self._secrets)

    def add_sca_findings(self, items: list[dict]) -> None:
        with self._lock:
            self._sca.extend(items)

    def get_sca_findings(self) -> list[dict]:
        with self._lock:
            return list(self._sca)

    def add_sbom(self, sbom: dict) -> None:
        with self._lock:
            self._sboms.append(sbom)

    def get_sboms(self) -> list[dict]:
        with self._lock:
            return list(self._sboms)

    def add_policy_verdict(self, verdict: dict) -> None:
        with self._lock:
            self._policy_verdicts.append(verdict)

    def get_policy_verdicts(self) -> list[dict]:
        with self._lock:
            return list(self._policy_verdicts)

    def add_scan(self, scan: dict) -> None:
        with self._lock:
            self._scans.append(scan)

    def get_scans(self) -> list[dict]:
        with self._lock:
            return list(self._scans)


@lru_cache()
def get_data_store() -> InMemoryStore:
    return InMemoryStore()
