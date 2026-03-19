"""Source quality tracking engine."""

from __future__ import annotations

from typing import Any


class SourceQualityEngine:
    """Track and score the reliability of intelligence feed sources.

    Each source has a quality score (0-100) that is adjusted by analyst
    feedback on false-positive rates and freshness.
    """

    def __init__(self) -> None:
        self._sources: dict[str, dict[str, Any]] = {}

    def register_source(self, name: str, initial_score: float = 50.0) -> None:
        self._sources[name] = {
            "name": name,
            "quality_score": min(max(initial_score, 0.0), 100.0),
            "total_iocs": 0,
            "false_positives": 0,
            "true_positives": 0,
        }

    def record_true_positive(self, source: str) -> None:
        s = self._sources.get(source)
        if not s:
            return
        s["true_positives"] += 1
        s["total_iocs"] += 1
        s["quality_score"] = min(s["quality_score"] + 1.0, 100.0)

    def record_false_positive(self, source: str) -> None:
        s = self._sources.get(source)
        if not s:
            return
        s["false_positives"] += 1
        s["total_iocs"] += 1
        s["quality_score"] = max(s["quality_score"] - 5.0, 0.0)

    def get_quality_score(self, source: str) -> float:
        s = self._sources.get(source)
        return s["quality_score"] if s else 50.0

    def get_false_positive_rate(self, source: str) -> float:
        s = self._sources.get(source)
        if not s or s["total_iocs"] == 0:
            return 0.0
        return round(s["false_positives"] / s["total_iocs"], 4)

    def get_all_sources(self) -> list[dict[str, Any]]:
        return list(self._sources.values())
