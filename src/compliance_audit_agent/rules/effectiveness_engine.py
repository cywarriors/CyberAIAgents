"""EffectivenessEngine – score and rate control effectiveness from evidence."""

from __future__ import annotations

from typing import Any


# Scoring weights per evidence source type
_SOURCE_TYPE_WEIGHTS: dict[str, float] = {
    "log_summary": 0.8,
    "access_report": 0.9,
    "config_snapshot": 0.85,
    "scan_result": 0.9,
    "policy_doc": 0.7,
    "vuln_scan": 0.85,
    "audit_trail": 1.0,
}


class EffectivenessEngine:
    """Evaluate control effectiveness based on collected evidence."""

    def evaluate(
        self,
        control_id: str,
        framework: str,
        evidence_list: list[dict[str, Any]],
        threshold_full: float = 85.0,
        threshold_partial: float = 60.0,
    ) -> tuple[str, float]:
        """Return (rating, score_0_to_100)."""
        if not evidence_list:
            return ("not_assessed", 0.0)

        # Base score from evidence weight average
        weights = [_SOURCE_TYPE_WEIGHTS.get(ev.get("source_type", ""), 0.5) for ev in evidence_list]
        raw_score = (sum(weights) / len(weights)) * 100.0

        # Boost for multiple corroborating evidence items (up to +10)
        corroboration_bonus = min(len(evidence_list) - 1, 5) * 2.0
        score = min(raw_score + corroboration_bonus, 100.0)

        if score >= threshold_full:
            rating = "fully_effective"
        elif score >= threshold_partial:
            rating = "partially_effective"
        else:
            rating = "ineffective"

        return (rating, round(score, 2))
