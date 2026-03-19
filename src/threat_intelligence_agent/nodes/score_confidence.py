"""Node: Score IOC confidence based on source reliability, age, and corroboration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from threat_intelligence_agent.config import get_settings

logger = structlog.get_logger(__name__)

# Source reliability baselines (0-100)
_SOURCE_RELIABILITY: dict[str, float] = {
    "otx": 65.0,
    "abusech": 70.0,
    "circl": 75.0,
    "commercial": 85.0,
    "isac": 80.0,
    "internal": 90.0,
}


def _age_decay(first_seen: str, max_age_days: int) -> float:
    """Return 1.0 for fresh IOCs, decaying linearly to 0.0 at max_age_days."""
    if not first_seen:
        return 0.5
    try:
        dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days <= 0:
            return 1.0
        return max(0.0, 1.0 - age_days / max_age_days)
    except (ValueError, TypeError):
        return 0.5


def score_confidence(state: dict[str, Any]) -> dict[str, Any]:
    """Compute a 0-100 confidence score for each deduplicated IOC."""
    iocs: list[dict[str, Any]] = state.get("deduplicated_iocs", [])
    settings = get_settings()
    scored: list[dict[str, Any]] = []

    for ioc in iocs:
        sources: list[str] = ioc.get("sources", [])

        # 1. Source reliability (average across all reporting sources)
        reliability_scores = [_SOURCE_RELIABILITY.get(s, 50.0) for s in sources]
        source_rel = sum(reliability_scores) / max(len(reliability_scores), 1)

        # 2. Age decay
        age_factor = _age_decay(ioc.get("first_seen", ""), settings.ioc_max_age_days)

        # 3. Corroboration: number of independent sources
        corroboration_count = len(sources)
        corroboration_bonus = min(corroboration_count * 10, 30)  # max 30-point bonus

        # 4. Historical baseline
        historical = 50.0  # neutral — could be enhanced with persistence layer

        # Weighted composite
        raw = (
            source_rel * settings.confidence_source_weight
            + (age_factor * 100) * settings.confidence_age_weight
            + corroboration_bonus / 30 * 100 * settings.confidence_corroboration_weight
            + historical * settings.confidence_historical_weight
        )
        confidence = round(min(max(raw, 0.0), 100.0), 2)

        parts: list[str] = []
        if source_rel >= 80:
            parts.append("high-reliability source(s)")
        if corroboration_count >= 3:
            parts.append(f"corroborated by {corroboration_count} sources")
        if age_factor < 0.3:
            parts.append("aging indicator")

        scored.append(
            {
                "ioc_id": ioc.get("ioc_id", ""),
                "value": ioc.get("value", ""),
                "ioc_type": ioc.get("ioc_type", ""),
                "confidence": confidence,
                "source_reliability": round(source_rel, 2),
                "age_factor": round(age_factor, 4),
                "corroboration_count": corroboration_count,
                "explanation": "; ".join(parts) if parts else "baseline scoring",
            }
        )

    logger.info("score_confidence.done", count=len(scored))
    return {"confidence_scores": scored}
