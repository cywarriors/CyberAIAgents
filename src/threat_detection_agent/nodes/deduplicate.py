"""DeduplicateNode – suppress duplicate alerts within time/entity window."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog

from threat_detection_agent.config import get_settings

logger = structlog.get_logger(__name__)

# In-process dedup cache (production would use Redis)
_dedup_cache: dict[str, float] = {}


def _dedup_key(candidate: dict) -> str:
    """Deterministic key from technique IDs + entity IDs."""
    parts = sorted(candidate.get("mitre_technique_ids", [])) + sorted(
        candidate.get("entity_ids", [])
    )
    raw = json.dumps(parts, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def deduplicate(state: dict[str, Any]) -> dict[str, Any]:
    """Drop alert candidates that duplicate a recently published alert."""
    candidates: list[dict] = state.get("alert_candidates", [])
    settings = get_settings()
    window = settings.dedup_window_seconds
    kept: list[dict] = []
    suppressed = 0

    from datetime import datetime, timezone

    now_ts = datetime.now(timezone.utc).timestamp()

    for c in candidates:
        key = _dedup_key(c)
        last_seen = _dedup_cache.get(key)
        if last_seen and (now_ts - last_seen) < window:
            suppressed += 1
            continue
        _dedup_cache[key] = now_ts
        kept.append(c)

    logger.info("deduplicate", kept=len(kept), suppressed=suppressed)
    # Pass kept candidates forward as final_alerts (promoted from candidate)
    return {"alert_candidates": kept}


def reset_dedup_cache() -> None:
    """Clear the in-process cache (for testing)."""
    _dedup_cache.clear()
