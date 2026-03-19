"""Node: Ingest intelligence from configured feed sources."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from threat_intelligence_agent.integrations.osint_feeds import (
    fetch_abusech_feed,
    fetch_circl_taxii,
    fetch_otx_pulses,
)
from threat_intelligence_agent.integrations.commercial_feeds import fetch_commercial_intel
from threat_intelligence_agent.integrations.isac import fetch_isac_intel

logger = structlog.get_logger(__name__)


def ingest_feeds(state: dict[str, Any]) -> dict[str, Any]:
    """Pull intelligence from all configured sources.

    Gracefully degrades — a failing source does not block the pipeline.
    """
    raw_intel: list[dict[str, Any]] = list(state.get("raw_intel", []))
    errors: list[dict[str, Any]] = []

    # If state already contains pre-loaded intel (e.g. injected by tests), skip fetching
    if raw_intel:
        logger.info("ingest_feeds.pre_loaded", count=len(raw_intel))
        return {"raw_intel": raw_intel}

    fetchers: list[tuple[str, Any]] = [
        ("otx", fetch_otx_pulses),
        ("abusech", fetch_abusech_feed),
        ("circl", fetch_circl_taxii),
        ("commercial", fetch_commercial_intel),
        ("isac", fetch_isac_intel),
    ]

    for name, fn in fetchers:
        try:
            records = fn()
            for rec in records:
                rec.setdefault("record_id", f"raw-{uuid.uuid4().hex[:12]}")
                rec.setdefault("source_name", name)
                rec.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            raw_intel.extend(records)
            logger.info("ingest_feeds.source_ok", source=name, count=len(records))
        except Exception as exc:
            logger.warning("ingest_feeds.source_error", source=name, error=str(exc))
            errors.append({"node": "ingest_feeds", "source": name, "error": str(exc)})

    result: dict[str, Any] = {"raw_intel": raw_intel}
    if errors:
        result["processing_errors"] = errors
    return result
