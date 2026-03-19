"""Node: Deduplicate IOCs across sources, maintaining provenance."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def deduplicate_iocs(state: dict[str, Any]) -> dict[str, Any]:
    """Deduplicate normalised STIX objects by (value, indicator_type).

    Maintains a provenance chain of all sources that reported each IOC and
    tracks first_seen / last_seen timestamps.
    """
    normalized: list[dict[str, Any]] = state.get("normalized_objects", [])

    # key = (value, indicator_type) -> merged record
    seen: dict[tuple[str, str], dict[str, Any]] = {}

    for obj in normalized:
        value = obj.get("value", "").strip()
        ioc_type = obj.get("indicator_type", "")
        if not value:
            continue

        key = (value.lower(), ioc_type)
        source_refs: list[str] = obj.get("source_refs", [])
        timestamp = obj.get("created", "")

        if key in seen:
            existing = seen[key]
            # Merge provenance
            for src in source_refs:
                if src not in existing["sources"]:
                    existing["sources"].append(src)
            existing["provenance"].append(
                {"source": source_refs[0] if source_refs else "unknown", "timestamp": timestamp}
            )
            # Update first/last seen
            if timestamp and (not existing["first_seen"] or timestamp < existing["first_seen"]):
                existing["first_seen"] = timestamp
            if timestamp and (not existing["last_seen"] or timestamp > existing["last_seen"]):
                existing["last_seen"] = timestamp
        else:
            seen[key] = {
                "ioc_id": f"ioc-{uuid.uuid4().hex[:12]}",
                "ioc_type": ioc_type,
                "value": value,
                "sources": list(source_refs),
                "first_seen": timestamp,
                "last_seen": timestamp,
                "provenance": [
                    {"source": source_refs[0] if source_refs else "unknown", "timestamp": timestamp}
                ],
                "lifecycle": "new",
                "tlp": obj.get("tlp", "TLP:GREEN"),
                "stix_id": obj.get("stix_id", ""),
                "labels": obj.get("labels", []),
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "actor": obj.get("actor", ""),
                "campaign": obj.get("campaign", ""),
            }

    deduped = list(seen.values())
    logger.info(
        "deduplicate_iocs.done",
        input_count=len(normalized),
        output_count=len(deduped),
        dedup_ratio=round(1 - len(deduped) / max(len(normalized), 1), 4),
    )
    return {"deduplicated_iocs": deduped}
