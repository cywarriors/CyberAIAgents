"""NormalizeSchemaNode – map raw events to OCSF / ECS common schema."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from threat_detection_agent.models.events import EventCategory

logger = structlog.get_logger(__name__)

# Mapping from raw source_type keywords to EventCategory
_CATEGORY_MAP: dict[str, EventCategory] = {
    "auth": EventCategory.AUTHENTICATION,
    "login": EventCategory.AUTHENTICATION,
    "network": EventCategory.NETWORK,
    "firewall": EventCategory.FIREWALL,
    "process": EventCategory.PROCESS,
    "file": EventCategory.FILE,
    "dns": EventCategory.DNS,
    "cloud": EventCategory.CLOUD_AUDIT,
    "iam": EventCategory.IAM,
    "endpoint": EventCategory.ENDPOINT,
    "edr": EventCategory.ENDPOINT,
}


def _infer_category(raw: dict[str, Any]) -> str:
    """Best-effort category inference from raw payload fields."""
    source_type = str(raw.get("source_type", "")).lower()
    category = str(raw.get("category", "")).lower()
    action = str(raw.get("action", "")).lower()

    for token, cat in _CATEGORY_MAP.items():
        if token in source_type or token in category or token in action:
            return cat.value
    return EventCategory.OTHER.value


def normalize_schema(state: dict[str, Any]) -> dict[str, Any]:
    """Normalise every raw event into the common schema."""
    raw_events: list[dict] = state.get("raw_events", [])
    normalized: list[dict] = []

    for raw in raw_events:
        payload = raw.get("raw_payload", raw)
        event_id = payload.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"
        ts_raw = payload.get("timestamp") or raw.get("timestamp")
        try:
            ts = (
                datetime.fromisoformat(str(ts_raw))
                if ts_raw
                else datetime.now(timezone.utc)
            )
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)

        norm = {
            "event_id": event_id,
            "timestamp": ts.isoformat(),
            "category": _infer_category(payload),
            "source": raw.get("source", payload.get("source", "unknown")),
            "source_type": raw.get("source_type", payload.get("source_type", "json")),
            "src_ip": payload.get("src_ip"),
            "dst_ip": payload.get("dst_ip"),
            "user_name": payload.get("user_name") or payload.get("user"),
            "host_name": payload.get("host_name") or payload.get("host"),
            "process_name": payload.get("process_name") or payload.get("process"),
            "domain": payload.get("domain"),
            "action": payload.get("action"),
            "outcome": payload.get("outcome"),
            "asset_criticality": payload.get("asset_criticality"),
            "user_department": payload.get("user_department"),
            "user_role": payload.get("user_role"),
            "raw_snippet": {
                k: v
                for k, v in payload.items()
                if k not in ("_batch_id", "_ingested_at")
            },
        }
        normalized.append(norm)

    logger.info("normalize_schema", normalized_count=len(normalized))
    return {"normalized_events": normalized}
