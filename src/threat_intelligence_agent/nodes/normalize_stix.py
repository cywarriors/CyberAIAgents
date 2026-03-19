"""Node: Normalize raw intelligence records into STIX 2.1-like objects."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_IOC_TYPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("hash_sha256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("hash_sha1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("hash_md5", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("url", re.compile(r"^https?://", re.IGNORECASE)),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("ip", re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")),
    ("domain", re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")),
]


def _detect_ioc_type(value: str) -> str:
    """Heuristic IOC type detection from raw value."""
    for ioc_type, pattern in _IOC_TYPE_PATTERNS:
        if pattern.match(value.strip()):
            return ioc_type
    return "domain"


def _deterministic_stix_id(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    return f"indicator--{digest}"


def normalize_to_stix(state: dict[str, Any]) -> dict[str, Any]:
    """Convert every raw_intel record into a normalised STIX 2.1-like dict."""
    raw_intel: list[dict[str, Any]] = state.get("raw_intel", [])
    normalized: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    now = datetime.now(timezone.utc).isoformat()

    for rec in raw_intel:
        try:
            payload = rec.get("raw_payload", rec)
            indicators: list[str] = payload.get("indicators", [])

            # If the record itself is a single indicator
            if not indicators and payload.get("value"):
                indicators = [payload["value"]]
            if not indicators and rec.get("value"):
                indicators = [rec["value"]]

            source = rec.get("source_name", "unknown")
            tlp = rec.get("tlp", "TLP:GREEN")
            labels = payload.get("labels", [])
            kill_chain = payload.get("kill_chain_phases", [])
            actor = payload.get("actor", "")
            campaign = payload.get("campaign", "")

            for val in indicators:
                val = val.strip()
                if not val:
                    continue
                ioc_type = _detect_ioc_type(val)
                stix_obj: dict[str, Any] = {
                    "stix_id": _deterministic_stix_id(val),
                    "stix_type": "indicator",
                    "indicator_type": ioc_type,
                    "value": val,
                    "labels": labels,
                    "kill_chain_phases": kill_chain,
                    "created": rec.get("timestamp", now),
                    "modified": now,
                    "source_refs": [source],
                    "tlp": tlp,
                }
                if actor:
                    stix_obj["actor"] = actor
                if campaign:
                    stix_obj["campaign"] = campaign
                normalized.append(stix_obj)
        except Exception as exc:
            logger.warning("normalize.error", record_id=rec.get("record_id"), error=str(exc))
            errors.append({"node": "normalize_to_stix", "record_id": rec.get("record_id"), "error": str(exc)})

    logger.info("normalize_to_stix.done", total_stix=len(normalized))
    result: dict[str, Any] = {"normalized_objects": normalized}
    if errors:
        result["processing_errors"] = errors
    return result
