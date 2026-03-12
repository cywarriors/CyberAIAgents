"""EnrichEntityNode – fetch user, host, asset, and vulnerability context (§12.2, FR-03)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Simulated enrichment data (in production these come from CMDB/IAM/TI APIs)
_ASSET_CRITICALITY: dict[str, str] = {
    "srv-db-01": "critical",
    "srv-web-01": "high",
    "srv-app-01": "high",
    "ws-001": "medium",
    "ws-002": "medium",
    "dc-01": "critical",
    "vpn-gw-01": "high",
}

_USER_PROFILES: dict[str, dict[str, Any]] = {
    "alice": {"role": "engineer", "department": "Engineering", "is_privileged": False},
    "bob": {"role": "analyst", "department": "Finance", "is_privileged": False},
    "charlie": {"role": "admin", "department": "IT", "is_privileged": True},
    "dave": {"role": "manager", "department": "HR", "is_privileged": False},
    "eve": {"role": "contractor", "department": "Engineering", "is_privileged": False},
    "admin": {"role": "sysadmin", "department": "IT", "is_privileged": True},
    "svc-backup": {"role": "service_account", "department": "IT", "is_privileged": True},
}

_VULN_DATA: dict[str, dict[str, int]] = {
    "srv-db-01": {"open_vulns": 3, "critical_vulns": 1},
    "srv-web-01": {"open_vulns": 7, "critical_vulns": 2},
    "srv-app-01": {"open_vulns": 2, "critical_vulns": 0},
    "ws-001": {"open_vulns": 1, "critical_vulns": 0},
    "ws-002": {"open_vulns": 0, "critical_vulns": 0},
    "dc-01": {"open_vulns": 1, "critical_vulns": 1},
}

_GEO_DATA: dict[str, dict[str, str]] = {
    "10.0.1.10": {"country": "US", "city": "New York"},
    "10.0.1.20": {"country": "US", "city": "San Francisco"},
    "10.0.2.30": {"country": "US", "city": "Chicago"},
    "10.0.3.40": {"country": "US", "city": "Austin"},
    "192.168.1.100": {"country": "US", "city": "Seattle"},
    "203.0.113.55": {"country": "RU", "city": "Moscow"},
    "198.51.100.12": {"country": "CN", "city": "Beijing"},
    "185.220.100.240": {"country": "IR", "city": "Tehran"},
    "192.0.2.77": {"country": "KP", "city": "Pyongyang"},
}


def _build_entity_profile(
    entity_id: str, entity_type: str
) -> dict[str, Any]:
    """Build enriched entity profile from available data sources."""
    now = datetime.now(timezone.utc).isoformat()
    profile: dict[str, Any] = {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "enrichment_quality": "complete",
        "enrichment_timestamp": now,
    }

    if entity_type == "user":
        user_data = _USER_PROFILES.get(entity_id, {})
        if user_data:
            profile.update({
                "user_name": entity_id,
                "user_role": user_data.get("role"),
                "user_department": user_data.get("department"),
                "is_privileged": user_data.get("is_privileged", False),
            })
        else:
            profile["enrichment_quality"] = "partial"

    elif entity_type == "host":
        criticality = _ASSET_CRITICALITY.get(entity_id, "low")
        vuln_data = _VULN_DATA.get(entity_id, {})
        profile.update({
            "host_name": entity_id,
            "asset_criticality": criticality,
            "open_vuln_count": vuln_data.get("open_vulns", 0),
            "critical_vuln_count": vuln_data.get("critical_vulns", 0),
        })
        if entity_id not in _ASSET_CRITICALITY:
            profile["enrichment_quality"] = "partial"

    elif entity_type == "ip":
        geo = _GEO_DATA.get(entity_id, {})
        profile.update({
            "geo_country": geo.get("country"),
            "geo_city": geo.get("city"),
        })
        if not geo:
            profile["enrichment_quality"] = "partial"

    return profile


def _classify_entity(entity_id: str) -> str:
    """Best-effort classification of entity type from identifier format."""
    if entity_id in _USER_PROFILES:
        return "user"
    if entity_id in _ASSET_CRITICALITY:
        return "host"
    # IP-like pattern
    parts = entity_id.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    # Hostname-like
    if "-" in entity_id or entity_id.startswith(("ws-", "srv-", "dc-", "vpn-")):
        return "host"
    return "user"  # Default assumption


def enrich_entity(state: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich all entities referenced in alerts with user, host,
    asset criticality, geo, and vulnerability context (FR-03, FR-12).
    """
    raw_alerts: list[dict] = state.get("raw_alerts", [])

    # Collect unique entities
    all_entities: set[str] = set()
    for alert in raw_alerts:
        for eid in alert.get("entity_ids", []):
            if eid:
                all_entities.add(eid)
        payload = alert.get("raw_payload", {})
        for field in ("user_name", "user", "host_name", "host", "src_ip", "dst_ip"):
            val = payload.get(field)
            if val:
                all_entities.add(str(val))
        for ev in alert.get("evidence", []):
            for field in ("user_name", "host_name", "src_ip", "entity_id"):
                val = ev.get(field)
                if val:
                    all_entities.add(str(val))

    # Build profiles
    entity_profiles: list[dict] = []
    enriched = 0
    partial = 0
    for entity_id in sorted(all_entities):
        entity_type = _classify_entity(entity_id)
        profile = _build_entity_profile(entity_id, entity_type)
        entity_profiles.append(profile)
        if profile["enrichment_quality"] == "complete":
            enriched += 1
        else:
            partial += 1

    total = enriched + partial
    completeness = (enriched / total * 100) if total > 0 else 100.0

    logger.info(
        "enrich_entity",
        total_entities=total,
        enriched=enriched,
        partial=partial,
        completeness_pct=round(completeness, 1),
    )
    return {"entity_context": entity_profiles}
