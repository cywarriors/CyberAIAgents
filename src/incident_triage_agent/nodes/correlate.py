"""CorrelateIncidentNode – group related alerts by entity, time, and attack chain (§12.2, FR-02)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)

# MITRE ATT&CK kill-chain ordering for attack chain detection
_TACTIC_ORDER = {
    "Reconnaissance": 0,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Defense Evasion": 6,
    "Credential Access": 7,
    "Discovery": 8,
    "Lateral Movement": 9,
    "Collection": 10,
    "Command and Control": 11,
    "Exfiltration": 12,
    "Impact": 13,
}


def _extract_entities(alert: dict[str, Any]) -> set[str]:
    """Extract all entity identifiers from an alert."""
    entities: set[str] = set()
    for eid in alert.get("entity_ids", []):
        if eid:
            entities.add(eid)
    # Also extract from raw_payload
    payload = alert.get("raw_payload", {})
    for field in ("user_name", "user", "host_name", "host", "src_ip", "dst_ip"):
        val = payload.get(field)
        if val:
            entities.add(str(val))
    # From evidence
    for ev in alert.get("evidence", []):
        for field in ("user_name", "host_name", "src_ip", "entity_id"):
            val = ev.get(field)
            if val:
                entities.add(str(val))
    return entities


def _parse_timestamp(alert: dict[str, Any]) -> float:
    """Parse alert timestamp to epoch seconds."""
    ts = alert.get("timestamp")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).timestamp()


def correlate_incident(state: dict[str, Any]) -> dict[str, Any]:
    """
    Group related alerts into correlation groups by:
    1. Shared entities (user, host, IP)
    2. Time window proximity
    3. ATT&CK attack chain progression (FR-02)
    """
    raw_alerts: list[dict] = state.get("raw_alerts", [])
    settings = get_settings()
    window = settings.correlation_window_seconds

    if not raw_alerts:
        return {"correlations": []}

    # Build entity-to-alert index
    entity_to_alerts: dict[str, list[int]] = {}
    alert_entities: list[set[str]] = []
    alert_timestamps: list[float] = []

    for i, alert in enumerate(raw_alerts):
        entities = _extract_entities(alert)
        alert_entities.append(entities)
        alert_timestamps.append(_parse_timestamp(alert))
        for entity in entities:
            entity_to_alerts.setdefault(entity, []).append(i)

    # Union-find for grouping
    parent = list(range(len(raw_alerts)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Merge alerts sharing entities within time window
    for entity, indices in entity_to_alerts.items():
        for i in range(len(indices)):
            for j in range(i + 1, len(indices)):
                ai, aj = indices[i], indices[j]
                if abs(alert_timestamps[ai] - alert_timestamps[aj]) <= window:
                    union(ai, aj)

    # Build groups
    groups: dict[int, list[int]] = {}
    for i in range(len(raw_alerts)):
        root = find(i)
        groups.setdefault(root, []).append(i)

    correlations: list[dict] = []
    for member_indices in groups.values():
        alerts_in_group = [raw_alerts[i] for i in member_indices]
        shared = set()
        for i in member_indices:
            shared |= alert_entities[i]

        # Determine attack chain from MITRE tactics
        all_tactics: list[str] = []
        for a in alerts_in_group:
            all_tactics.extend(a.get("mitre_tactics", []))
        # Sort by kill-chain order
        ordered_tactics = sorted(
            set(all_tactics), key=lambda t: _TACTIC_ORDER.get(t, 99)
        )

        # Time span
        timestamps = [alert_timestamps[i] for i in member_indices]
        time_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

        alert_ids = [a.get("alert_id", "") for a in alerts_in_group]

        reason_parts = []
        if len(shared) > 0:
            reason_parts.append(f"shared entities: {', '.join(sorted(shared)[:5])}")
        if len(ordered_tactics) > 1:
            reason_parts.append(f"attack chain: {' → '.join(ordered_tactics)}")
        if time_span > 0:
            reason_parts.append(f"within {time_span:.0f}s window")

        correlations.append({
            "group_id": f"corr-{uuid.uuid4().hex[:12]}",
            "alert_ids": alert_ids,
            "shared_entities": sorted(shared),
            "attack_chain": ordered_tactics,
            "time_span_seconds": round(time_span, 2),
            "correlation_reason": "; ".join(reason_parts) if reason_parts else "single alert",
        })

    logger.info("correlate_incident", group_count=len(correlations))
    return {"correlations": correlations}
