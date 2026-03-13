"""IngestIdentityEventsNode – parse and normalise auth/MFA/role events (FR-01)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def ingest_identity_events(state: dict[str, Any]) -> dict[str, Any]:
    """Consume raw authentication, MFA and role-change events.

    Implements FR-01.
    """
    raw_auth: list[dict] = state.get("raw_auth_events", [])
    raw_roles: list[dict] = state.get("raw_role_changes", [])
    batch_id = state.get("batch_id") or f"iam-{uuid.uuid4().hex[:12]}"

    logger.info(
        "ingest_identity_events",
        batch_id=batch_id,
        auth_count=len(raw_auth),
        role_count=len(raw_roles),
    )

    normalised_auth: list[dict[str, Any]] = []
    for evt in raw_auth:
        event_id = evt.get("event_id") or f"auth-{uuid.uuid4().hex[:12]}"
        normalised_auth.append({
            "event_id": event_id,
            "user_id": evt.get("user_id", ""),
            "username": evt.get("username", ""),
            "outcome": evt.get("outcome", "success"),
            "mfa_method": evt.get("mfa_method", "none"),
            "mfa_passed": evt.get("mfa_passed", True),
            "source_ip": evt.get("source_ip", ""),
            "geo_latitude": float(evt.get("geo_latitude", 0.0)),
            "geo_longitude": float(evt.get("geo_longitude", 0.0)),
            "geo_city": evt.get("geo_city", ""),
            "geo_country": evt.get("geo_country", ""),
            "device_id": evt.get("device_id", ""),
            "device_type": evt.get("device_type", ""),
            "user_agent": evt.get("user_agent", ""),
            "application": evt.get("application", ""),
            "timestamp": evt.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "_batch_id": batch_id,
        })

    normalised_roles: list[dict[str, Any]] = []
    for evt in raw_roles:
        event_id = evt.get("event_id") or f"role-{uuid.uuid4().hex[:12]}"
        normalised_roles.append({
            "event_id": event_id,
            "user_id": evt.get("user_id", ""),
            "username": evt.get("username", ""),
            "action": evt.get("action", "role_assigned"),
            "role_name": evt.get("role_name", ""),
            "role_risk_level": evt.get("role_risk_level", "low"),
            "changed_by": evt.get("changed_by", ""),
            "justification": evt.get("justification", ""),
            "timestamp": evt.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "_batch_id": batch_id,
        })

    return {
        "batch_id": batch_id,
        "raw_auth_events": normalised_auth,
        "raw_role_changes": normalised_roles,
    }
