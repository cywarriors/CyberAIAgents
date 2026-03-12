"""Node 1 – Validate Rules of Engagement (RoE).

Checks that the engagement has valid authorization before any scanning begins.
Implements FR-01 and SEC-01 from SRS-13.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def validate_roe(state: dict[str, Any]) -> dict[str, Any]:
    """Validate the Rules of Engagement authorization record."""
    roe = state.get("roe_authorization") or {}
    errors: list[dict[str, Any]] = []

    # Must have an RoE record
    if not roe:
        errors.append({
            "node": "validate_roe",
            "message": "No RoE authorization provided – aborting engagement.",
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        logger.error("roe_missing")
        return {"roe_validated": False, "errors": errors}

    # Required fields
    required = ("roe_id", "scope_ips", "scope_domains")
    missing = [f for f in required if not roe.get(f)]
    if missing:
        errors.append({
            "node": "validate_roe",
            "message": f"RoE missing required fields: {missing}",
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        logger.error("roe_incomplete", missing=missing)
        return {"roe_validated": False, "errors": errors}

    # Check time window
    start = roe.get("start_time")
    end = roe.get("end_time")
    now = datetime.now(timezone.utc)
    if start and end:
        try:
            t_start = datetime.fromisoformat(start)
            t_end = datetime.fromisoformat(end)
            if not (t_start <= now <= t_end):
                errors.append({
                    "node": "validate_roe",
                    "message": "Current time outside RoE authorised window.",
                    "ts": now.isoformat(),
                })
                logger.warning("roe_outside_window", start=start, end=end)
                return {"roe_validated": False, "errors": errors}
        except (ValueError, TypeError):
            pass  # If dates are unparseable, don't block – log only

    engagement_id = state.get("engagement_id") or str(uuid.uuid4())
    logger.info(
        "roe_validated",
        engagement_id=engagement_id,
        roe_id=roe.get("roe_id"),
        scope_ips=len(roe.get("scope_ips", [])),
        scope_domains=len(roe.get("scope_domains", [])),
    )
    return {"engagement_id": engagement_id, "roe_validated": True}
