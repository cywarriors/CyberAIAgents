"""PublishAlertNode – write alerts to SIEM, ticketing, and notification channels."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from threat_detection_agent.config import get_settings
from threat_detection_agent.integrations.messaging import send_soc_notification
from threat_detection_agent.integrations.siem import publish_to_siem
from threat_detection_agent.integrations.ticketing import create_ticket

logger = structlog.get_logger(__name__)


def publish_alert(state: dict[str, Any]) -> dict[str, Any]:
    """Promote alert candidates to final alerts and publish to downstream systems."""
    candidates: list[dict] = state.get("alert_candidates", [])
    settings = get_settings()
    final_alerts: list[dict] = []

    for candidate in candidates:
        alert = {
            "alert_id": f"alert-{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": candidate.get("severity", "Medium"),
            "confidence": candidate.get("confidence", 50),
            "mitre_technique_ids": candidate.get("mitre_technique_ids", []),
            "mitre_tactics": candidate.get("mitre_tactics", []),
            "source_type": candidate.get("source_type", "unknown"),
            "entity_ids": candidate.get("entity_ids", []),
            "matched_event_ids": candidate.get("matched_event_ids", []),
            "evidence": candidate.get("evidence", []),
            "description": candidate.get("description", ""),
            "published_to": [],
        }

        # Publish to SIEM queue
        try:
            publish_to_siem(alert)
            alert["published_to"].append("siem")
        except Exception:
            logger.exception("publish_to_siem_failed", alert_id=alert["alert_id"])

        # Create ticket
        try:
            create_ticket(alert)
            alert["published_to"].append("ticketing")
        except Exception:
            logger.exception("create_ticket_failed", alert_id=alert["alert_id"])

        # Page SOC for high-severity
        severity = alert.get("severity", "Info")
        if severity in ("Critical", "High"):
            try:
                send_soc_notification(alert)
                alert["published_to"].append("messaging")
            except Exception:
                logger.exception("send_notification_failed", alert_id=alert["alert_id"])

        final_alerts.append(alert)

    logger.info("publish_alert", published_count=len(final_alerts))
    return {"final_alerts": final_alerts}
