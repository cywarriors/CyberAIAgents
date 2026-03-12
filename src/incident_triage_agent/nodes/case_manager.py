"""CreateOrUpdateCaseNode – open/update ITSM ticket with enriched payload (§12.2, FR-08, FR-10)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from incident_triage_agent.config import get_settings
from incident_triage_agent.integrations.messaging import send_soc_notification
from incident_triage_agent.integrations.ticketing import create_ticket

logger = structlog.get_logger(__name__)


def create_or_update_case(state: dict[str, Any]) -> dict[str, Any]:
    """
    Assemble final triaged incidents and publish to ITSM,
    messaging, and downstream systems (FR-08, FR-10).
    """
    raw_alerts: list[dict] = state.get("raw_alerts", [])
    entity_context: list[dict] = state.get("entity_context", [])
    correlations: list[dict] = state.get("correlations", [])
    priority_scores: list[dict] = state.get("priority_scores", [])
    triage_summaries: list[dict] = state.get("triage_summaries", [])
    classifications: list[dict] = state.get("classifications", [])
    recommended_actions: list[dict] = state.get("recommended_actions", [])
    settings = get_settings()

    if not raw_alerts:
        return {"triaged_incidents": [], "case_ids": [], "incident_timeline": []}

    # Use first available values
    primary_score = priority_scores[0] if priority_scores else {}
    primary_summary = triage_summaries[0] if triage_summaries else {}
    primary_classification = (
        classifications[0].get("classification", "unknown") if classifications else "unknown"
    )
    priority = primary_score.get("priority", "P3")
    confidence = primary_score.get("confidence", 50)

    # Determine severity from priority
    severity_map = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}
    severity = severity_map.get(priority, "Medium")

    # Build incident timeline (FR-10)
    timeline: list[dict] = []
    for alert in sorted(raw_alerts, key=lambda a: str(a.get("timestamp", ""))):
        timeline.append({
            "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "event_type": "alert_ingested",
            "alert_id": alert.get("alert_id"),
            "description": alert.get("description", ""),
            "severity": alert.get("severity", "Medium"),
        })
    timeline.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "triage_completed",
        "description": f"Incident triaged as {priority} – {primary_classification}",
    })

    # Collect all MITRE data
    all_techniques: list[str] = []
    all_tactics: list[str] = []
    all_evidence: list[dict] = []
    all_alert_ids: list[str] = []
    for alert in raw_alerts:
        all_techniques.extend(alert.get("mitre_technique_ids", []))
        all_tactics.extend(alert.get("mitre_tactics", []))
        all_evidence.extend(alert.get("evidence", []))
        alert_id = alert.get("alert_id")
        if alert_id:
            all_alert_ids.append(alert_id)

    incident_id = f"inc-{uuid.uuid4().hex[:12]}"
    case_id = f"case-{uuid.uuid4().hex[:12]}"

    incident = {
        "incident_id": incident_id,
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "priority": priority,
        "classification": primary_classification,
        "severity": severity,
        "confidence": confidence,
        "triage_summary": primary_summary.get("text", ""),
        "alert_ids": all_alert_ids,
        "entity_profiles": entity_context,
        "correlation_groups": correlations,
        "recommended_actions": recommended_actions,
        "timeline": timeline,
        "mitre_technique_ids": sorted(set(all_techniques)),
        "mitre_tactics": sorted(set(all_tactics)),
        "evidence": all_evidence,
        "published_to": [],
    }

    # Publish to ticketing
    try:
        create_ticket(incident)
        incident["published_to"].append("ticketing")
    except Exception:
        logger.exception("create_ticket_failed", incident_id=incident_id)

    # Page SOC for P1/P2
    if priority in ("P1", "P2"):
        try:
            send_soc_notification(incident)
            incident["published_to"].append("messaging")
        except Exception:
            logger.exception("send_notification_failed", incident_id=incident_id)

    logger.info(
        "create_or_update_case",
        incident_id=incident_id,
        case_id=case_id,
        priority=priority,
        classification=primary_classification,
    )

    return {
        "triaged_incidents": [incident],
        "case_ids": [{"case_id": case_id, "incident_id": incident_id}],
        "incident_timeline": timeline,
    }
