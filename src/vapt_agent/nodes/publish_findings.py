"""Node 9 – Publish Findings.

Writes findings to ticketing system, sends notifications, archives results.
Implements FR-14 from SRS-13.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from vapt_agent.integrations.messaging import send_notification
from vapt_agent.integrations.ticketing import create_ticket

logger = structlog.get_logger(__name__)


def publish_findings(state: dict[str, Any]) -> dict[str, Any]:
    """Publish scored findings to ticketing and messaging integrations."""
    risk_scores = state.get("risk_scores", [])
    remediation_items = state.get("remediation_items", [])
    engagement_id = state.get("engagement_id", "unknown")

    # Build remediation lookup
    remed_by_finding: dict[str, dict] = {}
    for r in remediation_items:
        remed_by_finding[r.get("finding_id", "")] = r

    published: list[dict[str, Any]] = []
    for scored in risk_scores:
        fid = scored.get("finding_id", "")
        remed = remed_by_finding.get(fid, {})

        ticket_payload = {
            "title": scored.get("title", ""),
            "description": remed.get("guidance", ""),
            "severity": scored.get("severity", "info"),
            "cve_id": scored.get("cve_id"),
            "asset_id": scored.get("asset_id"),
            "remediation": remed.get("guidance"),
            "engagement_id": engagement_id,
        }

        ticket_id = create_ticket(ticket_payload)

        published.append({
            "finding_id": fid,
            "ticket_id": ticket_id,
            "published_at": datetime.now(timezone.utc).isoformat(),
        })

    # Summary notification
    critical_count = sum(1 for s in risk_scores if s.get("severity") == "critical")
    high_count = sum(1 for s in risk_scores if s.get("severity") == "high")
    send_notification({
        "text": (
            f"VAPT engagement {engagement_id} complete: "
            f"{len(risk_scores)} findings "
            f"({critical_count} critical, {high_count} high)"
        ),
        "severity": "critical" if critical_count else "high" if high_count else "info",
        "engagement_id": engagement_id,
        "findings_count": len(risk_scores),
    })

    logger.info(
        "findings_published",
        engagement_id=engagement_id,
        total=len(published),
        tickets_created=sum(1 for p in published if p.get("ticket_id")),
    )
    return {"published_findings": published}
