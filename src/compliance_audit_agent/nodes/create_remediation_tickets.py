"""CreateRemediationTicketsNode – open ITSM tickets for identified gaps (FR-09)."""

from __future__ import annotations

from typing import Any

import structlog

from compliance_audit_agent.config import get_settings
from compliance_audit_agent.integrations.itsm import ITSMConnector

log = structlog.get_logger()

_SEVERITY_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
}


def _s(state: Any, key: str, default: Any) -> Any:
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def create_remediation_tickets(state: Any) -> dict[str, Any]:
    """FR-09: Create ITSM tickets for each identified compliance gap."""
    s = get_settings()
    gaps = _s(state, "gaps", [])

    if not s.itsm_api_url or not gaps:
        log.info("create_remediation_tickets.skipped", reason="no_itsm_url_or_gaps")
        return {"remediation_tickets": []}

    itsm = ITSMConnector(base_url=s.itsm_api_url, api_key=s.itsm_api_key)
    tickets: list[dict[str, Any]] = []

    for gap in gaps:
        try:
            priority = _SEVERITY_PRIORITY.get(gap.get("severity", "medium"), "P3")
            ticket_id = itsm.create_ticket(
                project=s.itsm_project,
                title=f"[Compliance Gap] {gap['framework']}: {gap['control_id']}",
                description=gap.get("description", ""),
                priority=priority,
                metadata={
                    "gap_id": gap["gap_id"],
                    "framework": gap["framework"],
                    "control_id": gap["control_id"],
                    "remediation_guidance": gap.get("remediation_guidance", ""),
                },
            )
            tickets.append({
                "ticket_id": ticket_id,
                "gap_id": gap["gap_id"],
                "control_id": gap["control_id"],
                "framework": gap["framework"],
                "priority": priority,
            })
        except Exception as exc:
            log.warning("create_remediation_tickets.error", gap_id=gap.get("gap_id"), error=str(exc))

    log.info("create_remediation_tickets.done", tickets=len(tickets))
    return {"remediation_tickets": tickets}
