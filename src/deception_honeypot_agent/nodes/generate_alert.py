"""GenerateAlertNode — create high-fidelity SOC alerts."""
from __future__ import annotations
import uuid
import structlog
from datetime import datetime, timezone

log = structlog.get_logger()

_SEVERITY_MAP = {
    "exploit":        "critical",
    "lateral":        "critical",
    "credential_use": "high",
    "scan":           "medium",
    "probe":          "medium",
    "file_access":    "medium",
    "unknown":        "low",
}


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def generate_alert(state) -> dict:
    """Create SOC alerts for each classified honeypot interaction."""
    classified = list(_s(state, "classified_interactions", []))
    ttp_mappings = list(_s(state, "ttp_mappings", []))

    ttp_by_interaction: dict[str, list[dict]] = {}
    for m in ttp_mappings:
        iid = m.get("interaction_id", "")
        ttp_by_interaction.setdefault(iid, []).append(m)

    alerts = []
    for interaction in classified:
        iid = interaction.get("interaction_id", "")
        itype = interaction.get("interaction_type", "unknown")
        severity = _SEVERITY_MAP.get(itype, "low")
        ttps = ttp_by_interaction.get(iid, [])

        alert = {
            "alert_id": str(uuid.uuid4()),
            "severity": severity,
            "interaction_id": iid,
            "source_ip": interaction.get("source_ip", ""),
            "decoy_id": interaction.get("decoy_id", ""),
            "decoy_type": interaction.get("decoy_type", ""),
            "interaction_type": itype,
            "techniques": [t["technique_id"] for t in ttps],
            "tactics": list({t["tactic"] for t in ttps}),
            "title": f"Honeypot {itype.replace('_', ' ').title()} Detected",
            "description": (
                f"Attacker at {interaction.get('source_ip', 'unknown')} "
                f"performed {itype} on {interaction.get('decoy_type', 'decoy')} asset."
            ),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "false_positive": False,
        }
        alerts.append(alert)

    log.info("generate_alert.done", alerts=len(alerts))
    return {"alerts": alerts}
