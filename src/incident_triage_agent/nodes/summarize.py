"""GenerateSummaryNode – create structured triage summary with key findings (§12.2, FR-05, FR-06)."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Classification mapping based on MITRE technique IDs
_TECHNIQUE_CLASSIFICATION: dict[str, str] = {
    "T1059": "malware",
    "T1059.001": "malware",
    "T1059.003": "malware",
    "T1566": "phishing",
    "T1566.001": "phishing",
    "T1566.002": "phishing",
    "T1110": "credential_abuse",
    "T1110.001": "credential_abuse",
    "T1078": "credential_abuse",
    "T1078.003": "privilege_escalation",
    "T1548": "privilege_escalation",
    "T1041": "data_exfiltration",
    "T1048": "data_exfiltration",
    "T1071": "command_and_control",
    "T1071.004": "command_and_control",
    "T1021": "lateral_movement",
    "T1021.001": "lateral_movement",
    "T1486": "ransomware",
    "T1498": "denial_of_service",
    "T1499": "denial_of_service",
}

# Severity keywords for insider threat detection
_INSIDER_SIGNALS = {"after_hours", "unusual_volume", "terminated", "departing"}


def _classify_incident(
    alerts: list[dict],
    entity_context: list[dict],
    correlations: list[dict],
) -> str:
    """Propose initial incident classification based on techniques and context (FR-05)."""
    # Collect all MITRE techniques
    all_techniques: list[str] = []
    for alert in alerts:
        all_techniques.extend(alert.get("mitre_technique_ids", []))

    # Count classification votes
    votes: dict[str, int] = {}
    for technique in all_techniques:
        classification = _TECHNIQUE_CLASSIFICATION.get(technique)
        if classification:
            votes[classification] = votes.get(classification, 0) + 1

    # Check for insider threat signals in evidence
    for alert in alerts:
        desc = str(alert.get("description", "")).lower()
        for ev in alert.get("evidence", []):
            desc += " " + str(ev).lower()
        if any(signal in desc for signal in _INSIDER_SIGNALS):
            votes["insider_threat"] = votes.get("insider_threat", 0) + 2

    # Privileged user actions may indicate insider threat
    for entity in entity_context:
        if entity.get("is_privileged") and entity.get("entity_type") == "user":
            # Privileged actions in unusual context
            votes["insider_threat"] = votes.get("insider_threat", 0) + 1

    if not votes:
        return "unknown"

    return max(votes, key=lambda k: votes[k])


def _generate_triage_text(
    alerts: list[dict],
    entity_context: list[dict],
    correlations: list[dict],
    priority_score: dict | None,
    classification: str,
) -> str:
    """Generate analyst-ready structured triage summary (FR-06)."""
    parts: list[str] = []

    # Header
    priority = priority_score.get("priority", "P3") if priority_score else "P3"
    confidence = priority_score.get("confidence", 50) if priority_score else 50
    parts.append(
        f"INCIDENT TRIAGE SUMMARY [{priority}] – Classification: {classification.upper()}"
    )
    parts.append(f"Confidence: {confidence}%  |  Alerts: {len(alerts)}")
    parts.append("")

    # Key findings
    parts.append("KEY FINDINGS:")
    all_techniques = set()
    all_tactics = set()
    descriptions = []
    for alert in alerts:
        all_techniques.update(alert.get("mitre_technique_ids", []))
        all_tactics.update(alert.get("mitre_tactics", []))
        desc = alert.get("description", "")
        if desc:
            descriptions.append(f"  - {desc[:200]}")

    if all_tactics:
        parts.append(f"  ATT&CK Tactics: {', '.join(sorted(all_tactics))}")
    if all_techniques:
        parts.append(f"  ATT&CK Techniques: {', '.join(sorted(all_techniques))}")
    parts.extend(descriptions[:5])
    parts.append("")

    # Affected entities
    parts.append("AFFECTED ENTITIES:")
    for entity in entity_context[:10]:
        etype = entity.get("entity_type", "unknown")
        eid = entity.get("entity_id", "unknown")
        quality = entity.get("enrichment_quality", "unknown")
        detail_parts = [f"  [{etype}] {eid}"]
        if etype == "user":
            role = entity.get("user_role", "")
            dept = entity.get("user_department", "")
            priv = "PRIVILEGED" if entity.get("is_privileged") else ""
            detail_parts.append(f"role={role}, dept={dept} {priv}".strip())
        elif etype == "host":
            crit = entity.get("asset_criticality", "low")
            vulns = entity.get("open_vuln_count", 0)
            detail_parts.append(f"criticality={crit}, open_vulns={vulns}")
        elif etype == "ip":
            geo = entity.get("geo_country", "")
            detail_parts.append(f"geo={geo}")
        if quality != "complete":
            detail_parts.append(f"[ENRICHMENT: {quality}]")
        parts.append(" | ".join(detail_parts))
    parts.append("")

    # Correlation
    if correlations:
        parts.append("CORRELATION:")
        for group in correlations[:3]:
            reason = group.get("correlation_reason", "")
            n_alerts = len(group.get("alert_ids", []))
            chain = " → ".join(group.get("attack_chain", []))
            parts.append(f"  Group ({n_alerts} alerts): {reason}")
            if chain:
                parts.append(f"  Attack chain: {chain}")
        parts.append("")

    # Score breakdown
    if priority_score and priority_score.get("components"):
        parts.append("PRIORITY SCORE BREAKDOWN:")
        for component, value in priority_score["components"].items():
            parts.append(f"  {component}: {value:.0f}")

    return "\n".join(parts)


def generate_summary(state: dict[str, Any]) -> dict[str, Any]:
    """
    Classify the incident and generate structured triage summary (FR-05, FR-06).
    """
    raw_alerts: list[dict] = state.get("raw_alerts", [])
    entity_context: list[dict] = state.get("entity_context", [])
    correlations: list[dict] = state.get("correlations", [])
    priority_scores: list[dict] = state.get("priority_scores", [])

    if not raw_alerts:
        return {"triage_summaries": [], "classifications": []}

    # Use first priority score as primary
    primary_score = priority_scores[0] if priority_scores else None

    classification = _classify_incident(raw_alerts, entity_context, correlations)
    summary_text = _generate_triage_text(
        raw_alerts, entity_context, correlations, primary_score, classification
    )

    triage_summaries = [{
        "summary_id": f"sum-{uuid.uuid4().hex[:12]}",
        "text": summary_text,
        "classification": classification,
        "alert_count": len(raw_alerts),
    }]

    classifications = [{
        "classification": classification,
        "confidence": primary_score.get("confidence", 50) if primary_score else 50,
    }]

    logger.info(
        "generate_summary",
        classification=classification,
        summary_length=len(summary_text),
    )
    return {"triage_summaries": triage_summaries, "classifications": classifications}
