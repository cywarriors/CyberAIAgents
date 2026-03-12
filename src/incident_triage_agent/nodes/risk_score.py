"""RiskScoreNode – compute incident priority P1-P4 with configurable weights (§12.2, FR-04)."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)

_SEVERITY_SCORE = {"Critical": 100, "High": 75, "Medium": 50, "Low": 25, "Info": 10}
_CRITICALITY_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25}
_PRIORITY_THRESHOLDS = [(80, "P1"), (60, "P2"), (40, "P3"), (0, "P4")]


def _score_asset_criticality(entity_context: list[dict]) -> float:
    """Score based on highest asset criticality among involved entities."""
    max_score = 0.0
    for entity in entity_context:
        crit = entity.get("asset_criticality", "low")
        max_score = max(max_score, _CRITICALITY_SCORE.get(crit, 25))
    return max_score


def _score_threat_intel(alerts: list[dict]) -> float:
    """Score based on MITRE technique density and known campaign association."""
    all_techniques = set()
    all_tactics = set()
    for alert in alerts:
        all_techniques.update(alert.get("mitre_technique_ids", []))
        all_tactics.update(alert.get("mitre_tactics", []))

    # Multi-stage attack chains score higher
    technique_score = min(len(all_techniques) * 20, 100)
    tactic_score = min(len(all_tactics) * 15, 100)
    return (technique_score + tactic_score) / 2


def _score_user_risk(entity_context: list[dict]) -> float:
    """Score based on user privilege level and role sensitivity."""
    max_score = 0.0
    for entity in entity_context:
        if entity.get("entity_type") != "user":
            continue
        score = 30.0  # baseline
        if entity.get("is_privileged"):
            score = 90.0
        elif entity.get("user_role") in ("admin", "sysadmin", "service_account"):
            score = 80.0
        elif entity.get("user_department") in ("IT", "Finance", "Executive"):
            score = 60.0
        max_score = max(max_score, score)
    return max_score


def _score_alert_severity(alerts: list[dict]) -> float:
    """Score based on highest alert severity."""
    max_score = 0.0
    for alert in alerts:
        sev = alert.get("severity", "Medium")
        max_score = max(max_score, _SEVERITY_SCORE.get(sev, 50))
    return max_score


def _score_historical_accuracy(correlations: list[dict]) -> float:
    """Score based on correlation strength (number of correlated alerts, attack chain depth)."""
    if not correlations:
        return 50.0
    max_score = 0.0
    for group in correlations:
        n_alerts = len(group.get("alert_ids", []))
        chain_depth = len(group.get("attack_chain", []))
        # More correlated alerts and deeper chains = higher confidence
        group_score = min(n_alerts * 15 + chain_depth * 10, 100)
        max_score = max(max_score, group_score)
    return max_score


def _determine_priority(raw_score: float) -> str:
    """Map raw score (0-100) to priority level."""
    for threshold, priority in _PRIORITY_THRESHOLDS:
        if raw_score >= threshold:
            return priority
    return "P4"


def risk_score(state: dict[str, Any]) -> dict[str, Any]:
    """
    Compute incident priority (P1-P4) using configurable weighted formula.
    Produces one priority score per correlation group (FR-04).
    """
    raw_alerts: list[dict] = state.get("raw_alerts", [])
    entity_context: list[dict] = state.get("entity_context", [])
    correlations: list[dict] = state.get("correlations", [])
    settings = get_settings()

    if not correlations:
        # If no correlations, treat all alerts as one group
        correlations = [{
            "group_id": f"corr-{uuid.uuid4().hex[:12]}",
            "alert_ids": [a.get("alert_id", "") for a in raw_alerts],
            "shared_entities": [],
            "attack_chain": [],
        }]

    priority_scores: list[dict] = []

    for group in correlations:
        group_alert_ids = set(group.get("alert_ids", []))
        group_alerts = [a for a in raw_alerts if a.get("alert_id") in group_alert_ids]
        if not group_alerts:
            group_alerts = raw_alerts  # fallback

        # Compute component scores
        asset_score = _score_asset_criticality(entity_context)
        ti_score = _score_threat_intel(group_alerts)
        user_score = _score_user_risk(entity_context)
        severity_score = _score_alert_severity(group_alerts)
        historical_score = _score_historical_accuracy([group])

        # Weighted sum
        raw_score = (
            settings.weight_asset_criticality * asset_score
            + settings.weight_threat_intel * ti_score
            + settings.weight_alert_severity * severity_score
            + settings.weight_user_risk * user_score
            + settings.weight_historical_accuracy * historical_score
        )
        raw_score = min(raw_score, 100.0)

        priority = _determine_priority(raw_score)
        confidence = min(int(raw_score), 100)

        priority_scores.append({
            "group_id": group.get("group_id"),
            "priority": priority,
            "raw_score": round(raw_score, 2),
            "confidence": confidence,
            "components": {
                "asset_criticality": round(asset_score, 2),
                "threat_intel": round(ti_score, 2),
                "user_risk": round(user_score, 2),
                "alert_severity": round(severity_score, 2),
                "historical_accuracy": round(historical_score, 2),
            },
            "explanation": (
                f"Priority {priority} (score={raw_score:.1f}): "
                f"asset={asset_score:.0f}, threat_intel={ti_score:.0f}, "
                f"user_risk={user_score:.0f}, severity={severity_score:.0f}, "
                f"historical={historical_score:.0f}"
            ),
        })

    logger.info("risk_score", scores_computed=len(priority_scores))
    return {"priority_scores": priority_scores}
