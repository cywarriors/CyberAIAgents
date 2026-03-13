"""ComputeIdentityRiskNode – weighted risk scoring with explainability (FR-05)."""

from __future__ import annotations

from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def _session_anomaly_score(anomalies: list[dict], user_id: str) -> float:
    """Score from session anomalies (impossible travel, off-hours, new device)."""
    user_anomalies = [a for a in anomalies if a.get("user_id") == user_id]
    if not user_anomalies:
        return 0.0
    severity_scores = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0}
    max_score = max(severity_scores.get(a.get("severity", "low"), 25.0) for a in user_anomalies)
    count_bonus = min(25.0, len(user_anomalies) * 8.0)
    return min(100.0, max_score + count_bonus)


def _auth_failure_score(events: list[dict], user_id: str) -> float:
    """Score from failed authentications."""
    user_events = [e for e in events if e.get("user_id") == user_id]
    failures = sum(1 for e in user_events if e.get("outcome") == "failure")
    if failures == 0:
        return 0.0
    return min(100.0, failures * 15.0)


def _privilege_change_score(alerts: list[dict], sod: list[dict], user_id: str) -> float:
    """Score from privilege escalation and SoD violations."""
    user_alerts = [a for a in alerts if a.get("user_id") == user_id]
    user_sod = [v for v in sod if v.get("user_id") == user_id]
    if not user_alerts and not user_sod:
        return 0.0
    severity_map = {"critical": 100.0, "high": 75.0, "medium": 50.0}
    alert_score = max(
        (severity_map.get(a.get("severity", "medium"), 50.0) for a in user_alerts),
        default=0.0,
    )
    sod_score = 60.0 * len(user_sod) if user_sod else 0.0
    return min(100.0, max(alert_score, sod_score))


def _takeover_signal_score(signals: list[dict], user_id: str) -> float:
    """Score from takeover indicators."""
    user_signals = [s for s in signals if s.get("user_id") == user_id]
    if not user_signals:
        return 0.0
    severity_scores = {"critical": 100.0, "high": 80.0, "medium": 50.0, "low": 20.0}
    max_score = max(severity_scores.get(s.get("severity", "medium"), 50.0) for s in user_signals)
    return min(100.0, max_score + min(20.0, len(user_signals) * 5.0))


def _determine_risk_level(score: float, settings: Any) -> str:
    if score >= settings.risk_threshold_critical:
        return "critical"
    if score >= settings.risk_threshold_high:
        return "high"
    if score >= settings.risk_threshold_medium:
        return "medium"
    return "low"


def _build_explanation(
    components: dict[str, float], risk_level: str, user_id: str,
) -> str:
    parts = [f"Identity risk: {risk_level}."]
    for component, score in components.items():
        if score > 0:
            parts.append(f"{component}: {score:.1f}/100.")
    return " ".join(parts)


def compute_identity_risk(state: dict[str, Any]) -> dict[str, Any]:
    """Compute weighted risk scores with full explainability.

    Implements FR-05.
    """
    settings = get_settings()
    auth_events = state.get("raw_auth_events", [])
    anomalies = state.get("session_anomalies", [])
    privilege_alerts = state.get("privilege_alerts", [])
    sod_violations = state.get("sod_violations", [])
    takeover_signals = state.get("takeover_signals", [])
    session_profiles = state.get("session_profiles", [])

    logger.info("compute_identity_risk", profiles=len(session_profiles))

    # Collect all unique user IDs
    user_ids: set[str] = set()
    for p in session_profiles:
        user_ids.add(p.get("user_id", ""))
    for a in privilege_alerts:
        user_ids.add(a.get("user_id", ""))
    for v in sod_violations:
        user_ids.add(v.get("user_id", ""))
    user_ids.discard("")

    risk_scores: list[dict[str, Any]] = []
    for user_id in user_ids:
        profile = next((p for p in session_profiles if p.get("user_id") == user_id), {})
        username = profile.get("username", "")

        session_score = _session_anomaly_score(anomalies, user_id)
        auth_score = _auth_failure_score(auth_events, user_id)
        priv_score = _privilege_change_score(privilege_alerts, sod_violations, user_id)
        takeover_score = _takeover_signal_score(takeover_signals, user_id)
        context_score = 0.0  # Placeholder for endpoint/cloud context enrichment (FR-09)

        composite = (
            session_score * settings.weight_session_anomaly
            + auth_score * settings.weight_auth_failure
            + priv_score * settings.weight_privilege_change
            + takeover_score * settings.weight_takeover_signals
            + context_score * settings.weight_context_enrichment
        )
        composite = min(100.0, round(composite, 2))

        risk_level = _determine_risk_level(composite, settings)

        # Confidence: higher with more signals
        all_indicators = (
            [a for a in anomalies if a.get("user_id") == user_id]
            + [s for s in takeover_signals if s.get("user_id") == user_id]
            + [a for a in privilege_alerts if a.get("user_id") == user_id]
        )
        confidence = min(0.99, 0.5 + 0.05 * len(all_indicators))

        components = {
            "session_anomaly": round(session_score, 2),
            "auth_failure": round(auth_score, 2),
            "privilege_change": round(priv_score, 2),
            "takeover_signals": round(takeover_score, 2),
            "context_enrichment": round(context_score, 2),
        }

        risk_scores.append({
            "user_id": user_id,
            "username": username,
            "risk_score": composite,
            "risk_level": risk_level,
            "confidence": round(confidence, 2),
            "components": components,
            "indicators": [
                {"type": i.get("anomaly_type", i.get("signal_type", i.get("alert_type", ""))),
                 "severity": i.get("severity", ""),
                 "evidence": i.get("evidence", "")}
                for i in all_indicators
            ],
            "explanation": _build_explanation(components, risk_level, user_id),
        })

    return {"risk_scores": risk_scores}
