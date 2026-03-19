"""TrackDriftNode – compare current vs. previous assessment and alert on drift (FR-06)."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from compliance_audit_agent.config import get_settings
from compliance_audit_agent.monitoring.store import get_store

log = structlog.get_logger()


def _s(state: Any, key: str, default: Any) -> Any:
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def track_drift(state: Any) -> dict[str, Any]:
    """FR-06: Detect compliance score drift against previous assessment snapshots."""
    s = get_settings()
    framework_scores = _s(state, "framework_scores", {})
    store = get_store()
    drift_alerts: list[dict[str, Any]] = []

    for framework, current in framework_scores.items():
        current_score = current.get("score", 0.0)
        previous = store.get_previous_score(framework)

        if previous is not None:
            delta = previous - current_score  # positive = regression
            delta_pct = (delta / previous * 100.0) if previous > 0 else 0.0
            if delta_pct >= s.compliance_drift_alert_threshold:
                drift_alerts.append({
                    "alert_id": str(uuid.uuid4()),
                    "framework": framework,
                    "previous_score": previous,
                    "current_score": current_score,
                    "delta_pct": round(delta_pct, 2),
                    "period_days": 7,
                    "detected_at": __import__("datetime").datetime.utcnow().isoformat(),
                })
                log.warning(
                    "track_drift.alert",
                    framework=framework,
                    delta_pct=delta_pct,
                    previous=previous,
                    current=current_score,
                )

        # Persist current score for next run comparison
        store.save_score(framework, current_score)

    log.info("track_drift.done", drift_alerts=len(drift_alerts))
    return {"drift_alerts": drift_alerts}
