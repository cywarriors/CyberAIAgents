"""FeedbackLearnNode – ingest analyst disposition and queue for model update (§12.2, FR-09)."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def feedback_learn(state: dict[str, Any]) -> dict[str, Any]:
    """
    Collect analyst feedback for scoring model retraining.

    In production this node would write to a durable feedback store
    (PostgreSQL / object store) and trigger model retraining jobs when
    the approved schedule is reached (FR-09).
    """
    feedback_queue: list[dict] = state.get("feedback_queue", [])

    for item in feedback_queue:
        logger.info(
            "feedback_received",
            incident_id=item.get("incident_id"),
            verdict=item.get("verdict"),
            analyst=item.get("analyst_id"),
            corrected_priority=item.get("corrected_priority"),
            corrected_classification=item.get("corrected_classification"),
        )

    return {"feedback_queue": feedback_queue}
