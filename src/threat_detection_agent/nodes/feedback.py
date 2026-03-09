"""FeedbackUpdateNode – process analyst feedback and queue retraining data."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def feedback_update(state: dict[str, Any]) -> dict[str, Any]:
    """
    Collect any pending feedback items and log them for the retraining pipeline.

    In production this node would write to a durable feedback store
    (PostgreSQL / object store) and trigger model retraining jobs when
    the approved schedule is reached.
    """
    feedback_queue: list[dict] = state.get("feedback_queue", [])

    for item in feedback_queue:
        logger.info(
            "feedback_received",
            alert_id=item.get("alert_id"),
            verdict=item.get("verdict"),
            analyst=item.get("analyst_id"),
        )

    return {"feedback_queue": feedback_queue}
