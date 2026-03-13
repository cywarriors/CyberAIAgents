"""LearnFromReleaseNode – process analyst feedback for model tuning (FR-10)."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def learn_from_release(state: dict[str, Any]) -> dict[str, Any]:
    """Collect analyst release decisions and feedback for model improvement.

    Implements FR-10 (false-positive review and analyst-authorized release).
    """
    feedback_queue: list[dict] = state.get("feedback_queue", [])
    verdicts: list[dict] = state.get("verdicts", [])

    logger.info(
        "learn_from_release",
        verdicts_count=len(verdicts),
        pending_feedback=len(feedback_queue),
    )

    # In production, this node would:
    # 1. Persist verdicts to PostgreSQL for historical analysis
    # 2. Process analyst release decisions from the quarantine queue
    # 3. Update model weights based on TP/FP feedback
    # 4. Trigger retraining jobs if FP rate exceeds threshold

    # For now, log statistics
    action_counts: dict[str, int] = {}
    for v in verdicts:
        action = v.get("action", "allow")
        action_counts[action] = action_counts.get(action, 0) + 1

    logger.info(
        "verdict_statistics",
        total=len(verdicts),
        **action_counts,
    )

    return {"feedback_queue": feedback_queue}
