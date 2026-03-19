"""Node: Process analyst feedback to tune source quality and IOC confidence."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def feedback_loop(state: dict[str, Any]) -> dict[str, Any]:
    """Process any pending analyst feedback.

    Feedback can:
    - Mark IOCs as true-positive / false-positive
    - Deprecate or revoke IOCs
    - Adjust source quality scores
    """
    iocs = state.get("deduplicated_iocs", [])
    scores = state.get("confidence_scores", [])
    # Feedback injected into state before pipeline run (or via API)
    pending_feedback: list[dict[str, Any]] = state.get("feedback_results", [])

    if not pending_feedback:
        logger.info("feedback_loop.no_pending")
        return {"feedback_results": []}

    ioc_map = {i.get("ioc_id"): i for i in iocs}
    score_map = {s["ioc_id"]: s for s in scores}
    processed: list[dict[str, Any]] = []

    for fb in pending_feedback:
        ioc_id = fb.get("ioc_id", "")
        action = fb.get("action", "")  # true_positive | false_positive | deprecate | revoke
        analyst = fb.get("analyst", "unknown")

        ioc = ioc_map.get(ioc_id)
        if not ioc:
            processed.append({"ioc_id": ioc_id, "action": action, "result": "ioc_not_found"})
            continue

        if action == "false_positive":
            ioc["lifecycle"] = "deprecated"
            if ioc_id in score_map:
                score_map[ioc_id]["confidence"] = max(score_map[ioc_id].get("confidence", 0) - 30, 0)
            processed.append({"ioc_id": ioc_id, "action": action, "result": "deprecated", "analyst": analyst})

        elif action == "true_positive":
            ioc["lifecycle"] = "active"
            if ioc_id in score_map:
                score_map[ioc_id]["confidence"] = min(score_map[ioc_id].get("confidence", 0) + 10, 100)
            processed.append({"ioc_id": ioc_id, "action": action, "result": "activated", "analyst": analyst})

        elif action == "deprecate":
            ioc["lifecycle"] = "deprecated"
            processed.append({"ioc_id": ioc_id, "action": action, "result": "deprecated", "analyst": analyst})

        elif action == "revoke":
            ioc["lifecycle"] = "revoked"
            processed.append({"ioc_id": ioc_id, "action": action, "result": "revoked", "analyst": analyst})

        else:
            processed.append({"ioc_id": ioc_id, "action": action, "result": "unknown_action"})

    logger.info("feedback_loop.done", processed=len(processed))
    return {"feedback_results": processed}
