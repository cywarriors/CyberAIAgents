"""RuleMatchNode – apply detection rules and tag MITRE ATT&CK IDs."""

from __future__ import annotations

from typing import Any

import structlog

from threat_detection_agent.rules.engine import RulesEngine

logger = structlog.get_logger(__name__)

# Singleton engine – rules are loaded once and reused across batches.
_engine = RulesEngine()


def rule_match(state: dict[str, Any]) -> dict[str, Any]:
    """Run all enabled detection rules against normalised events."""
    normalized_events: list[dict] = state.get("normalized_events", [])
    matches: list[dict] = []

    for event in normalized_events:
        hits = _engine.evaluate(event)
        matches.extend(hits)

    logger.info("rule_match", match_count=len(matches))
    return {"matched_rules": matches}
