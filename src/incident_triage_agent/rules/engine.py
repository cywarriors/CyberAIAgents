"""Correlation rules engine – evaluates alert pairs against grouping rules (FR-11)."""

from __future__ import annotations

from typing import Any, Callable

import structlog

from incident_triage_agent.rules.correlation_rules import BASELINE_CORRELATION_RULES

logger = structlog.get_logger(__name__)


class CorrelationEngine:
    """Configurable correlation rule execution engine."""

    def __init__(self) -> None:
        self._rules: list[Callable[[dict[str, Any], dict[str, Any]], dict | None]] = list(
            BASELINE_CORRELATION_RULES
        )
        self._disabled_rule_ids: set[str] = set()

    def add_rule(
        self, rule_fn: Callable[[dict[str, Any], dict[str, Any]], dict | None]
    ) -> None:
        self._rules.append(rule_fn)

    def disable_rule(self, rule_id: str) -> None:
        self._disabled_rule_ids.add(rule_id)

    def enable_rule(self, rule_id: str) -> None:
        self._disabled_rule_ids.discard(rule_id)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def evaluate_pair(
        self, alert_a: dict[str, Any], alert_b: dict[str, Any]
    ) -> list[dict]:
        """Run all enabled correlation rules against an alert pair."""
        matches: list[dict] = []
        for rule_fn in self._rules:
            try:
                result = rule_fn(alert_a, alert_b)
                if result is None:
                    continue
                if result.get("rule_id") in self._disabled_rule_ids:
                    continue
                matches.append(result)
            except Exception:
                logger.exception("correlation_rule_error", rule=rule_fn.__name__)
        return matches
