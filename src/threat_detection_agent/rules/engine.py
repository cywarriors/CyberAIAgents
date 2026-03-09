"""Detection rules engine – evaluates events against all enabled rules."""

from __future__ import annotations

from typing import Any, Callable

import structlog

from threat_detection_agent.rules.base_rules import BASELINE_RULES

logger = structlog.get_logger(__name__)


class RulesEngine:
    """Configurable rule execution engine."""

    def __init__(self) -> None:
        self._rules: list[Callable[[dict[str, Any]], dict | None]] = list(BASELINE_RULES)
        self._disabled_rule_ids: set[str] = set()

    # -- Management ----------------------------------------------------------

    def add_rule(self, rule_fn: Callable[[dict[str, Any]], dict | None]) -> None:
        self._rules.append(rule_fn)

    def disable_rule(self, rule_id: str) -> None:
        self._disabled_rule_ids.add(rule_id)

    def enable_rule(self, rule_id: str) -> None:
        self._disabled_rule_ids.discard(rule_id)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    # -- Evaluation ----------------------------------------------------------

    def evaluate(self, event: dict[str, Any]) -> list[dict]:
        """Run all enabled rules against a single normalised event."""
        matches: list[dict] = []
        for rule_fn in self._rules:
            try:
                result = rule_fn(event)
                if result is None:
                    continue
                if result.get("rule_id") in self._disabled_rule_ids:
                    continue
                matches.append(result)
            except Exception:
                logger.exception("rule_execution_error", rule=rule_fn.__name__)
        return matches
