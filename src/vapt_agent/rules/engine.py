"""VAPT rules engine – evaluate vulnerability rules against scan findings."""

from __future__ import annotations

from typing import Any, Callable

import structlog

logger = structlog.get_logger(__name__)

RuleFunc = Callable[[dict[str, Any]], dict[str, Any] | None]


class VulnRulesEngine:
    """Registry-based vulnerability rules engine.

    Rules are callable ``(finding: dict) -> dict | None``.
    Return a dict with ``rule_id``, ``title``, ``severity`` on match; ``None`` otherwise.
    """

    def __init__(self) -> None:
        self._rules: dict[str, RuleFunc] = {}
        self._disabled: set[str] = set()

    def add(self, rule_id: str, fn: RuleFunc) -> None:
        self._rules[rule_id] = fn

    def disable(self, rule_id: str) -> None:
        self._disabled.add(rule_id)

    def enable(self, rule_id: str) -> None:
        self._disabled.discard(rule_id)

    def evaluate(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for rule_id, fn in self._rules.items():
            if rule_id in self._disabled:
                continue
            try:
                result = fn(finding)
                if result is not None:
                    result.setdefault("rule_id", rule_id)
                    matches.append(result)
            except Exception:
                logger.exception("rule_eval_error", rule_id=rule_id)
        return matches
