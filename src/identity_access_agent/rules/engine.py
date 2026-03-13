"""Identity risk rules engine – configurable rule execution."""

from __future__ import annotations

from typing import Any, Callable

import structlog

logger = structlog.get_logger(__name__)

RuleFunc = Callable[[dict[str, Any]], dict[str, Any] | None]


# ── Baseline Rules ─────────────────────────────────────────────


def _impossible_travel_rule(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag sessions with impossible travel detected."""
    if ctx.get("is_impossible_travel"):
        speed = ctx.get("travel_speed_kmh", 0)
        return {
            "rule_id": "IAM-SESSION-001",
            "rule_name": "Impossible Travel",
            "severity": "high",
            "reason": f"Login from geographically implausible location ({speed:.0f} km/h)",
            "score_adjustment": 30.0,
        }
    return None


def _off_hours_login_rule(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag logins outside normal business hours."""
    if ctx.get("is_off_hours"):
        return {
            "rule_id": "IAM-SESSION-002",
            "rule_name": "Off-Hours Login",
            "severity": "medium",
            "reason": "Login attempt outside normal business hours",
            "score_adjustment": 15.0,
        }
    return None


def _new_device_rule(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag logins from previously unseen devices."""
    if ctx.get("is_new_device"):
        return {
            "rule_id": "IAM-SESSION-003",
            "rule_name": "New Device",
            "severity": "medium",
            "reason": f"Login from unrecognised device: {ctx.get('device_id', 'unknown')}",
            "score_adjustment": 10.0,
        }
    return None


def _brute_force_rule(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag brute force attempts (>=5 failures in window)."""
    failures = ctx.get("failed_login_count_24h", 0)
    if failures >= 5:
        return {
            "rule_id": "IAM-TAKEOVER-001",
            "rule_name": "Brute Force Attempt",
            "severity": "critical" if failures >= 10 else "high",
            "reason": f"{failures} failed login attempts in 24 h",
            "score_adjustment": 25.0 + min(failures, 20) * 1.5,
        }
    return None


def _mfa_fatigue_rule(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag MFA fatigue / prompt-bombing attacks."""
    denied = ctx.get("mfa_denied_count_1h", 0)
    if denied >= 5:
        return {
            "rule_id": "IAM-TAKEOVER-002",
            "rule_name": "MFA Fatigue Attack",
            "severity": "critical",
            "reason": f"{denied} MFA denials in 1 h – possible prompt bombing",
            "score_adjustment": 35.0,
        }
    return None


def _privilege_escalation_rule(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag self-privilege escalation."""
    if ctx.get("is_self_escalation"):
        return {
            "rule_id": "IAM-PRIV-001",
            "rule_name": "Self-Privilege Escalation",
            "severity": "critical",
            "reason": f"User escalated own privileges to {ctx.get('role_name', 'unknown')}",
            "score_adjustment": 40.0,
        }
    return None


def _sod_violation_rule(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag segregation-of-duties violations."""
    conflicts = ctx.get("conflicting_roles", [])
    if conflicts:
        return {
            "rule_id": "IAM-PRIV-002",
            "rule_name": "SoD Violation",
            "severity": "high",
            "reason": f"Conflicting roles held: {', '.join(conflicts[:4])}",
            "score_adjustment": 25.0,
        }
    return None


BASELINE_RULES: list[RuleFunc] = [
    _impossible_travel_rule,
    _off_hours_login_rule,
    _new_device_rule,
    _brute_force_rule,
    _mfa_fatigue_rule,
    _privilege_escalation_rule,
    _sod_violation_rule,
]


# ── Engine ─────────────────────────────────────────────────────


class IdentityRuleEngine:
    """Configurable identity risk rule engine."""

    def __init__(self) -> None:
        self._rules: list[RuleFunc] = list(BASELINE_RULES)
        self._disabled_rule_ids: set[str] = set()

    def add_rule(self, rule_fn: RuleFunc) -> None:
        self._rules.append(rule_fn)

    def disable_rule(self, rule_id: str) -> None:
        self._disabled_rule_ids.add(rule_id)

    def enable_rule(self, rule_id: str) -> None:
        self._disabled_rule_ids.discard(rule_id)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def evaluate(self, identity_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """Run all enabled rules against an identity context."""
        matches: list[dict[str, Any]] = []
        for rule_fn in self._rules:
            try:
                result = rule_fn(identity_ctx)
                if result is None:
                    continue
                if result.get("rule_id") in self._disabled_rule_ids:
                    continue
                matches.append(result)
            except Exception:
                logger.exception("rule_evaluation_error", rule=rule_fn.__name__)
        return matches
