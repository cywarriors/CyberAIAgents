"""Phishing detection rules engine – configurable rule execution."""

from __future__ import annotations

from typing import Any, Callable

import structlog

logger = structlog.get_logger(__name__)

# Type alias for a rule function
RuleFunc = Callable[[dict[str, Any]], dict[str, Any] | None]


# ── Baseline Rules ─────────────────────────────────────────────


def _auth_failure_rule(email_ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag emails with authentication failures."""
    auth = email_ctx.get("auth", {})
    failures = []
    if auth.get("spf_status") == "fail":
        failures.append("SPF")
    if auth.get("dkim_status") == "fail":
        failures.append("DKIM")
    if auth.get("dmarc_status") == "fail":
        failures.append("DMARC")

    if failures:
        return {
            "rule_id": "PHISH-AUTH-001",
            "rule_name": "Authentication Failure",
            "severity": "high" if len(failures) >= 2 else "medium",
            "reason": f"Failed checks: {', '.join(failures)}",
            "score_adjustment": 15.0 * len(failures),
        }
    return None


def _lookalike_domain_rule(email_ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag emails from lookalike domains."""
    auth = email_ctx.get("auth", {})
    if auth.get("is_lookalike_domain"):
        return {
            "rule_id": "PHISH-DOMAIN-001",
            "rule_name": "Lookalike Domain",
            "severity": "high",
            "reason": f"Sender domain resembles: {auth.get('lookalike_target', 'unknown')}",
            "score_adjustment": 30.0,
        }
    return None


def _new_domain_rule(email_ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag emails from newly registered domains."""
    auth = email_ctx.get("auth", {})
    age = auth.get("domain_age_days", -1)
    if 0 <= age < 30:
        return {
            "rule_id": "PHISH-DOMAIN-002",
            "rule_name": "New Domain",
            "severity": "medium",
            "reason": f"Sender domain registered {age} days ago",
            "score_adjustment": 20.0,
        }
    return None


def _credential_harvest_rule(email_ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag emails with credential harvesting indicators."""
    signals = email_ctx.get("content_signals", [])
    for s in signals:
        if s.get("signal_type") == "credential_harvest":
            return {
                "rule_id": "PHISH-CRED-001",
                "rule_name": "Credential Harvesting",
                "severity": "high",
                "reason": f"Detected: {s.get('evidence', '')[:120]}",
                "score_adjustment": 25.0,
            }
    return None


def _malicious_attachment_rule(email_ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag emails with malicious attachments."""
    sandbox = email_ctx.get("sandbox", {})
    for att in sandbox.get("attachment_results", []):
        if att.get("sandbox_verdict") == "malicious":
            return {
                "rule_id": "PHISH-ATTACH-001",
                "rule_name": "Malicious Attachment",
                "severity": "critical",
                "reason": f"Malicious file: {att.get('filename', 'unknown')}",
                "score_adjustment": 40.0,
            }
    return None


def _malicious_url_rule(email_ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag emails containing malicious URLs."""
    sandbox = email_ctx.get("sandbox", {})
    for ur in sandbox.get("url_results", []):
        if ur.get("sandbox_verdict") == "malicious" or ur.get("is_known_phishing"):
            return {
                "rule_id": "PHISH-URL-001",
                "rule_name": "Malicious URL",
                "severity": "critical",
                "reason": f"Malicious URL detected: {ur.get('url', '')[:100]}",
                "score_adjustment": 35.0,
            }
    return None


def _bec_rule(email_ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Flag business email compromise attempts."""
    signals = email_ctx.get("content_signals", [])
    for s in signals:
        if s.get("signal_type") == "business_email_compromise":
            return {
                "rule_id": "PHISH-BEC-001",
                "rule_name": "Business Email Compromise",
                "severity": "critical",
                "reason": f"BEC indicators: {s.get('evidence', '')[:120]}",
                "score_adjustment": 35.0,
            }
    return None


BASELINE_RULES: list[RuleFunc] = [
    _auth_failure_rule,
    _lookalike_domain_rule,
    _new_domain_rule,
    _credential_harvest_rule,
    _malicious_attachment_rule,
    _malicious_url_rule,
    _bec_rule,
]


# ── Engine ─────────────────────────────────────────────────────


class PhishingRuleEngine:
    """Configurable phishing detection rule engine."""

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

    def evaluate(self, email_ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """Run all enabled rules against an email context."""
        matches: list[dict[str, Any]] = []
        for rule_fn in self._rules:
            try:
                result = rule_fn(email_ctx)
                if result is None:
                    continue
                if result.get("rule_id") in self._disabled_rule_ids:
                    continue
                matches.append(result)
            except Exception:
                logger.exception("rule_evaluation_error", rule=rule_fn.__name__)
        return matches
