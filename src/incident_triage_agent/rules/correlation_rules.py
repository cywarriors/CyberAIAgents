"""Baseline correlation rules for incident grouping (FR-02, FR-11)."""

from __future__ import annotations

from typing import Any, Callable


def _same_user_rule(alert_a: dict[str, Any], alert_b: dict[str, Any]) -> dict | None:
    """Correlate alerts targeting the same user account."""
    user_a = _extract_user(alert_a)
    user_b = _extract_user(alert_b)
    if user_a and user_b and user_a == user_b:
        return {
            "rule_id": "CORR-USER-001",
            "rule_name": "Same User Entity",
            "reason": f"Both alerts involve user '{user_a}'",
            "shared_entity": user_a,
            "entity_type": "user",
        }
    return None


def _same_host_rule(alert_a: dict[str, Any], alert_b: dict[str, Any]) -> dict | None:
    """Correlate alerts from the same host."""
    host_a = _extract_host(alert_a)
    host_b = _extract_host(alert_b)
    if host_a and host_b and host_a == host_b:
        return {
            "rule_id": "CORR-HOST-001",
            "rule_name": "Same Host Entity",
            "reason": f"Both alerts involve host '{host_a}'",
            "shared_entity": host_a,
            "entity_type": "host",
        }
    return None


def _same_ip_rule(alert_a: dict[str, Any], alert_b: dict[str, Any]) -> dict | None:
    """Correlate alerts sharing a source IP."""
    ips_a = _extract_ips(alert_a)
    ips_b = _extract_ips(alert_b)
    shared = ips_a & ips_b
    if shared:
        ip = next(iter(shared))
        return {
            "rule_id": "CORR-IP-001",
            "rule_name": "Shared Source IP",
            "reason": f"Both alerts share IP '{ip}'",
            "shared_entity": ip,
            "entity_type": "ip",
        }
    return None


def _attack_chain_rule(alert_a: dict[str, Any], alert_b: dict[str, Any]) -> dict | None:
    """Correlate alerts forming an ATT&CK kill-chain progression."""
    tactics_a = set(alert_a.get("mitre_tactics", []))
    tactics_b = set(alert_b.get("mitre_tactics", []))

    if not tactics_a or not tactics_b:
        return None

    # Different tactics suggest attack chain progression
    if tactics_a != tactics_b and (tactics_a | tactics_b):
        chain = sorted(tactics_a | tactics_b)
        return {
            "rule_id": "CORR-CHAIN-001",
            "rule_name": "Attack Chain Progression",
            "reason": f"Alerts span multiple ATT&CK tactics: {', '.join(chain)}",
            "shared_entity": "",
            "entity_type": "attack_chain",
        }
    return None


# --- Helpers ---

def _extract_user(alert: dict[str, Any]) -> str | None:
    """Extract user entity from alert."""
    for eid in alert.get("entity_ids", []):
        if eid and not _looks_like_ip(eid) and not _looks_like_host(eid):
            return eid
    payload = alert.get("raw_payload", {})
    return payload.get("user_name") or payload.get("user")


def _extract_host(alert: dict[str, Any]) -> str | None:
    """Extract host entity from alert."""
    for eid in alert.get("entity_ids", []):
        if _looks_like_host(eid):
            return eid
    payload = alert.get("raw_payload", {})
    return payload.get("host_name") or payload.get("host")


def _extract_ips(alert: dict[str, Any]) -> set[str]:
    """Extract IP addresses from alert."""
    ips: set[str] = set()
    for eid in alert.get("entity_ids", []):
        if _looks_like_ip(eid):
            ips.add(eid)
    payload = alert.get("raw_payload", {})
    for field in ("src_ip", "dst_ip"):
        val = payload.get(field)
        if val:
            ips.add(str(val))
    return ips


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _looks_like_host(s: str) -> bool:
    return "-" in s or s.startswith(("ws-", "srv-", "dc-", "vpn-"))


# --- Public registry ---

BASELINE_CORRELATION_RULES: list[Callable[[dict[str, Any], dict[str, Any]], dict | None]] = [
    _same_user_rule,
    _same_host_rule,
    _same_ip_rule,
    _attack_chain_rule,
]
