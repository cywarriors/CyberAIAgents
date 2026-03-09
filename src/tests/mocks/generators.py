"""Mock telemetry generators for testing.

Produces schema-compliant raw events that exercise every node in the
detection pipeline. Events cover both benign baseline traffic and
malicious scenarios mapped to MITRE ATT&CK technique IDs.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RNG = random.Random(42)  # deterministic by default

_INTERNAL_IPS = ["10.0.1.10", "10.0.1.20", "10.0.2.30", "10.0.3.40", "192.168.1.100"]
_EXTERNAL_IPS = ["203.0.113.55", "198.51.100.12", "192.0.2.77", "185.220.100.240"]
_USERS = ["alice", "bob", "charlie", "dave", "eve"]
_HOSTS = ["ws-001", "ws-002", "srv-db-01", "srv-web-01", "srv-app-01"]
_DEPARTMENTS = ["Engineering", "Finance", "HR", "IT", "Marketing"]
_DOMAINS = ["example.com", "legit-cdn.com", "updates.corp.local"]
_SUSPICIOUS_DOMAINS = [
    "c2-dropper.evil.xyz",
    "data-exfil-tunnel.bad.co",
    "a]" * 35 + ".evil.io",  # 70-char domain for DNS tunnelling rule
]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Benign (baseline) generators
# ---------------------------------------------------------------------------


def generate_benign_auth_event() -> dict[str, Any]:
    """Normal successful login."""
    return {
        "source": "siem",
        "source_type": "auth",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "authentication",
            "action": "login_success",
            "outcome": "success",
            "user_name": _RNG.choice(_USERS),
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "host_name": _RNG.choice(_HOSTS),
            "attempt_count": 1,
            "geo_country": "US",
            "expected_country": "US",
        },
    }


def generate_benign_network_event() -> dict[str, Any]:
    """Normal outbound network traffic."""
    return {
        "source": "firewall",
        "source_type": "network",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "network",
            "action": "allow",
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "dst_ip": _RNG.choice(_EXTERNAL_IPS),
            "host_name": _RNG.choice(_HOSTS),
            "bytes_out": _RNG.randint(100, 50_000),
            "protocol": "HTTPS",
        },
    }


def generate_benign_dns_event() -> dict[str, Any]:
    """Normal DNS query."""
    return {
        "source": "dns",
        "source_type": "dns",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "dns",
            "action": "query",
            "domain": _RNG.choice(_DOMAINS),
            "host_name": _RNG.choice(_HOSTS),
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "query_count": _RNG.randint(1, 30),
        },
    }


def generate_benign_process_event() -> dict[str, Any]:
    """Normal process creation."""
    return {
        "source": "edr",
        "source_type": "endpoint",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "process",
            "action": "process_create",
            "host_name": _RNG.choice(_HOSTS),
            "process_name": "notepad.exe",
            "command_line": "notepad.exe readme.txt",
            "user_name": _RNG.choice(_USERS),
        },
    }


# ---------------------------------------------------------------------------
# Attack-scenario generators (mapped to MITRE ATT&CK)
# ---------------------------------------------------------------------------


def generate_brute_force_event() -> dict[str, Any]:
    """T1110 – Brute Force: excessive failed logins."""
    return {
        "source": "siem",
        "source_type": "auth",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "authentication",
            "action": "login_failure",
            "outcome": "failure",
            "user_name": _RNG.choice(_USERS),
            "src_ip": _RNG.choice(_EXTERNAL_IPS),
            "host_name": _RNG.choice(_HOSTS),
            "attempt_count": _RNG.randint(8, 50),
            "geo_country": "US",
            "expected_country": "US",
        },
    }


def generate_impossible_travel_event() -> dict[str, Any]:
    """T1078 – Valid Accounts: login from unexpected country."""
    user = _RNG.choice(_USERS)
    return {
        "source": "siem",
        "source_type": "auth",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "authentication",
            "action": "login_success",
            "outcome": "success",
            "user_name": user,
            "src_ip": "185.220.100.240",
            "host_name": _RNG.choice(_HOSTS),
            "attempt_count": 1,
            "geo_country": "RU",
            "expected_country": "US",
        },
    }


def generate_data_exfil_event() -> dict[str, Any]:
    """T1041 – Exfiltration Over C2 Channel."""
    return {
        "source": "firewall",
        "source_type": "network",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "network",
            "action": "allow",
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "dst_ip": _RNG.choice(_EXTERNAL_IPS),
            "host_name": _RNG.choice(_HOSTS),
            "bytes_out": _RNG.randint(600_000, 5_000_000),
            "protocol": "HTTPS",
        },
    }


def generate_dns_tunnelling_event() -> dict[str, Any]:
    """T1071.004 – DNS Tunnelling."""
    return {
        "source": "dns",
        "source_type": "dns",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "dns",
            "action": "query",
            "domain": _RNG.choice(_SUSPICIOUS_DOMAINS),
            "host_name": _RNG.choice(_HOSTS),
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "query_count": _RNG.randint(150, 500),
        },
    }


def generate_privilege_escalation_event() -> dict[str, Any]:
    """T1078.003 – Unexpected admin role assumption."""
    return {
        "source": "cloud",
        "source_type": "iam",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "iam",
            "action": "AssumeRole",
            "user_name": _RNG.choice(_USERS),
            "host_name": "aws-account-prod",
            "src_ip": _RNG.choice(_INTERNAL_IPS),
        },
    }


def generate_lateral_movement_event() -> dict[str, Any]:
    """T1021 – Internal remote service (RDP/SSH)."""
    return {
        "source": "firewall",
        "source_type": "network",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "network",
            "action": "rdp_session",
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "dst_ip": _RNG.choice(_INTERNAL_IPS),
            "host_name": _RNG.choice(_HOSTS),
            "internal": True,
        },
    }


def generate_malware_execution_event() -> dict[str, Any]:
    """T1059 – Suspicious encoded command execution."""
    return {
        "source": "edr",
        "source_type": "endpoint",
        "timestamp": _ts(),
        "raw_payload": {
            "event_id": _event_id(),
            "category": "process",
            "action": "process_create",
            "host_name": _RNG.choice(_HOSTS),
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoA...",
            "user_name": _RNG.choice(_USERS),
        },
    }


# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------

_BENIGN_GENERATORS = [
    generate_benign_auth_event,
    generate_benign_network_event,
    generate_benign_dns_event,
    generate_benign_process_event,
]

_ATTACK_GENERATORS = [
    generate_brute_force_event,
    generate_impossible_travel_event,
    generate_data_exfil_event,
    generate_dns_tunnelling_event,
    generate_privilege_escalation_event,
    generate_lateral_movement_event,
    generate_malware_execution_event,
]


def generate_mixed_batch(
    total: int = 100,
    attack_ratio: float = 0.2,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Generate a batch mixing benign and attack events.

    Args:
        total: Total number of events.
        attack_ratio: Fraction of events that should be attacks (0–1).
        seed: Optional RNG seed for reproducibility.
    """
    rng = random.Random(seed) if seed is not None else _RNG
    n_attack = int(total * attack_ratio)
    n_benign = total - n_attack

    events: list[dict[str, Any]] = []
    for _ in range(n_benign):
        gen = rng.choice(_BENIGN_GENERATORS)
        events.append(gen())
    for _ in range(n_attack):
        gen = rng.choice(_ATTACK_GENERATORS)
        events.append(gen())

    rng.shuffle(events)
    return events


def generate_all_attack_scenarios() -> list[dict[str, Any]]:
    """One event per attack scenario — useful for detection coverage testing."""
    return [gen() for gen in _ATTACK_GENERATORS]
