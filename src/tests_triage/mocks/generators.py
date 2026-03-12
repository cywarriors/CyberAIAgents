"""Production-like mock alert generators for triage testing.

Produces schema-compliant alert objects that simulate output from SRS-01
Threat Detection Agent and EDR systems. Covers both benign and malicious
scenarios mapped to MITRE ATT&CK technique IDs.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RNG = random.Random(42)  # deterministic by default

_INTERNAL_IPS = ["10.0.1.10", "10.0.1.20", "10.0.2.30", "10.0.3.40", "192.168.1.100"]
_EXTERNAL_IPS = ["203.0.113.55", "198.51.100.12", "192.0.2.77", "185.220.100.240"]
_USERS = ["alice", "bob", "charlie", "dave", "eve"]
_PRIVILEGED_USERS = ["admin", "svc-backup", "charlie"]
_HOSTS = ["ws-001", "ws-002", "srv-db-01", "srv-web-01", "srv-app-01"]
_CRITICAL_HOSTS = ["srv-db-01", "dc-01", "vpn-gw-01"]
_DEPARTMENTS = ["Engineering", "Finance", "HR", "IT", "Marketing"]
_DOMAINS = ["example.com", "legit-cdn.com", "updates.corp.local"]
_SUSPICIOUS_DOMAINS = [
    "c2-dropper.evil.xyz",
    "data-exfil-tunnel.bad.co",
    "a]" * 35 + ".evil.io",
]


def _ts(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat()


def _alert_id() -> str:
    return f"alert-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Benign alert generators (low-severity, routine noise)
# ---------------------------------------------------------------------------


def generate_benign_auth_alert() -> dict[str, Any]:
    """Low-severity authentication alert – routine failed login."""
    user = _RNG.choice(_USERS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(),
        "source": "siem",
        "severity": "Low",
        "confidence": 30,
        "mitre_technique_ids": [],
        "mitre_tactics": [],
        "entity_ids": [user, _RNG.choice(_HOSTS)],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": f"Single failed login attempt for user '{user}'",
        "evidence": [{"user_name": user, "action": "login_failure", "attempt_count": 1}],
        "raw_payload": {
            "user_name": user,
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "host_name": _RNG.choice(_HOSTS),
            "action": "login_failure",
            "attempt_count": 1,
        },
    }


def generate_benign_network_alert() -> dict[str, Any]:
    """Info-level network alert – minor traffic anomaly."""
    host = _RNG.choice(_HOSTS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(),
        "source": "siem",
        "severity": "Info",
        "confidence": 20,
        "mitre_technique_ids": [],
        "mitre_tactics": [],
        "entity_ids": [host],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": f"Minor outbound traffic spike from '{host}'",
        "evidence": [{"host_name": host, "bytes_out": 60000}],
        "raw_payload": {
            "host_name": host,
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "bytes_out": 60000,
        },
    }


def generate_benign_process_alert() -> dict[str, Any]:
    """Info-level endpoint alert – legit admin process."""
    host = _RNG.choice(_HOSTS)
    user = _RNG.choice(_USERS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(),
        "source": "edr",
        "severity": "Info",
        "confidence": 15,
        "mitre_technique_ids": [],
        "mitre_tactics": [],
        "entity_ids": [user, host],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": f"Routine admin tool execution on '{host}'",
        "evidence": [{"process_name": "mmc.exe", "user_name": user}],
        "raw_payload": {
            "host_name": host,
            "user_name": user,
            "process_name": "mmc.exe",
        },
    }


# ---------------------------------------------------------------------------
# Attack-scenario alert generators (mapped to MITRE ATT&CK)
# ---------------------------------------------------------------------------


def generate_brute_force_alert() -> dict[str, Any]:
    """T1110 – Brute Force alert: excessive failed logins."""
    user = _RNG.choice(_USERS)
    host = _RNG.choice(_HOSTS)
    src_ip = _RNG.choice(_EXTERNAL_IPS)
    attempts = _RNG.randint(15, 100)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 10)),
        "source": "siem",
        "severity": "High",
        "confidence": 85,
        "mitre_technique_ids": ["T1110"],
        "mitre_tactics": ["Credential Access"],
        "entity_ids": [user, host, src_ip],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}" for _ in range(3)],
        "description": (
            f"Brute-force attack: {attempts} failed login attempts for user '{user}' "
            f"from {src_ip}"
        ),
        "evidence": [
            {"user_name": user, "src_ip": src_ip, "attempt_count": attempts},
            {"host_name": host, "action": "login_failure"},
        ],
        "raw_payload": {
            "user_name": user,
            "src_ip": src_ip,
            "host_name": host,
            "attempt_count": attempts,
            "action": "login_failure",
        },
    }


def generate_impossible_travel_alert() -> dict[str, Any]:
    """T1078 – Valid Accounts: login from anomalous geolocation."""
    user = _RNG.choice(_USERS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 5)),
        "source": "siem",
        "severity": "High",
        "confidence": 80,
        "mitre_technique_ids": ["T1078"],
        "mitre_tactics": ["Initial Access"],
        "entity_ids": [user, "185.220.100.240"],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"Impossible travel: user '{user}' logged in from Russia "
            f"(expected US) within 30 minutes of prior US login"
        ),
        "evidence": [
            {"user_name": user, "geo_country": "RU", "expected_country": "US"},
        ],
        "raw_payload": {
            "user_name": user,
            "src_ip": "185.220.100.240",
            "geo_country": "RU",
            "expected_country": "US",
        },
    }


def generate_data_exfil_alert() -> dict[str, Any]:
    """T1041 – Exfiltration Over C2 Channel."""
    host = _RNG.choice(_HOSTS)
    dst_ip = _RNG.choice(_EXTERNAL_IPS)
    bytes_out = _RNG.randint(1_000_000, 50_000_000)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 15)),
        "source": "siem",
        "severity": "Critical",
        "confidence": 90,
        "mitre_technique_ids": ["T1041"],
        "mitre_tactics": ["Exfiltration"],
        "entity_ids": [host, dst_ip],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"Potential data exfiltration: {bytes_out:,} bytes transferred from "
            f"'{host}' to {dst_ip}"
        ),
        "evidence": [
            {"host_name": host, "dst_ip": dst_ip, "bytes_out": bytes_out},
        ],
        "raw_payload": {
            "host_name": host,
            "src_ip": _RNG.choice(_INTERNAL_IPS),
            "dst_ip": dst_ip,
            "bytes_out": bytes_out,
        },
    }


def generate_dns_tunnelling_alert() -> dict[str, Any]:
    """T1071.004 – DNS Tunnelling C2 communication."""
    host = _RNG.choice(_HOSTS)
    domain = _RNG.choice(_SUSPICIOUS_DOMAINS)
    query_count = _RNG.randint(200, 1000)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 10)),
        "source": "siem",
        "severity": "High",
        "confidence": 75,
        "mitre_technique_ids": ["T1071.004"],
        "mitre_tactics": ["Command and Control"],
        "entity_ids": [host],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"DNS tunnelling suspected: {query_count} queries to '{domain[:40]}...' "
            f"from '{host}'"
        ),
        "evidence": [
            {"host_name": host, "domain": domain, "query_count": query_count},
        ],
        "raw_payload": {
            "host_name": host,
            "domain": domain,
            "query_count": query_count,
        },
    }


def generate_privilege_escalation_alert() -> dict[str, Any]:
    """T1078.003 – Unexpected admin role assumption."""
    user = _RNG.choice(_USERS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 5)),
        "source": "siem",
        "severity": "Critical",
        "confidence": 88,
        "mitre_technique_ids": ["T1078.003"],
        "mitre_tactics": ["Privilege Escalation"],
        "entity_ids": [user, "aws-account-prod"],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"Privilege escalation: user '{user}' assumed admin role on "
            f"production cloud account"
        ),
        "evidence": [
            {"user_name": user, "action": "AssumeRole", "host_name": "aws-account-prod"},
        ],
        "raw_payload": {
            "user_name": user,
            "action": "AssumeRole",
            "host_name": "aws-account-prod",
        },
    }


def generate_lateral_movement_alert() -> dict[str, Any]:
    """T1021 – Internal remote service (RDP/SSH)."""
    src_ip = _RNG.choice(_INTERNAL_IPS)
    dst_ip = _RNG.choice(_INTERNAL_IPS)
    host = _RNG.choice(_HOSTS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 10)),
        "source": "siem",
        "severity": "Medium",
        "confidence": 65,
        "mitre_technique_ids": ["T1021"],
        "mitre_tactics": ["Lateral Movement"],
        "entity_ids": [host, src_ip, dst_ip],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"Lateral movement: RDP session from {src_ip} to {dst_ip} "
            f"on host '{host}'"
        ),
        "evidence": [
            {"src_ip": src_ip, "dst_ip": dst_ip, "action": "rdp_session", "internal": True},
        ],
        "raw_payload": {
            "host_name": host,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "action": "rdp_session",
            "internal": True,
        },
    }


def generate_malware_execution_alert() -> dict[str, Any]:
    """T1059 – Suspicious encoded command execution."""
    host = _RNG.choice(_HOSTS)
    user = _RNG.choice(_USERS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 5)),
        "source": "edr",
        "severity": "High",
        "confidence": 82,
        "mitre_technique_ids": ["T1059"],
        "mitre_tactics": ["Execution"],
        "entity_ids": [user, host],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"Malicious process: powershell.exe launched with encoded arguments "
            f"on host '{host}' by user '{user}'"
        ),
        "evidence": [
            {
                "host_name": host,
                "user_name": user,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgAIAAoA...",
            },
        ],
        "raw_payload": {
            "host_name": host,
            "user_name": user,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoA...",
        },
    }


def generate_insider_threat_alert() -> dict[str, Any]:
    """Insider threat – privileged user accessing sensitive data after hours."""
    user = _RNG.choice(_PRIVILEGED_USERS)
    host = _RNG.choice(_CRITICAL_HOSTS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 5)),
        "source": "siem",
        "severity": "High",
        "confidence": 70,
        "mitre_technique_ids": ["T1078"],
        "mitre_tactics": ["Initial Access", "Credential Access"],
        "entity_ids": [user, host],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"Insider threat indicator: privileged user '{user}' accessed "
            f"critical host '{host}' after_hours with unusual_volume of queries"
        ),
        "evidence": [
            {"user_name": user, "host_name": host, "after_hours": True, "unusual_volume": True},
        ],
        "raw_payload": {
            "user_name": user,
            "host_name": host,
            "action": "data_access",
            "after_hours": True,
        },
    }


def generate_phishing_alert() -> dict[str, Any]:
    """T1566 – Phishing: user clicked malicious link."""
    user = _RNG.choice(_USERS)
    host = _RNG.choice(_HOSTS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(_RNG.randint(0, 5)),
        "source": "edr",
        "severity": "High",
        "confidence": 78,
        "mitre_technique_ids": ["T1566", "T1566.002"],
        "mitre_tactics": ["Initial Access"],
        "entity_ids": [user, host],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
        "description": (
            f"Phishing: user '{user}' clicked malicious link leading to "
            f"credential harvesting page"
        ),
        "evidence": [
            {"user_name": user, "host_name": host, "url": "https://evil-phish.example/login"},
        ],
        "raw_payload": {
            "user_name": user,
            "host_name": host,
            "url": "https://evil-phish.example/login",
        },
    }


def generate_ransomware_alert() -> dict[str, Any]:
    """T1486 – Data Encrypted for Impact (ransomware)."""
    host = _RNG.choice(_CRITICAL_HOSTS)
    user = _RNG.choice(_USERS)
    return {
        "alert_id": _alert_id(),
        "timestamp": _ts(),
        "source": "edr",
        "severity": "Critical",
        "confidence": 95,
        "mitre_technique_ids": ["T1486"],
        "mitre_tactics": ["Impact"],
        "entity_ids": [user, host],
        "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}" for _ in range(5)],
        "description": (
            f"Ransomware activity: mass file encryption detected on "
            f"critical host '{host}'"
        ),
        "evidence": [
            {"host_name": host, "user_name": user, "files_encrypted": 1500},
        ],
        "raw_payload": {
            "host_name": host,
            "user_name": user,
            "action": "file_encrypt",
            "files_encrypted": 1500,
        },
    }


# ---------------------------------------------------------------------------
# Multi-alert attack scenarios (correlated chains)
# ---------------------------------------------------------------------------


def generate_multi_stage_intrusion() -> list[dict[str, Any]]:
    """Multi-stage attack: phishing → credential theft → lateral movement → exfil.

    All alerts share common entities and span multiple ATT&CK tactics for
    correlation testing.
    """
    user = "bob"
    host = "ws-002"
    target_host = "srv-db-01"
    base_time = datetime.now(timezone.utc)

    return [
        {
            "alert_id": _alert_id(),
            "timestamp": (base_time - timedelta(minutes=30)).isoformat(),
            "source": "edr",
            "severity": "High",
            "confidence": 78,
            "mitre_technique_ids": ["T1566"],
            "mitre_tactics": ["Initial Access"],
            "entity_ids": [user, host],
            "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
            "description": f"Phishing: user '{user}' opened malicious attachment on '{host}'",
            "evidence": [{"user_name": user, "host_name": host}],
            "raw_payload": {"user_name": user, "host_name": host},
        },
        {
            "alert_id": _alert_id(),
            "timestamp": (base_time - timedelta(minutes=20)).isoformat(),
            "source": "siem",
            "severity": "High",
            "confidence": 85,
            "mitre_technique_ids": ["T1110"],
            "mitre_tactics": ["Credential Access"],
            "entity_ids": [user, host],
            "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
            "description": f"Credential harvesting on '{host}' targeting user '{user}'",
            "evidence": [{"user_name": user, "host_name": host}],
            "raw_payload": {"user_name": user, "host_name": host},
        },
        {
            "alert_id": _alert_id(),
            "timestamp": (base_time - timedelta(minutes=10)).isoformat(),
            "source": "siem",
            "severity": "Medium",
            "confidence": 65,
            "mitre_technique_ids": ["T1021"],
            "mitre_tactics": ["Lateral Movement"],
            "entity_ids": [user, host, target_host],
            "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
            "description": f"Lateral movement from '{host}' to '{target_host}' by '{user}'",
            "evidence": [{"user_name": user, "src_host": host, "dst_host": target_host}],
            "raw_payload": {"user_name": user, "host_name": host, "dst_host": target_host},
        },
        {
            "alert_id": _alert_id(),
            "timestamp": base_time.isoformat(),
            "source": "siem",
            "severity": "Critical",
            "confidence": 90,
            "mitre_technique_ids": ["T1041"],
            "mitre_tactics": ["Exfiltration"],
            "entity_ids": [target_host, "198.51.100.12"],
            "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
            "description": f"Data exfiltration from '{target_host}' to external IP",
            "evidence": [{"host_name": target_host, "bytes_out": 25_000_000}],
            "raw_payload": {"host_name": target_host, "bytes_out": 25_000_000, "dst_ip": "198.51.100.12"},
        },
    ]


def generate_credential_stuffing_campaign() -> list[dict[str, Any]]:
    """Credential stuffing: multiple users targeted from same IP within minutes."""
    src_ip = "203.0.113.55"
    base_time = datetime.now(timezone.utc)
    alerts = []
    for i, user in enumerate(["alice", "bob", "charlie", "dave"]):
        alerts.append({
            "alert_id": _alert_id(),
            "timestamp": (base_time - timedelta(minutes=i * 2)).isoformat(),
            "source": "siem",
            "severity": "High",
            "confidence": 85,
            "mitre_technique_ids": ["T1110"],
            "mitre_tactics": ["Credential Access"],
            "entity_ids": [user, src_ip],
            "matched_event_ids": [f"evt-{uuid.uuid4().hex[:12]}"],
            "description": f"Brute-force: {_RNG.randint(20, 80)} failed logins for '{user}' from {src_ip}",
            "evidence": [{"user_name": user, "src_ip": src_ip}],
            "raw_payload": {"user_name": user, "src_ip": src_ip, "action": "login_failure"},
        })
    return alerts


# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------

_BENIGN_GENERATORS = [
    generate_benign_auth_alert,
    generate_benign_network_alert,
    generate_benign_process_alert,
]

_ATTACK_GENERATORS = [
    generate_brute_force_alert,
    generate_impossible_travel_alert,
    generate_data_exfil_alert,
    generate_dns_tunnelling_alert,
    generate_privilege_escalation_alert,
    generate_lateral_movement_alert,
    generate_malware_execution_alert,
    generate_insider_threat_alert,
    generate_phishing_alert,
    generate_ransomware_alert,
]


def generate_mixed_alert_batch(
    total: int = 100,
    attack_ratio: float = 0.3,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Generate a batch mixing benign and attack alerts."""
    rng = random.Random(seed) if seed is not None else _RNG
    n_attack = int(total * attack_ratio)
    n_benign = total - n_attack

    alerts: list[dict[str, Any]] = []
    for _ in range(n_benign):
        gen = rng.choice(_BENIGN_GENERATORS)
        alerts.append(gen())
    for _ in range(n_attack):
        gen = rng.choice(_ATTACK_GENERATORS)
        alerts.append(gen())

    rng.shuffle(alerts)
    return alerts


def generate_all_attack_alerts() -> list[dict[str, Any]]:
    """One alert per attack scenario for coverage testing."""
    return [gen() for gen in _ATTACK_GENERATORS]
