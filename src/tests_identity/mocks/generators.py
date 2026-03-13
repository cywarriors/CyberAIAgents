"""Production-like mock event generators for identity access monitoring testing.

Produces schema-compliant auth events and role changes simulating real-world
identity attacks: brute force, impossible travel, MFA fatigue, privilege
escalation, SoD violations, and normal baseline traffic.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

_RNG = random.Random(42)

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

_USERS = [
    {"user_id": "USR-001", "username": "alice.johnson"},
    {"user_id": "USR-002", "username": "bob.smith"},
    {"user_id": "USR-003", "username": "carol.white"},
    {"user_id": "USR-004", "username": "dave.kumar"},
    {"user_id": "USR-005", "username": "eve.chen"},
    {"user_id": "USR-006", "username": "frank.garcia"},
    {"user_id": "USR-007", "username": "grace.kim"},
    {"user_id": "USR-008", "username": "hank.wilson"},
    {"user_id": "USR-009", "username": "irene.lee"},
    {"user_id": "USR-010", "username": "jack.brown"},
]

_DEVICES = [
    {"device_id": "DEV-001", "device_type": "windows_laptop", "user_agent": "Mozilla/5.0 (Windows NT 10.0)"},
    {"device_id": "DEV-002", "device_type": "macbook", "user_agent": "Mozilla/5.0 (Macintosh)"},
    {"device_id": "DEV-003", "device_type": "iphone", "user_agent": "Mozilla/5.0 (iPhone)"},
    {"device_id": "DEV-004", "device_type": "android", "user_agent": "Mozilla/5.0 (Linux; Android)"},
    {"device_id": "DEV-005", "device_type": "linux_workstation", "user_agent": "Mozilla/5.0 (X11; Linux)"},
]

_APPLICATIONS = ["Office365", "VPN", "AWS Console", "GitHub", "Jira", "Salesforce", "SAP ERP"]

# ---------------------------------------------------------------------------
# Locations (IP, lat, lon, city, country)
# ---------------------------------------------------------------------------

_LOCATIONS = [
    {"source_ip": "192.168.1.10", "geo_latitude": 40.7128, "geo_longitude": -74.0060, "geo_city": "New York", "geo_country": "US"},
    {"source_ip": "10.0.1.20", "geo_latitude": 51.5074, "geo_longitude": -0.1278, "geo_city": "London", "geo_country": "GB"},
    {"source_ip": "172.16.0.30", "geo_latitude": 35.6762, "geo_longitude": 139.6503, "geo_city": "Tokyo", "geo_country": "JP"},
    {"source_ip": "10.10.10.40", "geo_latitude": -33.8688, "geo_longitude": 151.2093, "geo_city": "Sydney", "geo_country": "AU"},
    {"source_ip": "192.168.2.50", "geo_latitude": 48.8566, "geo_longitude": 2.3522, "geo_city": "Paris", "geo_country": "FR"},
    {"source_ip": "10.0.0.100", "geo_latitude": 37.7749, "geo_longitude": -122.4194, "geo_city": "San Francisco", "geo_country": "US"},  # VPN IP
    {"source_ip": "172.20.0.60", "geo_latitude": 55.7558, "geo_longitude": 37.6173, "geo_city": "Moscow", "geo_country": "RU"},
    {"source_ip": "192.168.3.70", "geo_latitude": 22.3193, "geo_longitude": 114.1694, "geo_city": "Hong Kong", "geo_country": "HK"},
]

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

_NORMAL_ROLES = ["viewer", "contributor", "editor", "team_member", "analyst"]
_HIGH_RISK_ROLES = ["global_admin", "security_admin", "domain_admin", "exchange_admin", "root", "superadmin"]
_SOD_CONFLICT_PAIRS = [
    ("finance_approver", "finance_requester"),
    ("admin", "auditor"),
    ("developer", "production_deployer"),
    ("hr_admin", "payroll_admin"),
    ("security_admin", "system_admin"),
]

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

_BASE_TIME = datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc)


def _ts(offset_minutes: int = 0) -> str:
    """Generate an ISO timestamp offset from base time."""
    return (_BASE_TIME + timedelta(minutes=offset_minutes)).isoformat()


def _ts_off_hours(offset_minutes: int = 0) -> str:
    """Generate an ISO timestamp during off-hours (03:00 UTC)."""
    base = datetime(2025, 1, 15, 3, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(minutes=offset_minutes)).isoformat()


def _uid() -> str:
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Auth event generators
# ---------------------------------------------------------------------------


def _make_auth_event(
    user: dict[str, str],
    location: dict[str, Any],
    device: dict[str, str],
    outcome: str = "success",
    mfa_method: str = "push",
    mfa_passed: bool = True,
    timestamp: str | None = None,
    application: str | None = None,
) -> dict[str, Any]:
    """Create a single auth event dict."""
    return {
        "event_id": f"auth-{_uid()}",
        "user_id": user["user_id"],
        "username": user["username"],
        "outcome": outcome,
        "mfa_method": mfa_method,
        "mfa_passed": mfa_passed,
        "source_ip": location["source_ip"],
        "geo_latitude": location["geo_latitude"],
        "geo_longitude": location["geo_longitude"],
        "geo_city": location["geo_city"],
        "geo_country": location["geo_country"],
        "device_id": device["device_id"],
        "device_type": device["device_type"],
        "user_agent": device["user_agent"],
        "application": application or _RNG.choice(_APPLICATIONS),
        "timestamp": timestamp or _ts(),
    }


def generate_normal_auth_events(count: int = 10) -> list[dict[str, Any]]:
    """Generate clean, normal authentication events."""
    events = []
    for i in range(count):
        user = _USERS[i % len(_USERS)]
        loc = _LOCATIONS[0]  # Same location
        device = _DEVICES[0]  # Same device
        events.append(_make_auth_event(
            user=user,
            location=loc,
            device=device,
            timestamp=_ts(i * 15),
        ))
    return events


def generate_brute_force_events(
    user: dict[str, str] | None = None,
    failure_count: int = 8,
) -> list[dict[str, Any]]:
    """Generate brute-force attack events (multiple failures for same user)."""
    user = user or _USERS[0]  # alice
    loc = _LOCATIONS[6]  # Moscow
    device = _DEVICES[3]  # Android
    events = []
    for i in range(failure_count):
        events.append(_make_auth_event(
            user=user,
            location=loc,
            device=device,
            outcome="failure",
            mfa_method="none",
            mfa_passed=False,
            timestamp=_ts(i * 2),
        ))
    # One success at the end
    events.append(_make_auth_event(
        user=user,
        location=loc,
        device=device,
        outcome="success",
        timestamp=_ts(failure_count * 2 + 1),
    ))
    return events


def generate_impossible_travel_events(
    user: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate impossible-travel events (NYC then Tokyo 30min later)."""
    user = user or _USERS[1]  # bob
    events = [
        _make_auth_event(
            user=user,
            location=_LOCATIONS[0],  # New York
            device=_DEVICES[0],
            timestamp=_ts(0),
        ),
        _make_auth_event(
            user=user,
            location=_LOCATIONS[2],  # Tokyo (10,800 km away)
            device=_DEVICES[1],
            timestamp=_ts(30),  # 30 minutes later
        ),
    ]
    return events


def generate_mfa_fatigue_events(
    user: dict[str, str] | None = None,
    denial_count: int = 7,
) -> list[dict[str, Any]]:
    """Generate MFA fatigue / push-bombing events."""
    user = user or _USERS[2]  # carol
    loc = _LOCATIONS[4]  # Paris
    device = _DEVICES[2]  # iPhone
    events = []
    for i in range(denial_count):
        events.append(_make_auth_event(
            user=user,
            location=loc,
            device=device,
            outcome="mfa_denied",
            mfa_method="push",
            mfa_passed=False,
            timestamp=_ts(i),
        ))
    return events


def generate_off_hours_events(
    user: dict[str, str] | None = None,
    count: int = 3,
) -> list[dict[str, Any]]:
    """Generate logins outside business hours (03:00 UTC)."""
    user = user or _USERS[3]  # dave
    loc = _LOCATIONS[0]
    device = _DEVICES[0]
    events = []
    for i in range(count):
        events.append(_make_auth_event(
            user=user,
            location=loc,
            device=device,
            timestamp=_ts_off_hours(i * 10),
        ))
    return events


def generate_new_device_events(
    user: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate events from multiple new devices for the same user."""
    user = user or _USERS[4]  # eve
    loc = _LOCATIONS[0]
    events = []
    for i, device in enumerate(_DEVICES[:3]):
        events.append(_make_auth_event(
            user=user,
            location=loc,
            device=device,
            timestamp=_ts(i * 10),
        ))
    return events


def generate_lockout_events(
    user: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate account lockout events."""
    user = user or _USERS[5]  # frank
    loc = _LOCATIONS[1]
    device = _DEVICES[0]
    events = [
        _make_auth_event(user=user, location=loc, device=device, outcome="failure", timestamp=_ts(0)),
        _make_auth_event(user=user, location=loc, device=device, outcome="failure", timestamp=_ts(1)),
        _make_auth_event(user=user, location=loc, device=device, outcome="locked_out", timestamp=_ts(2)),
    ]
    return events


def generate_mfa_bypass_events(
    user: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate MFA bypass scenario: failures then success without MFA."""
    user = user or _USERS[6]  # grace
    loc = _LOCATIONS[3]
    device = _DEVICES[0]
    events = [
        _make_auth_event(user=user, location=loc, device=device, outcome="failure", mfa_method="push", mfa_passed=False, timestamp=_ts(0)),
        _make_auth_event(user=user, location=loc, device=device, outcome="failure", mfa_method="push", mfa_passed=False, timestamp=_ts(1)),
        _make_auth_event(user=user, location=loc, device=device, outcome="success", mfa_method="none", mfa_passed=False, timestamp=_ts(5)),
    ]
    return events


def generate_impossible_travel_with_vpn(
    user: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate travel events where one IP is a VPN (should be skipped)."""
    user = user or _USERS[7]  # hank
    events = [
        _make_auth_event(
            user=user,
            location=_LOCATIONS[0],  # New York
            device=_DEVICES[0],
            timestamp=_ts(0),
        ),
        _make_auth_event(
            user=user,
            location=_LOCATIONS[5],  # San Francisco VPN IP (10.0.0.100)
            device=_DEVICES[0],
            timestamp=_ts(30),
        ),
    ]
    return events


# ---------------------------------------------------------------------------
# Role change generators
# ---------------------------------------------------------------------------


def _make_role_change(
    user: dict[str, str],
    role_name: str,
    action: str = "role_assigned",
    risk_level: str = "low",
    changed_by: str = "admin-001",
    justification: str = "Approved role change",
    timestamp: str | None = None,
) -> dict[str, Any]:
    return {
        "event_id": f"role-{_uid()}",
        "user_id": user["user_id"],
        "username": user["username"],
        "action": action,
        "role_name": role_name,
        "role_risk_level": risk_level,
        "changed_by": changed_by,
        "justification": justification,
        "timestamp": timestamp or _ts(),
    }


def generate_normal_role_changes(count: int = 5) -> list[dict[str, Any]]:
    """Generate standard, low-risk role assignments."""
    changes = []
    for i in range(count):
        user = _USERS[i % len(_USERS)]
        role = _NORMAL_ROLES[i % len(_NORMAL_ROLES)]
        changes.append(_make_role_change(
            user=user,
            role_name=role,
            timestamp=_ts(i * 5),
        ))
    return changes


def generate_high_risk_role_changes(
    user: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate high-risk role assignments."""
    user = user or _USERS[0]
    return [
        _make_role_change(user=user, role_name="global_admin", risk_level="critical"),
        _make_role_change(user=user, role_name="security_admin", risk_level="high"),
    ]


def generate_self_escalation_role_changes(
    user: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Generate self-escalation events (user gives role to themselves)."""
    user = user or _USERS[1]
    return [
        _make_role_change(
            user=user,
            role_name="global_admin",
            risk_level="critical",
            changed_by=user["user_id"],  # self-assignment
            justification="",
        ),
    ]


def generate_sod_violating_role_changes(
    user: dict[str, str] | None = None,
    pair_index: int = 0,
) -> list[dict[str, Any]]:
    """Generate role assignments that create a SoD violation."""
    user = user or _USERS[2]
    role_a, role_b = _SOD_CONFLICT_PAIRS[pair_index]
    return [
        _make_role_change(user=user, role_name=role_a, timestamp=_ts(0)),
        _make_role_change(user=user, role_name=role_b, timestamp=_ts(5)),
    ]


# ---------------------------------------------------------------------------
# Mixed batch generators
# ---------------------------------------------------------------------------


def generate_mixed_auth_batch(
    normal_count: int = 10,
    brute_count: int = 6,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Generate a mixed batch with normal + attack events."""
    rng = random.Random(seed)
    events = generate_normal_auth_events(normal_count)
    events.extend(generate_brute_force_events(failure_count=brute_count))
    events.extend(generate_impossible_travel_events())
    events.extend(generate_mfa_fatigue_events(denial_count=5))
    rng.shuffle(events)
    return events


def generate_mixed_role_batch(seed: int = 42) -> list[dict[str, Any]]:
    """Generate a mixed batch of role changes."""
    rng = random.Random(seed)
    events = generate_normal_role_changes(5)
    events.extend(generate_high_risk_role_changes())
    events.extend(generate_self_escalation_role_changes())
    events.extend(generate_sod_violating_role_changes())
    rng.shuffle(events)
    return events
