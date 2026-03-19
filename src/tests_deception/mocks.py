"""Mock / factory helpers for deception honeypot tests."""
from __future__ import annotations

import random
import uuid

_RNG = random.Random(42)


def make_decoy(
    decoy_type: str = "fake_server",
    service: str = "ssh",
    ip: str | None = None,
    interaction_count: int = 0,
    active: bool = True,
) -> dict:
    return {
        "decoy_id": str(uuid.UUID(int=_RNG.getrandbits(128))),
        "decoy_type": decoy_type,
        "service": service,
        "port": 22,
        "os": "Ubuntu 22.04",
        "ip_address": ip or f"10.0.{_RNG.randint(1, 254)}.{_RNG.randint(1, 254)}",
        "deployed_at": "2024-01-01T00:00:00+00:00",
        "active": active,
        "interaction_count": interaction_count,
    }


def make_interaction(
    interaction_id: str | None = None,
    source_ip: str = "192.168.1.100",
    decoy_id: str | None = None,
    action: str = "connect",
    raw_event: str = "",
) -> dict:
    return {
        "interaction_id": interaction_id or str(uuid.UUID(int=_RNG.getrandbits(128))),
        "source_ip": source_ip,
        "decoy_id": decoy_id or str(uuid.UUID(int=_RNG.getrandbits(128))),
        "action": action,
        "raw_event": raw_event,
        "timestamp": "2024-01-01T12:00:00+00:00",
    }


def make_exploit_interaction(**kw) -> dict:
    return make_interaction(raw_event="exploit shellcode payload rce", action="exploit_attempt", **kw)


def make_scan_interaction(**kw) -> dict:
    return make_interaction(raw_event="port scan discover recon", action="scan", **kw)


def make_credential_interaction(**kw) -> dict:
    return make_interaction(raw_event="auth login credential honey", action="login_attempt", **kw)


def make_lateral_interaction(**kw) -> dict:
    return make_interaction(raw_event="lateral pivot psexec pass-the-hash", action="lateral_move", **kw)


def make_classified_interaction(interaction_type: str = "scan", source_ip: str = "10.0.0.1") -> dict:
    base = make_interaction(source_ip=source_ip)
    base["interaction_type"] = interaction_type
    return base


def make_ttp_mapping(interaction_id: str, technique_id: str = "T1046", tactic: str = "discovery") -> dict:
    return {
        "interaction_id": interaction_id,
        "technique_id": technique_id,
        "technique_name": "Network Service Discovery",
        "tactic": tactic,
        "source_ip": "10.0.0.1",
    }
