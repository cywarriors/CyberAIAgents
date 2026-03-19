"""
generators.py – Deterministic mock data generators for Threat Intelligence Agent tests.

All generators use random.Random(42) for reproducibility.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

_RNG = random.Random(42)

# ── Pools ────────────────────────────────────────────────────────────────────

_IP_POOL = [
    "1.2.3.4", "5.6.7.8", "10.20.30.40", "45.56.67.78",
    "103.52.75.100", "92.118.160.50", "198.51.100.10", "203.0.113.55",
    "185.220.101.20", "91.108.4.30",
]

_DOMAIN_POOL = [
    "malicious-c2.example.com", "phishing-site.evil.io", "apt-infra.ru",
    "ransomware-cdn.net", "exfil-server.co", "dropper.bad-actor.xyz",
    "c2-beacon.darknet.org", "stagingdrop.compromised.info",
]

_URL_POOL = [
    "http://1.2.3.4/payload.exe",
    "https://malicious-c2.example.com/gate.php",
    "http://dropper.bad-actor.xyz/stage2",
    "https://exfil-server.co/upload",
]

_HASH_POOL = [
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
    "aabbccdd112233440decafbad0000000deadbeef11223344aabbccdd00112233",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
]

_ACTOR_POOL = ["APT28", "APT29", "Lazarus Group", "Cobalt Group", "FIN7", "Sandworm"]
_SECTOR_POOL = ["financial", "healthcare", "energy", "government", "technology", "defence"]
_REGION_POOL = ["US", "EU", "APAC", "MENA", "LATAM", "RU"]
_SOURCE_POOL = ["otx", "abuse.ch", "circl", "commercial-feed", "isac-fs", "internal-siem"]
_TECHNIQUE_POOL = [
    "T1566.001", "T1059.001", "T1071.001", "T1486", "T1055",
    "T1027", "T1105", "T1562.001", "T1036.005", "T1041",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _past(days: int = 0, hours: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days, hours=hours)).isoformat()


def _uid() -> str:
    return str(uuid.uuid4())


# ── Individual generators ────────────────────────────────────────────────────

def generate_osint_intel_record(ioc_type: str = "ip", value: str | None = None) -> dict[str, Any]:
    """Generate a realistic OSINT feed IOC record."""
    val = value or _RNG.choice(_IP_POOL if ioc_type == "ip" else _DOMAIN_POOL)
    return {
        "id": _uid(),
        "source_type": "osint",
        "source_name": "otx",
        "ioc_type": ioc_type,
        "value": val,
        "tlp": "GREEN",
        "confidence": _RNG.randint(55, 85),
        "first_seen": _past(days=_RNG.randint(1, 30)),
        "last_seen": _past(hours=_RNG.randint(1, 48)),
        "tags": _RNG.sample(["malware", "c2", "phishing", "ransomware", "apt"], k=2),
        "description": f"OSINT-sourced {ioc_type} indicator from OTX pulse",
        "raw": {"pulse_id": _uid(), "created": _now()},
    }


def generate_commercial_intel_record(ioc_type: str = "domain") -> dict[str, Any]:
    """Generate a mock commercial threat feed record."""
    val = _RNG.choice(_DOMAIN_POOL if ioc_type == "domain" else _IP_POOL)
    return {
        "id": _uid(),
        "source_type": "commercial",
        "source_name": "commercial-feed",
        "ioc_type": ioc_type,
        "value": val,
        "tlp": "AMBER",
        "confidence": _RNG.randint(70, 95),
        "first_seen": _past(days=_RNG.randint(0, 14)),
        "last_seen": _past(hours=_RNG.randint(0, 12)),
        "tags": _RNG.sample(["apt", "nation-state", "espionage", "lateral-movement"], k=2),
        "description": f"Commercial feed {ioc_type} indicator with high fidelity",
        "actor": _RNG.choice(_ACTOR_POOL),
        "kill_chain_phase": "command-and-control",
        "raw": {"feed_id": _uid(), "score": _RNG.randint(70, 100)},
    }


def generate_isac_intel_record(ioc_type: str = "hash") -> dict[str, Any]:
    """Generate a mock ISAC/STIX-style intel record."""
    val = _RNG.choice(_HASH_POOL)
    return {
        "id": _uid(),
        "source_type": "isac",
        "source_name": "isac-fs",
        "ioc_type": "md5" if ioc_type == "hash" else ioc_type,
        "value": val,
        "tlp": "AMBER",
        "confidence": _RNG.randint(75, 92),
        "first_seen": _past(days=_RNG.randint(0, 7)),
        "last_seen": _past(hours=_RNG.randint(0, 6)),
        "tags": ["financial-sector", "malware"],
        "description": "ISAC-shared indicator – financial sector targeting",
        "stix_id": f"indicator--{_uid()}",
        "raw": {"bundle_id": _uid(), "object_marking_refs": ["marking-definition--amber"]},
    }


def generate_internal_ioc(ioc_type: str = "ip") -> dict[str, Any]:
    """Generate an IOC from internal SIEM/EDR events."""
    val = _RNG.choice(_IP_POOL)
    return {
        "id": _uid(),
        "source_type": "internal",
        "source_name": "internal-siem",
        "ioc_type": ioc_type,
        "value": val,
        "tlp": "RED",
        "confidence": _RNG.randint(80, 99),
        "first_seen": _past(hours=_RNG.randint(1, 12)),
        "last_seen": _past(hours=0),
        "tags": ["internal-detection", "confirmed-malicious"],
        "description": "Internal detection – confirmed malicious activity",
        "incident_id": f"INC-{_RNG.randint(10000, 99999)}",
        "raw": {"alert_id": _uid(), "severity": "critical"},
    }


def generate_benign_intel_record() -> dict[str, Any]:
    """Generate a benign/false-positive record for negative testing."""
    return {
        "id": _uid(),
        "source_type": "osint",
        "source_name": "otx",
        "ioc_type": "ip",
        "value": "8.8.8.8",  # Google DNS – should never be treated as malicious
        "tlp": "WHITE",
        "confidence": _RNG.randint(10, 30),
        "first_seen": _past(days=90),
        "last_seen": _past(days=90),
        "tags": [],
        "description": "Likely false positive – well-known public DNS resolver",
        "raw": {},
    }


def generate_stale_ioc(days_old: int = 200) -> dict[str, Any]:
    """Generate an IOC old enough to trigger auto-deprecation."""
    record = generate_osint_intel_record()
    record["first_seen"] = _past(days=days_old)
    record["last_seen"] = _past(days=days_old)
    record["tags"].append("stale")
    return record


def generate_duplicate_ioc_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return two records with the same value+type (different sources)."""
    shared_ip = _RNG.choice(_IP_POOL)
    rec1 = generate_osint_intel_record(ioc_type="ip", value=shared_ip)
    rec2 = generate_commercial_intel_record(ioc_type="ip")
    rec2["value"] = shared_ip  # force same value
    rec2["ioc_type"] = "ip"
    return rec1, rec2


def generate_high_relevance_ioc(org_industry: str = "financial") -> dict[str, Any]:
    """IOC with sector targeting that matches org profile."""
    record = generate_commercial_intel_record()
    record["tags"] = [org_industry, "targeted-attack", "apt"]
    record["description"] = f"APT campaign specifically targeting {org_industry} sector"
    record["actor"] = "APT28"
    return record


def generate_low_relevance_ioc() -> dict[str, Any]:
    """IOC from unrelated sector with low relevance to typical org."""
    record = generate_osint_intel_record()
    record["tags"] = ["ics-scada", "industrial", "power-grid"]
    record["description"] = "ICS/SCADA-specific indicator – low relevance to IT sector"
    record["confidence"] = _RNG.randint(30, 55)
    return record


def generate_mixed_intel_batch(count: int = 20) -> list[dict[str, Any]]:
    """Generate a realistic mixed batch of intel records."""
    batch: list[dict[str, Any]] = []
    generators = [
        generate_osint_intel_record,
        generate_commercial_intel_record,
        generate_isac_intel_record,
        generate_internal_ioc,
    ]
    for i in range(count):
        gen = generators[i % len(generators)]
        ioc_type = _RNG.choice(["ip", "domain", "hash"])
        try:
            batch.append(gen(ioc_type=ioc_type))
        except TypeError:
            batch.append(gen())
    # Inject edge cases
    batch.append(generate_benign_intel_record())
    batch.append(generate_stale_ioc())
    dup1, dup2 = generate_duplicate_ioc_pair()
    batch.extend([dup1, dup2])
    return batch


def generate_threat_actor_profile(name: str | None = None) -> dict[str, Any]:
    """Generate a realistic threat actor profile dict."""
    actor_name = name or _RNG.choice(_ACTOR_POOL)
    return {
        "id": _uid(),
        "name": actor_name,
        "aliases": [f"{actor_name}-alias-{_RNG.randint(1, 5)}"],
        "description": f"State-sponsored APT group {actor_name}",
        "motivation": _RNG.choice(["espionage", "financial", "destruction"]),
        "sophistication": _RNG.choice(["advanced", "expert"]),
        "primary_motivation": "espionage",
        "sectors_targeted": _RNG.sample(_SECTOR_POOL, k=_RNG.randint(2, 4)),
        "regions_targeted": _RNG.sample(_REGION_POOL, k=_RNG.randint(2, 3)),
        "ttps": _RNG.sample(_TECHNIQUE_POOL, k=_RNG.randint(3, 6)),
        "first_seen": _past(days=_RNG.randint(365, 1825)),
        "last_active": _past(days=_RNG.randint(1, 60)),
        "ioc_count": _RNG.randint(50, 500),
        "attribution_confidence": _RNG.randint(60, 95),
    }


def generate_campaign() -> dict[str, Any]:
    """Generate a realistic campaign dict."""
    actor = _RNG.choice(_ACTOR_POOL)
    return {
        "id": _uid(),
        "name": f"Operation {_RNG.choice(['Shadow', 'Storm', 'Eclipse', 'Phantom', 'Vortex'])}",
        "description": f"Campaign attributed to {actor} targeting {_RNG.choice(_SECTOR_POOL)} sector",
        "actor": actor,
        "start_date": _past(days=_RNG.randint(30, 365)),
        "end_date": _past(days=_RNG.randint(0, 30)) if _RNG.random() > 0.3 else None,
        "status": _RNG.choice(["active", "dormant", "concluded"]),
        "ioc_count": _RNG.randint(10, 200),
        "affected_sectors": _RNG.sample(_SECTOR_POOL, k=_RNG.randint(1, 3)),
        "techniques": _RNG.sample(_TECHNIQUE_POOL, k=_RNG.randint(2, 5)),
        "confidence": _RNG.randint(65, 95),
    }
