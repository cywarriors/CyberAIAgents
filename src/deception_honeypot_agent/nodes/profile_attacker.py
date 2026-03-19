"""ProfileAttackerNode — build and update attacker TTP profiles."""
from __future__ import annotations
import uuid
import structlog
from datetime import datetime, timezone
from collections import Counter

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def profile_attacker(state) -> dict:
    """Build attacker profiles grouped by source IP with TTP summaries."""
    classified = list(_s(state, "classified_interactions", []))
    ttp_mappings = list(_s(state, "ttp_mappings", []))
    existing_profiles = list(_s(state, "attacker_profiles", []))

    # Group by source IP
    by_ip: dict[str, dict] = {}
    for interaction in classified:
        ip = interaction.get("source_ip", "unknown")
        if ip not in by_ip:
            by_ip[ip] = {
                "interactions": [],
                "ttps": [],
                "interaction_types": [],
            }
        by_ip[ip]["interactions"].append(interaction.get("interaction_id", ""))
        by_ip[ip]["interaction_types"].append(interaction.get("interaction_type", "unknown"))

    for mapping in ttp_mappings:
        ip = mapping.get("source_ip", "unknown")
        if ip in by_ip:
            by_ip[ip]["ttps"].append(mapping.get("technique_id", ""))

    profiles = []
    for ip, data in by_ip.items():
        type_counts = Counter(data["interaction_types"])
        dominant_behavior = type_counts.most_common(1)[0][0] if type_counts else "unknown"
        profiles.append({
            "profile_id": str(uuid.uuid4()),
            "source_ip": ip,
            "interaction_count": len(data["interactions"]),
            "unique_techniques": list(set(data["ttps"])),
            "interaction_types": dict(type_counts),
            "dominant_behavior": dominant_behavior,
            "threat_level": _threat_level(dominant_behavior),
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
        })

    log.info("profile_attacker.done", profiles=len(profiles))
    return {"attacker_profiles": profiles}


def _threat_level(behavior: str) -> str:
    mapping = {
        "exploit": "critical",
        "lateral": "critical",
        "credential_use": "high",
        "probe": "medium",
        "scan": "low",
        "file_access": "medium",
    }
    return mapping.get(behavior, "low")
