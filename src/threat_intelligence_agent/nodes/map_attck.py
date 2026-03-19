"""Node: Map threat actors and campaigns to MITRE ATT&CK techniques."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Knowledge base: actor → typical TTPs
_ACTOR_TTP_MAP: dict[str, list[dict[str, str]]] = {
    "apt28": [
        {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access"},
        {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
        {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control"},
        {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"},
    ],
    "apt29": [
        {"technique_id": "T1195.002", "technique_name": "Supply Chain Compromise", "tactic": "Initial Access"},
        {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
        {"technique_id": "T1027", "technique_name": "Obfuscated Files", "tactic": "Defense Evasion"},
        {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control"},
    ],
    "lazarus": [
        {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "Initial Access"},
        {"technique_id": "T1059.005", "technique_name": "Visual Basic", "tactic": "Execution"},
        {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection"},
    ],
    "fin7": [
        {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "Initial Access"},
        {"technique_id": "T1059.003", "technique_name": "Windows Command Shell", "tactic": "Execution"},
        {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactic": "Persistence"},
        {"technique_id": "T1041", "technique_name": "Exfiltration Over C2", "tactic": "Exfiltration"},
    ],
    "sandworm": [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing App", "tactic": "Initial Access"},
        {"technique_id": "T1059.004", "technique_name": "Unix Shell", "tactic": "Execution"},
        {"technique_id": "T1485", "technique_name": "Data Destruction", "tactic": "Impact"},
        {"technique_id": "T1562.001", "technique_name": "Disable Security Tools", "tactic": "Defense Evasion"},
    ],
    "turla": [
        {"technique_id": "T1189", "technique_name": "Drive-by Compromise", "tactic": "Initial Access"},
        {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
        {"technique_id": "T1573.002", "technique_name": "Asymmetric Cryptography", "tactic": "Command and Control"},
    ],
    "kimsuky": [
        {"technique_id": "T1566.002", "technique_name": "Spearphishing Link", "tactic": "Initial Access"},
        {"technique_id": "T1056.001", "technique_name": "Keylogging", "tactic": "Collection"},
        {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control"},
    ],
    "conti": [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing App", "tactic": "Initial Access"},
        {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    ],
}

# IOC-type → generic kill-chain mapping fallback
_IOC_GENERIC_TTP: dict[str, dict[str, str]] = {
    "ip": {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"},
    "domain": {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"},
    "url": {"technique_id": "T1566.002", "technique_name": "Spearphishing Link", "tactic": "Initial Access"},
    "hash_sha256": {"technique_id": "T1204.002", "technique_name": "Malicious File", "tactic": "Execution"},
    "hash_md5": {"technique_id": "T1204.002", "technique_name": "Malicious File", "tactic": "Execution"},
    "hash_sha1": {"technique_id": "T1204.002", "technique_name": "Malicious File", "tactic": "Execution"},
    "email": {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "Initial Access"},
}


def map_attck(state: dict[str, Any]) -> dict[str, Any]:
    """Produce ATT&CK mappings for IOCs, actors, and campaigns."""
    iocs: list[dict[str, Any]] = state.get("deduplicated_iocs", [])
    mappings: list[dict[str, Any]] = []
    seen_actor_keys: set[str] = set()

    for ioc in iocs:
        actor = (ioc.get("actor", "") or "").lower().replace(" ", "").replace("_", "")
        campaign = ioc.get("campaign", "") or ""
        ioc_type = ioc.get("ioc_type", "")

        # Actor-specific TTP mapping
        if actor:
            # Normalise actor name for lookup
            actor_key = actor.replace("group", "").strip()
            actor_ttps = _ACTOR_TTP_MAP.get(actor_key, [])
            for ttp in actor_ttps:
                dedup_key = f"{ioc.get('ioc_id')}-{ttp['technique_id']}"
                if dedup_key not in seen_actor_keys:
                    seen_actor_keys.add(dedup_key)
                    mappings.append(
                        {
                            "entity_id": ioc.get("ioc_id", ""),
                            "entity_type": "ioc",
                            "technique_id": ttp["technique_id"],
                            "technique_name": ttp["technique_name"],
                            "tactic": ttp["tactic"],
                            "actor": ioc.get("actor", ""),
                            "campaign": campaign,
                            "confidence": 75.0,
                        }
                    )

        # Generic IOC-type fallback if no actor mapping produced results
        if not actor or actor.replace("group", "").strip() not in _ACTOR_TTP_MAP:
            generic = _IOC_GENERIC_TTP.get(ioc_type)
            if generic:
                mappings.append(
                    {
                        "entity_id": ioc.get("ioc_id", ""),
                        "entity_type": "ioc",
                        "technique_id": generic["technique_id"],
                        "technique_name": generic["technique_name"],
                        "tactic": generic["tactic"],
                        "actor": ioc.get("actor", ""),
                        "campaign": campaign,
                        "confidence": 50.0,
                    }
                )

    logger.info("map_attck.done", mappings=len(mappings))
    return {"attck_mappings": mappings}
