"""ClassifyInteractionNode — categorize interaction type."""
from __future__ import annotations
import re
import structlog

log = structlog.get_logger()

_PATTERNS = [
    ("exploit",         re.compile(r"exploit|shellcode|payload|overflow|injection|rce", re.I)),
    ("lateral",         re.compile(r"lateral|pivot|psexec|wmi|pass.the.hash|kerberos|mimikatz", re.I)),
    ("credential_use",  re.compile(r"auth|login|password|credential|honey|canary", re.I)),
    ("probe",           re.compile(r"banner|version|finger|enum|oscp|nmap|masscan", re.I)),
    ("scan",            re.compile(r"scan|port|sweep|recon|discover", re.I)),
]


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def _classify(interaction: dict) -> str:
    raw = " ".join([
        interaction.get("raw_event", ""),
        interaction.get("action", ""),
        interaction.get("command", ""),
        interaction.get("user_agent", ""),
    ]).lower()

    for interaction_type, pattern in _PATTERNS:
        if pattern.search(raw):
            return interaction_type
    return "unknown"


def classify_interaction(state) -> dict:
    """Classify each interaction by type (scan/probe/exploit/lateral/credential_use)."""
    interactions = list(_s(state, "interactions", []))
    classified = []
    for interaction in interactions:
        interaction_type = _classify(interaction)
        classified.append({
            **interaction,
            "interaction_type": interaction_type,
            "confidence": 0.85 if interaction_type != "unknown" else 0.40,
        })

    log.info("classify_interaction.done", classified=len(classified))
    return {"classified_interactions": classified}
