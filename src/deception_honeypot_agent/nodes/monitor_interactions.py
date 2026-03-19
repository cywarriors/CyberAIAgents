"""MonitorInteractionsNode — collect interaction events from decoys."""
from __future__ import annotations
import structlog

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def monitor_interactions(state) -> dict:
    """Collect real-time interaction events from all active decoys."""
    interactions = list(_s(state, "interactions", []))
    decoys = list(_s(state, "decoy_inventory", []))

    # Enrich interactions with decoy metadata
    decoy_map = {d["decoy_id"]: d for d in decoys}
    enriched = []
    for interaction in interactions:
        decoy_id = interaction.get("decoy_id", "")
        decoy = decoy_map.get(decoy_id, {})
        enriched.append({
            **interaction,
            "decoy_type": decoy.get("decoy_type", "unknown"),
            "decoy_service": decoy.get("service", "unknown"),
        })

    log.info("monitor_interactions.done", count=len(enriched))
    return {"interactions": enriched}
