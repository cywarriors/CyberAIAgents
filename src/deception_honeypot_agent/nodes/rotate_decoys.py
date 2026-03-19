"""RotateDecoysNode — retire stale decoys and schedule fresh deployments."""
from __future__ import annotations
import uuid
import structlog
from datetime import datetime, timezone

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def rotate_decoys(state) -> dict:
    """Retire high-interaction decoys and recommend new variants."""
    from deception_honeypot_agent.config import get_settings
    s = get_settings()

    decoys = list(_s(state, "decoy_inventory", []))
    coverage = _s(state, "coverage_assessment", {})
    missing_types = coverage.get("missing_types", [])

    rotation_actions = []
    updated_inventory = []

    for decoy in decoys:
        # Retire decoys with high interaction counts (they may be burned)
        if decoy.get("interaction_count", 0) > 100:
            rotation_actions.append({
                "action": "retire",
                "decoy_id": decoy["decoy_id"],
                "reason": "High interaction count — likely compromised/burned",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            updated_inventory.append({**decoy, "active": False})
        else:
            updated_inventory.append(decoy)

    # Add fresh decoys for missing types
    for dt in missing_types:
        new_decoy = {
            "decoy_id": str(uuid.uuid4()),
            "decoy_type": dt,
            "service": "generic",
            "port": 0,
            "ip_address": f"10.0.100.{len(rotation_actions) + 1}",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "active": True,
            "interaction_count": 0,
        }
        updated_inventory.append(new_decoy)
        rotation_actions.append({
            "action": "deploy",
            "decoy_id": new_decoy["decoy_id"],
            "decoy_type": dt,
            "reason": "Coverage gap — new decoy deployed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    log.info("rotate_decoys.done", actions=len(rotation_actions))
    return {
        "decoy_inventory": updated_inventory,
        "rotation_actions": rotation_actions,
    }
