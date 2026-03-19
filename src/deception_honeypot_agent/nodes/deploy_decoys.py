"""DeployDecoysNode — provision and configure decoy assets."""
from __future__ import annotations
import uuid
import structlog
from datetime import datetime, timezone

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


_DECOY_TEMPLATES = [
    {"decoy_type": "fake_server", "service": "ssh", "port": 22, "os": "Ubuntu 22.04"},
    {"decoy_type": "honey_db",    "service": "postgresql", "port": 5432, "os": "Ubuntu 22.04"},
    {"decoy_type": "fake_share",  "service": "smb", "port": 445, "os": "Windows Server 2019"},
    {"decoy_type": "fake_api",    "service": "http", "port": 8080, "os": "Ubuntu 22.04"},
]


def deploy_decoys(state) -> dict:
    """Deploy or refresh decoy assets per configured strategy."""
    from deception_honeypot_agent.config import get_settings
    s = get_settings()

    existing = list(_s(state, "decoy_inventory", []))
    if existing:
        log.info("deploy_decoys.passthrough", count=len(existing))
        return {"decoy_inventory": existing}

    # Provision mock decoys (real infra call when s.infra_api_url is set)
    decoys = []
    for tpl in _DECOY_TEMPLATES[:min(4, s.max_decoys)]:
        decoy = {
            "decoy_id": str(uuid.uuid4()),
            "decoy_type": tpl["decoy_type"],
            "service": tpl["service"],
            "port": tpl["port"],
            "os": tpl["os"],
            "ip_address": f"10.0.{len(decoys)+1}.50",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "active": True,
            "interaction_count": 0,
        }
        decoys.append(decoy)

    log.info("deploy_decoys.done", deployed=len(decoys))
    return {"decoy_inventory": decoys}
