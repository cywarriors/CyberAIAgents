"""PlaceHoneyCreds — generate and place honey credentials and canary tokens.

SEC-01: Honey credentials MUST NOT be real credentials. All values are synthetic.
"""
from __future__ import annotations
import hashlib
import uuid
import structlog
from datetime import datetime, timezone

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def _fake_cred(username: str, service: str) -> dict:
    """Generate a synthetic credential — never a real password."""
    token = hashlib.sha256(f"honey-{username}-{service}-{uuid.uuid4()}".encode()).hexdigest()[:16]
    return {
        "cred_id": str(uuid.uuid4()),
        "username": username,
        "password_hash": f"$2b$12$FAKEHASH{token}",  # SEC-01: synthetic, never real
        "service": service,
        "placed_at": datetime.now(timezone.utc).isoformat(),
        "triggered": False,
        "is_synthetic": True,  # explicit marker
    }


def _canary_token(token_type: str, target_path: str) -> dict:
    return {
        "token_id": str(uuid.uuid4()),
        "token_type": token_type,
        "target_path": target_path,
        "token_value": f"CANARY-{uuid.uuid4().hex[:12].upper()}",
        "placed_at": datetime.now(timezone.utc).isoformat(),
        "triggered": False,
    }


def place_honey_creds(state) -> dict:
    """Place synthetic honey credentials and canary tokens in decoy assets."""
    existing_creds = list(_s(state, "honey_credentials", []))
    existing_tokens = list(_s(state, "canary_tokens", []))

    if existing_creds and existing_tokens:
        return {"honey_credentials": existing_creds, "canary_tokens": existing_tokens}

    creds = [
        _fake_cred("admin", "ssh"),
        _fake_cred("sa", "mssql"),
        _fake_cred("oracle", "oracle_db"),
        _fake_cred("apiuser", "rest_api"),
    ]
    tokens = [
        _canary_token("file", "/home/admin/.ssh/id_rsa"),
        _canary_token("registry", r"HKLM\Software\Company\Config"),
        _canary_token("url", "http://internal-api.corp/secret"),
    ]

    log.info("place_honey_creds.done", creds=len(creds), tokens=len(tokens))
    return {"honey_credentials": creds, "canary_tokens": tokens}
