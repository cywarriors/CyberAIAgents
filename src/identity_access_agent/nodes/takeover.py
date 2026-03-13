"""DetectTakeoverSignalsNode – credential stuffing, MFA fatigue, brute-force (FR-03)."""

from __future__ import annotations

from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def detect_takeover_signals(state: dict[str, Any]) -> dict[str, Any]:
    """Identify credential-stuffing, MFA fatigue (push-bombing), and brute-force.

    Implements FR-03.
    """
    auth_events: list[dict] = state.get("raw_auth_events", [])
    session_profiles: list[dict] = state.get("session_profiles", [])
    settings = get_settings()

    logger.info("detect_takeover_signals", event_count=len(auth_events))

    profile_by_user = {p["user_id"]: p for p in session_profiles}

    signals: list[dict[str, Any]] = []

    # Group events by user
    by_user: dict[str, list[dict]] = {}
    for evt in auth_events:
        uid = evt.get("user_id", "unknown")
        by_user.setdefault(uid, []).append(evt)

    for user_id, events in by_user.items():
        username = events[0].get("username", "")
        profile = profile_by_user.get(user_id, {})

        # Brute-force / credential stuffing: excessive failures
        failures = [e for e in events if e.get("outcome") == "failure"]
        if len(failures) >= 5:
            signals.append({
                "user_id": user_id,
                "username": username,
                "signal_type": "brute_force",
                "severity": "high",
                "confidence": min(0.99, 0.6 + 0.05 * len(failures)),
                "evidence": f"{len(failures)} failed login attempts detected",
                "source_event_id": failures[-1].get("event_id", ""),
            })

        # MFA fatigue / push-bombing
        mfa_denied = [e for e in events if e.get("outcome") == "mfa_denied"]
        mfa_challenges = [e for e in events if e.get("mfa_method", "none") != "none"]
        if len(mfa_denied) >= settings.mfa_fatigue_threshold:
            signals.append({
                "user_id": user_id,
                "username": username,
                "signal_type": "mfa_fatigue",
                "severity": "critical",
                "confidence": min(0.99, 0.7 + 0.04 * len(mfa_denied)),
                "evidence": (
                    f"{len(mfa_denied)} MFA denials detected "
                    f"(threshold: {settings.mfa_fatigue_threshold})"
                ),
                "source_event_id": mfa_denied[-1].get("event_id", ""),
            })

        # MFA bypass: success without MFA after failures
        successes_no_mfa = [
            e for e in events
            if e.get("outcome") == "success"
            and e.get("mfa_method", "none") == "none"
            and not e.get("mfa_passed", True)
        ]
        if failures and successes_no_mfa:
            signals.append({
                "user_id": user_id,
                "username": username,
                "signal_type": "mfa_bypass_suspected",
                "severity": "critical",
                "confidence": 0.85,
                "evidence": "Successful login without MFA after prior failures",
                "source_event_id": successes_no_mfa[-1].get("event_id", ""),
            })

        # Account lockout
        lockouts = [e for e in events if e.get("outcome") == "locked_out"]
        if lockouts:
            signals.append({
                "user_id": user_id,
                "username": username,
                "signal_type": "account_lockout",
                "severity": "medium",
                "confidence": 0.95,
                "evidence": f"Account locked out ({len(lockouts)} lockout events)",
                "source_event_id": lockouts[-1].get("event_id", ""),
            })

        # Impossible-travel correlated with failure
        if profile.get("is_impossible_travel") and failures:
            signals.append({
                "user_id": user_id,
                "username": username,
                "signal_type": "impossible_travel_with_failures",
                "severity": "critical",
                "confidence": 0.9,
                "evidence": "Impossible travel detected alongside authentication failures",
                "source_event_id": events[-1].get("event_id", ""),
            })

    logger.info("takeover_detection_complete", signals=len(signals))
    return {"takeover_signals": signals}
