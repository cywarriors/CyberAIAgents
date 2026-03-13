"""SessionPatternNode – detect impossible travel, atypical logins, device anomalies (FR-02)."""

from __future__ import annotations

import math
from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)

_EARTH_RADIUS_KM = 6371.0


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance in km between two coordinates."""
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(dlon / 2) ** 2
    )
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def _is_vpn_ip(ip: str, settings: Any) -> bool:
    allowed = [s.strip() for s in settings.vpn_allowed_ips.split(",") if s.strip()]
    return ip in allowed


def _is_off_hours(timestamp_str: str) -> bool:
    """Check if login is outside 08:00-18:00 local (simplified UTC)."""
    try:
        from datetime import datetime, timezone

        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return ts.hour < 8 or ts.hour >= 18
    except Exception:
        return False


def analyze_session_patterns(state: dict[str, Any]) -> dict[str, Any]:
    """Build session profiles and detect anomalies per user.

    Implements FR-02 (impossible travel, atypical login, unusual device/location).
    """
    auth_events: list[dict] = state.get("raw_auth_events", [])
    settings = get_settings()

    logger.info("analyze_session_patterns", event_count=len(auth_events))

    # Group events by user
    by_user: dict[str, list[dict]] = {}
    for evt in auth_events:
        uid = evt.get("user_id", "unknown")
        by_user.setdefault(uid, []).append(evt)

    profiles: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []

    for user_id, events in by_user.items():
        events_sorted = sorted(events, key=lambda e: e.get("timestamp", ""))
        username = events_sorted[0].get("username", "")

        unique_ips = {e.get("source_ip", "") for e in events_sorted} - {""}
        unique_devices = {e.get("device_id", "") for e in events_sorted} - {""}
        failed = [e for e in events_sorted if e.get("outcome") == "failure"]
        mfa_denied = [e for e in events_sorted if e.get("outcome") == "mfa_denied"]

        # Impossible travel detection
        is_impossible_travel = False
        travel_speed = 0.0
        for i in range(1, len(events_sorted)):
            prev, curr = events_sorted[i - 1], events_sorted[i]
            lat1, lon1 = prev.get("geo_latitude", 0), prev.get("geo_longitude", 0)
            lat2, lon2 = curr.get("geo_latitude", 0), curr.get("geo_longitude", 0)
            if lat1 == 0 and lon1 == 0:
                continue
            if lat2 == 0 and lon2 == 0:
                continue
            # Skip if either IP is a VPN
            if _is_vpn_ip(prev.get("source_ip", ""), settings) or _is_vpn_ip(curr.get("source_ip", ""), settings):
                continue
            dist = _haversine(lat1, lon1, lat2, lon2)
            if dist < settings.impossible_travel_min_distance_km:
                continue
            try:
                from datetime import datetime

                t1 = datetime.fromisoformat(prev["timestamp"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(curr["timestamp"].replace("Z", "+00:00"))
                hours = max((t2 - t1).total_seconds() / 3600, 0.01)
                speed = dist / hours
                if speed > settings.impossible_travel_speed_kmh:
                    is_impossible_travel = True
                    travel_speed = speed
                    anomalies.append({
                        "user_id": user_id,
                        "username": username,
                        "anomaly_type": "impossible_travel",
                        "severity": "high",
                        "confidence": min(0.99, 0.7 + 0.001 * speed),
                        "evidence": (
                            f"Travel {dist:.0f}km in {hours:.1f}h "
                            f"({speed:.0f}km/h) from {prev.get('geo_city', '?')} "
                            f"to {curr.get('geo_city', '?')}"
                        ),
                        "source_event_id": curr.get("event_id", ""),
                    })
            except Exception:
                pass

        # Off-hours detection
        for evt in events_sorted:
            if _is_off_hours(evt.get("timestamp", "")):
                anomalies.append({
                    "user_id": user_id,
                    "username": username,
                    "anomaly_type": "off_hours_login",
                    "severity": "low",
                    "confidence": 0.6,
                    "evidence": f"Login at unusual hour from {evt.get('source_ip', '?')}",
                    "source_event_id": evt.get("event_id", ""),
                })
                break  # one per user per batch

        # New device
        new_device = len(unique_devices) > 1
        if new_device:
            anomalies.append({
                "user_id": user_id,
                "username": username,
                "anomaly_type": "new_device",
                "severity": "medium",
                "confidence": 0.65,
                "evidence": f"Multiple devices: {', '.join(list(unique_devices)[:3])}",
                "source_event_id": events_sorted[-1].get("event_id", ""),
            })

        profile: dict[str, Any] = {
            "user_id": user_id,
            "username": username,
            "login_count_24h": len(events_sorted),
            "failed_login_count_24h": len(failed),
            "mfa_denied_count_1h": len(mfa_denied),
            "unique_ips_24h": len(unique_ips),
            "unique_devices_24h": len(unique_devices),
            "is_impossible_travel": is_impossible_travel,
            "travel_speed_kmh": travel_speed,
            "is_new_device": new_device,
            "is_off_hours": any(_is_off_hours(e.get("timestamp", "")) for e in events_sorted),
        }
        profiles.append(profile)

    logger.info("session_analysis_complete", profiles=len(profiles), anomalies=len(anomalies))
    return {"session_profiles": profiles, "session_anomalies": anomalies}
