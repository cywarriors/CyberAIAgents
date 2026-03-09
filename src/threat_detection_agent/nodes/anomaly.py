"""BehaviorAnomalyNode – score events against ML behaviour baselines."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Baseline thresholds (in production these come from the model inference service)
_BASELINES: dict[str, dict[str, float]] = {
    "failed_login_count": {"mean": 2.0, "std": 1.5, "threshold": 5.0},
    "bytes_out": {"mean": 50_000.0, "std": 30_000.0, "threshold": 200_000.0},
    "process_spawn_rate": {"mean": 10.0, "std": 5.0, "threshold": 30.0},
    "dns_query_rate": {"mean": 50.0, "std": 20.0, "threshold": 150.0},
}


def _score_event(event: dict[str, Any]) -> list[dict]:
    """Return anomaly results for a single event if thresholds are exceeded."""
    results: list[dict] = []
    action = str(event.get("action", "")).lower()
    category = str(event.get("category", "")).lower()

    # Failed-login anomaly
    if "fail" in action and category == "authentication":
        bl = _BASELINES["failed_login_count"]
        observed = float(event.get("raw_snippet", {}).get("attempt_count", 1))
        if observed > bl["threshold"]:
            score = min((observed - bl["mean"]) / (bl["std"] * 3 + 0.01), 1.0)
            results.append(
                {
                    "model_id": "baseline-auth-v1",
                    "anomaly_type": "excessive_failed_logins",
                    "anomaly_score": round(score, 4),
                    "baseline_value": bl["mean"],
                    "observed_value": observed,
                    "entity_type": "user",
                    "entity_id": event.get("user_name", "unknown"),
                    "matched_event_ids": [event["event_id"]],
                    "description": (
                        f"User '{event.get('user_name')}' had {int(observed)} failed logins "
                        f"(baseline mean {bl['mean']})"
                    ),
                }
            )

    # Data exfil anomaly
    bytes_out = event.get("raw_snippet", {}).get("bytes_out")
    if bytes_out is not None:
        bl = _BASELINES["bytes_out"]
        observed = float(bytes_out)
        if observed > bl["threshold"]:
            score = min((observed - bl["mean"]) / (bl["std"] * 3 + 0.01), 1.0)
            results.append(
                {
                    "model_id": "baseline-network-v1",
                    "anomaly_type": "high_outbound_bytes",
                    "anomaly_score": round(score, 4),
                    "baseline_value": bl["mean"],
                    "observed_value": observed,
                    "entity_type": "host",
                    "entity_id": event.get("host_name") or event.get("src_ip", "unknown"),
                    "matched_event_ids": [event["event_id"]],
                    "description": (
                        f"Host '{event.get('host_name')}' sent {int(observed)} bytes "
                        f"outbound (baseline {bl['mean']})"
                    ),
                }
            )

    # DNS tunnelling anomaly
    if category == "dns":
        bl = _BASELINES["dns_query_rate"]
        observed = float(event.get("raw_snippet", {}).get("query_count", 0))
        if observed > bl["threshold"]:
            score = min((observed - bl["mean"]) / (bl["std"] * 3 + 0.01), 1.0)
            results.append(
                {
                    "model_id": "baseline-dns-v1",
                    "anomaly_type": "dns_tunnelling_suspect",
                    "anomaly_score": round(score, 4),
                    "baseline_value": bl["mean"],
                    "observed_value": observed,
                    "entity_type": "host",
                    "entity_id": event.get("host_name") or event.get("src_ip", "unknown"),
                    "matched_event_ids": [event["event_id"]],
                    "description": (
                        f"Host '{event.get('host_name')}' made {int(observed)} DNS queries "
                        f"in window (baseline {bl['mean']})"
                    ),
                }
            )

    return results


def behavior_anomaly(state: dict[str, Any]) -> dict[str, Any]:
    """Score all normalised events against behaviour baselines."""
    normalized_events: list[dict] = state.get("normalized_events", [])
    anomalies: list[dict] = []

    for event in normalized_events:
        anomalies.extend(_score_event(event))

    logger.info("behavior_anomaly", anomaly_count=len(anomalies))
    return {"anomalies": anomalies}
