"""Track posture drift node - compares current vs. previous configuration snapshots."""

from datetime import datetime, timezone
import hashlib
import json
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.models import DriftRecord


def _config_hash(config: dict) -> str:
    """Create a stable hash of a configuration dict."""
    return hashlib.sha256(json.dumps(config, sort_keys=True, default=str).encode()).hexdigest()[:16]


async def track_posture_drift(state: CloudPostureState) -> CloudPostureState:
    """Compare current resource configurations against previous snapshot to detect drift."""

    drift_records: list[DriftRecord] = []

    if state.drift_records:
        # Drift records already provided (e.g., from mock data injection)
        drift_records = state.drift_records
    elif state.previous_snapshot:
        # Build lookup of previous configs
        previous_lookup: dict[str, dict] = {}
        for resource in state.previous_snapshot:
            previous_lookup[resource.resource_id] = resource.configuration

        # Compare current vs previous
        for resource in state.resource_inventory:
            prev_config = previous_lookup.get(resource.resource_id)
            if prev_config is None:
                continue  # New resource, not a drift

            curr_config = resource.configuration
            if _config_hash(curr_config) == _config_hash(prev_config):
                continue  # No change

            # Identify changed fields
            all_keys = set(list(curr_config.keys()) + list(prev_config.keys()))
            for key in all_keys:
                prev_val = prev_config.get(key)
                curr_val = curr_config.get(key)
                if prev_val != curr_val:
                    # Classify drift type
                    drift_type = "neutral"
                    security_fields = {
                        "encryption_enabled", "public_access_enabled",
                        "logging_enabled", "mfa_enabled", "tls_version",
                        "versioning_enabled",
                    }
                    if key in security_fields:
                        # Check if it's a regression or improvement
                        if key == "public_access_enabled":
                            drift_type = "security_regression" if curr_val else "improvement"
                        elif key in ("encryption_enabled", "logging_enabled", "mfa_enabled", "versioning_enabled"):
                            drift_type = "improvement" if curr_val else "security_regression"
                        elif key == "tls_version":
                            drift_type = "improvement" if str(curr_val) >= str(prev_val) else "security_regression"

                    drift_records.append(DriftRecord(
                        drift_id=hashlib.sha256(
                            f"{resource.resource_id}:{key}".encode()
                        ).hexdigest()[:12],
                        resource_id=resource.resource_id,
                        resource_type=resource.resource_type,
                        account_id=resource.account_id,
                        provider=resource.provider,
                        field_changed=key,
                        previous_value=str(prev_val) if prev_val is not None else "",
                        current_value=str(curr_val) if curr_val is not None else "",
                        drift_type=drift_type,
                    ))

    state.drift_records = drift_records
    state.metrics["drift_total"] = len(drift_records)
    state.metrics["drift_regressions"] = len(
        [d for d in drift_records if d.drift_type == "security_regression"]
    )
    state.metrics["drift_improvements"] = len(
        [d for d in drift_records if d.drift_type == "improvement"]
    )

    return state
