"""MapControlsNode – map evidence to controls across ISO 27001, NIST CSF, SOC 2, PCI DSS, HIPAA."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from compliance_audit_agent.rules.control_catalog import ControlCatalog

log = structlog.get_logger()

_CATALOG = ControlCatalog()


def _s(state: Any, key: str, default: Any) -> Any:
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def map_controls(state: Any) -> dict[str, Any]:
    """FR-02: Map each evidence item to controls across all enabled frameworks."""
    evidence_items = _s(state, "evidence_items", [])
    mappings: list[dict[str, Any]] = []
    mapping_index: dict[str, dict[str, Any]] = {}

    for ev in evidence_items:
        control_id = ev.get("control_id", "")
        framework = ev.get("framework", "CUSTOM")

        # Look up cross-framework harmonisation
        harmonised = _CATALOG.get_harmonised_controls(control_id, framework)

        key = f"{framework}::{control_id}"
        if key not in mapping_index:
            mapping_index[key] = {
                "mapping_id": str(uuid.uuid4()),
                "control_id": control_id,
                "framework": framework,
                "control_name": _CATALOG.get_control_name(control_id, framework),
                "evidence_ids": [],
                "cross_framework_ids": harmonised,
            }
        mapping_index[key]["evidence_ids"].append(ev["evidence_id"])

    mappings = list(mapping_index.values())
    log.info("map_controls.done", mappings=len(mappings))
    return {"control_mappings": mappings}
