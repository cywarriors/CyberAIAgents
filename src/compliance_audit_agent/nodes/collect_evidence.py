"""CollectEvidenceNode – gather evidence from SIEM, EDR, IAM, Cloud sources."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

import structlog

from compliance_audit_agent.config import get_settings
from compliance_audit_agent.integrations.siem import SIEMConnector
from compliance_audit_agent.integrations.iam import IAMConnector
from compliance_audit_agent.integrations.cloud import CloudConnector

log = structlog.get_logger()


def _make_evidence(source: str, source_type: str, framework: str, control_id: str, content: dict[str, Any]) -> dict[str, Any]:
    raw = str(content).encode()
    sha = hashlib.sha256(raw).hexdigest()
    return {
        "evidence_id": str(uuid.uuid4()),
        "source_system": source,
        "source_type": source_type,
        "framework": framework,
        "control_id": control_id,
        "content": content,
        "sha256_hash": sha,
        "pii_redacted": False,
        "collected_at": __import__("datetime").datetime.utcnow().isoformat(),
    }


def _s(state: Any, key: str, default: Any) -> Any:
    """Get field from state whether it's a dict or a Pydantic model."""
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def collect_evidence(state: Any) -> dict[str, Any]:
    """FR-01: Collect evidence from all configured security tool APIs."""
    s = get_settings()
    collected: list[dict[str, Any]] = list(_s(state, "evidence_items", []))

    # ── SIEM evidence ────────────────────────────────────────────────────
    if s.siem_api_url:
        try:
            siem = SIEMConnector(base_url=s.siem_api_url, api_key=s.siem_api_key)
            for rec in siem.get_log_summary():
                collected.append(_make_evidence("SIEM", "log_summary", "ISO27001", "A.12.4.1", rec))
        except Exception as exc:
            log.warning("collect_evidence.siem_error", error=str(exc))

    # ── IAM evidence ─────────────────────────────────────────────────────
    if s.iam_api_url:
        try:
            iam = IAMConnector(base_url=s.iam_api_url, api_key=s.iam_api_key)
            for rec in iam.get_access_report():
                collected.append(_make_evidence("IAM", "access_report", "ISO27001", "A.9.1.1", rec))
        except Exception as exc:
            log.warning("collect_evidence.iam_error", error=str(exc))

    # ── Cloud platform evidence ───────────────────────────────────────────
    if s.aws_api_url or s.azure_api_url or s.gcp_api_url:
        try:
            cloud = CloudConnector(
                aws_url=s.aws_api_url, aws_key=s.aws_api_key,
                azure_url=s.azure_api_url, azure_key=s.azure_api_key,
                gcp_url=s.gcp_api_url, gcp_key=s.gcp_api_key,
            )
            for rec in cloud.get_config_snapshot():
                collected.append(_make_evidence("Cloud", "config_snapshot", "NIST_CSF", "PR.AC-1", rec))
        except Exception as exc:
            log.warning("collect_evidence.cloud_error", error=str(exc))

    # Pre-loaded evidence passes through unchanged
    log.info("collect_evidence.done", total=len(collected))
    return {"evidence_items": collected}
