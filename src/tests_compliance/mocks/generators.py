"""Deterministic mock data generators for compliance tests."""

from __future__ import annotations

import random
import uuid

_RNG = random.Random(42)


def _eid() -> str:
    return str(uuid.UUID(int=_RNG.getrandbits(128)))


def generate_evidence_record(
    framework: str = "ISO27001",
    control_id: str = "A.9.1.1",
    source_system: str = "IAM",
    source_type: str = "access_report",
) -> dict:
    return {
        "evidence_id": _eid(),
        "source_system": source_system,
        "source_type": source_type,
        "framework": framework,
        "control_id": control_id,
        "content": {"record_count": _RNG.randint(50, 500), "last_review": "2026-01-01"},
        "sha256_hash": "a" * 64,
        "pii_redacted": False,
        "collected_at": "2026-03-01T00:00:00",
    }


def generate_iso27001_evidence_batch() -> list[dict]:
    controls = [
        ("A.5.1.1", "SIEM", "log_summary"),
        ("A.9.1.1", "IAM", "access_report"),
        ("A.12.4.1", "SIEM", "log_summary"),
        ("A.12.6.1", "EDR", "scan_result"),
        ("A.16.1.1", "SIEM", "audit_trail"),
    ]
    return [generate_evidence_record("ISO27001", c, s, t) for c, s, t in controls]


def generate_nist_csf_evidence_batch() -> list[dict]:
    controls = [
        ("PR.AC-1", "IAM", "access_report"),
        ("PR.DS-1", "Cloud", "config_snapshot"),
        ("DE.AE-1", "SIEM", "log_summary"),
    ]
    return [generate_evidence_record("NIST_CSF", c, s, t) for c, s, t in controls]


def generate_soc2_evidence_batch() -> list[dict]:
    return [
        generate_evidence_record("SOC2", "CC6.1", "IAM", "access_report"),
        generate_evidence_record("SOC2", "CC7.1", "SIEM", "log_summary"),
    ]


def generate_mixed_evidence_batch(count: int = 15) -> list[dict]:
    batch = (
        generate_iso27001_evidence_batch()
        + generate_nist_csf_evidence_batch()
        + generate_soc2_evidence_batch()
    )
    # Pad with additional ISO27001 records if needed
    while len(batch) < count:
        batch.append(generate_evidence_record())
    return batch[:count]


def generate_weak_evidence_record(framework: str = "ISO27001", control_id: str = "A.9.1.1") -> dict:
    """Evidence with a low-value source type (policy doc = lower effectiveness score)."""
    return {
        "evidence_id": _eid(),
        "source_system": "DocumentRepo",
        "source_type": "policy_doc",
        "framework": framework,
        "control_id": control_id,
        "content": {"document_name": "policy.pdf"},
        "sha256_hash": "b" * 64,
        "pii_redacted": False,
        "collected_at": "2026-03-01T00:00:00",
    }


def generate_pii_evidence_record() -> dict:
    """Evidence containing PII fields that should be redacted in audit packs."""
    rec = generate_evidence_record()
    rec["content"]["email"] = "user@example.com"
    rec["content"]["username"] = "jsmith"
    rec["content"]["ssn"] = "123-45-6789"
    return rec
