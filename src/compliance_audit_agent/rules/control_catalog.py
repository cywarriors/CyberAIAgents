"""Control Catalog – framework control definitions and cross-framework harmonisation."""

from __future__ import annotations

# Minimal catalog seeded with representative controls per framework
_CONTROLS: dict[str, dict[str, str]] = {
    # ISO 27001
    "ISO27001::A.5.1.1": "Information security policies",
    "ISO27001::A.9.1.1": "Access control policy",
    "ISO27001::A.12.4.1": "Event logging",
    "ISO27001::A.12.6.1": "Management of technical vulnerabilities",
    "ISO27001::A.16.1.1": "Responsibilities and procedures (incident mgmt)",
    "ISO27001::A.18.1.1": "Identification of applicable legislation",
    # NIST CSF
    "NIST_CSF::ID.AM-1": "Physical devices and systems inventoried",
    "NIST_CSF::PR.AC-1": "Identities and credentials managed",
    "NIST_CSF::PR.DS-1": "Data-at-rest protected",
    "NIST_CSF::DE.AE-1": "Baseline of network operations established",
    "NIST_CSF::RS.RP-1": "Response plan executed",
    # SOC 2
    "SOC2::CC6.1": "Logical and physical access controls",
    "SOC2::CC7.1": "System monitoring procedures",
    "SOC2::CC9.1": "Risk mitigation activities",
    # PCI DSS
    "PCI_DSS::1.1": "Network security controls",
    "PCI_DSS::8.3": "Strong authentication for all users",
    "PCI_DSS::10.2": "Audit logs implemented",
    # HIPAA
    "HIPAA::164.308(a)(1)": "Security management process",
    "HIPAA::164.312(a)(2)(iv)": "Encryption and decryption",
    "HIPAA::164.308(a)(5)": "Security awareness training",
}

# Cross-framework harmonisation: one control satisfies multiple (FR-08)
_HARMONISATION: dict[str, list[str]] = {
    "ISO27001::A.9.1.1": ["NIST_CSF::PR.AC-1", "SOC2::CC6.1", "PCI_DSS::8.3"],
    "ISO27001::A.12.4.1": ["NIST_CSF::DE.AE-1", "SOC2::CC7.1", "PCI_DSS::10.2"],
    "ISO27001::A.16.1.1": ["NIST_CSF::RS.RP-1"],
    "NIST_CSF::PR.DS-1": ["HIPAA::164.312(a)(2)(iv)"],
    "ISO27001::A.18.1.1": ["HIPAA::164.308(a)(1)"],
}

_REQUIRED_CONTROLS: dict[str, list[str]] = {
    "ISO27001": ["A.5.1.1", "A.9.1.1", "A.12.4.1", "A.12.6.1", "A.16.1.1", "A.18.1.1"],
    "NIST_CSF": ["ID.AM-1", "PR.AC-1", "PR.DS-1", "DE.AE-1", "RS.RP-1"],
    "SOC2": ["CC6.1", "CC7.1", "CC9.1"],
    "PCI_DSS": ["1.1", "8.3", "10.2"],
    "HIPAA": ["164.308(a)(1)", "164.312(a)(2)(iv)", "164.308(a)(5)"],
}


class ControlCatalog:
    def get_control_name(self, control_id: str, framework: str) -> str:
        key = f"{framework}::{control_id}"
        return _CONTROLS.get(key, control_id)

    def get_harmonised_controls(self, control_id: str, framework: str) -> list[str]:
        key = f"{framework}::{control_id}"
        return _HARMONISATION.get(key, [])

    def get_required_controls(self, framework: str) -> list[str]:
        return _REQUIRED_CONTROLS.get(framework, [])
