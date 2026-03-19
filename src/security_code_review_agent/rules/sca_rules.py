import uuid

# Simulated vulnerable package database
_KNOWN_VULNS = {
    ("requests", "2.18.0", "critical", "CVE-2023-32681", "2.31.0"),
    ("django", "2.2.0", "high", "CVE-2023-36053", "3.2.19"),
    ("flask", "1.0.0", "medium", "CVE-2023-30861", "2.3.2"),
    ("pillow", "8.0.0", "critical", "CVE-2023-44271", "10.0.0"),
    ("cryptography", "38.0.0", "high", "CVE-2023-49083", "41.0.6"),
    ("urllib3", "1.26.0", "medium", "CVE-2023-45803", "1.26.18"),
    ("pyyaml", "5.4.0", "high", "CVE-2022-1471", "6.0"),
}


class SCAEngine:
    def scan_dependencies(self, deps: list) -> list[dict]:
        findings = []
        for dep in deps:
            name = dep.get("name", "") if isinstance(dep, dict) else str(dep)
            version = dep.get("version", "0.0.0") if isinstance(dep, dict) else "0.0.0"
            for pkg_name, pkg_ver, sev, cve_id, fix_ver in _KNOWN_VULNS:
                if name.lower() == pkg_name and version == pkg_ver:
                    findings.append({
                        "finding_id": str(uuid.uuid4()),
                        "package_name": name,
                        "package_version": version,
                        "cve_id": cve_id,
                        "severity": sev,
                        "cvss_score": {
                            "critical": 9.8,
                            "high": 7.5,
                            "medium": 5.3,
                            "low": 3.1,
                        }.get(sev, 5.0),
                        "fix_version": fix_ver,
                        "language": "python",
                    })
        return findings
