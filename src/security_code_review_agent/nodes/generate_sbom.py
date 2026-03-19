import uuid
import structlog
from datetime import datetime, timezone

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def generate_sbom(state) -> dict:
    """FR-07: Produce SBOM in CycloneDX format."""
    target = _s(state, "scan_target", {})
    sca_findings = _s(state, "sca_findings", [])

    vuln_by_pkg: dict = {}
    for finding in sca_findings:
        pkg = finding.get("package_name", "")
        vuln_by_pkg.setdefault(pkg, []).append(finding.get("cve_id", ""))

    components = []
    for dep in target.get("dependencies", []):
        pkg_name = dep.get("name", "") if isinstance(dep, dict) else str(dep)
        pkg_ver = dep.get("version", "unknown") if isinstance(dep, dict) else "unknown"
        components.append({
            "name": pkg_name,
            "version": pkg_ver,
            "purl": f"pkg:{target.get('language', 'generic')}/{pkg_name}@{pkg_ver}",
            "licenses": dep.get("licenses", []) if isinstance(dep, dict) else [],
            "vulnerabilities": vuln_by_pkg.get(pkg_name, []),
        })

    sbom = {
        "sbom_id": str(uuid.uuid4()),
        "format": "cyclonedx",
        "spec_version": "1.4",
        "repository": target.get("repo", ""),
        "components": components,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    log.info("generate_sbom.done", components=len(components))
    return {"sbom": sbom}
