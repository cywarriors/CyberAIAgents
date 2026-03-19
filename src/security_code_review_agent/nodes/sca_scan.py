import uuid
import structlog

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def sca_scan(state) -> dict:
    """FR-03: Analyze dependencies for known CVEs."""
    from security_code_review_agent.rules.sca_rules import SCAEngine
    target = _s(state, "scan_target", {})
    engine = SCAEngine()
    findings = engine.scan_dependencies(target.get("dependencies", []))
    log.info("sca_scan.done", findings=len(findings))
    return {"sca_findings": findings}
