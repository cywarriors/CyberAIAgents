import uuid
import structlog

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def sast_scan(state) -> dict:
    """FR-01: Static analysis mapped to OWASP Top 10 and CWE categories."""
    from security_code_review_agent.rules.sast_rules import SASTRulesEngine
    target = _s(state, "scan_target", {})
    engine = SASTRulesEngine()
    findings = engine.scan(target)
    log.info("sast_scan.done", findings=len(findings))
    return {"sast_findings": findings}
