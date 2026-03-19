import structlog

log = structlog.get_logger()

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def evaluate_policy(state) -> dict:
    """FR-06: Enforce policy gates (block/warn/pass) per severity."""
    from security_code_review_agent.config import get_settings
    s = get_settings()
    sast = _s(state, "sast_findings", [])
    secrets = _s(state, "secrets_findings", [])
    sca = _s(state, "sca_findings", [])
    all_findings = list(sast) + list(secrets) + list(sca)

    block_level = _SEVERITY_ORDER.get(s.policy_block_severity.lower(), 4)
    warn_level = _SEVERITY_ORDER.get(s.policy_warn_severity.lower(), 3)

    verdict = "pass"
    blocking_findings = []
    warning_findings = []

    for f in all_findings:
        sev = f.get("severity", "info").lower()
        sev_level = _SEVERITY_ORDER.get(sev, 0)
        if sev_level >= block_level:
            verdict = "block"
            blocking_findings.append(f.get("finding_id", ""))
        elif sev_level >= warn_level and verdict != "block":
            verdict = "warn"
            warning_findings.append(f.get("finding_id", ""))

    log.info("evaluate_policy.done", verdict=verdict, blocking=len(blocking_findings))
    return {
        "policy_verdict": {
            "verdict": verdict,
            "blocking_findings": blocking_findings,
            "warning_findings": warning_findings,
            "total_findings": len(all_findings),
            "requires_appsec_approval": verdict == "block",
        }
    }
