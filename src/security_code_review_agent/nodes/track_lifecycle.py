import structlog

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def track_lifecycle(state) -> dict:
    """FR-08: Update finding lifecycle state (new/acknowledged/remediated/false_positive)."""
    from security_code_review_agent.monitoring.store import get_findings_store
    sast = _s(state, "sast_findings", [])
    secrets = _s(state, "secrets_findings", [])
    sca = _s(state, "sca_findings", [])

    store = get_findings_store()
    updates = []

    for finding in list(sast) + list(secrets) + list(sca):
        fid = finding.get("finding_id", "")
        existing = store.get_finding(fid)
        if existing is None:
            store.save_finding(fid, {**finding, "status": "new"})
            updates.append({"finding_id": fid, "status": "new", "action": "created"})
        else:
            updates.append({
                "finding_id": fid,
                "status": existing.get("status", "new"),
                "action": "seen",
            })

    log.info("track_lifecycle.done", updates=len(updates))
    return {"lifecycle_updates": updates}
