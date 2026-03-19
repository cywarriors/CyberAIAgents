def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def ingest_code(state) -> dict:
    """FR: Fetch PR diff or full repo snapshot from VCS."""
    from security_code_review_agent.config import get_settings
    s = get_settings()
    existing_target = _s(state, "scan_target", {})
    if existing_target:
        return {"scan_target": existing_target}
    # No VCS configured — return empty scan target
    return {
        "scan_target": {
            "repo": "",
            "pr_number": None,
            "diff_lines": [],
            "files": [],
            "language": "python",
        }
    }
