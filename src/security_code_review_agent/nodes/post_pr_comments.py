import uuid
import structlog

log = structlog.get_logger()


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def post_pr_comments(state) -> dict:
    """FR-04: Post inline PR comments with findings and fix suggestions."""
    from security_code_review_agent.config import get_settings
    s = get_settings()
    sast = _s(state, "sast_findings", [])
    secrets = _s(state, "secrets_findings", [])
    sca = _s(state, "sca_findings", [])
    fixes_list = _s(state, "fix_suggestions", [])
    target = _s(state, "scan_target", {})

    # Build fix lookup
    fix_index = {f["finding_id"]: f for f in fixes_list}

    comments = []
    all_findings = (
        [(f, "sast") for f in sast]
        + [(f, "secret") for f in secrets]
        + [(f, "sca") for f in sca]
    )

    for finding, ftype in all_findings:
        fid = finding.get("finding_id", "")
        fix = fix_index.get(fid, {})
        sev = finding.get("severity", "medium")
        sev_emoji = {
            "critical": "\U0001f534",
            "high": "\U0001f7e0",
            "medium": "\U0001f7e1",
            "low": "\U0001f7e2",
            "info": "\u26aa",
        }.get(sev, "\u26aa")
        body = (
            f"{sev_emoji} **[{sev.upper()}]** Security Finding: "
            f"{finding.get('description', ftype + ' finding')}\n\n"
            f"**Type**: {ftype.upper()}\n"
        )
        if ftype == "sast":
            body += (
                f"**CWE**: {finding.get('cwe_id', 'N/A')} | "
                f"**OWASP**: {finding.get('owasp_category', 'N/A')}\n"
            )
        if fix:
            body += (
                f"\n**Fix**: {fix.get('description', '')}\n"
                f"```\n{fix.get('code_example', '')}\n```"
            )

        comment = {
            "comment_id": str(uuid.uuid4()),
            "file_path": finding.get("file_path", ""),
            "line_number": finding.get("line_number", 0),
            "body": body,
            "severity": sev,
            "posted": False,  # Would be True if VCS API is configured
        }

        # Post to VCS if configured
        if s.vcs_api_url and target.get("pr_number"):
            try:
                from security_code_review_agent.integrations.vcs import VCSConnector
                vcs = VCSConnector(
                    base_url=s.vcs_api_url,
                    token=s.vcs_api_token,
                    platform=s.vcs_platform,
                )
                vcs.post_comment(
                    repo=target.get("repo", ""),
                    pr=target["pr_number"],
                    comment=body,
                    file_path=comment["file_path"],
                    line=comment["line_number"],
                )
                comment["posted"] = True
            except Exception as exc:
                log.warning("post_pr_comments.vcs_error", error=str(exc))

        comments.append(comment)

    log.info("post_pr_comments.done", comments=len(comments))
    return {"pr_comments": comments}
