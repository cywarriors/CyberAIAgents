"""Findings API endpoints."""

import re
from fastapi import APIRouter, Query, HTTPException, Body
from cloud_security_agent.api.schemas import FindingResponse, FindingDetailResponse

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

# In-memory storage for demo (would be database in production)
findings_db: dict[str, dict] = {}

_FINDING_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


def _validate_finding_id(finding_id: str) -> str:
    """Validate finding_id to prevent injection attacks."""
    if not _FINDING_ID_RE.match(finding_id):
        raise HTTPException(status_code=400, detail="Invalid finding ID format")
    return finding_id


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    severity: str = Query(None, pattern="^(critical|high|medium|low|info)$"),
    provider: str = Query(None, pattern="^(aws|azure|gcp)$"),
    account_id: str = Query(None, max_length=128),
    framework: str = Query(None, max_length=64),
    remediation_status: str = Query(None, pattern="^(open|in_progress|remediated|risk_accepted|deferred)$"),
    region: str = Query(None, max_length=64),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """Get paginated list of findings with filters."""

    findings = list(findings_db.values())

    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if provider:
        findings = [f for f in findings if f.get("provider") == provider]
    if account_id:
        findings = [f for f in findings if f.get("account_id") == account_id]
    if framework:
        findings = [f for f in findings if f.get("framework") == framework]
    if remediation_status:
        findings = [f for f in findings if f.get("remediation_status") == remediation_status]
    if region:
        findings = [f for f in findings if f.get("region") == region]

    findings.sort(key=lambda f: f.get("risk_score", 0), reverse=True)

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    return findings[start_idx:end_idx]


@router.get("/{finding_id}", response_model=FindingDetailResponse)
async def get_finding_detail(finding_id: str):
    """Get detailed finding information."""
    _validate_finding_id(finding_id)

    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    return findings_db[finding_id]


@router.put("/{finding_id}/status", response_model=dict)
async def update_finding_status(
    finding_id: str,
    new_status: str = Body(..., embed=True),
):
    """Update remediation status of a finding."""
    _validate_finding_id(finding_id)

    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")

    valid_states = {"open", "in_progress", "remediated", "risk_accepted", "deferred"}
    if new_status not in valid_states:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid_states))}",
        )

    findings_db[finding_id]["remediation_status"] = new_status
    return {"success": True, "finding_id": finding_id, "new_status": new_status}
