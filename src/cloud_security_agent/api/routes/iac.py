"""IaC scanning API endpoints."""

from fastapi import APIRouter, Query
from cloud_security_agent.api.schemas import IaCScanResultResponse, IaCScanRequest

router = APIRouter(prefix="/api/v1/iac", tags=["iac"])


@router.get("/scans", response_model=list[IaCScanResultResponse])
async def list_iac_scans(
    framework: str = Query(None, pattern="^(terraform|cloudformation|bicep|pulumi)$"),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """List IaC scan results."""

    scans = [
        IaCScanResultResponse(scan_id="iac-scan-001", template_path="infra/main.tf", framework="terraform", repository="org/infra-repo", branch="main", total_resources=45, passed_checks=38, failed_checks=7, findings_count=7, scan_duration_seconds=12.3, scanned_at="2026-03-13T08:30:00Z"),
        IaCScanResultResponse(scan_id="iac-scan-002", template_path="infra/network.tf", framework="terraform", repository="org/infra-repo", branch="feature/vpc-update", total_resources=22, passed_checks=20, failed_checks=2, findings_count=2, scan_duration_seconds=6.1, scanned_at="2026-03-13T08:25:00Z"),
        IaCScanResultResponse(scan_id="iac-scan-003", template_path="templates/stack.yaml", framework="cloudformation", repository="org/cfn-templates", branch="main", total_resources=30, passed_checks=27, failed_checks=3, findings_count=3, scan_duration_seconds=8.5, scanned_at="2026-03-13T07:45:00Z"),
        IaCScanResultResponse(scan_id="iac-scan-004", template_path="infra/main.bicep", framework="bicep", repository="org/azure-infra", branch="main", total_resources=18, passed_checks=16, failed_checks=2, findings_count=2, scan_duration_seconds=5.2, scanned_at="2026-03-13T06:30:00Z"),
    ]

    if framework:
        scans = [s for s in scans if s.framework == framework]

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    return scans[start_idx:end_idx]


@router.post("/scans", response_model=IaCScanResultResponse)
async def trigger_iac_scan(request: IaCScanRequest):
    """Trigger an IaC template scan."""

    return IaCScanResultResponse(
        scan_id="iac-scan-new-001",
        template_path=request.template_path,
        framework=request.framework,
        repository=request.repository,
        branch=request.branch,
        total_resources=15,
        passed_checks=12,
        failed_checks=3,
        findings_count=3,
        scan_duration_seconds=4.8,
        scanned_at="2026-03-13T12:00:00Z",
    )
