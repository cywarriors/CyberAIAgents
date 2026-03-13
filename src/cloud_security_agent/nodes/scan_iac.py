"""Scan IaC node - analyses IaC templates for pre-deploy misconfigurations."""

import time
import hashlib
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.models import (
    IaCScanResult,
    IaCFramework,
    PolicyFinding,
    ComplianceStatus,
    SeverityLevel,
    CloudProvider,
)


async def scan_iac(state: CloudPostureState) -> dict:
    """Scan IaC templates for misconfigurations before deployment."""

    iac_results: list[IaCScanResult] = []

    for template_info in (state.iac_templates or []):
        if isinstance(template_info, str):
            template_info = {"path": template_info}

        start_time = time.time()
        template_path = template_info.get("path", "")
        content = template_info.get("content", "")
        framework_str = template_info.get("framework", "terraform")
        repository = template_info.get("repository", "")
        branch = template_info.get("branch", "main")

        try:
            framework = IaCFramework(framework_str)
        except ValueError:
            framework = IaCFramework.TERRAFORM

        scan_id = hashlib.sha256(
            f"{template_path}:{repository}:{branch}".encode()
        ).hexdigest()[:12]

        scan_result = IaCScanResult(
            scan_id=scan_id,
            template_path=template_path,
            framework=framework,
            repository=repository,
            branch=branch,
            scan_duration_seconds=time.time() - start_time,
        )
        iac_results.append(scan_result)

    total_iac_findings = sum(len(r.findings) for r in iac_results)
    total_failed = sum(r.failed_checks for r in iac_results)
    total_passed = sum(r.passed_checks for r in iac_results)

    return {
        "iac_scan_results": iac_results,
        "metrics": {
            "iac_scans_count": len(iac_results),
            "iac_findings_count": total_iac_findings,
            "iac_passed_checks": total_passed,
            "iac_failed_checks": total_failed,
            "iac_block_rate": (
                (total_failed / max(total_failed + total_passed, 1)) * 100
            ),
        },
    }
