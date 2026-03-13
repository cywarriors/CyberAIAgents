"""IaC template scanner for Terraform, CloudFormation, and Bicep."""

from typing import Any
from cloud_security_agent.models import IaCScanResult, IaCFramework, PolicyFinding


class IaCScanner:
    """Base IaC scanner."""

    async def scan_template(
        self,
        template_content: str,
        template_path: str,
        framework: IaCFramework,
        repository: str = "",
        branch: str = "main",
    ) -> IaCScanResult:
        """Scan an IaC template for misconfigurations."""
        raise NotImplementedError


class TerraformScanner(IaCScanner):
    """Terraform template scanner."""

    async def scan_template(
        self,
        template_content: str,
        template_path: str,
        framework: IaCFramework = IaCFramework.TERRAFORM,
        repository: str = "",
        branch: str = "main",
    ) -> IaCScanResult:
        """Scan Terraform template."""
        return IaCScanResult(
            scan_id="",
            template_path=template_path,
            framework=framework,
            repository=repository,
            branch=branch,
        )


class CloudFormationScanner(IaCScanner):
    """CloudFormation template scanner."""

    async def scan_template(
        self,
        template_content: str,
        template_path: str,
        framework: IaCFramework = IaCFramework.CLOUDFORMATION,
        repository: str = "",
        branch: str = "main",
    ) -> IaCScanResult:
        """Scan CloudFormation template."""
        return IaCScanResult(
            scan_id="",
            template_path=template_path,
            framework=framework,
            repository=repository,
            branch=branch,
        )


class BicepScanner(IaCScanner):
    """Bicep template scanner."""

    async def scan_template(
        self,
        template_content: str,
        template_path: str,
        framework: IaCFramework = IaCFramework.BICEP,
        repository: str = "",
        branch: str = "main",
    ) -> IaCScanResult:
        """Scan Bicep template."""
        return IaCScanResult(
            scan_id="",
            template_path=template_path,
            framework=framework,
            repository=repository,
            branch=branch,
        )


def get_iac_scanner(framework: IaCFramework) -> IaCScanner:
    """Factory for IaC scanners."""
    scanners = {
        IaCFramework.TERRAFORM: TerraformScanner,
        IaCFramework.CLOUDFORMATION: CloudFormationScanner,
        IaCFramework.BICEP: BicepScanner,
    }
    scanner_cls = scanners.get(framework)
    if not scanner_cls:
        raise ValueError(f"Unsupported IaC framework: {framework}")
    return scanner_cls()
