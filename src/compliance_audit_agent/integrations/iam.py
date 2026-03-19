"""IAM connector for access control evidence."""
from __future__ import annotations
from typing import Any
import structlog

log = structlog.get_logger()


class IAMConnector:
    def __init__(self, base_url: str, api_key: str) -> None:
        self._base_url = base_url
        self._api_key = api_key

    def get_access_report(self) -> list[dict[str, Any]]:
        """Return user access entitlement report as evidence."""
        log.debug("iam.get_access_report", url=self._base_url)
        return []
