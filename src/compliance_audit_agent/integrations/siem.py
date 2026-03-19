"""SIEM connector for evidence collection."""
from __future__ import annotations
from typing import Any
import structlog

log = structlog.get_logger()


class SIEMConnector:
    def __init__(self, base_url: str, api_key: str) -> None:
        self._base_url = base_url
        self._api_key = api_key

    def get_log_summary(self) -> list[dict[str, Any]]:
        """Return summarised security event logs as evidence."""
        # Real implementation would call self._base_url with auth header
        log.debug("siem.get_log_summary", url=self._base_url)
        return []
