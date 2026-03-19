"""Cloud platform connector (AWS/Azure/GCP) for configuration evidence."""
from __future__ import annotations
from typing import Any
import structlog

log = structlog.get_logger()


class CloudConnector:
    def __init__(self, aws_url: str = "", aws_key: str = "",
                 azure_url: str = "", azure_key: str = "",
                 gcp_url: str = "", gcp_key: str = "") -> None:
        self._aws = (aws_url, aws_key)
        self._azure = (azure_url, azure_key)
        self._gcp = (gcp_url, gcp_key)

    def get_config_snapshot(self) -> list[dict[str, Any]]:
        """Return cloud configuration compliance snapshot."""
        log.debug("cloud.get_config_snapshot")
        return []
