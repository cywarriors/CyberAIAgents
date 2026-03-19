"""Entry-point for the Compliance and Audit Agent."""

from __future__ import annotations

import uvicorn

from compliance_audit_agent.config import get_settings
from compliance_audit_agent.api.app import app  # noqa: F401 – imported for side-effects


def main() -> None:
    s = get_settings()
    uvicorn.run(
        "compliance_audit_agent.api.app:app",
        host="0.0.0.0",  # noqa: S104 - bound by container network policy
        port=s.api_port,
        reload=False,
        log_level=s.log_level.lower(),
    )


if __name__ == "__main__":
    main()
