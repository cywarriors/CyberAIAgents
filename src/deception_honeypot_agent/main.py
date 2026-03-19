"""Entry point for the Deception and Honeypot Agent."""
from __future__ import annotations
import logging
import uvicorn
from deception_honeypot_agent.config import get_settings
from deception_honeypot_agent.api.app import app

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def main() -> None:
    s = get_settings()
    log.info("Starting Deception Honeypot Agent", port=s.api_port)
    uvicorn.run(app, host="0.0.0.0", port=s.api_port, log_level=s.log_level.lower())  # noqa: S104


if __name__ == "__main__":
    main()
