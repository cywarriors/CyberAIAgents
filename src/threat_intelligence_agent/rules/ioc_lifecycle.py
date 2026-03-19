"""IOC lifecycle management rules."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class IOCLifecycleEngine:
    """Manage IOC aging, deprecation, and revocation.

    Rules:
    - IOCs older than ``max_age_days`` are auto-deprecated.
    - Analyst can revoke IOCs with justification.
    - Re-activation is allowed when fresh corroboration arrives.
    """

    def __init__(self, max_age_days: int = 90) -> None:
        self.max_age_days = max_age_days

    def evaluate(self, iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return IOCs with updated lifecycle status."""
        now = datetime.now(timezone.utc)
        updated: list[dict[str, Any]] = []

        for ioc in iocs:
            lifecycle = ioc.get("lifecycle", "new")

            # Skip already-revoked IOCs
            if lifecycle == "revoked":
                updated.append(ioc)
                continue

            # Age-based deprecation
            first_seen = ioc.get("first_seen", "")
            if first_seen and lifecycle not in ("deprecated", "revoked"):
                try:
                    dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                    age_days = (now - dt).days
                    if age_days > self.max_age_days:
                        ioc["lifecycle"] = "deprecated"
                        updated.append(ioc)
                        continue
                except (ValueError, TypeError):
                    pass

            # Transition new → active when corroborated by 2+ sources
            if lifecycle == "new" and len(ioc.get("sources", [])) >= 2:
                ioc["lifecycle"] = "active"

            updated.append(ioc)

        return updated

    def deprecate(self, ioc: dict[str, Any], reason: str = "") -> dict[str, Any]:
        ioc["lifecycle"] = "deprecated"
        ioc["deprecation_reason"] = reason
        return ioc

    def revoke(self, ioc: dict[str, Any], reason: str = "") -> dict[str, Any]:
        ioc["lifecycle"] = "revoked"
        ioc["revocation_reason"] = reason
        return ioc

    def reactivate(self, ioc: dict[str, Any]) -> dict[str, Any]:
        if ioc.get("lifecycle") in ("deprecated",):
            ioc["lifecycle"] = "active"
        return ioc
