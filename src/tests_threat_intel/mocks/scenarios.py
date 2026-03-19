"""
scenarios.py – Pre-defined test scenarios for Threat Intelligence Agent integration tests.

Each scenario mimics a realistic operational situation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .generators import (
    generate_osint_intel_record,
    generate_commercial_intel_record,
    generate_isac_intel_record,
    generate_internal_ioc,
    generate_benign_intel_record,
    generate_stale_ioc,
    generate_duplicate_ioc_pair,
    generate_high_relevance_ioc,
    generate_low_relevance_ioc,
    generate_mixed_intel_batch,
)


@dataclass
class IntelScenario:
    name: str
    description: str
    raw_intel: list[dict[str, Any]]
    expected_min_iocs: int = 1
    expected_min_briefs: int = 1
    expect_distribution: bool = True
    expect_dedup: bool = False
    expect_stale_removal: bool = False
    tags: list[str] = field(default_factory=list)


def _build_apt_campaign_scenario() -> IntelScenario:
    """Multiple high-confidence IOCs from an APT campaign across sources."""
    intel = [
        generate_commercial_intel_record("domain"),
        generate_commercial_intel_record("ip"),
        generate_isac_intel_record("hash"),
        generate_internal_ioc("ip"),
        generate_high_relevance_ioc("financial"),
    ]
    return IntelScenario(
        name="APT Campaign Discovery",
        description="Cross-source APT campaign detection with high-confidence IOCs",
        raw_intel=intel,
        expected_min_iocs=4,
        expected_min_briefs=1,
        expect_distribution=True,
        tags=["apt", "multi-source", "financial"],
    )


def _build_zero_day_surge_scenario() -> IntelScenario:
    """Sudden influx of zero-day IOCs from OSINT."""
    intel = [generate_osint_intel_record("ip") for _ in range(10)]
    intel += [generate_osint_intel_record("domain") for _ in range(5)]
    return IntelScenario(
        name="Zero-Day IOC Surge",
        description="High-volume OSINT IOC surge requiring rapid triage",
        raw_intel=intel,
        expected_min_iocs=10,
        expected_min_briefs=1,
        expect_distribution=True,
        tags=["zero-day", "osint", "high-volume"],
    )


def _build_stale_ioc_deprecation_scenario() -> IntelScenario:
    """Mix of fresh and stale IOCs to test auto-deprecation logic."""
    intel = [generate_stale_ioc(days_old=d) for d in [200, 300, 365]]
    intel += [generate_osint_intel_record("ip") for _ in range(3)]
    return IntelScenario(
        name="Stale IOC Deprecation",
        description="Auto-deprecation triggered for IOCs older than 180 days",
        raw_intel=intel,
        expected_min_iocs=3,
        expected_min_briefs=1,
        expect_distribution=False,
        expect_stale_removal=True,
        tags=["lifecycle", "deprecation", "stale"],
    )


def _build_poisoned_feed_scenario() -> IntelScenario:
    """Feed containing benign IPs mixed with malicious indicators (poisoning simulation)."""
    intel = [generate_benign_intel_record() for _ in range(5)]
    intel += [generate_commercial_intel_record("ip") for _ in range(5)]
    return IntelScenario(
        name="Poisoned Feed Detection",
        description="Feed contains known-benign indicators mixed with real IOCs",
        raw_intel=intel,
        expected_min_iocs=3,
        expected_min_briefs=1,
        expect_distribution=False,
        tags=["feed-quality", "false-positive", "poisoned"],
    )


def _build_corroboration_scenario() -> IntelScenario:
    """Same IOC appearing in 3+ sources — tests corroboration score boost."""
    dup1, dup2 = generate_duplicate_ioc_pair()
    dup3 = generate_internal_ioc("ip")
    dup3["value"] = dup1["value"]  # force same value for max corroboration
    dup3["ioc_type"] = "ip"
    intel = [dup1, dup2, dup3]
    return IntelScenario(
        name="Cross-Source Corroboration",
        description="Same IOC from 3 sources should receive corroboration confidence boost",
        raw_intel=intel,
        expected_min_iocs=1,
        expected_min_briefs=1,
        expect_dedup=True,
        expect_distribution=True,
        tags=["deduplication", "corroboration", "confidence"],
    )


def _build_sector_relevance_scenario() -> IntelScenario:
    """Mix of sector-specific and irrelevant IOCs to test relevance filtering."""
    intel = [generate_high_relevance_ioc("financial") for _ in range(4)]
    intel += [generate_low_relevance_ioc() for _ in range(4)]
    return IntelScenario(
        name="Sector-Specific Relevance",
        description="Only financial-sector-relevant IOCs should score high in relevance",
        raw_intel=intel,
        expected_min_iocs=3,
        expected_min_briefs=1,
        expect_distribution=True,
        tags=["relevance", "sector", "filtering"],
    )


def _build_tlp_restricted_scenario() -> IntelScenario:
    """TLP:RED IOCs must not be auto-distributed to SIEM/EDR."""
    intel = [generate_internal_ioc("ip") for _ in range(3)]  # TLP:RED
    return IntelScenario(
        name="TLP-Restricted Intel",
        description="TLP:RED indicators must not be auto-distributed",
        raw_intel=intel,
        expected_min_iocs=2,
        expected_min_briefs=1,
        expect_distribution=False,  # RED must not be distributed automatically
        tags=["tlp", "access-control", "restriction"],
    )


def _build_duplicate_merge_scenario() -> IntelScenario:
    """Duplicate IOCs from different sources should be merged with combined provenance."""
    pairs = [generate_duplicate_ioc_pair() for _ in range(5)]
    intel = [rec for pair in pairs for rec in pair]
    return IntelScenario(
        name="Duplicate IOC Merge",
        description="Duplicate IOCs from different sources merged with combined provenance",
        raw_intel=intel,
        expected_min_iocs=4,
        expected_min_briefs=1,
        expect_dedup=True,
        expect_distribution=True,
        tags=["deduplication", "merge", "provenance"],
    )


# ── Public scenario list ─────────────────────────────────────────────────────

SCENARIOS: list[IntelScenario] = [
    _build_apt_campaign_scenario(),
    _build_zero_day_surge_scenario(),
    _build_stale_ioc_deprecation_scenario(),
    _build_poisoned_feed_scenario(),
    _build_corroboration_scenario(),
    _build_sector_relevance_scenario(),
    _build_tlp_restricted_scenario(),
    _build_duplicate_merge_scenario(),
]
