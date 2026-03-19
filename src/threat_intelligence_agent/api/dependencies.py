"""In-memory store singleton for the BFF API (MVP)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

_store_instance: InMemoryStore | None = None


class InMemoryStore:
    """Simple in-memory data store seeded with realistic demo data."""

    def __init__(self) -> None:
        self.iocs: list[dict[str, Any]] = []
        self.briefs: list[dict[str, Any]] = []
        self.actors: list[dict[str, Any]] = []
        self.feeds: list[dict[str, Any]] = []
        self.campaigns: list[dict[str, Any]] = []
        self.feedback: list[dict[str, Any]] = []
        self.audit_log: list[dict[str, Any]] = []
        self._seed()

    def _seed(self) -> None:
        """Pre-populate with realistic demo data."""
        now = datetime.now(timezone.utc)

        # ── Feeds ────────────────────────────────────────────────────────
        self.feeds = [
            {"feed_id": "feed-otx", "name": "AlienVault OTX", "source_type": "osint", "url": "https://otx.alienvault.com", "enabled": True, "last_poll": (now - timedelta(minutes=12)).isoformat(), "success_rate": 0.98, "ioc_yield": 342, "quality_score": 72.0, "false_positive_rate": 0.04},
            {"feed_id": "feed-abusech", "name": "abuse.ch URLhaus", "source_type": "osint", "url": "https://urlhaus-api.abuse.ch", "enabled": True, "last_poll": (now - timedelta(minutes=8)).isoformat(), "success_rate": 0.99, "ioc_yield": 567, "quality_score": 78.0, "false_positive_rate": 0.02},
            {"feed_id": "feed-circl", "name": "CIRCL TAXII", "source_type": "osint", "url": "https://www.circl.lu/taxii", "enabled": True, "last_poll": (now - timedelta(minutes=25)).isoformat(), "success_rate": 0.95, "ioc_yield": 189, "quality_score": 75.0, "false_positive_rate": 0.03},
            {"feed_id": "feed-commercial-1", "name": "Recorded Future", "source_type": "commercial", "url": "", "enabled": True, "last_poll": (now - timedelta(minutes=5)).isoformat(), "success_rate": 1.0, "ioc_yield": 823, "quality_score": 88.0, "false_positive_rate": 0.01},
            {"feed_id": "feed-isac-fs", "name": "FS-ISAC", "source_type": "isac", "url": "", "enabled": True, "last_poll": (now - timedelta(hours=1)).isoformat(), "success_rate": 0.97, "ioc_yield": 156, "quality_score": 82.0, "false_positive_rate": 0.02},
            {"feed_id": "feed-internal", "name": "Internal Malware Lab", "source_type": "internal", "url": "", "enabled": True, "last_poll": (now - timedelta(minutes=45)).isoformat(), "success_rate": 1.0, "ioc_yield": 78, "quality_score": 92.0, "false_positive_rate": 0.005},
        ]

        # ── Actors ───────────────────────────────────────────────────────
        self.actors = [
            {"actor_id": "actor-apt28", "name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Sednit"], "description": "Russian state-sponsored cyber espionage group attributed to GRU Unit 26165.", "targeted_sectors": ["government", "military", "media"], "targeted_regions": ["europe", "north_america"], "ttps": [{"technique_id": "T1566", "tactic": "Initial Access"}, {"technique_id": "T1059.001", "tactic": "Execution"}, {"technique_id": "T1071.001", "tactic": "C2"}], "campaigns": ["campaign-sofacy-2026"], "associated_iocs": ["ioc-apt28-c2-1", "ioc-apt28-c2-2"], "confidence": 92.0},
            {"actor_id": "actor-apt29", "name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "Nobelium"], "description": "Russian SVR-linked threat actor known for stealthy long-term access operations.", "targeted_sectors": ["government", "technology", "think_tanks"], "targeted_regions": ["north_america", "europe"], "ttps": [{"technique_id": "T1195.002", "tactic": "Initial Access"}, {"technique_id": "T1027", "tactic": "Defense Evasion"}], "campaigns": ["campaign-solarwinds"], "associated_iocs": ["ioc-apt29-domain-1"], "confidence": 95.0},
            {"actor_id": "actor-lazarus", "name": "Lazarus Group", "aliases": ["Hidden Cobra", "ZINC", "Diamond Sleet"], "description": "North Korean state-sponsored group conducting financial theft and espionage.", "targeted_sectors": ["financial_services", "cryptocurrency", "defense"], "targeted_regions": ["global"], "ttps": [{"technique_id": "T1566.001", "tactic": "Initial Access"}, {"technique_id": "T1486", "tactic": "Impact"}], "campaigns": ["campaign-applejeus"], "associated_iocs": ["ioc-lazarus-hash-1"], "confidence": 88.0},
            {"actor_id": "actor-fin7", "name": "FIN7", "aliases": ["Carbanak", "Navigator Group"], "description": "Financially motivated threat group targeting retail and hospitality sectors.", "targeted_sectors": ["retail", "hospitality", "financial_services"], "targeted_regions": ["north_america", "europe"], "ttps": [{"technique_id": "T1566.001", "tactic": "Initial Access"}, {"technique_id": "T1041", "tactic": "Exfiltration"}], "campaigns": ["campaign-carbanak-2026"], "associated_iocs": ["ioc-fin7-domain-1"], "confidence": 85.0},
            {"actor_id": "actor-sandworm", "name": "Sandworm", "aliases": ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard"], "description": "Russian GRU Unit 74455 responsible for destructive attacks against critical infrastructure.", "targeted_sectors": ["energy", "government", "telecom"], "targeted_regions": ["europe", "middle_east"], "ttps": [{"technique_id": "T1190", "tactic": "Initial Access"}, {"technique_id": "T1485", "tactic": "Impact"}], "campaigns": ["campaign-industroyer"], "associated_iocs": ["ioc-sandworm-ip-1"], "confidence": 90.0},
        ]

        # ── IOCs ─────────────────────────────────────────────────────────
        _ioc_seed = [
            ("ioc-001", "ip", "185.174.137.70", ["otx", "commercial"], "active", 82.5, 71.0, "TLP:GREEN", "APT28", ""),
            ("ioc-002", "domain", "c2-relay.malware-infra.xyz", ["abusech", "isac"], "active", 78.0, 65.0, "TLP:GREEN", "", ""),
            ("ioc-003", "hash_sha256", "e99a18c428cb38d5f260853678922e03abd7e3f3ebe9df71b8bfb6e7105a3f7c", ["commercial"], "active", 90.0, 80.0, "TLP:AMBER", "Lazarus Group", "campaign-applejeus"),
            ("ioc-004", "url", "https://phishing-login.example.com/auth", ["otx", "abusech", "isac"], "active", 88.0, 75.0, "TLP:GREEN", "FIN7", "campaign-carbanak-2026"),
            ("ioc-005", "ip", "91.234.99.42", ["commercial", "isac", "internal"], "active", 92.0, 85.0, "TLP:AMBER", "Sandworm", "campaign-industroyer"),
            ("ioc-006", "domain", "update-service-cdn.net", ["otx"], "new", 55.0, 45.0, "TLP:WHITE", "", ""),
            ("ioc-007", "hash_md5", "d41d8cd98f00b204e9800998ecf8427e", ["abusech"], "deprecated", 30.0, 20.0, "TLP:WHITE", "", ""),
            ("ioc-008", "email", "admin@suspicious-domain.ru", ["isac"], "active", 70.0, 60.0, "TLP:GREEN", "APT28", "campaign-sofacy-2026"),
            ("ioc-009", "ip", "198.51.100.23", ["internal"], "active", 85.0, 90.0, "TLP:AMBER", "APT29", "campaign-solarwinds"),
            ("ioc-010", "domain", "download-payload.evil.net", ["otx", "abusech", "commercial"], "active", 95.0, 78.0, "TLP:GREEN", "Lazarus Group", ""),
            ("ioc-011", "hash_sha256", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", ["commercial", "internal"], "active", 88.0, 82.0, "TLP:AMBER", "FIN7", ""),
            ("ioc-012", "ip", "203.0.113.50", ["otx"], "new", 48.0, 35.0, "TLP:WHITE", "", ""),
            ("ioc-013", "url", "https://malware-drop.site/payload.exe", ["abusech", "commercial"], "active", 91.0, 70.0, "TLP:GREEN", "Sandworm", ""),
            ("ioc-014", "domain", "legit-looking-cdn.cloud", ["isac", "internal"], "active", 76.0, 68.0, "TLP:AMBER", "APT29", ""),
            ("ioc-015", "ip", "10.0.0.1", ["internal"], "revoked", 10.0, 5.0, "TLP:WHITE", "", ""),
        ]
        for ioc_id, itype, val, sources, lifecycle, conf, rel, tlp, actor, camp in _ioc_seed:
            self.iocs.append({
                "ioc_id": ioc_id, "ioc_type": itype, "value": val, "sources": sources,
                "first_seen": (now - timedelta(days=len(ioc_id))).isoformat(),
                "last_seen": (now - timedelta(hours=len(sources))).isoformat(),
                "lifecycle": lifecycle, "confidence": conf, "relevance": rel,
                "tlp": tlp, "actor": actor, "campaign": camp,
                "labels": [], "provenance": [{"source": s, "timestamp": now.isoformat()} for s in sources],
            })

        # ── Briefs ───────────────────────────────────────────────────────
        self.briefs = [
            {"brief_id": "brief-str-001", "level": "strategic", "title": "Q1 2026 Strategic Threat Landscape", "executive_summary": "15 unique IOCs processed from 6 sources. Average confidence 74.8%. 10 IOCs assessed as organisationally relevant. Tracking 5 threat actors across 4 active campaigns.", "technical_analysis": "Top actors: APT28, APT29, Lazarus Group. Dominant tactics: Initial Access, Command and Control, Impact.", "ioc_appendix": [], "attck_mapping": [{"tactic": "Initial Access", "count": 5}, {"tactic": "Command and Control", "count": 4}, {"tactic": "Impact", "count": 2}], "recommendations": ["Review threat model alignment with current actor targeting patterns.", "Ensure detection coverage across identified ATT&CK techniques."], "created": (now - timedelta(hours=2)).isoformat(), "tlp": "TLP:AMBER"},
            {"brief_id": "brief-ops-001", "level": "operational", "title": "Operational Brief — APT28 Sofacy Campaign", "executive_summary": "APT28 campaign targeting government and military sectors with spearphishing and PowerShell-based execution. 3 high-relevance IOCs identified.", "technical_analysis": "Top actors: APT28. Campaign: Sofacy 2026. TTPs: T1566 (Phishing), T1059.001 (PowerShell), T1071.001 (Web Protocols).", "ioc_appendix": [{"ioc_id": "ioc-001", "value": "185.174.137.70", "relevance": 71.0}], "attck_mapping": [{"technique_id": "T1566", "tactic": "Initial Access"}], "recommendations": ["Prioritize monitoring for APT28 activity.", "Update threat model with newly mapped TTPs."], "created": (now - timedelta(hours=1)).isoformat(), "tlp": "TLP:AMBER"},
            {"brief_id": "brief-tac-001", "level": "tactical", "title": "Tactical IOC Feed — High-Confidence Indicators", "executive_summary": "10 high-confidence IOCs ready for operationalization.", "technical_analysis": "Total IOCs after deduplication: 15. High-confidence (≥70): 10. Mapped to 8 ATT&CK techniques.", "ioc_appendix": [{"ioc_id": "ioc-001", "type": "ip", "value": "185.174.137.70", "confidence": 82.5}], "attck_mapping": [{"technique_id": "T1566"}, {"technique_id": "T1059.001"}], "recommendations": ["Ingest high-confidence IOCs into SIEM detection rules.", "Block critical IP/domain IOCs at perimeter firewall."], "created": now.isoformat(), "tlp": "TLP:GREEN"},
        ]

        # ── Campaigns ────────────────────────────────────────────────────
        self.campaigns = [
            {"campaign_id": "campaign-sofacy-2026", "name": "Sofacy 2026", "actor": "APT28", "description": "Renewed phishing campaign targeting European government entities.", "start_date": "2026-01-15", "targeted_sectors": ["government", "military"], "targeted_regions": ["europe"], "ttps": [{"technique_id": "T1566"}], "iocs": ["ioc-001", "ioc-008"], "status": "active"},
            {"campaign_id": "campaign-solarwinds", "name": "SolarWinds Follow-on", "actor": "APT29", "description": "Supply chain compromise follow-on activity.", "start_date": "2025-11-01", "targeted_sectors": ["technology", "government"], "targeted_regions": ["north_america"], "ttps": [{"technique_id": "T1195.002"}], "iocs": ["ioc-009", "ioc-014"], "status": "active"},
            {"campaign_id": "campaign-applejeus", "name": "AppleJeus 3.0", "actor": "Lazarus Group", "description": "Cryptocurrency theft via trojanized trading applications.", "start_date": "2026-02-01", "targeted_sectors": ["financial_services", "cryptocurrency"], "targeted_regions": ["global"], "ttps": [{"technique_id": "T1566.001"}], "iocs": ["ioc-003"], "status": "active"},
            {"campaign_id": "campaign-carbanak-2026", "name": "Carbanak Revival", "actor": "FIN7", "description": "Financial fraud campaign targeting retail POS systems.", "start_date": "2026-03-01", "targeted_sectors": ["retail", "financial_services"], "targeted_regions": ["north_america"], "ttps": [{"technique_id": "T1566.001"}], "iocs": ["ioc-004", "ioc-011"], "status": "active"},
        ]

        self.audit_log.append({"timestamp": now.isoformat(), "action": "store_initialised", "detail": "Demo data seeded"})


def get_store() -> InMemoryStore:
    global _store_instance
    if _store_instance is None:
        _store_instance = InMemoryStore()
    return _store_instance
