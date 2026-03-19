"""Prometheus metrics for the Threat Intelligence Agent."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# ── Counters ─────────────────────────────────────────────────────────────────
IOCS_INGESTED = Counter(
    "ti_iocs_ingested_total",
    "Total IOCs ingested from all sources",
    ["source"],
)
IOCS_DISTRIBUTED = Counter(
    "ti_iocs_distributed_total",
    "Total IOCs distributed to detection tools",
    ["target"],
)
BRIEFS_GENERATED = Counter(
    "ti_briefs_generated_total",
    "Intelligence briefs produced",
    ["level"],
)
FEED_ERRORS = Counter(
    "ti_feed_errors_total",
    "Feed ingestion errors",
    ["source"],
)

# ── Histograms ───────────────────────────────────────────────────────────────
FEED_INGESTION_LATENCY = Histogram(
    "ti_feed_ingestion_latency_seconds",
    "Time to ingest feeds",
    buckets=[1, 5, 15, 30, 60, 120, 300],
)
IOC_DISTRIBUTION_LATENCY = Histogram(
    "ti_ioc_distribution_latency_seconds",
    "Time to distribute IOCs to a target",
    ["target"],
    buckets=[1, 5, 10, 30, 60],
)
PIPELINE_DURATION = Histogram(
    "ti_pipeline_duration_seconds",
    "Full pipeline execution time",
    buckets=[5, 15, 30, 60, 120, 300, 600],
)

# ── Gauges ───────────────────────────────────────────────────────────────────
ACTIVE_IOCS = Gauge("ti_active_iocs_count", "Currently active IOCs in the system")
FEED_SOURCES_CONNECTED = Gauge("ti_feed_sources_connected", "Number of healthy feed sources")
DEDUP_RATIO = Gauge("ti_dedup_ratio", "IOC deduplication ratio (1 = all unique)")
AVG_CONFIDENCE = Gauge("ti_avg_confidence_score", "Average IOC confidence score")

# ── Info ─────────────────────────────────────────────────────────────────────
AGENT_INFO = Info("ti_agent", "Threat Intelligence Agent build information")
AGENT_INFO.info({"version": "1.0.0", "agent": "threat_intelligence_agent"})
