"""Prometheus metrics for the Incident Triage Agent (§10)."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# -- Counters ---------------------------------------------------------------
alerts_ingested_total = Counter(
    "ita_alerts_ingested_total",
    "Total alerts ingested for triage",
    ["source"],
)

incidents_triaged_total = Counter(
    "ita_incidents_triaged_total",
    "Total incidents triaged and published",
    ["priority", "classification"],
)

correlation_groups_total = Counter(
    "ita_correlation_groups_total",
    "Total correlation groups created",
)

enrichment_requests_total = Counter(
    "ita_enrichment_requests_total",
    "Total entity enrichment requests",
    ["entity_type"],
)

tickets_created_total = Counter(
    "ita_tickets_created_total",
    "Total ITSM tickets created",
    ["priority"],
)

ticket_creation_failures_total = Counter(
    "ita_ticket_creation_failures_total",
    "Total ITSM ticket creation failures",
)

feedback_received_total = Counter(
    "ita_feedback_received_total",
    "Total analyst feedback items received",
    ["verdict"],
)

correlation_errors_total = Counter(
    "ita_correlation_errors_total",
    "Correlation engine execution errors",
)

# -- Histograms -------------------------------------------------------------
triage_latency_seconds = Histogram(
    "ita_triage_latency_seconds",
    "Time from alert ingestion to triage completion (seconds)",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

enrichment_latency_seconds = Histogram(
    "ita_enrichment_latency_seconds",
    "Entity enrichment request latency (seconds)",
    buckets=[0.1, 0.5, 1, 2, 5, 10],
)

scoring_latency_seconds = Histogram(
    "ita_scoring_latency_seconds",
    "Priority scoring computation latency (seconds)",
    buckets=[0.1, 0.5, 1, 2, 5, 10],
)

# -- Gauges -----------------------------------------------------------------
ingestion_backlog_size = Gauge(
    "ita_ingestion_backlog_size",
    "Pending alerts awaiting triage",
)

enrichment_completeness_pct = Gauge(
    "ita_enrichment_completeness_pct",
    "Percentage of entities fully enriched",
)

feedback_backlog_size = Gauge(
    "ita_feedback_backlog_size",
    "Pending feedback items awaiting processing",
)

data_source_connected = Gauge(
    "ita_data_source_connected",
    "Whether a data source is currently connected (1=up, 0=down)",
    ["source"],
)

model_scoring_drift = Gauge(
    "ita_model_scoring_drift",
    "Scoring model drift from baseline (percentage)",
)

# -- Info -------------------------------------------------------------------
agent_info = Info(
    "ita_agent",
    "Incident Triage Agent build metadata",
)
agent_info.info({"version": "1.0.0", "srs": "SRS-CYBER-02"})
