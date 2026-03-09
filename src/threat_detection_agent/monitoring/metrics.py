"""Prometheus metrics for the Threat Detection Agent (§10)."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info

# -- Counters ---------------------------------------------------------------
events_ingested_total = Counter(
    "tda_events_ingested_total",
    "Total raw events ingested",
    ["source"],
)

alerts_published_total = Counter(
    "tda_alerts_published_total",
    "Total alerts published to downstream systems",
    ["severity", "destination"],
)

rule_matches_total = Counter(
    "tda_rule_matches_total",
    "Total detection rule matches",
    ["rule_id"],
)

anomalies_detected_total = Counter(
    "tda_anomalies_detected_total",
    "Total ML anomalies detected",
    ["anomaly_type"],
)

duplicates_suppressed_total = Counter(
    "tda_duplicates_suppressed_total",
    "Total duplicate alerts suppressed",
)

feedback_received_total = Counter(
    "tda_feedback_received_total",
    "Total analyst feedback items received",
    ["verdict"],
)

rule_errors_total = Counter(
    "tda_rule_errors_total",
    "Detection rule execution errors",
    ["rule_id"],
)

# -- Histograms -------------------------------------------------------------
alert_latency_seconds = Histogram(
    "tda_alert_latency_seconds",
    "Time from event ingestion to alert publication (seconds)",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

model_inference_latency_seconds = Histogram(
    "tda_model_inference_latency_seconds",
    "Anomaly model inference latency (seconds)",
    buckets=[0.1, 0.5, 1, 2, 5, 10],
)

# -- Gauges -----------------------------------------------------------------
ingestion_lag_seconds = Gauge(
    "tda_ingestion_lag_seconds",
    "Current ingestion lag in seconds",
)

feedback_backlog_size = Gauge(
    "tda_feedback_backlog_size",
    "Pending feedback items awaiting processing",
)

data_source_connected = Gauge(
    "tda_data_source_connected",
    "Whether a data source is currently connected (1=up, 0=down)",
    ["source"],
)

# -- Info -------------------------------------------------------------------
agent_info = Info(
    "tda_agent",
    "Threat Detection Agent build metadata",
)
agent_info.info({"version": "1.0.0", "srs": "SRS-CYBER-01"})
