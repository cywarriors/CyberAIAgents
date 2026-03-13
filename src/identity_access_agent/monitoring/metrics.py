"""Prometheus metrics for Identity & Access Monitoring Agent."""

from prometheus_client import Counter, Gauge, Histogram

# ── Counters ──────────────────────────────────────────────────

auth_events_processed_total = Counter(
    "iam_auth_events_processed_total",
    "Total authentication events processed",
    ["outcome"],
)

risk_scores_computed_total = Counter(
    "iam_risk_scores_computed_total",
    "Total identity risk scores computed",
    ["risk_level"],
)

alerts_created_total = Counter(
    "iam_alerts_created_total",
    "Total SOC alerts generated",
    ["severity"],
)

takeover_signals_total = Counter(
    "iam_takeover_signals_total",
    "Total account takeover signals detected",
    ["signal_type"],
)

privilege_changes_total = Counter(
    "iam_privilege_changes_total",
    "Total privilege change events processed",
    ["action"],
)

sod_violations_total = Counter(
    "iam_sod_violations_total",
    "Total SoD violations detected",
)

feedback_received_total = Counter(
    "iam_feedback_received_total",
    "Total analyst feedback items",
    ["feedback_verdict"],
)

recommendations_issued_total = Counter(
    "iam_recommendations_issued_total",
    "Total control recommendations issued",
    ["control"],
)

# ── Histograms ────────────────────────────────────────────────

pipeline_latency_seconds = Histogram(
    "iam_pipeline_latency_seconds",
    "Identity risk pipeline processing latency (seconds)",
    buckets=[0.5, 1, 2, 5, 10, 15, 30],
)

risk_score_distribution = Histogram(
    "iam_risk_score_distribution",
    "Distribution of computed identity risk scores",
    buckets=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
)

# ── Gauges ────────────────────────────────────────────────────

active_high_risk_users = Gauge(
    "iam_active_high_risk_users",
    "Current number of users with high/critical risk scores",
)

false_positive_rate = Gauge(
    "iam_false_positive_rate",
    "Current false positive rate (0.0-1.0)",
)

detection_rate = Gauge(
    "iam_detection_rate",
    "Current identity threat detection rate (0.0-1.0)",
)

data_source_connected = Gauge(
    "iam_data_source_connected",
    "Whether a data source is connected (1=up, 0=down)",
    ["source"],
)
