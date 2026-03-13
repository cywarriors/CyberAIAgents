"""Prometheus metrics for Phishing Defense Agent."""

from prometheus_client import Counter, Gauge, Histogram

# ── Counters ──────────────────────────────────────────────────

emails_processed_total = Counter(
    "pda_emails_processed_total",
    "Total emails processed through verdict pipeline",
    ["verdict"],
)

verdicts_total = Counter(
    "pda_verdicts_total",
    "Total verdicts issued",
    ["verdict", "action"],
)

iocs_extracted_total = Counter(
    "pda_iocs_extracted_total",
    "Total IOCs extracted from phishing emails",
    ["ioc_type"],
)

quarantine_actions_total = Counter(
    "pda_quarantine_actions_total",
    "Total quarantine actions",
    ["action"],  # quarantine, release, delete
)

user_reports_total = Counter(
    "pda_user_reports_total",
    "Total user-reported phishing submissions",
)

feedback_received_total = Counter(
    "pda_feedback_received_total",
    "Total analyst feedback items",
    ["feedback_verdict"],
)

sandbox_requests_total = Counter(
    "pda_sandbox_requests_total",
    "Total sandbox detonation requests",
    ["type"],  # url, file
)

# ── Histograms ────────────────────────────────────────────────

verdict_latency_seconds = Histogram(
    "pda_verdict_latency_seconds",
    "Email verdict processing latency (seconds)",
    buckets=[0.5, 1, 2, 5, 10, 15, 30],
)

sandbox_latency_seconds = Histogram(
    "pda_sandbox_latency_seconds",
    "Sandbox detonation latency (seconds)",
    buckets=[1, 5, 10, 20, 30, 60],
)

# ── Gauges ────────────────────────────────────────────────────

quarantine_queue_size = Gauge(
    "pda_quarantine_queue_size",
    "Current number of emails in quarantine",
)

false_positive_rate = Gauge(
    "pda_false_positive_rate",
    "Current false positive rate (0.0-1.0)",
)

detection_rate = Gauge(
    "pda_detection_rate",
    "Current phishing detection rate (0.0-1.0)",
)

data_source_connected = Gauge(
    "pda_data_source_connected",
    "Whether a data source is connected (1=up, 0=down)",
    ["source"],
)
