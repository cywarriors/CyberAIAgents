"""Prometheus metrics for the VAPT agent."""

from prometheus_client import Counter, Gauge, Histogram, Info

VAPT_INFO = Info("vapt_agent", "VAPT Agent metadata")
VAPT_INFO.info({"version": "1.0.0", "srs": "SRS-CYBER-13"})

ENGAGEMENTS_TOTAL = Counter(
    "vapt_engagements_total",
    "Total VAPT engagements processed",
)

ENGAGEMENT_DURATION = Histogram(
    "vapt_engagement_duration_seconds",
    "Time to complete a full VAPT engagement pipeline",
    buckets=(30, 60, 120, 300, 600, 1800, 3600, 7200),
)

FINDINGS_TOTAL = Counter(
    "vapt_findings_total",
    "Total vulnerability findings discovered",
    ["severity"],
)

EXPLOITS_ATTEMPTED = Counter(
    "vapt_exploits_attempted_total",
    "Total exploit validations attempted",
)

EXPLOITS_SUCCESSFUL = Counter(
    "vapt_exploits_successful_total",
    "Total successful exploit validations",
)

ASSETS_DISCOVERED = Counter(
    "vapt_assets_discovered_total",
    "Total assets discovered across engagements",
)

ATTACK_PATHS_FOUND = Counter(
    "vapt_attack_paths_total",
    "Total attack paths identified",
)

REPORTS_GENERATED = Counter(
    "vapt_reports_generated_total",
    "Total report artifacts generated",
    ["report_type"],
)

TICKETS_CREATED = Counter(
    "vapt_tickets_created_total",
    "Total remediation tickets created",
)

NODE_ERRORS = Counter(
    "vapt_node_errors_total",
    "Errors encountered in graph nodes",
    ["node"],
)

ACTIVE_ENGAGEMENTS = Gauge(
    "vapt_active_engagements",
    "Currently active VAPT engagements",
)
