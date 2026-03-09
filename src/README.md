# Threat Detection Agent (SRS-01)

AI-powered Threat Detection Agent that identifies malicious or anomalous activity across enterprise security telemetry in near real time, built with **LangGraph**.

## Architecture

```
Telemetry Sources → Kafka/EventHub → LangGraph Pipeline → Alerts
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              ▼                          ▼                          ▼
        RuleMatchNode           BehaviorAnomalyNode          (parallel)
              │                          │
              └──────────┬───────────────┘
                         ▼
               ScoreAndPrioritize → Deduplicate → PublishAlert → Feedback
```

### Pipeline Nodes

| Node | Purpose |
|------|---------|
| IngestTelemetry | Consume events from Kafka / API |
| NormalizeSchema | Map raw events to OCSF/ECS |
| RuleMatch | MITRE ATT&CK rule-based detections |
| BehaviorAnomaly | ML baseline anomaly scoring |
| ScoreAndPrioritize | Merge + severity/confidence assignment |
| Deduplicate | Suppress duplicate alerts |
| PublishAlert | Publish to SIEM, ticketing, SOC chat |
| FeedbackUpdate | Process analyst feedback |

### Detection Rules (MITRE ATT&CK Mapped)

| Rule ID | Technique | Description |
|---------|-----------|-------------|
| RULE-AUTH-001 | T1110 | Brute Force – Excessive Failed Logins |
| RULE-AUTH-002 | T1078 | Impossible Travel – Anomalous Geolocation |
| RULE-NET-001 | T1041 | Data Exfiltration – Large Outbound Transfer |
| RULE-DNS-001 | T1071.004 | DNS Tunnelling – High Query Volume |
| RULE-IAM-001 | T1078.003 | Privilege Escalation – Unexpected Role Change |
| RULE-NET-002 | T1021 | Lateral Movement – Internal Remote Service |
| RULE-END-001 | T1059 | Suspicious Encoded Command Execution |

## Quick Start

### 1. Install dependencies

```bash
cd src
pip install -r requirements.txt
```

### 2. Run tests with mock data

```bash
# Unit tests
python -m pytest tests/unit -v

# Integration tests (full pipeline with mock telemetry)
python -m pytest tests/integration -v

# Detection scenario coverage tests
python -m pytest tests/integration/test_detection.py -v

# All tests
python -m pytest tests/ -v --tb=short
```

### 3. Run locally with Docker Compose

```bash
cd src/deploy
docker compose up --build
```

### 4. Run the agent standalone

```bash
cd src
cp .env.example .env   # edit with your values
python -m threat_detection_agent.main
```

## Project Structure

```
src/
├── threat_detection_agent/
│   ├── config.py                  # Settings from env vars
│   ├── graph.py                   # LangGraph pipeline definition
│   ├── main.py                    # Entry point (Kafka consumer + health server)
│   ├── models/
│   │   ├── alerts.py              # Alert, RuleMatch, AnomalyResult models
│   │   ├── events.py              # RawEvent, NormalizedEvent models
│   │   └── state.py               # EventBatchState (LangGraph state)
│   ├── nodes/
│   │   ├── ingest.py              # IngestTelemetryNode
│   │   ├── normalize.py           # NormalizeSchemaNode
│   │   ├── rule_match.py          # RuleMatchNode
│   │   ├── anomaly.py             # BehaviorAnomalyNode
│   │   ├── score.py               # ScoreAndPrioritizeNode
│   │   ├── deduplicate.py         # DeduplicateNode
│   │   ├── publish.py             # PublishAlertNode
│   │   └── feedback.py            # FeedbackUpdateNode
│   ├── rules/
│   │   ├── base_rules.py          # 7 MITRE ATT&CK–mapped rules
│   │   └── engine.py              # Configurable rules engine
│   ├── integrations/
│   │   ├── siem.py                # SIEM REST client
│   │   ├── edr.py                 # EDR REST client
│   │   ├── ticketing.py           # ServiceNow / Jira client
│   │   ├── messaging.py           # Teams / Slack webhook
│   │   ├── threat_intel.py        # IOC feed client
│   │   └── asset_inventory.py     # CMDB enrichment client
│   └── monitoring/
│       ├── metrics.py             # Prometheus counters/histograms/gauges
│       └── health.py              # /healthz, /readyz, /metrics endpoints
├── tests/
│   ├── conftest.py                # Shared fixtures + dedup cache reset
│   ├── mocks/
│   │   ├── generators.py          # Mock telemetry generators (benign + attack)
│   │   └── scenarios.py           # Named attack scenarios for detection tests
│   ├── unit/                      # Per-node unit tests
│   └── integration/               # Full pipeline + detection coverage tests
├── deploy/
│   ├── Dockerfile                 # Production container image
│   ├── docker-compose.yml         # Local dev stack (Kafka, Redis, Postgres)
│   └── k8s/                       # Kubernetes manifests (Deployment, Service, HPA, ConfigMap)
├── .github/workflows/ci.yml       # CI/CD pipeline
├── .env.example                   # Environment variable template
├── requirements.txt
└── pyproject.toml
```

## Monitoring

| Endpoint | Purpose |
|----------|---------|
| `GET /healthz` | Liveness probe |
| `GET /readyz` | Readiness probe |
| `GET /metrics` | Prometheus metrics |

## Configuration

All settings are loaded from environment variables (see `.env.example`). Key tunables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEDUP_WINDOW_SECONDS` | 300 | Duplicate suppression window |
| `SEVERITY_THRESHOLD_FOR_PAGING` | Critical | Min severity for SOC paging |
| `CONFIDENCE_THRESHOLD` | 50 | Min confidence to publish alert |

## SRS Reference

This implementation fulfils **SRS-CYBER-01 v2.0** — see [`srs/srs-01-threat-detection-agent.md`](../srs/srs-01-threat-detection-agent.md).
