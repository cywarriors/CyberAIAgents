# SRS-02: Incident Triage Agent

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| Document ID        | SRS-CYBER-02                                   |
| Version            | 2.0                                            |
| Status             | Production-Ready                               |
| Classification     | Internal-Confidential                          |
| Author             | Cybersecurity AI Engineering Team               |
| Reviewer           | SOC Manager, Incident Response Lead             |
| Approver           | CISO                                           |
| Created            | 2026-03-07                                     |
| Last Updated       | 2026-03-07                                     |

---

## 1. Introduction

### 1.1 Purpose
This SRS defines requirements for an AI-powered Incident Triage Agent that enriches, correlates, and prioritizes security alerts to accelerate SOC analyst decision-making and reduce mean time to triage.

### 1.2 Intended Audience
- Tier-1 and Tier-2 SOC analysts
- Incident response leads
- Security engineering and architecture teams
- Governance and audit stakeholders

### 1.3 Definitions and Acronyms

| Term    | Definition                                                   |
|---------|--------------------------------------------------------------|
| CMDB    | Configuration Management Database                            |
| ITSM    | IT Service Management                                        |
| MTTT    | Mean Time to Triage                                          |
| SOC     | Security Operations Center                                   |
| TTP     | Tactics, Techniques, and Procedures                          |

---

## 2. Scope

### 2.1 In Scope
- Alert ingestion from SIEM and EDR systems.
- Cross-alert correlation by entity, time window, and attack chain.
- Entity enrichment (user, host, asset criticality, geolocation, vulnerability context).
- Priority scoring (P1-P4), classification, and triage summary generation.
- Recommended investigative next actions and ticket lifecycle management.

### 2.2 Out of Scope
- Direct containment/response execution (covered by SRS-03).
- Long-term threat hunting campaigns.
- Initial alert/detection creation (covered by SRS-01).

---

## 3. Stakeholders

| Role                    | Responsibility                                    |
|-------------------------|--------------------------------------------------|
| SOC Analyst (Tier 1/2)  | Act on triaged incidents, provide feedback         |
| Incident Response Lead  | Review P1/P2 incidents, approve classifications    |
| Security Engineering    | Maintain enrichment integrations                   |
| Governance / Audit      | Validate triage audit trail completeness           |
| CISO                    | Approve deployment and oversee operational metrics |

---

## 4. Assumptions and Constraints

### 4.1 Assumptions
- Alerts arrive from at least one SIEM source with entity identifiers.
- CMDB asset criticality data and identity directory are available and current.
- ITSM/ticketing APIs support programmatic create and update.

### 4.2 Constraints
- Human analyst remains the final decision authority for incident closure and escalation.
- Enrichment data freshness must be within 15 minutes of source update.
- Triage latency must not exceed 30 seconds (p95) per incident.

---

## 5. Functional Requirements

| ID     | Requirement                                                                                       | Priority |
|--------|---------------------------------------------------------------------------------------------------|----------|
| FR-01  | System SHALL ingest alerts from SIEM and EDR systems in near real time.                           | Must     |
| FR-02  | System SHALL correlate related alerts by entity, time window, and ATT&CK attack chain.            | Must     |
| FR-03  | System SHALL enrich alerts with user role, host criticality, geolocation, and vulnerability data.  | Must     |
| FR-04  | System SHALL compute incident priority score (P1-P4) using configurable weighting formula.        | Must     |
| FR-05  | System SHALL propose initial incident classification (malware, phishing, credential abuse, insider, etc.). | Must |
| FR-06  | System SHALL generate analyst-ready triage summary in structured plain language.                   | Must     |
| FR-07  | System SHALL recommend prioritized investigative next actions.                                    | Must     |
| FR-08  | System SHALL create or update ticket records with enriched incident data and timeline.             | Must     |
| FR-09  | System SHALL learn from analyst disposition outcomes to improve scoring accuracy.                  | Should   |
| FR-10  | System SHALL maintain incident timeline across all merged and correlated alerts.                   | Must     |
| FR-11  | System SHALL support configurable correlation rules and enrichment source weights.                | Should   |
| FR-12  | System SHALL flag stale or incomplete enrichment data with quality indicators.                    | Should   |

---

## 6. Non-Functional Requirements

| ID      | Requirement                                        | Target                  |
|---------|----------------------------------------------------|-------------------------|
| NFR-01  | Priority score generation latency (p95)            | < 30 seconds/incident   |
| NFR-02  | Enrichment data completeness (onboarded systems)   | > 95%                   |
| NFR-03  | Service uptime                                     | 99.9% monthly           |
| NFR-04  | Recommendation precision improvement               | Measurable monthly gain |
| NFR-05  | Horizontal scalability                             | Linear to 10K alerts/hr |
| NFR-06  | RTO                                                | < 15 minutes            |
| NFR-07  | RPO                                                | < 2 minutes             |

---

## 7. Data Requirements

### 7.1 Inputs
- SIEM alerts and EDR detections with entity identifiers.
- IAM logs and user directory attributes.
- CMDB asset records with criticality and ownership.
- Threat intelligence tags and vulnerability exposure data.

### 7.2 Outputs
- Prioritized incident objects with severity, classification, and confidence.
- Analyst-ready triage summaries with entity context.
- Recommended next investigative actions.
- Ticket payloads (create/update) with enriched fields.

### 7.3 Retention
- Incident metadata and triage decisions: 12 months.
- Training feedback data: 18 months.
- Enrichment cache: 30 days rolling.

---

## 8. Integration Requirements

| System                   | Protocol / Method | Direction  | Purpose                           |
|--------------------------|-------------------|------------|-----------------------------------|
| SIEM (Splunk/Sentinel)   | REST API / Kafka  | Inbound    | Alert ingestion                   |
| EDR (Defender/CrowdStrike)| REST API         | Inbound    | Detection enrichment              |
| Identity Directory        | LDAP / Graph API | Inbound    | User context enrichment           |
| CMDB                     | REST API          | Inbound    | Asset criticality lookup          |
| Threat Intel Platform    | STIX/TAXII or API | Inbound    | IOC and TTP context               |
| ITSM (ServiceNow/Jira)  | REST API          | Outbound   | Ticket create/update              |
| Messaging (Teams/Slack)  | Webhook           | Outbound   | P1/P2 notification                |

---

## 9. Security and Privacy Requirements

| ID      | Requirement                                                                        |
|---------|------------------------------------------------------------------------------------|
| SEC-01  | Enrichment access SHALL follow least privilege with just-in-time credential issuance.|
| SEC-02  | Analyst notes and evidence updates SHALL be fully auditable and tamper-evident.      |
| SEC-03  | Sensitive user fields SHALL be redacted in low-privilege analyst views.              |
| SEC-04  | All inter-service calls SHALL use mutual TLS.                                       |
| SEC-05  | Data at rest SHALL be encrypted with AES-256 or equivalent.                         |
| SEC-06  | Service account credentials SHALL rotate automatically via managed vault.           |

---

## 10. Monitoring and Observability

| Metric                              | Alert Threshold         | Dashboard   |
|--------------------------------------|-------------------------|-------------|
| Triage latency (p95)                | > 30 seconds            | Real-time   |
| Enrichment completeness rate         | < 95%                   | Hourly      |
| Correlation engine error rate        | > 0.5%                  | Real-time   |
| Alert ingestion backlog             | > 1,000 pending         | Real-time   |
| Ticket creation failure rate        | > 1%                    | Hourly      |
| Model scoring drift                 | Baseline deviation > 10%| Weekly      |

---

## 11. Deployment and Environment

### 11.1 Target Environment
- Cloud-native Kubernetes deployment (AKS/EKS/GKE).
- LangGraph orchestrator as stateless pods with shared checkpoint store.
- Enrichment microservices deployed as sidecar or independent services.

### 11.2 Infrastructure Requirements
- Compute: minimum 4 vCPU / 16 GB RAM per worker; auto-scaling.
- Storage: managed database for incident graph; Redis for enrichment cache.
- Networking: private subnets; service mesh with mTLS.

### 11.3 CI/CD
- GitOps pipeline with automated unit, integration, and regression tests.
- Canary deployment for scoring model updates.
- Rollback within 5 minutes.

---

## 12. Framework Implementation (LangGraph)

### 12.1 Graph Design
- **Graph Type**: Alert-to-incident triage graph with enrichment fan-out.
- **State Model**: `TriageState`
  - `raw_alerts: list[Alert]`
  - `entity_context: dict[str, EntityProfile]`
  - `correlations: list[CorrelationGroup]`
  - `priority_score: PriorityScore`
  - `triage_summary: str`
  - `recommended_actions: list[Action]`
  - `case_id: str`

### 12.2 Node Definitions

| Node                    | Responsibility                                          | Tool Access         |
|-------------------------|---------------------------------------------------------|---------------------|
| IngestAlertNode         | Consume alerts from SIEM/EDR queue                      | Kafka/API           |
| CorrelateIncidentNode   | Group related alerts by entity and attack chain          | Graph store         |
| EnrichEntityNode        | Fetch user, host, asset, and vuln context                | CMDB/IAM/TI APIs   |
| RiskScoreNode           | Compute priority (P1-P4) with configurable weights       | Scoring engine     |
| GenerateSummaryNode     | Create structured triage summary with key findings       | LLM service        |
| RecommendActionsNode    | Suggest prioritized investigative steps                  | Playbook catalog   |
| CreateOrUpdateCaseNode  | Open/update ITSM ticket with enriched payload            | ITSM API           |
| FeedbackLearnNode       | Ingest analyst disposition and queue for model update     | Feedback store     |

### 12.3 Control Flow
```
Start -> IngestAlert -> CorrelateIncident -> EnrichEntity
  -> RiskScore -> GenerateSummary -> RecommendActions
  -> CreateOrUpdateCase -> FeedbackLearn -> End
```

### 12.4 Human-in-the-Loop
- **Checkpoint**: Analyst confirms or overrides priority and classification before incident closure.
- **Override**: Analyst can re-classify, merge, or split correlated incidents.

---

## 13. Reference Architecture

```
+------------------+     +------------------+     +---------------------+
| Alert Sources    | --> | Message Queue    | --> | LangGraph Triage    |
| (SIEM/EDR)       |     | (Kafka/EventHub) |     | Workers (K8s Pods)  |
+------------------+     +------------------+     +---------------------+
                                                        |
                                          +-------------+-------------+
                                          v             v             v
                                   +-----------+  +---------+  +-----------+
                                   | CMDB/IAM  |  | Threat  |  | Vuln      |
                                   | Enrichment|  | Intel   |  | Context   |
                                   +-----------+  +---------+  +-----------+
                                          |             |             |
                                          +------Merge Context-------+
                                                    |
                                          +---------v---------+
                                          | Score + Summarize  |
                                          +---------+---------+
                                                    |
                                    +---------------+---------------+
                                    v               v               v
                              +-----------+  +-------------+  +----------+
                              | ITSM      |  | SOC Console |  | ChatOps  |
                              | Tickets   |  | Dashboard   |  | Notify   |
                              +-----------+  +-------------+  +----------+

Governance: Incident Graph Store | Feedback DB | Audit Logs | Checkpoint DB
```

---

## 14. Testing Strategy

| Test Type            | Scope                                                      | Frequency      |
|----------------------|------------------------------------------------------------|----------------|
| Unit Tests           | Scoring logic, enrichment mappers, correlation rules        | Every commit   |
| Integration Tests    | Full triage pipeline with simulated alerts                  | Every PR       |
| Accuracy Tests       | Priority agreement vs analyst panel decisions               | Bi-weekly      |
| Load Tests           | 10K alerts/hr sustained with latency measurement            | Monthly        |
| Chaos Tests          | Enrichment source failure; queue backpressure               | Quarterly      |
| UAT                  | Analyst validation of triage quality in shadow mode         | Pre-production |

---

## 15. Cross-Agent Dependencies

| Dependency Agent              | Relationship                                              |
|-------------------------------|-----------------------------------------------------------|
| SRS-01: Threat Detection      | Provides alerts consumed by this agent                    |
| SRS-03: Automated Response    | Receives triaged P1/P2 incidents for containment          |
| SRS-09: Threat Intelligence   | Supplies TTP context for enrichment                       |
| SRS-06: Identity Monitoring   | Provides identity risk scores for user enrichment         |

---

## 16. Risk Register

| Risk                                   | Likelihood | Impact | Mitigation                                                 |
|----------------------------------------|------------|--------|------------------------------------------------------------|
| Enrichment source latency degrades triage SLA | Medium | High | Timeout with partial-enrichment fallback; async enrichment |
| Priority misclassification erodes analyst trust | Medium | High | Shadow mode validation; monthly accuracy reviews          |
| Correlation over-merging creates mega-incidents | Low    | Medium| Configurable correlation window limits; split capability   |
| CMDB data staleness leads to wrong priority     | Medium | Medium| CMDB freshness monitoring; stale-data quality flags       |
| Single point of failure in scoring service      | Low    | High  | Redundant replicas; health checks; auto-failover          |

---

## 17. How to Use This Agent

### 17.1 Initial Setup
1. Configure alert source connections and define ingestion priority weights.
2. Bind CMDB, identity directory, and threat intel enrichment APIs.
3. Deploy LangGraph triage workers and checkpoint store.

### 17.2 Pilot Phase (Weeks 1-3)
4. Run in **shadow mode** — agent scores and summarizes, but analysts use existing workflow.
5. Compare agent priority assignments against analyst decisions; target >= 85% agreement.
6. Tune correlation windows and scoring weights based on pilot data.

### 17.3 Production Rollout
7. Enable auto-summary delivery and recommended next actions in analyst console.
8. Activate ticket creation/update automation.

### 17.4 Ongoing Operations
9. Review misclassification reports weekly; adjust weights and correlation rules.
10. Monitor enrichment completeness and source health dashboards daily.

---

## 18. Acceptance Criteria

| ID    | Criterion                                                                  | Validation Method       |
|-------|---------------------------------------------------------------------------|-------------------------|
| AC-01 | Triage time per alert reduced >= 35% vs pre-agent baseline.               | Before/after comparison |
| AC-02 | Priority assignment agreement with senior analysts >= 85%.                | Blind comparison test   |
| AC-03 | >= 90% of incidents include enriched entity context.                      | Automated completeness  |
| AC-04 | All triage summaries written to case records with full audit trail.       | Audit log verification  |
| AC-05 | System recovers from enrichment source outage within 5 minutes.          | Chaos test validation   |

---

## 19. KPIs and Success Metrics

| KPI                                 | Baseline Target        | Measurement Cadence |
|-------------------------------------|------------------------|---------------------|
| Mean Time to Triage (MTTT)          | < 5 minutes            | Daily               |
| Alert-to-Incident Conversion Quality| > 90% analyst agreement| Weekly              |
| Analyst Handling Capacity per Shift | >= 20% increase        | Monthly             |
| Priority Misclassification Rate     | < 15%                  | Weekly              |
| Enrichment Completeness             | > 95%                  | Daily               |

---

## Revision History

| Version | Date       | Author              | Changes                          |
|---------|------------|----------------------|----------------------------------|
| 1.0     | 2026-03-07 | AI Engineering Team  | Initial SRS creation             |
| 2.0     | 2026-03-07 | AI Engineering Team  | Production-ready refinement      |
