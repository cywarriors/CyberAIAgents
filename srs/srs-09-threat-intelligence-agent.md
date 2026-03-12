# SRS-09: Threat Intelligence Agent

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| Document ID        | SRS-CYBER-09                                   |
| Version            | 2.0                                            |
| Status             | Production-Ready                               |
| Classification     | Internal-Confidential                          |
| Author             | Cybersecurity AI Engineering Team               |
| Reviewer           | Threat Intelligence Lead, SOC Manager           |
| Approver           | CISO                                           |
| Created            | 2026-03-07                                     |
| Last Updated       | 2026-03-07                                     |

---

## 1. Introduction

### 1.1 Purpose
This SRS defines requirements for an AI-powered Threat Intelligence Agent that ingests, normalizes, correlates, and scores threat intelligence from multiple sources, maps indicators to MITRE ATT&CK, assesses organizational relevance, and produces actionable intelligence briefs for defensive teams.

### 1.2 Intended Audience
- Threat intelligence analysts
- SOC analysts
- Incident responders
- Security leadership

### 1.3 Definitions and Acronyms

| Term    | Definition                                                |
|---------|-----------------------------------------------------------|
| TIP     | Threat Intelligence Platform                              |
| STIX    | Structured Threat Information Expression                  |
| TAXII   | Trusted Automated Exchange of Intelligence Information    |
| ATT&CK  | Adversarial Tactics, Techniques, and Common Knowledge    |
| IOC     | Indicator of Compromise                                   |

---

## 2. Scope

### 2.1 In Scope
- Multi-source intelligence ingestion (OSINT, commercial feeds, ISACs, internal).
- IOC normalization, deduplication, and confidence scoring.
- Threat actor and campaign tracking with ATT&CK TTP mapping.
- Organizational relevance scoring based on industry, geography, and attack surface.
- Actionable intelligence brief generation for strategic, operational, and tactical consumers.
- IOC distribution to detection tools (SIEM, EDR, firewall).

### 2.2 Out of Scope
- Active threat hunting and live investigation (SOC responsibility).
- Vulnerability scanning and patch management (SRS-04 scope).
- Dark web / deep web crawling and collection (specialized HUMINT tools).

---

## 3. Stakeholders

| Role                      | Responsibility                                     |
|---------------------------|---------------------------------------------------|
| Threat Intelligence Lead  | Define collection priorities and source quality    |
| SOC Analyst               | Consume tactical intelligence and IOC feeds        |
| Incident Responder        | Use threat context for investigation and scoping   |
| Security Director / CISO  | Consume strategic intelligence briefs              |
| Detection Engineering     | Operationalize IOCs into detection rules           |

---

## 4. Assumptions and Constraints

### 4.1 Assumptions
- At least 3 intelligence sources (OSINT + commercial + ISAC) are available.
- STIX/TAXII infrastructure is provisioned for feed exchange.
- Organizational asset inventory is available for relevance scoring.

### 4.2 Constraints
- Intelligence sharing with external parties MUST comply with TLP (Traffic Light Protocol) markings.
- Automated IOC blocking MUST be gated by confidence threshold and analyst approval for new sources.
- Attribution claims MUST include confidence level and supporting evidence.

---

## 5. Functional Requirements

| ID     | Requirement                                                                                         | Priority |
|--------|-----------------------------------------------------------------------------------------------------|----------|
| FR-01  | System SHALL ingest threat intelligence from OSINT, commercial feeds, ISACs, and internal sources.   | Must     |
| FR-02  | System SHALL normalize all intelligence data into STIX 2.1 format.                                   | Must     |
| FR-03  | System SHALL deduplicate IOCs across sources and maintain provenance.                                | Must     |
| FR-04  | System SHALL score IOC confidence based on source reliability, age, and corroboration.              | Must     |
| FR-05  | System SHALL map threat actors and campaigns to MITRE ATT&CK tactics and techniques.                | Must     |
| FR-06  | System SHALL compute organizational relevance scores based on industry, geography, and attack surface.| Must    |
| FR-07  | System SHALL generate intelligence briefs at strategic, operational, and tactical levels.            | Must     |
| FR-08  | System SHALL distribute high-confidence IOCs to SIEM, EDR, and firewall for detection.              | Must     |
| FR-09  | System SHALL track intelligence lifecycle (new, active, deprecated, revoked).                       | Should   |
| FR-10  | System SHALL support analyst feedback to adjust source quality and IOC confidence.                  | Should   |
| FR-11  | System SHALL produce weekly threat landscape summaries with trend analysis.                         | Should   |
| FR-12  | System SHALL support configurable collection priorities by threat actor or campaign.                | Should   |

---

## 6. Non-Functional Requirements

| ID      | Requirement                                    | Target                        |
|---------|-------------------------------------------------|-------------------------------|
| NFR-01  | Feed ingestion and normalization latency        | < 5 minutes from publication  |
| NFR-02  | IOC distribution to detection tools             | < 10 minutes                  |
| NFR-03  | Service availability                            | 99.9% monthly                 |
| NFR-04  | IOC deduplication accuracy                      | >= 99%                        |
| NFR-05  | RTO                                             | < 15 minutes                  |
| NFR-06  | RPO                                             | < 2 minutes                   |

---

## 7. Data Requirements

### 7.1 Inputs
- OSINT feeds (abuse.ch, AlienVault OTX, CIRCL, public STIX/TAXII).
- Commercial threat intelligence feeds.
- ISAC sector-specific intelligence sharing.
- Internal IOCs from malware analysis (SRS-08) and incident investigations.
- Organizational asset inventory for relevance scoring.

### 7.2 Outputs
- Normalized STIX 2.1 intelligence objects (indicators, threat actors, campaigns, TTPs).
- Confidence-scored IOC feeds for detection tool consumption.
- Intelligence briefs (strategic, operational, tactical) in Markdown/PDF.
- Weekly threat landscape trend reports.
- ATT&CK heat maps showing relevant techniques.

### 7.3 Retention
- Intelligence objects: 24 months (active lifecycle tracking).
- Intelligence briefs: 36 months.
- Source quality metrics: indefinite.

---

## 8. Integration Requirements

| System                        | Protocol / Method | Direction     | Purpose                                |
|-------------------------------|-------------------|---------------|----------------------------------------|
| OSINT Feeds                   | STIX/TAXII / REST | Inbound       | Open-source intelligence ingestion     |
| Commercial Feeds              | REST API          | Inbound       | Premium intelligence ingestion         |
| ISACs                         | STIX/TAXII        | Bidirectional | Sector intelligence sharing            |
| SIEM                          | REST API / Syslog | Outbound      | IOC feed and alert context             |
| EDR Platform                  | REST API          | Outbound      | IOC push for endpoint detection        |
| Firewall / Proxy              | REST API          | Outbound      | IOC blocklist distribution             |
| Malware Analysis Agent (SRS-08)| REST API         | Inbound       | Internal IOCs from analysis            |
| ITSM (ServiceNow/Jira)       | REST API          | Outbound      | Intelligence request ticketing         |

---

## 9. Security and Privacy Requirements

| ID      | Requirement                                                                             |
|---------|-----------------------------------------------------------------------------------------|
| SEC-01  | TLP markings SHALL be enforced on all intelligence objects and briefs.                    |
| SEC-02  | Access to intelligence data SHALL be controlled by analyst clearance tier.               |
| SEC-03  | External sharing SHALL be audited and comply with source agreements.                      |
| SEC-04  | All inter-service communication SHALL use mutual TLS.                                    |
| SEC-05  | Data at rest SHALL be encrypted with AES-256 or equivalent.                             |
| SEC-06  | API keys for commercial feeds SHALL be stored in managed secret store.                   |

---

## 10. Monitoring and Observability

| Metric                             | Alert Threshold         | Dashboard   |
|-------------------------------------|-------------------------|-------------|
| Feed ingestion lag                  | > 15 minutes            | Real-time   |
| IOC distribution lag to SIEM/EDR   | > 15 minutes            | Real-time   |
| Source failure rate                 | > 0 for any source      | Real-time   |
| Daily IOC volume                   | > 200% or < 50% baseline| Daily       |
| Deduplication ratio                | Drift > 10%             | Weekly      |
| Service health (uptime)           | < 99.9% rolling 30d     | Real-time   |

---

## 11. Deployment and Environment

### 11.1 Target Environment
- Cloud-native Kubernetes deployment.
- LangGraph workers for intelligence processing and correlation.
- Graph database for threat actor and campaign relationship modeling.

### 11.2 Infrastructure Requirements
- Compute: minimum 4 vCPU / 16 GB RAM per worker; auto-scaling.
- Storage: graph database (Neo4j/Neptune) for entity relationships; PostgreSQL for IOC state.
- Networking: private subnets; mTLS service mesh; outbound access to feed endpoints.

### 11.3 CI/CD
- GitOps pipeline with intelligence processing regression tests.
- Canary deployment for relevance model updates.
- Rollback within 5 minutes.

---

## 12. Framework Implementation (LangGraph)

### 12.1 Graph Design
- **Graph Type**: Intelligence ingestion to actionability graph (streaming with periodic batch).
- **State Model**: `ThreatIntelState`
  - `raw_intel: list[RawIntelRecord]`
  - `normalized_objects: list[STIXObject]`
  - `deduplicated_iocs: list[IOCRecord]`
  - `confidence_scores: dict[str, float]`
  - `relevance_assessments: list[RelevanceScore]`
  - `attck_mappings: list[ATTCKMapping]`
  - `briefs: list[IntelBrief]`

### 12.2 Node Definitions

| Node                       | Responsibility                                         | Tool Access              |
|----------------------------|-------------------------------------------------------|--------------------------|
| IngestFeedsNode            | Pull intelligence from configured sources              | Feed APIs/TAXII          |
| NormalizeToSTIXNode        | Convert all formats to STIX 2.1                        | STIX library             |
| DeduplicateNode            | Deduplicate IOCs; maintain provenance chain             | Dedup engine             |
| ScoreConfidenceNode        | Score IOC confidence by source, age, corroboration      | Scoring model            |
| AssessRelevanceNode        | Compute organizational relevance scores                 | Asset inventory API      |
| MapATTCKNode               | Map threat actors and campaigns to ATT&CK               | ATT&CK knowledge base   |
| GenerateBriefsNode         | Produce strategic, operational, tactical briefs          | Report template engine   |
| DistributeIOCsNode         | Push IOCs to SIEM, EDR, firewall                        | Detection tool APIs      |
| FeedbackLoopNode           | Process analyst feedback on source quality and IOC value | Feedback store           |

### 12.3 Control Flow
```
Start -> IngestFeeds -> NormalizeToSTIX -> Deduplicate
  -> ScoreConfidence -> AssessRelevance -> MapATTCK
  -> [GenerateBriefs, DistributeIOCs] (parallel)
  -> FeedbackLoop -> End
```

### 12.4 Human-in-the-Loop
- **Checkpoint**: Analyst approval required before distributing IOCs from new/untested sources.
- **Override**: Analyst can revoke or deprecate IOCs with documented justification.

---

## 13. Reference Architecture

```
+---------------------+     +-------------------+     +-----------------------+
| Intelligence Sources| --> | Feed Ingestion    | --> | LangGraph Intel       |
| (OSINT/Comm/ISAC)   |     | (TAXII/API)       |     | Workers (K8s)         |
+---------------------+     +-------------------+     +-----------------------+
                                                          |
                                               +----------+----------+
                                               v          v          v
                                        +-----------+ +--------+ +----------+
                                        | Normalize | | Dedup  | | Score    |
                                        | (STIX)    | | Engine | | Confidence|
                                        +-----------+ +--------+ +----------+
                                               |          |          |
                                               +---  Merge State  --+
                                                        |
                                              +---------v---------+
                                              | Relevance +       |
                                              | ATT&CK Mapping    |
                                              +---------+---------+
                                                        |
                                       +----------------+----------------+
                                       v                v                v
                                +-----------+  +-------------+  +-----------+
                                | IOC Dist  |  | Intelligence|  | ATT&CK    |
                                | (SIEM/EDR)|  | Briefs      |  | Heat Maps |
                                +-----------+  +-------------+  +-----------+

Governance: Source Quality Registry | IOC Lifecycle Store | TLP Enforcement | Feedback Store
```

---

## 14. Testing Strategy

| Test Type           | Scope                                                        | Frequency      |
|---------------------|--------------------------------------------------------------|----------------|
| Unit Tests          | STIX normalization, deduplication, confidence scoring         | Every commit   |
| Scenario Tests      | Seeded intelligence scenarios with known expected outcomes    | Every PR       |
| Integration Tests   | Full pipeline with mock feed sources                          | Weekly         |
| Load Tests          | High-volume feed ingestion (10K+ IOCs/hour)                   | Monthly        |
| Relevance Accuracy  | Validate relevance scoring against analyst-labeled dataset    | Monthly        |
| Source Reliability   | Verify source quality tracking and degradation detection     | Quarterly      |

---

## 15. Cross-Agent Dependencies

| Dependency Agent              | Relationship                                              |
|-------------------------------|-----------------------------------------------------------|
| SRS-01: Threat Detection      | IOC feeds consumed by detection rules                      |
| SRS-02: Incident Triage       | Threat context enriches alert triage                       |
| SRS-03: Automated Response    | IOC blocklists consumed by containment playbooks           |
| SRS-08: Malware Analysis      | IOCs and family data ingested from analysis results        |
| SRS-12: Deception & Honeypot  | Threat actor profiles inform decoy deployment strategy     |

---

## 16. Risk Register

| Risk                                        | Likelihood | Impact   | Mitigation                                              |
|---------------------------------------------|------------|----------|---------------------------------------------------------|
| Poisoned feed injects false IOCs             | Medium     | High     | Multi-source corroboration; source quality scoring      |
| Stale IOCs causing alert fatigue             | High       | Medium   | IOC lifecycle management; automatic expiry/deprecation  |
| Source API outage interrupting feed          | Medium     | Medium   | Redundant sources; graceful degradation; alerting       |
| TLP violation through automated sharing      | Low        | Critical | TLP enforcement engine; sharing audit log               |
| Relevance model bias toward specific sectors | Medium     | Medium   | Regular model validation; analyst feedback loop         |

---

## 17. How to Use This Agent

### 17.1 Initial Setup
1. Configure intelligence source connections (OSINT, commercial, ISAC).
2. Import organizational asset inventory for relevance scoring.
3. Deploy LangGraph threat intelligence workers and graph database.
4. Configure IOC distribution targets (SIEM, EDR, firewall).

### 17.2 Pilot Phase (Weeks 1-3)
5. Enable feed ingestion and normalization for all configured sources.
6. Enable **review-only mode** for IOC distribution (analysts approve each batch).
7. Calibrate confidence thresholds and relevance scoring with analyst feedback.

### 17.3 Production Rollout
8. Enable automated IOC distribution for high-confidence, high-relevance indicators.
9. Activate intelligence brief generation on weekly schedule.
10. Enable analyst feedback loop for continuous source quality tuning.

### 17.4 Ongoing Operations
11. Review source quality metrics quarterly and onboard/remove sources as needed.
12. Update relevance model as organizational attack surface changes.
13. Produce ad hoc intelligence briefs for emerging threats on demand.

---

## 18. Acceptance Criteria

| ID    | Criterion                                                                  | Validation Method       |
|-------|----------------------------------------------------------------------------|-------------------------|
| AC-01 | Agent ingests and normalizes data from >= 3 intelligence sources.          | Source integration test  |
| AC-02 | IOC deduplication accuracy >= 99%.                                          | Dedup validation suite  |
| AC-03 | High-confidence IOCs distributed to detection tools within 10 minutes.     | Latency monitoring      |
| AC-04 | Intelligence briefs include ATT&CK mapping and relevance assessment.       | Content validation      |
| AC-05 | TLP markings enforced on all shared intelligence objects.                   | Sharing audit review    |

---

## 19. KPIs and Success Metrics

| KPI                                        | Baseline Target       | Measurement Cadence |
|--------------------------------------------|-----------------------|---------------------|
| Mean Time to IOC Operationalization        | < 15 minutes          | Weekly              |
| IOC False Positive Rate in Detection       | < 3%                  | Weekly              |
| Intelligence Brief Utilization Rate        | >= 80% read rate      | Monthly             |
| Source Coverage (ATT&CK techniques)        | >= 70% relevant TTPs  | Quarterly           |
| Analyst Satisfaction with Intel Quality    | >= 4.0/5.0            | Quarterly           |

---

## 20. Graphical User Interface (GUI) Requirements

### 20.1 Overview
The Threat Intelligence Agent GUI provides a web-based interface for exploring intelligence feeds, managing IOC lifecycles, reviewing threat briefs, and analyzing threat actor profiles. Designed for threat intelligence analysts, SOC teams, and security leadership.

### 20.2 Technology Stack

| Component        | Technology                                    |
|------------------|-----------------------------------------------|
| Frontend         | React 18+ with TypeScript                     |
| Component Library| Shadcn/UI + Tailwind CSS                      |
| State Management | Zustand or Redux Toolkit                      |
| Data Fetching    | TanStack Query (React Query)                  |
| Charting         | Recharts / D3.js                              |
| Real-time        | WebSocket (Server-Sent Events fallback)       |
| Backend API      | FastAPI (Python) with OpenAPI spec             |
| Authentication   | OIDC / SAML SSO with RBAC enforcement          |

### 20.3 Screen Inventory

| Screen ID | Screen Name              | Primary Users                    | Purpose                                          |
|-----------|--------------------------|----------------------------------|--------------------------------------------------|
| GUI-01    | Intel Dashboard          | Threat Intel Analysts, Leadership| Feed health, IOC volume, operationalization rate, trending threats |
| GUI-02    | IOC Explorer             | Threat Intel, SOC Analysts       | Searchable IOC database with enrichment, relationships, and confidence |
| GUI-03    | Threat Brief Viewer      | All Security Teams               | Curated intelligence briefs with ATT&CK mapping and recommendations |
| GUI-04    | Actor Profile Database   | Threat Intel Analysts            | Threat actor profiles with TTPs, targets, campaign history |
| GUI-05    | Feed Manager             | Threat Intel Analysts            | Feed source configuration, health monitoring, quality scoring |
| GUI-06    | IOC Lifecycle Manager    | Threat Intel Analysts            | IOC aging, deprecation, re-validation workflow |
| GUI-07    | Detection Mapping        | Detection Engineers, Threat Intel| Map IOCs and TTPs to detection rules; coverage gap analysis |
| GUI-08    | Administration           | Platform Engineering             | Feed integration config, enrichment source management, system health |

### 20.4 Key Screen Specifications

#### GUI-01: Intel Dashboard
- **Widgets**: IOC ingestion rate timeline, feed health status grid, IOC type distribution (donut), operationalization rate gauge, trending threat actors/campaigns, intelligence brief publication rate.
- **Interactions**: Click-through to filtered IOC explorer or brief viewer. Time range selector. Auto-refresh every 60 seconds.

#### GUI-02: IOC Explorer
- **Features**: Data table with type (IP, domain, hash, URL, email), value, confidence score, source feed(s), first/last seen, associated campaigns/actors, and status (active/deprecated). Relationship graph showing IOC-to-IOC and IOC-to-actor links.
- **Actions**: Enrich, operationalize to detection, deprecate, export (STIX 2.1/CSV), pivot to external sources.
- **Search**: Full-text search with type-ahead across IOC values, descriptions, and tags.

#### GUI-03: Threat Brief Viewer
- **Features**: Rich-text intelligence briefs with executive summary, technical analysis, IOC appendix, ATT&CK mapping, and recommended defensive actions. Version history. Distribution tracking (read receipts).

#### GUI-04: Actor Profile Database
- **Features**: Actor cards with aliases, attributed campaigns, targeted sectors/regions, TTPs (ATT&CK mapped), associated IOCs. Relationship graph between actors, campaigns, and infrastructure.

#### GUI-05: Feed Manager
- **Features**: Feed source list with health indicators (last poll, success rate, IOC yield). Quality score per feed based on false positive rate and enrichment utility. Add/configure/disable feeds.

### 20.5 UX Requirements

| ID      | Requirement                                                                        |
|---------|------------------------------------------------------------------------------------|
| UX-01   | All critical actions SHALL be reachable within 3 clicks from the dashboard.         |
| UX-02   | GUI SHALL support responsive layout for desktop (1280px+) and tablet (768px+).      |
| UX-03   | GUI SHALL meet WCAG 2.1 AA accessibility compliance.                                |
| UX-04   | GUI SHALL support dark mode and light mode themes.                                  |
| UX-05   | Real-time data updates SHALL NOT cause visible page flicker or layout shifts.        |
| UX-06   | All data tables SHALL support column reordering, resizing, and preference persistence. |
| UX-07   | GUI SHALL display loading states, empty states, and error states for all data views. |

### 20.6 API Contract (Backend for Frontend)

| Endpoint Pattern                  | Method | Purpose                                  |
|-----------------------------------|--------|------------------------------------------|
| `/api/v1/iocs`                    | GET    | Paginated IOC query with filters          |
| `/api/v1/iocs/{id}`               | GET/PUT| IOC detail and lifecycle actions            |
| `/api/v1/iocs/{id}/relationships` | GET    | IOC relationship graph data                |
| `/api/v1/iocs/export`             | POST   | Bulk IOC export (STIX 2.1/CSV)             |
| `/api/v1/briefs`                  | GET    | Intelligence brief list                    |
| `/api/v1/briefs/{id}`             | GET    | Brief detail with IOC appendix             |
| `/api/v1/actors`                  | GET    | Threat actor profile list                  |
| `/api/v1/actors/{id}`             | GET    | Actor detail with TTP and campaign data    |
| `/api/v1/feeds`                   | CRUD   | Feed source management                     |
| `/api/v1/feeds/{id}/health`       | GET    | Feed health and quality metrics            |
| `/api/v1/dashboard/intel`         | GET    | Aggregated intelligence dashboard metrics  |
| `/ws/notifications`              | WS     | New IOC and brief publication alerts       |

### 20.7 Security Controls (GUI-Specific)

| ID       | Requirement                                                                        |
|----------|------------------------------------------------------------------------------------|
| GUI-SEC-01 | Authentication SHALL use SSO (OIDC/SAML) with session timeout of 30 minutes.    |
| GUI-SEC-02 | RBAC SHALL restrict screen access by role (e.g., Feed Manager restricted to Threat Intel Analyst role). |
| GUI-SEC-03 | All API calls SHALL include CSRF token validation.                               |
| GUI-SEC-04 | TLP-classified intel SHALL enforce access restrictions based on classification level. |
| GUI-SEC-05 | GUI SHALL enforce Content Security Policy (CSP) headers to prevent XSS.          |
| GUI-SEC-06 | Session activity SHALL be logged for audit trail.                                |

---

## Revision History

| Version | Date       | Author              | Changes                          |
|---------|------------|----------------------|----------------------------------|
| 1.0     | 2026-03-07 | AI Engineering Team  | Initial SRS creation             |
| 2.0     | 2026-03-07 | AI Engineering Team  | Production-ready refinement      |
