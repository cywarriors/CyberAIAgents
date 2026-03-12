# SRS-00: VAPT (Vulnerability Assessment and Penetration Testing) AI Agent

| Field          | Value                                                |
| -------------- | ---------------------------------------------------- |
| Document ID    | SRS-CYBER-13                                         |
| Version        | 2.0                                                  |
| Status         | Production-Ready                                     |
| Classification | Internal-Confidential                                |
| Author         | Cybersecurity AI Engineering Team                    |
| Reviewer       | Offensive Security Lead, AppSec Lead, Risk Committee |
| Approver       | CISO                                                 |
| Created        | 2026-03-12                                           |
| Last Updated   | 2026-03-12                                           |

---

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification defines the complete requirements for an AI-powered Vulnerability Assessment and Penetration Testing (VAPT) Agent that automates asset discovery, vulnerability scanning, exploitation validation, and penetration test reporting while maintaining strict safety guardrails and authorization controls.

### 1.2 Intended Audience

- Offensive security / red team engineers
- Vulnerability assessment analysts
- Security operations and engineering leadership
- Compliance and audit teams
- Application and infrastructure owners

### 1.3 Definitions and Acronyms

| Term  | Definition                                       |
| ----- | ------------------------------------------------ |
| VAPT  | Vulnerability Assessment and Penetration Testing |
| CVSS  | Common Vulnerability Scoring System              |
| EPSS  | Exploit Prediction Scoring System                |
| KEV   | Known Exploited Vulnerabilities (CISA catalog)   |
| PoC   | Proof of Concept (exploit)                       |
| OWASP | Open Worldwide Application Security Project      |
| PTES  | Penetration Testing Execution Standard           |
| RoE   | Rules of Engagement                              |
| CWE   | Common Weakness Enumeration                      |
| DAST  | Dynamic Application Security Testing             |
| SAST  | Static Application Security Testing              |
| BAS   | Breach and Attack Simulation                     |

---

## 2. Scope

### 2.1 In Scope

- Automated asset discovery and attack surface enumeration (network, web, API, cloud).
- Vulnerability scanning with multi-engine correlation (network, application, container, infrastructure).
- Safe exploitation validation with configurable risk guardrails and rollback capability.
- ATT&CK-mapped attack path analysis and lateral movement simulation.
- Compliance-grade VAPT report generation (executive, technical, remediation).
- Continuous assessment scheduling with drift detection.
- Rules of Engagement enforcement and authorization validation.

### 2.2 Out of Scope

- Offensive exploitation against unauthorized targets (strict RoE enforcement).
- Patch deployment or remediation execution (covered by SRS-04).
- Production incident response (covered by SRS-03).
- Source code review (covered by SRS-11).
- Threat intelligence feed management (covered by SRS-09).

---

## 3. Stakeholders

| Role                      | Responsibility                                     |
| ------------------------- | -------------------------------------------------- |
| Offensive Security Lead   | Define RoE, approve test plans, review findings    |
| Red Team Engineer         | Validate exploitation results, tune attack modules |
| Vulnerability Analyst     | Review scan results, verify findings               |
| Application / Infra Owner | Authorize testing scope, remediate findings        |
| CISO / Risk Committee     | Approve engagement scope, accept residual risk     |
| Compliance Team           | Validate VAPT cadence and reporting requirements   |

---

## 4. Assumptions and Constraints

### 4.1 Assumptions

- All target assets are within organizational ownership and have explicit written authorization for testing.
- Network access to target scopes is provisioned via dedicated VAPT VLAN or VPN tunnel.
- Asset inventory with IP ranges, domains, and cloud resource identifiers is current.
- Exploit module library is curated, version-controlled, and reviewed by offensive security lead.

### 4.2 Constraints

- Agent SHALL NOT execute exploitation against targets outside the authorized RoE scope.
- Exploitation modules classified as "destructive" require human approval before execution.
- Agent SHALL implement automatic rollback for any system state changes during exploitation validation.
- All VAPT activities SHALL be logged with full audit trail for compliance and legal defensibility.
- Testing windows must respect business-critical maintenance schedules.

---

## 5. Functional Requirements

| ID    | Requirement                                                                                                                         | Priority |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------- | -------- |
| FR-01 | System SHALL enforce Rules of Engagement (RoE) authorization check before any scanning or exploitation.                             | Must     |
| FR-02 | System SHALL perform automated asset discovery including host enumeration, port scanning, service detection, and OS fingerprinting. | Must     |
| FR-03 | System SHALL perform web application vulnerability scanning covering OWASP Top 10 categories.                                       | Must     |
| FR-04 | System SHALL perform network vulnerability scanning with CVE correlation and CVSS/EPSS enrichment.                                  | Must     |
| FR-05 | System SHALL perform API endpoint discovery and security testing (authentication, authorization, injection).                        | Must     |
| FR-06 | System SHALL validate exploitability of discovered vulnerabilities using safe PoC modules with rollback.                            | Must     |
| FR-07 | System SHALL map findings to MITRE ATT&CK technique IDs and CWE identifiers.                                                        | Must     |
| FR-08 | System SHALL generate attack path analysis showing lateral movement potential from initial foothold.                                | Must     |
| FR-09 | System SHALL calculate composite risk score per finding using CVSS, EPSS, exploitability, asset criticality, and exposure.          | Must     |
| FR-10 | System SHALL generate compliance-grade VAPT reports (executive summary, technical findings, remediation plan).                      | Must     |
| FR-11 | System SHALL support continuous assessment scheduling with configurable frequency (daily/weekly/monthly).                           | Must     |
| FR-12 | System SHALL detect attack surface drift by comparing current scan results against previous baselines.                              | Should   |
| FR-13 | System SHALL support cloud infrastructure assessment (AWS, Azure, GCP) for misconfigurations and exposed services.                  | Should   |
| FR-14 | System SHALL provide finding deduplication across scan cycles to track remediation progress.                                        | Must     |
| FR-15 | System SHALL support credential-based (authenticated) and unauthenticated scanning modes.                                           | Must     |

---

## 6. Non-Functional Requirements

| ID     | Requirement                                | Target                 |
| ------ | ------------------------------------------ | ---------------------- |
| NFR-01 | Full network scan completion (Class C /24) | < 30 minutes           |
| NFR-02 | Web application scan (medium complexity)   | < 2 hours              |
| NFR-03 | Platform availability                      | 99.9% monthly          |
| NFR-04 | Exploitation validation safety rate        | 100% rollback success  |
| NFR-05 | False positive rate (validated findings)   | < 10%                  |
| NFR-06 | Report generation time                     | < 5 minutes            |
| NFR-07 | Concurrent scan capacity                   | >= 50 targets parallel |
| NFR-08 | RTO                                        | < 30 minutes           |
| NFR-09 | RPO                                        | < 5 minutes            |

---

## 7. Data Requirements

### 7.1 Inputs

- RoE authorization records with scope definitions (IP ranges, domains, cloud accounts, exclusions).
- Asset inventory with ownership, criticality, environment tags.
- Exploit module library (PoC scripts, payloads, validation checks).
- CVE/EPSS/KEV feeds for enrichment.
- Previous scan baselines for drift detection.
- Credential vault for authenticated scanning (managed secrets).

### 7.2 Outputs

- Vulnerability findings with CVSS, EPSS, CWE, ATT&CK mapping, exploitability status.
- Attack path graphs showing lateral movement chains.
- VAPT reports: executive summary, technical findings, remediation roadmap.
- Attack surface drift reports.
- Compliance evidence artifacts.

### 7.3 Retention

- Scan results and findings: 24 months.
- VAPT reports: 36 months (compliance requirement).
- Exploitation validation logs: 24 months.
- RoE authorization records: 60 months.

---

## 8. Integration Requirements

| System                                        | Protocol / Method | Direction     | Purpose                             |
| --------------------------------------------- | ----------------- | ------------- | ----------------------------------- |
| Asset Inventory / CMDB                        | REST API          | Inbound       | Target scope and criticality data   |
| Vulnerability Scanners (Nmap, Nessus, Nuclei) | CLI / API         | Bidirectional | Scan execution and result ingestion |
| Web App Scanners (ZAP, Burp Suite API)        | REST API          | Bidirectional | DAST execution and findings         |
| Cloud APIs (AWS/Azure/GCP)                    | REST API / SDK    | Inbound       | Cloud asset enumeration and config  |
| NVD / EPSS / KEV Feeds                        | REST API / JSON   | Inbound       | CVE enrichment                      |
| Ticketing (ServiceNow/Jira)                   | REST API          | Outbound      | Finding-to-ticket creation          |
| Credential Vault                              | REST API          | Inbound       | Authenticated scan credentials      |
| Reporting Platform                            | REST API / File   | Outbound      | Report delivery and archival        |

---

## 9. Security and Privacy Requirements

| ID     | Requirement                                                                                                |
| ------ | ---------------------------------------------------------------------------------------------------------- |
| SEC-01 | RoE authorization SHALL be cryptographically verified before any scan or exploitation execution.           |
| SEC-02 | Exploit modules SHALL be version-controlled, reviewed, and approved before promotion to production.        |
| SEC-03 | All exploitation attempts SHALL be logged with target, technique, timestamp, outcome, and rollback status. |
| SEC-04 | Credentials for authenticated scanning SHALL be retrieved from managed vault with automatic rotation.      |
| SEC-05 | VAPT data access SHALL be restricted by engagement scope with RBAC enforcement.                            |
| SEC-06 | Agent SHALL NOT store or transmit captured credentials, tokens, or sensitive data beyond validation proof. |
| SEC-07 | All inter-service communication SHALL use mutual TLS.                                                      |
| SEC-08 | Destructive exploit modules SHALL require human-in-the-loop approval via dual authorization.               |

---

## 10. Monitoring and Observability

| Metric                          | Alert Threshold         | Dashboard |
| ------------------------------- | ----------------------- | --------- |
| Active scan count               | > capacity limit        | Real-time |
| Scan duration vs target SLA     | > 150% of target        | Real-time |
| RoE authorization failures      | Any failure             | Real-time |
| Exploitation rollback failures  | Any failure             | Real-time |
| Finding deduplication rate      | < 50% dedup             | Daily     |
| Report generation latency       | > 5 minutes             | Real-time |
| Scanner engine health           | Any engine offline > 5m | Real-time |
| Attack surface drift percentage | > 15% new findings      | Daily     |

---

## 11. Deployment and Environment

### 11.1 Target Environment

- Cloud-native Kubernetes deployment with dedicated VAPT namespace and network policies.
- LangGraph workers deployed as stateless containers with scan orchestration.
- Dedicated VAPT VLAN or VPN tunnel for target network access.
- Checkpoint store on managed PostgreSQL.

### 11.2 Infrastructure Requirements

- Compute: minimum 8 vCPU / 32 GB RAM per scan worker; auto-scaling group (up to 10 workers).
- Storage: managed PostgreSQL for findings; object store for reports and scan artifacts.
- Networking: isolated VAPT subnet; egress restricted to authorized target scopes only.
- Scanner engines: Nmap, Nuclei, ZAP deployed as sidecar containers or remote services.

### 11.3 CI/CD

- GitOps pipeline with automated tests for exploit module safety validation.
- Staged rollout for exploit module library updates with security review gate.
- Rollback capability within 5 minutes.

---

## 12. Framework Implementation (LangGraph)

### 12.1 Graph Design

- **Graph Type**: VAPT orchestration graph with durable execution, checkpointing, and human-in-the-loop gates.
- **State Model**: `VAPTState`
  - `engagement_id: str`
  - `roe_authorization: RoERecord`
  - `discovered_assets: list[Asset]`
  - `scan_results: list[ScanFinding]`
  - `validated_exploits: list[ExploitResult]`
  - `attack_paths: list[AttackPath]`
  - `risk_scores: list[ScoredFinding]`
  - `remediation_items: list[RemediationItem]`
  - `report_artifacts: list[ReportArtifact]`
  - `errors: list[Error]`

### 12.2 Node Definitions

| Node                    | Responsibility                                                    | Tool Access           |
| ----------------------- | ----------------------------------------------------------------- | --------------------- |
| ValidateRoENode         | Verify authorization, scope boundaries, and testing window        | RoE policy store      |
| DiscoverAssetsNode      | Enumerate hosts, ports, services, web apps, APIs, cloud resources | Nmap, cloud SDKs      |
| ScanVulnerabilitiesNode | Execute multi-engine vulnerability scanning                       | Nessus/Nuclei/ZAP     |
| ValidateExploitsNode    | Safely test exploitability with PoC modules and rollback          | Exploit library       |
| AnalyzeAttackPathsNode  | Map lateral movement chains and ATT&CK kill chain progression     | Graph analysis engine |
| ScoreAndPrioritizeNode  | Calculate composite risk score with exploitability weighting      | Scoring engine        |
| GenerateRemediationNode | Produce fix recommendations with effort estimates                 | Remediation KB        |
| GenerateReportNode      | Create executive, technical, and compliance VAPT reports          | Report templates      |
| PublishFindingsNode     | Write findings to ticketing, dashboard, and archive               | ITSM / reporting API  |

### 12.3 Control Flow

```
Start -> ValidateRoE
  -> DiscoverAssets -> ScanVulnerabilities
  -> ValidateExploits (HITL gate for destructive modules)
  -> AnalyzeAttackPaths -> ScoreAndPrioritize
  -> GenerateRemediation -> GenerateReport -> PublishFindings -> End
```

### 12.4 Human-in-the-Loop

- **Pre-Engagement Gate**: RoE authorization must be verified and approved before any scanning begins.
- **Exploitation Gate**: Destructive or high-risk exploit modules require dual human approval before execution.
- **Report Review Gate**: Final VAPT report requires offensive security lead sign-off before distribution.
- **Override**: Analysts can exclude specific targets, skip exploitation phases, or re-scope mid-engagement.

---

## 13. Reference Architecture

```
+--------------------+     +--------------------+     +------------------------+
| RoE Policy Store   | --> | LangGraph VAPT     | --> | VAPT Reports &         |
| (Authorization)    |     | Workers (K8s)      |     | Finding Backlog        |
+--------------------+     +--------------------+     +------------------------+
                                 |          |
                      +----------+          +----------+
                      v                                v
               +-------------+                 +---------------+
               | Scan Engines|                 | Exploit Module |
               | Nmap/Nuclei |                 | Library        |
               | ZAP/Nessus  |                 | (Version-Ctrl) |
               +-------------+                 +---------------+
                      |                                |
                      +------------ Merge -------------+
                                     |
                           +---------v---------+
                           | Attack Path       |
                           | Analysis + Score  |
                           +---------+---------+
                                     |
                      +--------------+--------------+
                      v              v              v
                +-----------+ +----------+ +-----------+
                | ITSM      | | VAPT     | | Compliance|
                | Tickets   | | Dashboard| | Archive   |
                +-----------+ +----------+ +-----------+

Governance: RoE Vault | Exploit Module Registry | Audit Logs | Findings History DB
```

---

## 14. Testing Strategy

| Test Type            | Scope                                                     | Frequency           |
| -------------------- | --------------------------------------------------------- | ------------------- |
| Unit Tests           | RoE validation, scoring logic, deduplication, enrichment  | Every commit        |
| Integration Tests    | Full pipeline with mock target environment                | Every PR            |
| Exploit Safety Tests | Validate rollback and containment for all exploit modules | Every module update |
| Scan Accuracy Tests  | Compare findings against known-vulnerable lab environment | Weekly              |
| Load Tests           | 50 concurrent target scans within performance targets     | Monthly             |
| Authorization Tests  | Verify RoE enforcement blocks out-of-scope targets        | Every commit        |
| Red Team Validation  | Manual validation of top findings and attack paths        | Per engagement      |

---

## 15. Cross-Agent Dependencies

| Dependency Agent               | Relationship                                                 |
| ------------------------------ | ------------------------------------------------------------ |
| SRS-01: Threat Detection       | VAPT findings inform detection rule creation                 |
| SRS-04: Vulnerability Mgmt     | VAPT validates and enriches existing vulnerability backlog   |
| SRS-07: Cloud Security Posture | Cloud assessment findings complement CSPM analysis           |
| SRS-09: Threat Intelligence    | Exploit availability and campaign data inform prioritization |
| SRS-11: Security Code Review   | Source code findings correlate with DAST/VAPT findings       |

---

## 16. Risk Register

| Risk                                             | Likelihood | Impact   | Mitigation                                                  |
| ------------------------------------------------ | ---------- | -------- | ----------------------------------------------------------- |
| Exploitation causes service disruption           | Low        | Critical | Rollback mechanisms; non-destructive PoC default; HITL gate |
| Agent scans unauthorized targets                 | Low        | Critical | Cryptographic RoE verification; scope boundary enforcement  |
| False positive findings waste remediation effort | Medium     | Medium   | Exploitation validation; multi-engine correlation           |
| Exploit module contains malicious code           | Low        | Critical | Mandatory code review; version control; sandboxed execution |
| Scan traffic triggers defensive alerts           | Medium     | Low      | Pre-notify SOC; allowlist VAPT source IPs                   |
| Report leaks sensitive vulnerability data        | Low        | High     | Encryption at rest; RBAC; watermarking; retention policies  |

---

## 17. How to Use This Agent

### 17.1 Initial Setup

1. Define and register Rules of Engagement with authorized scope (IP ranges, domains, cloud accounts, exclusions, testing windows).
2. Deploy LangGraph VAPT workers and scanner engine sidecars via CI/CD pipeline.
3. Import and validate exploit module library; configure safety rollback mechanisms.
4. Connect asset inventory (CMDB) and CVE enrichment feeds.

### 17.2 Pilot Phase (Weeks 1-2)

5. Run assessment against dedicated lab/staging environment with known vulnerabilities.
6. Validate finding accuracy, exploitation safety, and report quality with offensive security team.
7. Calibrate risk scoring weights and exploitation risk thresholds.

### 17.3 Production Rollout

8. Execute authorized VAPT engagements with full RoE enforcement.
9. Generate and distribute VAPT reports with offensive security lead sign-off.
10. Publish validated findings to remediation backlog (SRS-04 integration).

### 17.4 Ongoing Operations

11. Schedule continuous assessments (weekly for critical assets, monthly for standard).
12. Monitor attack surface drift and re-test after remediation claims.
13. Update exploit module library monthly; review and retire deprecated modules.

---

## 18. Acceptance Criteria

| ID    | Criterion                                                                    | Validation Method        |
| ----- | ---------------------------------------------------------------------------- | ------------------------ |
| AC-01 | 100% of RoE scope boundaries are enforced (zero out-of-scope scan attempts). | Authorization test suite |
| AC-02 | >= 90% of known vulnerabilities in lab environment are discovered.           | Scan accuracy test       |
| AC-03 | Exploitation validation rollback succeeds 100% of the time.                  | Exploit safety tests     |
| AC-04 | False positive rate for validated findings < 10%.                            | Manual verification      |
| AC-05 | VAPT report generation completes within 5 minutes.                           | Performance monitoring   |
| AC-06 | Attack path analysis covers >= 80% of discovered critical-severity findings. | Coverage analysis        |

---

## 19. KPIs and Success Metrics

| KPI                                        | Baseline Target         | Measurement Cadence |
| ------------------------------------------ | ----------------------- | ------------------- |
| Vulnerability Discovery Rate               | >= 90% vs manual VAPT   | Per engagement      |
| Mean Time to Complete Assessment (Class C) | < 4 hours               | Per engagement      |
| Exploitation Validation Accuracy           | >= 85%                  | Monthly             |
| Attack Surface Drift Detection Rate        | >= 80% of changes       | Monthly             |
| Remediation Tracking Coverage              | 100% of critical finds  | Weekly              |
| VAPT Engagement Throughput                 | >= 10 engagements/month | Monthly             |

---

## 20. Graphical User Interface (GUI) Requirements

### 20.1 Overview

The VAPT Agent GUI provides a unified web-based interface for engagement management, real-time scan monitoring, interactive finding exploration, attack path visualization, and report management. The GUI is designed for offensive security engineers, vulnerability analysts, and management stakeholders.

### 20.2 Technology Stack

| Component         | Technology                              |
| ----------------- | --------------------------------------- |
| Frontend          | React 18+ with TypeScript               |
| Component Library | Shadcn/UI + Tailwind CSS                |
| State Management  | Zustand or Redux Toolkit                |
| Data Fetching     | TanStack Query (React Query)            |
| Charting          | Recharts / D3.js for attack path graphs |
| Real-time         | WebSocket (Server-Sent Events fallback) |
| Backend API       | FastAPI (Python) with OpenAPI spec      |
| Authentication    | OIDC / SAML SSO with RBAC enforcement   |

### 20.3 Screen Inventory

| Screen ID | Screen Name            | Primary Users                 | Purpose                                                 |
| --------- | ---------------------- | ----------------------------- | ------------------------------------------------------- |
| GUI-01    | Dashboard              | All users                     | VAPT engagement overview, risk trends, KPIs             |
| GUI-02    | Engagement Manager     | Offensive Security Lead       | Create/edit engagements, define RoE, set schedule       |
| GUI-03    | Asset Discovery View   | Red Team Engineer, Analyst    | Interactive asset map with ports, services, OS          |
| GUI-04    | Scan Monitor           | Red Team Engineer             | Real-time scan progress, engine status, findings stream |
| GUI-05    | Findings Explorer      | All users                     | Filterable/sortable finding table with detail panels    |
| GUI-06    | Attack Path Visualizer | Red Team Engineer, Management | Interactive graph showing lateral movement chains       |
| GUI-07    | Exploitation Console   | Red Team Engineer             | Exploit module selection, approval, execution log       |
| GUI-08    | Report Builder         | Offensive Security Lead       | Configure, generate, preview, and distribute reports    |
| GUI-09    | Compliance Tracker     | Compliance Team               | VAPT schedule adherence, evidence collection            |
| GUI-10    | Administration         | Platform Engineering          | User management, scanner config, system health          |

### 20.4 Screen Specifications

#### GUI-01: Dashboard

- **Widgets**: Active engagement count, findings by severity (donut chart), risk trend over time (line chart), top 10 vulnerable assets (bar chart), upcoming scheduled assessments, SLA compliance gauge.
- **Interactions**: Click-through from any widget to filtered detail view. Time range selector (7d/30d/90d/custom).
- **Refresh**: Auto-refresh every 30 seconds via WebSocket; manual refresh button.

#### GUI-02: Engagement Manager

- **Features**: Create new engagement with RoE form (scope IPs/domains/cloud accounts, exclusions, testing window, authorized personnel, approval workflow). Edit/clone existing engagements. Status tracking (Draft → Approved → In Progress → Completed → Archived).
- **Authorization**: Digital signature capture for RoE approval. Dual-approval workflow for destructive testing authorization.
- **Schedule**: Calendar view for recurring assessments with conflict detection.

#### GUI-03: Asset Discovery View

- **Features**: Network topology map with discovered hosts, open ports, services, and OS detection. Filterable by subnet, service type, criticality. Expandable host detail panels.
- **Visualization**: Interactive network graph (D3.js force-directed layout). Table view toggle for accessibility.
- **Actions**: Add/remove assets from scan scope. Tag assets with notes.

#### GUI-04: Scan Monitor

- **Features**: Real-time scan progress bars per target/engine. Live finding stream as discoveries occur. Engine health indicators. Scan pause/resume/abort controls.
- **Layout**: Split view — progress overview (left), live finding feed (right).
- **Alerts**: Toast notifications for critical findings discovered during scan.

#### GUI-05: Findings Explorer

- **Features**: Data table with server-side pagination, sorting, and multi-facet filtering (severity, CVSS, exploitability, CWE, ATT&CK technique, asset, status). Inline detail panels with evidence, PoC output, remediation guidance.
- **Bulk Actions**: Assign to ticket, mark false positive, export CSV/PDF, compare across scan cycles.
- **Search**: Full-text search across finding descriptions, CVE IDs, CWE IDs.

#### GUI-06: Attack Path Visualizer

- **Features**: Directed graph visualization showing attack chains from initial foothold to high-value targets. Node colors indicate asset criticality; edge labels show technique used. Click-to-expand finding details on each step.
- **Interactions**: Zoom/pan, filter by severity threshold, highlight shortest path to crown jewels, export as image/SVG.
- **Integration**: Link each path step to its corresponding finding in Findings Explorer.

#### GUI-07: Exploitation Console

- **Features**: Module browser with search, risk classification, and description. Execution log with timestamp, target, technique, outcome, rollback status. HITL approval queue for destructive modules.
- **Safety**: Color-coded risk levels (green=safe, yellow=moderate, red=destructive). Confirmation dialogs with scope verification for all executions.
- **Audit**: Complete execution history with exportable audit trail.

#### GUI-08: Report Builder

- **Features**: Template selector (executive, technical, compliance, custom). Section toggle for including/excluding content. Live preview before generation. Delivery options: download (PDF/DOCX), email, archive.
- **Customization**: Drag-and-drop section ordering. Custom branding (logo, header, footer). Finding filter for selective inclusion.

#### GUI-09: Compliance Tracker

- **Features**: Calendar showing scheduled vs completed assessments. Coverage matrix by asset group and assessment type. Evidence collection status for audit readiness. Overdue assessment alerts.
- **Reports**: Exportable compliance posture summary per regulatory framework (PCI-DSS, SOC 2, ISO 27001, HIPAA).

#### GUI-10: Administration

- **Features**: User/role management (RBAC). Scanner engine configuration and health. System resource monitoring. API key management. Audit log viewer. Notification preferences.

### 20.5 UX Requirements

| ID    | Requirement                                                                                    |
| ----- | ---------------------------------------------------------------------------------------------- |
| UX-01 | All critical actions SHALL be reachable within 3 clicks from the dashboard.                    |
| UX-02 | GUI SHALL support responsive layout for desktop (1280px+) and tablet (768px+).                 |
| UX-03 | GUI SHALL meet WCAG 2.1 AA accessibility compliance.                                           |
| UX-04 | GUI SHALL support dark mode and light mode themes.                                             |
| UX-05 | Real-time data updates SHALL NOT cause visible page flicker or layout shifts.                  |
| UX-06 | All data tables SHALL support column reordering, resizing, and preference persistence.         |
| UX-07 | GUI SHALL display loading states, empty states, and error states for all data views.           |
| UX-08 | Critical finding notifications SHALL be surfaced via persistent toast with sound alert option. |

### 20.6 API Contract (Backend for Frontend)

| Endpoint Pattern                  | Method  | Purpose                                    |
| --------------------------------- | ------- | ------------------------------------------ |
| `/api/v1/engagements`           | CRUD    | Engagement lifecycle management            |
| `/api/v1/engagements/{id}/roe`  | GET/PUT | RoE authorization management               |
| `/api/v1/scans`                 | CRUD    | Scan execution and status                  |
| `/api/v1/scans/{id}/stream`     | WS      | Real-time scan progress and finding stream |
| `/api/v1/findings`              | GET     | Paginated finding query with filters       |
| `/api/v1/findings/{id}`         | GET/PUT | Finding detail and status update           |
| `/api/v1/attack-paths`          | GET     | Attack path graph data                     |
| `/api/v1/exploits`              | GET     | Exploit module catalog                     |
| `/api/v1/exploits/{id}/execute` | POST    | Trigger exploit with HITL approval check   |
| `/api/v1/reports`               | CRUD    | Report generation and retrieval            |
| `/api/v1/dashboard/summary`     | GET     | Aggregated dashboard metrics               |
| `/api/v1/compliance/schedule`   | CRUD    | Assessment schedule management             |
| `/ws/notifications`             | WS      | Global notification channel                |

### 20.7 Security Controls (GUI-Specific)

| ID         | Requirement                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------- |
| GUI-SEC-01 | Authentication SHALL use SSO (OIDC/SAML) with session timeout of 30 minutes.                        |
| GUI-SEC-02 | RBAC SHALL restrict screen access by role (e.g., exploitation console restricted to Red Team role). |
| GUI-SEC-03 | All API calls SHALL include CSRF token validation.                                                  |
| GUI-SEC-04 | Sensitive data (credentials, PoC output) SHALL be masked by default with reveal-on-click.           |
| GUI-SEC-05 | GUI SHALL enforce Content Security Policy (CSP) headers to prevent XSS.                             |
| GUI-SEC-06 | Session activity SHALL be logged for audit trail.                                                   |
| GUI-SEC-07 | Report downloads SHALL be watermarked with user identity and timestamp.                             |

---

## Revision History

| Version | Date       | Author              | Changes                           |
| ------- | ---------- | ------------------- | --------------------------------- |
| 1.0     | 2026-03-12 | AI Engineering Team | Initial SRS creation              |
| 2.0     | 2026-03-12 | AI Engineering Team | Production-ready with GUI section |
