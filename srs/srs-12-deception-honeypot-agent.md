# SRS-12: Deception and Honeypot Agent

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| Document ID        | SRS-CYBER-12                                   |
| Version            | 2.0                                            |
| Status             | Production-Ready                               |
| Classification     | Internal-Confidential                          |
| Author             | Cybersecurity AI Engineering Team               |
| Reviewer           | Deception Operations Lead, SOC Manager          |
| Approver           | CISO                                           |
| Created            | 2026-03-07                                     |
| Last Updated       | 2026-03-07                                     |

---

## 1. Introduction

### 1.1 Purpose
This SRS defines requirements for an AI-powered Deception and Honeypot Agent that deploys realistic decoy assets, honey credentials, and canary tokens across the environment to detect adversary lateral movement, credential theft, and reconnaissance activities, and profiles attacker tactics, techniques, and procedures (TTPs).

### 1.2 Intended Audience
- Deception operations and threat hunting teams
- SOC analysts
- Red team / purple team members
- Security architects

### 1.3 Definitions and Acronyms

| Term          | Definition                                                |
|---------------|-----------------------------------------------------------|
| Honeypot      | Decoy system designed to attract and detect attackers      |
| Honeytoken    | Fake credential or data object that triggers alerts when used |
| Canary Token  | Embedded marker that alerts when accessed or exfiltrated   |
| TTP           | Tactics, Techniques, and Procedures                       |
| MITRE ATT&CK  | Adversarial behavior knowledge base                      |

---

## 2. Scope

### 2.1 In Scope
- Automated deployment and lifecycle management of decoy assets (servers, services, shares).
- Honey credential and canary token generation and placement.
- Real-time monitoring of all interactions with decoy assets.
- Attacker TTP profiling and ATT&CK mapping from honeypot interactions.
- Integration with SOC alerting and threat intelligence workflows.
- Deception coverage analysis and gap identification.

### 2.2 Out of Scope
- Full intrusion detection and prevention (IDS/IPS responsibility).
- Endpoint detection and response (EDR responsibility).
- Active offensive operations against attackers.

---

## 3. Stakeholders

| Role                       | Responsibility                                    |
|----------------------------|--------------------------------------------------|
| Deception Operations Lead  | Define decoy strategy and coverage requirements   |
| SOC Analyst                | Investigate honeypot interaction alerts            |
| Threat Hunter              | Use TTP profiles for proactive hunting campaigns  |
| Red Team Lead              | Validate deception effectiveness                   |
| CISO                       | Approve deployment strategy and risk posture      |

---

## 4. Assumptions and Constraints

### 4.1 Assumptions
- Network segments allow deployment of decoy systems without operational impact.
- Active Directory or equivalent directory service supports honey account creation.
- SOC has capacity to investigate high-fidelity honeypot alerts.

### 4.2 Constraints
- Decoys MUST NOT contain real production data or genuine credentials.
- Decoy deployment MUST NOT impact production system performance or availability.
- Honey credential placement in production systems MUST be approved by system owners.
- All attacker interactions MUST be monitored passively; no active countermeasures.

---

## 5. Functional Requirements

| ID     | Requirement                                                                                         | Priority |
|--------|-----------------------------------------------------------------------------------------------------|----------|
| FR-01  | System SHALL deploy decoy assets (servers, services, SMB shares, databases) across network segments.| Must     |
| FR-02  | System SHALL generate and place honey credentials in strategic locations (LSASS, config files, vaults).| Must   |
| FR-03  | System SHALL deploy canary tokens in documents, emails, and file shares.                            | Must     |
| FR-04  | System SHALL monitor all interactions with decoy assets in real time.                                | Must     |
| FR-05  | System SHALL classify interactions as scan, probe, exploitation, or lateral movement.               | Must     |
| FR-06  | System SHALL map attacker behaviors to MITRE ATT&CK tactics and techniques.                         | Must     |
| FR-07  | System SHALL generate high-fidelity SOC alerts for confirmed attacker interactions.                 | Must     |
| FR-08  | System SHALL maintain decoy asset realism (OS fingerprint, service banners, response patterns).      | Must     |
| FR-09  | System SHALL analyze deception coverage and identify gaps across network segments.                   | Should   |
| FR-10  | System SHALL produce attacker TTP profiles and campaign correlation reports.                         | Should   |
| FR-11  | System SHALL support automated decoy rotation to prevent attacker fingerprinting.                    | Should   |
| FR-12  | System SHALL track decoy asset health and lifecycle (deploy, active, compromised, retired).          | Must     |

---

## 6. Non-Functional Requirements

| ID      | Requirement                                    | Target                        |
|---------|-------------------------------------------------|-------------------------------|
| NFR-01  | Interaction detection latency                   | < 10 seconds                  |
| NFR-02  | Decoy deployment time                           | < 5 minutes per asset         |
| NFR-03  | Service availability (monitoring)               | 99.9% monthly                 |
| NFR-04  | Decoy realism assessment score                  | >= 90% pass rate (red team)   |
| NFR-05  | RTO                                             | < 15 minutes                  |
| NFR-06  | RPO                                             | < 2 minutes                   |

---

## 7. Data Requirements

### 7.1 Inputs
- Network topology and segment inventory.
- Active Directory schema for realistic honey account creation.
- Service and application profiles for decoy realism calibration.
- Threat intelligence for attacker behavior context.

### 7.2 Outputs
- Honeypot interaction alerts with source IP, techniques, and timeline.
- Attacker TTP profiles mapped to ATT&CK.
- Deception coverage reports and gap analysis.
- Campaign correlation reports linking interactions across decoys.
- Honey credential usage alerts with context.

### 7.3 Retention
- Interaction logs: 24 months.
- TTP profiles: 36 months.
- Decoy deployment history: 24 months.

---

## 8. Integration Requirements

| System                        | Protocol / Method | Direction     | Purpose                                |
|-------------------------------|-------------------|---------------|----------------------------------------|
| Network Infrastructure        | API / Agents      | Bidirectional | Decoy deployment and monitoring        |
| Active Directory              | LDAP / REST       | Bidirectional | Honey account creation and monitoring  |
| SIEM                          | REST API / Syslog | Outbound      | High-fidelity alert publishing         |
| Threat Intelligence (SRS-09)  | REST API          | Bidirectional | TTP profiles and attacker context      |
| Incident Triage (SRS-02)      | REST API          | Outbound      | Alert enrichment with deception context|
| ITSM (ServiceNow/Jira)       | REST API          | Outbound      | Investigation case creation            |
| EDR Platform                  | REST API          | Inbound       | Endpoint context for interaction analysis|

---

## 9. Security and Privacy Requirements

| ID      | Requirement                                                                             |
|---------|-----------------------------------------------------------------------------------------|
| SEC-01  | Decoy assets SHALL NOT contain real production data or genuine credentials.              |
| SEC-02  | Honey credentials SHALL be distinguishable (internally) from real credentials.           |
| SEC-03  | Decoy management interfaces SHALL be access-controlled and audit-logged.                 |
| SEC-04  | All inter-service communication SHALL use mutual TLS.                                    |
| SEC-05  | Interaction logs SHALL be encrypted at rest and access-controlled.                       |
| SEC-06  | Decoy deployment SHALL be invisible to standard asset inventory tools.                   |

---

## 10. Monitoring and Observability

| Metric                             | Alert Threshold         | Dashboard   |
|-------------------------------------|-------------------------|-------------|
| Interaction detection latency       | > 15 seconds            | Real-time   |
| Decoy asset health (responsive)    | Any unresponsive decoy  | Real-time   |
| Honey credential usage events      | Any occurrence          | Real-time   |
| Canary token access events         | Any occurrence          | Real-time   |
| Deception coverage (% segments)    | < 80% target segments   | Weekly      |
| Service health (uptime)           | < 99.9% rolling 30d     | Real-time   |

---

## 11. Deployment and Environment

### 11.1 Target Environment
- Hybrid deployment: lightweight agents on existing infrastructure + dedicated decoy VMs/containers.
- LangGraph workers for deception orchestration and interaction analysis.
- Central management plane for decoy lifecycle and coverage visualization.

### 11.2 Infrastructure Requirements
- Compute: lightweight per decoy (1-2 vCPU / 2-4 GB RAM); management plane 4 vCPU / 16 GB RAM.
- Storage: PostgreSQL for interaction state; time-series DB for interaction analytics.
- Networking: decoy assets distributed across production VLANs; management traffic on isolated segment.

### 11.3 CI/CD
- GitOps pipeline for decoy template and configuration management.
- Staged decoy deployment with automated health checks.
- Rollback within 5 minutes.

---

## 12. Framework Implementation (LangGraph)

### 12.1 Graph Design
- **Graph Type**: Deception deployment and trigger analysis graph (event-driven with periodic coverage assessment).
- **State Model**: `DeceptionState`
  - `decoy_inventory: list[DecoyAsset]`
  - `honey_credentials: list[HoneyCredential]`
  - `canary_tokens: list[CanaryToken]`
  - `interactions: list[InteractionEvent]`
  - `ttp_profile: AttackerProfile`
  - `coverage_assessment: CoverageReport`

### 12.2 Node Definitions

| Node                       | Responsibility                                         | Tool Access              |
|----------------------------|-------------------------------------------------------|--------------------------|
| DeployDecoysNode           | Provision and configure decoy assets per strategy       | Infra API, VM/container  |
| PlaceHoneyCredsNode        | Generate and place honey credentials and tokens         | AD/LDAP, file systems    |
| MonitorInteractionsNode    | Real-time monitoring of all decoy interactions           | Agent telemetry          |
| ClassifyInteractionNode    | Categorize interaction type (scan, probe, exploit, lateral)| Classifier model      |
| MapTTPsNode                | Map observed behaviors to MITRE ATT&CK                  | ATT&CK knowledge base   |
| GenerateAlertNode          | Create high-fidelity SOC alert with full context         | SIEM API                 |
| ProfileAttackerNode        | Build and update attacker TTP profiles                    | Profile store            |
| AssessCoverageNode         | Evaluate deception coverage and recommend new placements  | Network topology         |
| RotateDecoysNode           | Retire stale decoys and deploy fresh variants             | Infra API                |

### 12.3 Control Flow
```
Start -> [DeployDecoys, PlaceHoneyCreds] (parallel, periodic)
  -> MonitorInteractions (streaming)
  -> ClassifyInteraction -> MapTTPs
  -> [GenerateAlert, ProfileAttacker] (parallel)
  -> AssessCoverage -> RotateDecoys -> End
```

### 12.4 Human-in-the-Loop
- **Checkpoint**: System owner approval required before placing honey credentials in production systems.
- **Override**: SOC analyst can escalate interaction to incident without waiting for full TTP profiling.

---

## 13. Reference Architecture

```
+-------------------+     +-------------------+     +-----------------------+
| Network Segments  | <-> | Decoy Assets      | --> | LangGraph Deception   |
| (Production VLANs)|     | (VMs/Containers)  |     | Workers (K8s)         |
+-------------------+     +-------------------+     +-----------------------+
                                                         |       |       |
                                              +----------+       |       +--------+
                                              v                  v                v
                                      +------------+    +-----------+    +----------+
                                      | Interaction|    | TTP       |    | Coverage |
                                      | Classifier |    | Profiler  |    | Analyzer |
                                      +------------+    +-----------+    +----------+
                                              |                  |                |
                                              +------  Merge Analysis  -----------+
                                                          |
                                                +---------v---------+
                                                | Alert + Profile   |
                                                | Generation        |
                                                +---------+---------+
                                                          |
                                         +----------------+----------------+
                                         v                v                v
                                   +-----------+  +-------------+  +-----------+
                                   | SIEM      |  | Threat Intel|  | Decoy     |
                                   | Alerts    |  | (TTP Feed)  |  | Rotation  |
                                   +-----------+  +-------------+  +-----------+

Governance: Decoy Registry | Honey Credential Vault | Interaction Log | Coverage Map
```

---

## 14. Testing Strategy

| Test Type           | Scope                                                        | Frequency      |
|---------------------|--------------------------------------------------------------|----------------|
| Unit Tests          | Interaction classification, TTP mapping, coverage calculation | Every commit   |
| Scenario Tests      | Simulated attacker interactions against deployed decoys       | Every PR       |
| Integration Tests   | Full deception pipeline with mock network interactions        | Weekly         |
| Realism Tests       | Red team assessment of decoy believability                    | Monthly        |
| Coverage Tests      | Verify deception coverage across all target segments          | Monthly        |
| Red Team Exercise   | Full adversary simulation to validate detection               | Quarterly      |

---

## 15. Cross-Agent Dependencies

| Dependency Agent              | Relationship                                              |
|-------------------------------|-----------------------------------------------------------|
| SRS-01: Threat Detection      | Honeypot alerts enrich detection context                   |
| SRS-02: Incident Triage       | Deception alerts feed into triage pipeline                 |
| SRS-03: Automated Response    | Confirmed attacker IPs trigger containment playbooks       |
| SRS-06: Identity & Access     | Honey credential usage signals feed identity risk scoring  |
| SRS-09: Threat Intelligence   | TTP profiles enrich threat intelligence platform           |

---

## 16. Risk Register

| Risk                                        | Likelihood | Impact   | Mitigation                                              |
|---------------------------------------------|------------|----------|---------------------------------------------------------|
| Attacker identifies and avoids decoys        | Medium     | High     | Regular decoy rotation; realism testing; adaptive placement |
| Honey credentials used by legitimate users   | Low        | Medium   | Clear internal documentation; credential naming conventions |
| Decoy asset impacts production performance   | Low        | High     | Resource isolation; performance monitoring; kill switch  |
| Decoy management plane compromise            | Low        | Critical | Hardened management; MFA; network isolation              |
| Alert fatigue from automated scanning        | Medium     | Medium   | Interaction classification; tunable alert thresholds    |

---

## 17. How to Use This Agent

### 17.1 Initial Setup
1. Map network segments and identify high-value target areas for deception coverage.
2. Define decoy asset profiles matching production environment (OS, services, naming).
3. Configure honey credential templates and canary token types.
4. Deploy LangGraph deception workers and central management plane.

### 17.2 Pilot Phase (Weeks 1-4)
5. Deploy decoys in 2-3 network segments with highest adversary risk.
6. Place honey credentials in strategic locations with system owner approval.
7. Enable **alert-only mode** for SOC to baseline normal interaction noise.
8. Validate decoy realism with red team exercises.

### 17.3 Production Rollout
9. Expand decoy deployment to all target network segments.
10. Enable SIEM integration and ITSM case creation for confirmed interactions.
11. Activate automated decoy rotation schedule.

### 17.4 Ongoing Operations
12. Review deception coverage and TTP profiles monthly.
13. Update decoy profiles as production environment evolves.
14. Conduct quarterly red team exercises to validate effectiveness.

---

## 18. Acceptance Criteria

| ID    | Criterion                                                                  | Validation Method       |
|-------|----------------------------------------------------------------------------|-------------------------|
| AC-01 | Agent deploys decoys in >= 80% of target network segments.                 | Coverage report         |
| AC-02 | Honeypot interactions detected and alerted within 10 seconds.              | Latency monitoring      |
| AC-03 | Red team rates decoy realism >= 90% pass rate.                             | Red team assessment     |
| AC-04 | Honey credential usage generates immediate high-fidelity alert.            | Scenario testing        |
| AC-05 | TTP profiles include ATT&CK mapping for all confirmed interactions.        | Content validation      |

---

## 19. KPIs and Success Metrics

| KPI                                        | Baseline Target       | Measurement Cadence |
|--------------------------------------------|-----------------------|---------------------|
| Deception Coverage (% target segments)     | >= 80%                | Monthly             |
| Mean Time to Detect Attacker Interaction   | < 10 seconds          | Weekly              |
| Red Team Detection Rate (% exercises)      | >= 85%                | Quarterly           |
| False Positive Rate (legitimate user trips) | < 2%                 | Monthly             |
| TTP Profile Completeness (ATT&CK coverage)| >= 75% of observed TTPs| Quarterly          |

---

## 20. Graphical User Interface (GUI) Requirements

### 20.1 Overview
The Deception and Honeypot Agent GUI provides a web-based interface for deploying and managing decoy assets, monitoring attacker interactions in real-time, analyzing captured TTPs, and managing deception campaigns. Designed for deception specialists, red/blue team engineers, and threat intelligence analysts.

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
| GUI-01    | Deception Dashboard      | Deception Specialist, Leadership | Decoy deployment status, interaction volume, detection effectiveness |
| GUI-02    | Decoy Deployment Manager | Deception Specialist             | Deploy, configure, and lifecycle-manage decoy assets |
| GUI-03    | Interaction Monitor      | Deception Specialist, SOC        | Real-time attacker interaction feed with session replay |
| GUI-04    | TTP Profiler             | Threat Intel, Red Team           | Captured attacker techniques mapped to ATT&CK framework |
| GUI-05    | Campaign Manager         | Deception Specialist             | Plan and manage deception campaigns with objectives and metrics |
| GUI-06    | Breadcrumb Designer      | Deception Specialist             | Design and deploy credential lures, document decoys, network breadcrumbs |
| GUI-07    | Coverage Heatmap         | Leadership, Blue Team            | Network topology overlay showing deception coverage density |
| GUI-08    | Administration           | Platform Engineering             | Decoy template management, network config, system health |

### 20.4 Key Screen Specifications

#### GUI-01: Deception Dashboard
- **Widgets**: Active decoy count by type (bar chart), interaction volume timeline, detection rate gauge, top interacted decoys (horizontal bar), geographic origin of interactions (map), TTP coverage percentage.
- **Interactions**: Click-through to interaction detail. Decoy type / network segment filter. Auto-refresh every 15 seconds.

#### GUI-02: Decoy Deployment Manager
- **Features**: Decoy template catalog (SSH honeypot, web app, file share, database, API endpoint, credential lure). Deploy wizard with network placement, fidelity level, and monitoring configuration. Lifecycle status (Staging → Active → Triggered → Investigating → Retired). Bulk management.
- **Visualization**: Network topology view showing decoy placement relative to real assets.

#### GUI-03: Interaction Monitor
- **Features**: Real-time interaction feed with timestamp, source IP, decoy target, interaction type, and risk level. Session replay for detailed analysis (keystroke capture, command log, file access). Alert on first interaction per unique source.
- **Layout**: Split view — interaction list (left), session detail/replay (right).

#### GUI-04: TTP Profiler
- **Features**: ATT&CK technique heatmap populated from captured interactions. Per-technique drill-down showing source, decoy, session data. Actor clustering based on behavioral patterns. Export to threat intelligence (SRS-09 integration).

#### GUI-06: Breadcrumb Designer
- **Features**: Visual breadcrumb trail designer showing lure placement across network. Template library for common lure types (credentials, documents, registry keys, DNS entries). Effectiveness tracking per lure.

#### GUI-07: Coverage Heatmap
- **Features**: Network topology overlay with deception coverage density by segment. Gap identification with deployment recommendations. Comparison of deception coverage vs asset criticality.

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
| UX-08   | Session replay SHALL render in sandboxed context with no outbound network access.   |

### 20.6 API Contract (Backend for Frontend)

| Endpoint Pattern                  | Method | Purpose                                  |
|-----------------------------------|--------|------------------------------------------|
| `/api/v1/decoys`                  | CRUD   | Decoy lifecycle management                 |
| `/api/v1/decoys/{id}/status`      | GET    | Decoy status and health                    |
| `/api/v1/interactions`            | GET    | Paginated interaction list with filters    |
| `/api/v1/interactions/{id}`       | GET    | Interaction detail with session data       |
| `/api/v1/interactions/{id}/replay`| GET    | Session replay data stream                 |
| `/api/v1/campaigns`               | CRUD   | Deception campaign management              |
| `/api/v1/breadcrumbs`             | CRUD   | Breadcrumb/lure lifecycle management       |
| `/api/v1/ttps`                    | GET    | Captured TTP data and ATT&CK mapping      |
| `/api/v1/coverage`                | GET    | Network deception coverage data            |
| `/api/v1/dashboard/deception`     | GET    | Aggregated deception dashboard metrics     |
| `/ws/interactions`                | WS     | Real-time interaction stream               |

### 20.7 Security Controls (GUI-Specific)

| ID       | Requirement                                                                        |
|----------|------------------------------------------------------------------------------------|
| GUI-SEC-01 | Authentication SHALL use SSO (OIDC/SAML) with session timeout of 30 minutes.    |
| GUI-SEC-02 | RBAC SHALL restrict screen access by role (e.g., Decoy Deployment restricted to Deception Specialist role). |
| GUI-SEC-03 | All API calls SHALL include CSRF token validation.                               |
| GUI-SEC-04 | Decoy network placement details SHALL be classified and access-restricted.       |
| GUI-SEC-05 | GUI SHALL enforce Content Security Policy (CSP) headers to prevent XSS.          |
| GUI-SEC-06 | Session replay content SHALL be rendered in isolated sandboxed context.          |
| GUI-SEC-07 | Session activity SHALL be logged for audit trail.                                |

---

## Revision History

| Version | Date       | Author              | Changes                          |
|---------|------------|----------------------|----------------------------------|
| 1.0     | 2026-03-07 | AI Engineering Team  | Initial SRS creation             |
| 2.0     | 2026-03-07 | AI Engineering Team  | Production-ready refinement      |
