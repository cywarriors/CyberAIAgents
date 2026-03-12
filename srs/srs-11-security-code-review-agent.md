# SRS-11: Security Code Review (AppSec) Agent

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| Document ID        | SRS-CYBER-11                                   |
| Version            | 2.0                                            |
| Status             | Production-Ready                               |
| Classification     | Internal-Confidential                          |
| Author             | Cybersecurity AI Engineering Team               |
| Reviewer           | AppSec Lead, Engineering Manager                |
| Approver           | CISO                                           |
| Created            | 2026-03-07                                     |
| Last Updated       | 2026-03-07                                     |

---

## 1. Introduction

### 1.1 Purpose
This SRS defines requirements for an AI-powered Security Code Review Agent that performs static application security testing (SAST), secrets detection, software composition analysis (SCA), and provides developer-friendly remediation guidance integrated into pull request workflows and CI/CD pipelines.

### 1.2 Intended Audience
- Application security engineers
- Software developers and team leads
- DevSecOps engineers
- Security architects

### 1.3 Definitions and Acronyms

| Term    | Definition                                                |
|---------|-----------------------------------------------------------|
| SAST    | Static Application Security Testing                       |
| SCA     | Software Composition Analysis                             |
| OWASP   | Open Worldwide Application Security Project               |
| CWE     | Common Weakness Enumeration                               |
| SBOM    | Software Bill of Materials                                |

---

## 2. Scope

### 2.1 In Scope
- SAST scanning for OWASP Top 10 and CWE-mapped vulnerability patterns.
- Secrets detection (API keys, tokens, passwords, certificates in source code).
- SCA for known vulnerabilities in third-party dependencies.
- PR-centric review workflow with inline findings and fix suggestions.
- Policy gate enforcement in CI/CD pipelines (block/warn/info).
- Developer-friendly remediation guidance with code fix examples.

### 2.2 Out of Scope
- Dynamic application security testing (DAST) and runtime protection.
- Penetration testing and manual security review.
- Infrastructure and container image scanning (SRS-07 scope).

---

## 3. Stakeholders

| Role                   | Responsibility                                    |
|------------------------|--------------------------------------------------|
| AppSec Lead            | Define scan policies and severity thresholds      |
| Software Developer     | Remediate findings and review PR feedback          |
| DevSecOps Engineer     | Integrate scans into CI/CD pipeline                |
| Engineering Manager    | Track security debt and remediation velocity       |
| CISO                   | Approve policy gates and risk acceptance           |

---

## 4. Assumptions and Constraints

### 4.1 Assumptions
- Source code repositories are accessible via version control API (GitHub/GitLab/Azure DevOps).
- CI/CD pipelines support custom scan step integration.
- A dependency manifest format (package.json, requirements.txt, pom.xml, etc.) exists.

### 4.2 Constraints
- Scan findings MUST NOT block deployments without AppSec team policy approval.
- Secret detection MUST redact actual secret values in all reports and logs.
- Scan results MUST be stored with access controls; only authorized roles may view source-level findings.

---

## 5. Functional Requirements

| ID     | Requirement                                                                                         | Priority |
|--------|-----------------------------------------------------------------------------------------------------|----------|
| FR-01  | System SHALL perform SAST scanning mapped to OWASP Top 10 and CWE categories.                      | Must     |
| FR-02  | System SHALL detect secrets (API keys, tokens, passwords, certificates) in source code and config.  | Must     |
| FR-03  | System SHALL perform SCA on third-party dependencies for known CVEs.                                 | Must     |
| FR-04  | System SHALL provide inline PR comments with finding details and severity.                           | Must     |
| FR-05  | System SHALL generate code fix suggestions for each finding where applicable.                       | Must     |
| FR-06  | System SHALL enforce configurable policy gates (block/warn/info) per severity in CI/CD.              | Must     |
| FR-07  | System SHALL produce SBOM for each scanned repository.                                               | Should   |
| FR-08  | System SHALL track finding lifecycle (new, acknowledged, remediated, false positive).                | Must     |
| FR-09  | System SHALL support language-specific scan rules (Python, Java, JavaScript, Go, C#, etc.).          | Must     |
| FR-10  | System SHALL provide a developer dashboard showing security debt and remediation trends.             | Should   |
| FR-11  | System SHALL support custom scan rules authored by AppSec team.                                      | Should   |
| FR-12  | System SHALL learn from false positive adjudications to reduce noise over time.                      | Should   |

---

## 6. Non-Functional Requirements

| ID      | Requirement                                    | Target                        |
|---------|-------------------------------------------------|-------------------------------|
| NFR-01  | SAST scan time per PR (diff-based)              | < 90 seconds                  |
| NFR-02  | Full repository scan time                       | < 10 minutes (medium repo)    |
| NFR-03  | Secrets detection latency                       | < 30 seconds per PR           |
| NFR-04  | SCA scan time                                   | < 60 seconds                  |
| NFR-05  | False positive rate (SAST)                      | < 15%                         |
| NFR-06  | Service availability                            | 99.9% monthly                 |
| NFR-07  | RTO                                             | < 15 minutes                  |

---

## 7. Data Requirements

### 7.1 Inputs
- Source code diffs (PR-scoped) and full repository snapshots.
- Dependency manifests and lock files.
- Known vulnerability databases (NVD, GitHub Advisory, OSV).
- Custom scan rule sets from AppSec team.
- Historical finding adjudications for ML-based noise reduction.

### 7.2 Outputs
- PR-inline finding comments with severity, CWE mapping, and fix suggestion.
- CI/CD pipeline scan reports (SARIF format).
- SBOM documents (CycloneDX/SPDX format).
- Developer security debt dashboard data.
- Finding lifecycle reports.

### 7.3 Retention
- Scan results: 24 months.
- SBOM snapshots: 24 months.
- Finding adjudication history: indefinite (for ML training).

---

## 8. Integration Requirements

| System                        | Protocol / Method | Direction     | Purpose                                    |
|-------------------------------|-------------------|---------------|--------------------------------------------|
| GitHub / GitLab / Azure DevOps| REST API / Webhooks| Bidirectional| PR events and inline comment posting       |
| CI/CD Pipeline (Actions/Jenkins)| CLI / REST API | Bidirectional | Scan step integration and policy gate      |
| NVD / OSV / GitHub Advisory   | REST API          | Inbound       | Vulnerability database for SCA             |
| SIEM                          | REST API / Syslog | Outbound      | High-severity finding alerts               |
| ITSM (ServiceNow/Jira)       | REST API          | Outbound      | Security debt ticket creation              |
| Developer Dashboard           | REST API          | Outbound      | Metrics and trend visualization            |

---

## 9. Security and Privacy Requirements

| ID      | Requirement                                                                             |
|---------|-----------------------------------------------------------------------------------------|
| SEC-01  | Source code SHALL NOT leave organizational boundaries during scanning.                   |
| SEC-02  | Detected secrets SHALL be redacted in all reports, logs, and notifications.             |
| SEC-03  | Scan results SHALL be access-controlled; only repo owners and AppSec may view.          |
| SEC-04  | All inter-service communication SHALL use mutual TLS.                                    |
| SEC-05  | Repository access tokens SHALL be stored in managed secret store.                        |
| SEC-06  | Scan workers SHALL have no persistent access to source code after scan completion.       |

---

## 10. Monitoring and Observability

| Metric                             | Alert Threshold         | Dashboard   |
|-------------------------------------|-------------------------|-------------|
| PR scan latency (p95)             | > 120 seconds           | Real-time   |
| Full repo scan latency (p95)      | > 15 minutes            | Real-time   |
| CI/CD pipeline scan failures       | > 0                     | Real-time   |
| False positive rate (SAST)        | > 20%                   | Weekly      |
| Daily scan volume                  | > 200% or < 50% baseline| Daily       |
| Service health (uptime)           | < 99.9% rolling 30d     | Real-time   |

---

## 11. Deployment and Environment

### 11.1 Target Environment
- Cloud-native Kubernetes deployment.
- LangGraph workers for scan orchestration.
- Ephemeral containers for source code analysis (no persistent code storage).

### 11.2 Infrastructure Requirements
- Compute: minimum 4 vCPU / 16 GB RAM per scan worker; auto-scaling by PR volume.
- Storage: PostgreSQL for findings and lifecycle state; object store for SBOM/SARIF artifacts.
- Networking: private subnets; mTLS service mesh; outbound access to vuln databases.

### 11.3 CI/CD
- GitOps pipeline with scan rule regression tests.
- Canary deployment for scan engine updates.
- Rollback within 5 minutes.

---

## 12. Framework Implementation (LangGraph)

### 12.1 Graph Design
- **Graph Type**: Code scan and remediation recommendation graph (parallel scan branches).
- **State Model**: `CodeReviewState`
  - `scan_target: ScanTarget`  (PR diff or full repo)
  - `sast_findings: list[SASTFinding]`
  - `secrets_findings: list[SecretFinding]`
  - `sca_findings: list[SCAFinding]`
  - `fix_suggestions: list[FixSuggestion]`
  - `policy_verdict: PolicyVerdict`
  - `sbom: SBOM`

### 12.2 Node Definitions

| Node                       | Responsibility                                         | Tool Access              |
|----------------------------|-------------------------------------------------------|--------------------------|
| IngestCodeNode             | Fetch PR diff or full repo snapshot                    | VCS API                  |
| SASTScanNode               | Run static analysis for vulnerability patterns         | SAST engine              |
| SecretsDetectNode          | Scan for exposed secrets and credentials               | Secrets scanner          |
| SCAScanNode                | Analyze dependencies for known CVEs                    | Vuln database API        |
| GenerateFixesNode          | Produce code fix suggestions for findings              | Fix suggestion engine    |
| EvaluatePolicyNode         | Apply policy gates (block/warn/info) by severity       | Policy rules engine      |
| PostPRCommentsNode         | Write inline PR comments with findings and fixes       | VCS API                  |
| GenerateSBOMNode           | Produce SBOM in CycloneDX/SPDX format                 | SBOM generator           |
| TrackLifecycleNode         | Update finding lifecycle and learn from adjudications   | State store, ML model    |

### 12.3 Control Flow
```
Start -> IngestCode
  -> [SASTScan, SecretsDetect, SCAScan] (parallel)
  -> GenerateFixes -> EvaluatePolicy
  -> [PostPRComments, GenerateSBOM] (parallel)
  -> TrackLifecycle -> End
```

### 12.4 Human-in-the-Loop
- **Checkpoint**: AppSec team approval required before enabling blocking policy gates.
- **Override**: Developer can mark findings as false positive with documented justification (reviewed by AppSec).

---

## 13. Reference Architecture

```
+-------------------+     +-------------------+     +-----------------------+
| VCS Platforms     | --> | PR / Repo Event   | --> | LangGraph CodeReview  |
| (GitHub/GitLab)   |     | Webhook           |     | Workers (K8s)         |
+-------------------+     +-------------------+     +-----------------------+
                                                         |       |       |
                                              +----------+       |       +--------+
                                              v                  v                v
                                      +------------+    +-----------+    +----------+
                                      | SAST       |    | Secrets   |    | SCA      |
                                      | Engine     |    | Scanner   |    | Engine   |
                                      +------------+    +-----------+    +----------+
                                              |                  |                |
                                              +------  Merge Findings  -----------+
                                                          |
                                                +---------v---------+
                                                | Fix Suggestion +  |
                                                | Policy Engine     |
                                                +---------+---------+
                                                          |
                                         +----------------+----------------+
                                         v                v                v
                                   +-----------+  +-------------+  +-----------+
                                   | PR Inline |  | SBOM        |  | SARIF     |
                                   | Comments  |  | Generation  |  | Reports   |
                                   +-----------+  +-------------+  +-----------+

Governance: Scan Rule Registry | Finding Lifecycle Store | Policy Config | FP Learning Model
```

---

## 14. Testing Strategy

| Test Type           | Scope                                                        | Frequency      |
|---------------------|--------------------------------------------------------------|----------------|
| Unit Tests          | SAST rules, secrets patterns, SCA matching, fix generation    | Every commit   |
| Scenario Tests      | Seeded vulnerable code samples across supported languages     | Every PR       |
| Integration Tests   | Full PR scan pipeline with mock VCS webhook                   | Weekly         |
| Load Tests          | 100+ concurrent PR scans                                      | Monthly        |
| FP Validation       | False positive rate measurement against labeled dataset       | Monthly        |
| Developer UX Test   | Validate PR comment clarity and fix suggestion quality        | Quarterly      |

---

## 15. Cross-Agent Dependencies

| Dependency Agent              | Relationship                                              |
|-------------------------------|-----------------------------------------------------------|
| SRS-04: Vulnerability Mgmt   | SCA findings feed vulnerability tracking and prioritization|
| SRS-07: Cloud Security Posture| IaC scan findings complement code-level security review    |
| SRS-10: Compliance & Audit    | Scan results provide evidence for secure SDLC controls    |

---

## 16. Risk Register

| Risk                                        | Likelihood | Impact   | Mitigation                                              |
|---------------------------------------------|------------|----------|---------------------------------------------------------|
| High false positive rate causing developer fatigue | High  | High     | ML-based FP reduction; adjustable sensitivity; FP feedback loop |
| Scan performance slowing CI/CD pipelines     | Medium     | High     | Diff-based scanning; caching; dedicated scan workers    |
| Secrets detected after commit to main branch | Medium     | Critical | Pre-commit hooks; real-time PR scanning; secret rotation|
| SCA database lag for zero-day CVEs           | Medium     | Medium   | Multiple vuln sources; rapid update pipeline            |
| Custom rules introducing scan errors         | Low        | Medium   | Rule validation suite; staged rollout; rollback support |

---

## 17. How to Use This Agent

### 17.1 Initial Setup
1. Configure VCS integration (GitHub App / GitLab webhook / Azure DevOps service hook).
2. Define scan policies and severity-based gates (block/warn/info) per repository tier.
3. Configure scan rules for target languages and custom patterns.
4. Deploy LangGraph code review workers.

### 17.2 Pilot Phase (Weeks 1-3)
5. Enable scanning on a subset of high-priority repositories in **warn-only mode**.
6. Collect developer feedback on finding quality and fix suggestion usefulness.
7. Tune false positive exclusions and severity thresholds.

### 17.3 Production Rollout
8. Expand scanning to all in-scope repositories.
9. Enable blocking policy gates for critical and high severity findings.
10. Activate secrets detection with automated rotation recommendations.

### 17.4 Ongoing Operations
11. Review false positive rate and developer satisfaction monthly.
12. Update scan rules quarterly for new vulnerability patterns and languages.
13. Retrain FP reduction model with new adjudication data.

---

## 18. Acceptance Criteria

| ID    | Criterion                                                                  | Validation Method       |
|-------|----------------------------------------------------------------------------|-------------------------|
| AC-01 | Agent detects >= 90% of OWASP Top 10 vulnerabilities in test samples.      | Vulnerable code suite   |
| AC-02 | PR diff-based scans complete within 90 seconds.                             | Latency monitoring      |
| AC-03 | Secrets detection catches 100% of seeded test secrets.                     | Secret detection suite  |
| AC-04 | Fix suggestions provided for >= 70% of findings.                           | Content validation      |
| AC-05 | False positive rate < 15% across supported languages.                      | FP analysis report      |

---

## 19. KPIs and Success Metrics

| KPI                                        | Baseline Target       | Measurement Cadence |
|--------------------------------------------|-----------------------|---------------------|
| Mean Time to Remediate Code Findings       | < 5 business days     | Weekly              |
| Security Finding Escape Rate to Production | < 5%                  | Monthly             |
| Developer Fix Adoption Rate                | >= 60%                | Monthly             |
| False Positive Rate                        | < 15%                 | Monthly             |
| Repository Scan Coverage                   | >= 95% of in-scope    | Monthly             |

---

## 20. Graphical User Interface (GUI) Requirements

### 20.1 Overview
The Security Code Review (AppSec) Agent GUI provides a web-based interface for browsing code security findings, reviewing PR-level scan results, managing fix suggestions, and tracking developer remediation metrics. Designed for application security engineers, developers, and engineering leadership.

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
| GUI-01    | AppSec Dashboard         | AppSec Engineers, Leadership     | Finding volume trends, fix rates, repo coverage, top CWE categories |
| GUI-02    | Finding Browser          | AppSec Engineers, Developers     | Filterable security finding table with code context and fix suggestions |
| GUI-03    | PR Review View           | Developers, AppSec Engineers     | PR-level scan results with inline code annotations |
| GUI-04    | Repository Overview      | AppSec Engineers                 | Per-repo security posture, finding density, scan history |
| GUI-05    | Fix Suggestion Manager   | AppSec Engineers                 | AI-generated fix suggestions with acceptance/rejection tracking |
| GUI-06    | Developer Dashboard      | Developers, Engineering Leads    | Per-developer/team finding metrics, fix adoption rate, learning resources |
| GUI-07    | Policy Manager           | AppSec Engineers                 | Security scanning policy configuration per repo/org |
| GUI-08    | Administration           | Platform Engineering             | Scanner engine config, language support, integration health |

### 20.4 Key Screen Specifications

#### GUI-01: AppSec Dashboard
- **Widgets**: Open finding count by severity (stacked bar), fix rate trend (line chart), top 10 CWE categories (horizontal bar), repository scan coverage gauge, mean time to fix trend, finding escape rate to production.
- **Interactions**: Repository/team/language filter. Time range selector. Click-through to filtered finding browser.

#### GUI-02: Finding Browser
- **Features**: Data table with server-side pagination, filtering by repository, severity, CWE, language, finding status, age. Inline code viewer with highlighted vulnerable lines and surrounding context. Fix suggestion panel with diff preview.
- **Actions**: Assign, create ticket, mark false positive, accept/modify fix suggestion, suppress with justification.

#### GUI-03: PR Review View
- **Features**: PR scan summary with new findings, fixed findings, and net change. Inline code annotations on diff view showing finding location, severity, and fix suggestion. One-click approve fix or dismiss with reason.
- **Integration**: Deep link from PR notification (GitHub/GitLab/Azure DevOps) to agent PR view.

#### GUI-04: Repository Overview
- **Features**: Repository security scorecard (finding density, fix velocity, coverage). Finding trend over time. Language breakdown. Branch protection and scanning policy status.

#### GUI-05: Fix Suggestion Manager
- **Features**: Queue of AI-generated fix suggestions with original vs suggested code diff. Confidence score. Acceptance rate metrics. Bulk approve/reject. Feedback mechanism for model improvement.

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
| UX-08   | Code viewers SHALL support syntax highlighting for all supported languages.          |

### 20.6 API Contract (Backend for Frontend)

| Endpoint Pattern                  | Method | Purpose                                  |
|-----------------------------------|--------|------------------------------------------|
| `/api/v1/findings`                | GET    | Paginated finding query with filters      |
| `/api/v1/findings/{id}`           | GET/PUT| Finding detail and analyst actions          |
| `/api/v1/findings/{id}/fix`       | GET/PUT| Fix suggestion detail and accept/reject    |
| `/api/v1/repos`                   | GET    | Repository list with security scores       |
| `/api/v1/repos/{id}/findings`     | GET    | Findings for a specific repository         |
| `/api/v1/repos/{id}/history`      | GET    | Scan history for a repository              |
| `/api/v1/prs/{id}/scan`           | GET    | PR-level scan results                      |
| `/api/v1/policies`                | CRUD   | Scanning policy management                 |
| `/api/v1/developers/metrics`      | GET    | Developer fix adoption metrics             |
| `/api/v1/dashboard/appsec`        | GET    | Aggregated AppSec dashboard metrics        |
| `/ws/notifications`              | WS     | New finding and PR scan completion alerts  |

### 20.7 Security Controls (GUI-Specific)

| ID       | Requirement                                                                        |
|----------|------------------------------------------------------------------------------------|
| GUI-SEC-01 | Authentication SHALL use SSO (OIDC/SAML) with session timeout of 30 minutes.    |
| GUI-SEC-02 | RBAC SHALL restrict finding visibility by repository access (e.g., developers see only their repos). |
| GUI-SEC-03 | All API calls SHALL include CSRF token validation.                               |
| GUI-SEC-04 | Source code rendering SHALL be read-only with no clipboard access to code context. |
| GUI-SEC-05 | GUI SHALL enforce Content Security Policy (CSP) headers to prevent XSS.          |
| GUI-SEC-06 | Session activity SHALL be logged for audit trail.                                |

---

## Revision History

| Version | Date       | Author              | Changes                          |
|---------|------------|----------------------|----------------------------------|
| 1.0     | 2026-03-07 | AI Engineering Team  | Initial SRS creation             |
| 2.0     | 2026-03-07 | AI Engineering Team  | Production-ready refinement      |
