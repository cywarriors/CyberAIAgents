# SRS-05: Phishing Defense Agent

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| Document ID        | SRS-CYBER-05                                   |
| Version            | 2.0                                            |
| Status             | Production-Ready                               |
| Classification     | Internal-Confidential                          |
| Author             | Cybersecurity AI Engineering Team               |
| Reviewer           | Email Security Lead, SOC Manager                |
| Approver           | CISO                                           |
| Created            | 2026-03-07                                     |
| Last Updated       | 2026-03-07                                     |

---

## 1. Introduction

### 1.1 Purpose
This SRS defines requirements for an AI-powered Phishing Defense Agent that detects, classifies, and mitigates phishing, spear-phishing, and business email compromise (BEC) attacks in real time.

### 1.2 Intended Audience
- SOC and email security teams
- IT messaging administrators
- End-user department managers
- Compliance and legal teams

### 1.3 Definitions and Acronyms

| Term    | Definition                                              |
|---------|---------------------------------------------------------|
| BEC     | Business Email Compromise                               |
| DKIM    | DomainKeys Identified Mail                              |
| DMARC   | Domain-based Message Authentication, Reporting & Conformance |
| IOC     | Indicator of Compromise                                 |
| NLP     | Natural Language Processing                             |
| SPF     | Sender Policy Framework                                 |

---

## 2. Scope

### 2.1 In Scope
- Inbound and internal email inspection for phishing indicators.
- Sender authentication validation (SPF/DKIM/DMARC), lookalike domain detection.
- NLP-based social-engineering intent classification.
- URL and attachment detonation in sandbox.
- Risk scoring and verdict assignment (allow/warn/quarantine/block).
- User-reported phishing intake and IOC extraction.

### 2.2 Out of Scope
- User security awareness training content creation.
- Outbound DLP scanning (separate program).
- SMS/voice phishing (vishing/smishing) defense.

---

## 3. Stakeholders

| Role                       | Responsibility                                    |
|----------------------------|--------------------------------------------------|
| Email Security Lead        | Own detection policy and tuning                   |
| SOC Analyst                | Review quarantined mail, process escalations       |
| IT Messaging Admin         | Maintain mail gateway and tenant integrations      |
| Compliance / Legal         | Ensure privacy and retention compliance            |
| CISO                       | Approve production rollout and risk acceptance     |

---

## 4. Assumptions and Constraints

### 4.1 Assumptions
- Mail gateway and tenant APIs (M365 / Google Workspace) are API-accessible.
- Sandbox service (cloud or on-prem) is available for URL and attachment detonation.
- SPF, DKIM, and DMARC records are deployed for organizational domains.

### 4.2 Constraints
- Email verdict latency must not exceed 10 seconds (p95) to avoid user-perceptible delay.
- Quarantine and release policy must support manual analyst override.
- Message content handling must comply with privacy and legal retention rules.

---

## 5. Functional Requirements

| ID     | Requirement                                                                                       | Priority |
|--------|---------------------------------------------------------------------------------------------------|----------|
| FR-01  | System SHALL inspect inbound and internal emails for phishing indicators in real time.            | Must     |
| FR-02  | System SHALL validate sender SPF, DKIM, and DMARC posture and detect lookalike domains.          | Must     |
| FR-03  | System SHALL classify suspicious language patterns, urgency cues, and social-engineering intent.  | Must     |
| FR-04  | System SHALL detonate URLs and attachments in sandboxed environment for behavior analysis.        | Must     |
| FR-05  | System SHALL assign risk score and final verdict: allow, warn, quarantine, or block.             | Must     |
| FR-06  | System SHALL apply user-visible warning banners for medium-risk emails.                          | Must     |
| FR-07  | System SHALL auto-quarantine high-risk messages with configurable policy controls.               | Must     |
| FR-08  | System SHALL ingest user-reported phishing submissions via report button and feedback mailbox.    | Must     |
| FR-09  | System SHALL extract IOCs (URLs, domains, IPs, file hashes) and distribute to blocking systems.  | Must     |
| FR-10  | System SHALL support false-positive review and analyst-authorized release workflow.              | Must     |
| FR-11  | System SHALL detect VIP impersonation and display-name spoofing.                                 | Should   |
| FR-12  | System SHALL provide phishing trend dashboards and campaign clustering.                          | Should   |

---

## 6. Non-Functional Requirements

| ID      | Requirement                                    | Target                    |
|---------|-------------------------------------------------|---------------------------|
| NFR-01  | Email verdict latency (p95)                     | < 10 seconds              |
| NFR-02  | Detection recall (known phishing tests)         | >= 95%                    |
| NFR-03  | False positive rate (business-critical email)   | < 1.5%                    |
| NFR-04  | Service availability                            | 99.95% monthly            |
| NFR-05  | Throughput capacity                             | >= 50,000 emails/hour     |
| NFR-06  | RTO                                             | < 10 minutes              |
| NFR-07  | RPO                                             | < 1 minute                |

---

## 7. Data Requirements

### 7.1 Inputs
- Email headers, body (text + HTML), embedded URLs, and attachments.
- Sender reputation data and domain registration metadata.
- Threat intelligence feeds (known phishing IOCs).
- Sandbox behavioral telemetry.

### 7.2 Outputs
- Verdict record: risk score, confidence, classification, evidence.
- Quarantine status and release/block decision audit trail.
- Extracted IOCs for SIEM and blocking systems.
- Phishing campaign cluster reports.

### 7.3 Retention
- Phishing case records: 12 months.
- Quarantined message metadata: 90 days (message content per legal policy).
- IOC feed history: 18 months.

---

## 8. Integration Requirements

| System                        | Protocol / Method | Direction    | Purpose                         |
|-------------------------------|-------------------|--------------|----------------------------------|
| Email Gateway (Proofpoint/Mimecast) | REST API   | Bidirectional| Mail inspection and action       |
| M365 / Google Workspace       | Graph API / Gmail API | Bidirectional | Tenant mailbox access         |
| Sandbox (Any.Run/Joe Sandbox) | REST API          | Outbound     | URL and attachment detonation    |
| SIEM                          | REST API / Syslog | Outbound     | Alert and IOC publishing         |
| Ticketing (ServiceNow/Jira)   | REST API          | Outbound     | Escalation case creation         |
| Threat Intel Platform         | STIX/TAXII or API | Inbound      | Known phishing IOC matching      |

---

## 9. Security and Privacy Requirements

| ID      | Requirement                                                                          |
|---------|--------------------------------------------------------------------------------------|
| SEC-01  | Message content handling SHALL comply with organizational privacy and legal policies. |
| SEC-02  | Access to quarantined emails SHALL be role-restricted and fully audited.              |
| SEC-03  | Sensitive personal data in reports SHALL be minimized and masked by role.             |
| SEC-04  | Sandbox detonation environments SHALL have strict egress controls.                   |
| SEC-05  | All inter-service communication SHALL use mutual TLS.                                |
| SEC-06  | Service credentials SHALL rotate automatically via managed vault.                    |

---

## 10. Monitoring and Observability

| Metric                            | Alert Threshold        | Dashboard   |
|------------------------------------|------------------------|-------------|
| Email verdict latency (p95)       | > 10 seconds           | Real-time   |
| Quarantine volume spike           | > 200% hourly baseline | Real-time   |
| Sandbox detonation failure rate   | > 2%                   | Hourly      |
| False positive release rate       | > 1.5%                 | Daily       |
| User-reported phishing volume     | > 150% daily baseline  | Daily       |
| IOC distribution failures         | > 0%                   | Real-time   |

---

## 11. Deployment and Environment

### 11.1 Target Environment
- Cloud-native Kubernetes deployment in high-availability mode.
- LangGraph verdict workers processing mail events from real-time queue.
- Quarantine vault with encrypted message storage.

### 11.2 Infrastructure Requirements
- Compute: minimum 4 vCPU / 16 GB RAM per worker; auto-scaling for peak mail volume.
- Storage: encrypted object store for quarantined messages; Redis for verdict cache.
- Networking: private subnets; restricted egress to sandbox and mail APIs.

### 11.3 CI/CD
- GitOps pipeline with phishing-sample regression test suite.
- Canary deployment for NLP model updates with A/B verdict comparison.
- Rollback within 3 minutes for verdict pipeline.

---

## 12. Framework Implementation (LangGraph)

### 12.1 Graph Design
- **Graph Type**: Email verdict and containment graph (low-latency, real-time).
- **State Model**: `PhishingVerdictState`
  - `email_metadata: EmailMetadata`
  - `auth_checks: AuthResult`
  - `content_signals: list[ContentSignal]`
  - `sandbox_result: SandboxResult | None`
  - `risk_score: float`
  - `verdict: Verdict`

### 12.2 Node Definitions

| Node                       | Responsibility                                         | Tool Access         |
|----------------------------|-------------------------------------------------------|---------------------|
| ExtractEmailFeaturesNode   | Parse headers, body, URLs, attachments                 | Mail parser         |
| ValidateSenderAuthNode     | Check SPF/DKIM/DMARC, detect lookalike domains         | DNS/reputation API  |
| AnalyzeLanguageIntentNode  | NLP classification of social-engineering intent         | LLM/NLP service    |
| DetonateAttachmentOrURLNode| Submit to sandbox; await behavioral verdict             | Sandbox API        |
| ScorePhishingRiskNode      | Combine signals into final risk score                   | Scoring engine     |
| ApplyMailActionNode        | Execute verdict: allow/warn/quarantine/block            | Mail gateway API   |
| NotifyUserAndSOCNode       | Send warning banner or SOC escalation                   | Messaging/SIEM     |
| LearnFromReleaseNode       | Process analyst release decisions for model tuning      | Feedback store     |

### 12.3 Control Flow
```
Start -> ExtractEmailFeatures
  -> [ValidateSenderAuth, AnalyzeLanguageIntent, DetonateAttachmentOrURL] (parallel)
  -> ScorePhishingRisk -> ApplyMailAction -> NotifyUserAndSOC
  -> LearnFromRelease -> End
```

### 12.4 Human-in-the-Loop
- **Checkpoint**: Analyst approval required before releasing quarantined business-critical messages.
- **Feedback**: User phishing reports and analyst release decisions feed model improvement.

---

## 13. Reference Architecture

```
+-------------------+     +-------------------+     +---------------------+
| Inbound Email     | --> | Mail Gateway /    | --> | LangGraph Verdict   |
| (M365 / GWS)     |     | Tenant API        |     | Workers (K8s Pods)  |
+-------------------+     +-------------------+     +---------------------+
                                                         |       |       |
                                              +----------+       |       +--------+
                                              v                  v                v
                                      +------------+    +-----------+    +----------+
                                      | Sender Auth|    | NLP Intent|    | Sandbox  |
                                      | Validator  |    | Classifier|    | Detonator|
                                      +------------+    +-----------+    +----------+
                                              |                  |                |
                                              +------  Merge Signals  -----------+
                                                          |
                                                +---------v---------+
                                                | Risk Score +      |
                                                | Verdict Engine    |
                                                +---------+---------+
                                                          |
                                         +----------------+----------------+
                                         v                v                v
                                   +-----------+  +-------------+  +-----------+
                                   | Quarantine|  | Warning     |  | IOC       |
                                   | Vault     |  | Banners     |  | Sharing   |
                                   +-----------+  +-------------+  +-----------+

Governance: Verdict Audit Logs | Feedback Store | Model Registry | Checkpoint DB
```

---

## 14. Testing Strategy

| Test Type            | Scope                                                     | Frequency      |
|----------------------|-----------------------------------------------------------|----------------|
| Unit Tests           | Feature extraction, auth checks, scoring logic             | Every commit   |
| Phishing Sample Tests| Known phishing corpus detection rate validation             | Every PR       |
| False Positive Tests | Business email corpus false quarantine rate                 | Every PR       |
| Integration Tests    | End-to-end verdict pipeline with test mailbox               | Weekly         |
| Load Tests           | 50K emails/hr sustained with latency measurement            | Monthly        |
| Sandbox Resilience   | Sandbox timeout/failure handling                            | Monthly        |
| Red Team             | Simulated phishing campaigns against live system            | Quarterly      |

---

## 15. Cross-Agent Dependencies

| Dependency Agent              | Relationship                                              |
|-------------------------------|-----------------------------------------------------------|
| SRS-01: Threat Detection      | Phishing IOCs fed to detection rule matching              |
| SRS-03: Automated Response    | Escalated BEC incidents trigger containment playbooks     |
| SRS-09: Threat Intelligence   | Provides known phishing IOC feeds and campaign intel      |
| SRS-06: Identity Monitoring   | Account takeover context enriches BEC detection           |

---

## 16. Risk Register

| Risk                                       | Likelihood | Impact   | Mitigation                                            |
|--------------------------------------------|------------|----------|-------------------------------------------------------|
| False positive quarantines critical email   | Medium     | High     | Analyst release workflow; VIP allowlisting             |
| Sandbox evasion by advanced malware         | Low        | High     | Multi-sandbox; behavioral heuristics supplement        |
| NLP model drift on new phishing language    | Medium     | Medium   | Continuous retraining; phishing sample corpus updates  |
| Mail volume spike overwhelms processing    | Low        | High     | Auto-scaling; priority queue for VIP domains           |
| Privacy violation from message content scan | Low        | Critical | Privacy-compliant processing; legal review of policies |

---

## 17. How to Use This Agent

### 17.1 Initial Setup
1. Integrate email gateway and tenant APIs (M365 / Google Workspace).
2. Configure sandbox service connection for URL and attachment detonation.
3. Enable SPF/DKIM/DMARC validation and import lookalike domain watchlist.
4. Deploy LangGraph verdict workers and quarantine vault.

### 17.2 Pilot Phase (Weeks 1-2)
5. Start with **warn + quarantine** for high-confidence detections only.
6. Connect user-reported phishing mailbox for feedback intake.
7. Review quarantine decisions daily; tune NLP model and scoring thresholds.

### 17.3 Production Rollout
8. Enable full verdict pipeline with automated quarantine and warning banners.
9. Activate IOC extraction and distribution to SIEM and blocking systems.

### 17.4 Ongoing Operations
10. Tune model and policy weekly based on false-positive release data and new phishing samples.
11. Run quarterly red-team phishing simulations to validate detection coverage.

---

## 18. Acceptance Criteria

| ID    | Criterion                                                                  | Validation Method      |
|-------|---------------------------------------------------------------------------|------------------------|
| AC-01 | Phishing simulation detection rate >= 95%.                                | Red team report        |
| AC-02 | High-confidence malicious email quarantined within verdict SLA.           | Latency monitoring     |
| AC-03 | Analyst release workflow completes with full audit trail.                 | Audit log verification |
| AC-04 | IOC sharing to SIEM occurs for 100% of blocked emails.                   | Integration test       |
| AC-05 | False positive rate for business-critical email < 1.5%.                  | FP analysis report     |

---

## 19. KPIs and Success Metrics

| KPI                                  | Baseline Target      | Measurement Cadence |
|--------------------------------------|----------------------|---------------------|
| Phishing Click-Through Reduction     | >= 50% vs baseline   | Quarterly           |
| Detection and Quarantine Rate        | >= 95%               | Weekly              |
| False Positive Release Rate          | < 1.5%               | Weekly              |
| Mean Time to Verdict                 | < 10 seconds         | Daily               |
| User-Reported Phishing Response Time | < 30 minutes         | Daily               |

---

## Revision History

| Version | Date       | Author              | Changes                          |
|---------|------------|----------------------|----------------------------------|
| 1.0     | 2026-03-07 | AI Engineering Team  | Initial SRS creation             |
| 2.0     | 2026-03-07 | AI Engineering Team  | Production-ready refinement      |
