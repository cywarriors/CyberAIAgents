# SRS-03: Automated Response (SOAR) Agent

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| Document ID        | SRS-CYBER-03                                   |
| Version            | 2.0                                            |
| Status             | Production-Ready                               |
| Classification     | Internal-Confidential                          |
| Author             | Cybersecurity AI Engineering Team               |
| Reviewer           | IR Lead, SOC Manager, Risk Officer              |
| Approver           | CISO                                           |
| Created            | 2026-03-07                                     |
| Last Updated       | 2026-03-07                                     |

---

## 1. Introduction

### 1.1 Purpose
This SRS defines requirements for an AI-powered Automated Response Agent that executes approved containment and remediation playbooks safely, consistently, and with full auditability.

### 1.2 Intended Audience
- Incident response and SOC teams
- IT operations and infrastructure teams
- Risk, compliance, and audit officers
- Security architecture review boards

### 1.3 Definitions and Acronyms

| Term    | Definition                                               |
|---------|----------------------------------------------------------|
| MTTR    | Mean Time to Respond                                     |
| PDP     | Policy Decision Point                                    |
| SOAR    | Security Orchestration, Automation, and Response         |
| mTLS    | Mutual Transport Layer Security                          |

---

## 2. Scope

### 2.1 In Scope
- Playbook orchestration mapped to incident type and severity.
- Human-in-the-loop approval workflows for high-impact containment actions.
- Action execution: host isolation, account lockout, token revocation, IOC blocking.
- Pre/post-action validation, rollback support, and evidence logging.
- Simulation/dry-run mode for tabletop and testing.

### 2.2 Out of Scope
- Autonomous destructive actions without policy-gate approval.
- Alert detection and triage (covered by SRS-01 and SRS-02).
- Long-term forensic investigation workflows.

---

## 3. Stakeholders

| Role                    | Responsibility                                     |
|-------------------------|---------------------------------------------------|
| Incident Response Lead  | Approve high-impact actions, validate outcomes     |
| SOC Manager             | Own response SLAs, review execution quality        |
| IT Operations           | Maintain target system APIs and credentials        |
| Risk / Compliance       | Validate policy adherence and audit completeness   |
| CISO                    | Approve production deployment and risk acceptance  |

---

## 4. Assumptions and Constraints

### 4.1 Assumptions
- Response target systems (EDR, IAM, firewall, email) expose stable, versioned APIs.
- Playbook definitions are version-controlled and approved before deployment.
- Approval service (e.g., Teams/Slack adaptive cards, PagerDuty) is operational.

### 4.2 Constraints
- High-impact actions (production host isolation, global account disable) MUST pass human approval gate.
- Emergency break-glass rollback procedure must be available at all times.
- All actions must be idempotent to prevent duplicate executions.
- Execution logs must be immutable and tamper-evident.

---

## 5. Functional Requirements

| ID     | Requirement                                                                                      | Priority |
|--------|--------------------------------------------------------------------------------------------------|----------|
| FR-01  | System SHALL map incident type and severity to approved playbook catalog.                        | Must     |
| FR-02  | System SHALL enforce human-in-the-loop approval gates for high-impact action categories.         | Must     |
| FR-03  | System SHALL execute containment actions: host isolate, account lock, token revoke, IOC block.   | Must     |
| FR-04  | System SHALL validate action preconditions before execution (entity exists, not already isolated).| Must     |
| FR-05  | System SHALL run post-action verification checks and capture success/failure status.             | Must     |
| FR-06  | System SHALL trigger automated rollback workflow when post-action verification fails.            | Must     |
| FR-07  | System SHALL maintain complete action timeline with operator identity and timestamps.            | Must     |
| FR-08  | System SHALL notify stakeholders at action initiation, completion, and failure.                   | Must     |
| FR-09  | System SHALL prevent duplicate or conflicting playbook runs on the same entity concurrently.     | Must     |
| FR-10  | System SHALL support simulation/dry-run mode that logs actions without executing them.           | Must     |
| FR-11  | System SHALL support playbook versioning with change approval workflow.                          | Should   |
| FR-12  | System SHALL provide execution metrics and success rate dashboards.                              | Should   |

---

## 6. Non-Functional Requirements

| ID      | Requirement                                       | Target                   |
|---------|----------------------------------------------------|--------------------------|
| NFR-01  | Critical containment action initiation after approval | < 60 seconds          |
| NFR-02  | Action execution success rate                      | >= 98% (excl. external outages) |
| NFR-03  | Platform uptime                                    | 99.95% monthly           |
| NFR-04  | Action log tamper-evidence                         | Cryptographic hash chain |
| NFR-05  | Rollback execution time                            | < 120 seconds            |
| NFR-06  | RTO                                                | < 10 minutes             |
| NFR-07  | RPO                                                | < 1 minute               |

---

## 7. Data Requirements

### 7.1 Inputs
- Incident context from triage agent (severity, entities, classification).
- Approved playbook definitions (YAML/JSON, version-controlled).
- Entity identifiers (host IDs, user UPNs, IP addresses, IOC values).

### 7.2 Outputs
- Action execution logs with actor, timestamp, target, result.
- Post-action verification artifacts (screenshots, API responses).
- Rollback records with success/failure status.

### 7.3 Retention
- Immutable execution logs: 2 years minimum.
- Playbook version history: indefinite.
- Approval audit trail: 3 years.

---

## 8. Integration Requirements

| System                        | Protocol / Method | Direction   | Purpose                        |
|-------------------------------|-------------------|-------------|--------------------------------|
| EDR (Defender/CrowdStrike)    | REST API          | Outbound    | Host isolation/release         |
| IAM / IdP (Entra/Okta)       | REST API / SCIM   | Outbound    | Account lock, token revoke     |
| Firewall / WAF                | REST API / CLI    | Outbound    | IP/domain block                |
| Email Security                | REST API          | Outbound    | Sender block, message purge    |
| ITSM (ServiceNow/Jira)       | REST API          | Bidirectional| Ticket update, approval        |
| ChatOps (Teams/Slack)         | Adaptive Cards    | Bidirectional| Approval request/response      |
| Secrets Vault (Key Vault/SM)  | SDK               | Inbound     | Credential retrieval           |

---

## 9. Security and Privacy Requirements

| ID      | Requirement                                                                           |
|---------|---------------------------------------------------------------------------------------|
| SEC-01  | Policy-based access control SHALL restrict playbook execution by role and scope.       |
| SEC-02  | Dual-control approval SHALL be enforced for critical playbooks (production isolation). |
| SEC-03  | Secrets and API keys SHALL be stored in managed vault with automatic rotation.         |
| SEC-04  | All inter-service calls SHALL use mutual TLS.                                          |
| SEC-05  | Execution logs SHALL be cryptographically signed and append-only.                      |
| SEC-06  | Break-glass override SHALL require out-of-band verification and post-incident review.  |

---

## 10. Monitoring and Observability

| Metric                            | Alert Threshold         | Dashboard     |
|----------------------------------  |-------------------------|---------------|
| Action execution latency (p95)    | > 60 seconds            | Real-time     |
| Action failure rate                | > 2%                    | Real-time     |
| Approval response time (p95)      | > 10 minutes            | Real-time     |
| Rollback trigger rate              | > 5%                    | Daily         |
| Playbook queue depth               | > 50 pending            | Real-time     |
| Target system connectivity         | Any target unreachable  | Real-time     |
| Credential expiry proximity        | < 7 days to rotation    | Daily         |

---

## 11. Deployment and Environment

### 11.1 Target Environment
- Cloud-native Kubernetes with high-availability configuration.
- LangGraph runtime with durable state store for in-flight playbooks.
- Dedicated namespace with network policies restricting egress to approved targets only.

### 11.2 Infrastructure Requirements
- Compute: minimum 4 vCPU / 16 GB RAM per orchestrator pod; auto-scaling.
- Storage: managed PostgreSQL for state/checkpoint; append-only log store.
- Networking: private subnets; service mesh for mTLS; explicit egress allowlist.

### 11.3 CI/CD
- Playbook changes require PR review + security approval before merge.
- Automated simulation-mode tests for all playbooks on every deployment.
- Blue/green deployment with instant rollback.

---

## 12. Framework Implementation (LangGraph)

### 12.1 Graph Design
- **Graph Type**: Playbook execution graph with approval gates and rollback branches.
- **State Model**: `ResponseState`
  - `incident_context: IncidentContext`
  - `selected_playbook: PlaybookDefinition`
  - `approval_state: ApprovalStatus`
  - `action_results: list[ActionResult]`
  - `verification_results: list[VerificationResult]`
  - `rollback_state: RollbackStatus`

### 12.2 Node Definitions

| Node                  | Responsibility                                          | Tool Access            |
|-----------------------|---------------------------------------------------------|------------------------|
| SelectPlaybookNode    | Match incident to approved playbook and action set       | Playbook catalog      |
| PolicyCheckNode       | Validate authorization and policy compliance             | PDP service           |
| RequestApprovalNode   | Send approval request; wait or timeout                   | ChatOps/PagerDuty     |
| ExecuteActionNode     | Run idempotent containment action against target         | EDR/IAM/FW APIs       |
| VerifyOutcomeNode     | Validate action success via target system query          | Target system APIs    |
| RollbackNode          | Reverse failed actions using compensating operations      | Target system APIs    |
| AuditLogNode          | Write signed execution record to append-only store        | Log store             |
| CloseResponseNode     | Update ticket, notify stakeholders, close workflow        | ITSM/ChatOps          |

### 12.3 Control Flow
```
Start -> SelectPlaybook -> PolicyCheck -> RequestApproval
  -> ExecuteAction -> VerifyOutcome
  -> [Success: CloseResponse | Failure: Rollback -> AuditLog -> Notify]
  -> AuditLog -> End
```

### 12.4 Human-in-the-Loop
- **Mandatory Gate**: Approval required for production host isolation, global account disable, and network-wide IOC blocks.
- **Timeout Policy**: If approval not received within configurable window (default 15 min), escalate to secondary approver.

---

## 13. Reference Architecture

```
+------------------+     +-------------------+     +---------------------+
| Incident Context | --> | LangGraph SOAR    | --> | Target Systems      |
| (from SRS-02)    |     | Orchestrator      |     | (EDR/IAM/FW/Email)  |
+------------------+     +-------------------+     +---------------------+
                               |         |
                    +----------+         +----------+
                    v                               v
            +-------------+                 +---------------+
            | Approval    |                 | Audit Log     |
            | Service     |                 | (Append-Only) |
            | (ChatOps)   |                 +---------------+
            +-------------+
                    |
            +-------v-------+
            | Policy        |
            | Decision Pt   |
            +---------------+

Governance: Playbook Registry | Secrets Vault | Execution Metrics | Checkpoint DB
```

---

## 14. Testing Strategy

| Test Type           | Scope                                                     | Frequency       |
|---------------------|-----------------------------------------------------------|-----------------|
| Unit Tests          | Action handlers, policy checks, rollback logic             | Every commit    |
| Playbook Sim Tests  | Full playbook execution in dry-run/simulation mode         | Every PR        |
| Approval Flow Tests | End-to-end approval with timeout and escalation            | Every PR        |
| Integration Tests   | Live target system API interactions (test environment)     | Weekly          |
| Rollback Tests      | Verify rollback for every reversible action type           | Monthly         |
| Red Team Validation | Unauthorized action attempt detection                      | Semi-annually   |
| Disaster Recovery   | State store failover and in-flight playbook recovery       | Quarterly       |

---

## 15. Cross-Agent Dependencies

| Dependency Agent              | Relationship                                           |
|-------------------------------|--------------------------------------------------------|
| SRS-02: Incident Triage       | Provides triaged incident context and entity data      |
| SRS-01: Threat Detection      | Source of high-severity alerts escalated for response   |
| SRS-04: Vulnerability Mgmt    | Provides asset vulnerability context for risk-based decisions |

---

## 16. Risk Register

| Risk                                       | Likelihood | Impact   | Mitigation                                              |
|--------------------------------------------|------------|----------|---------------------------------------------------------|
| Incorrect containment action on wrong entity| Low       | Critical | Precondition validation; dual-approval for critical actions |
| Approval bottleneck delays containment      | Medium     | High     | Auto-escalation; configurable timeout policies           |
| Target system API outage blocks response    | Medium     | High     | Retry with backoff; manual fallback procedures           |
| Rollback failure leaves entity in bad state | Low        | Critical | Rollback verification; manual remediation runbook        |
| Credential compromise of service account    | Low        | Critical | Managed vault; auto-rotation; least-privilege scoping    |
| Duplicate playbook execution on same entity | Low        | Medium   | Distributed lock; idempotent action handlers             |

---

## 17. How to Use This Agent

### 17.1 Initial Setup
1. Define approved playbooks in version-controlled catalog; classify each by risk tier.
2. Map playbook actions to target system credentials (stored in secrets vault).
3. Configure approval matrix: who can approve which action categories.
4. Deploy LangGraph SOAR orchestrator and checkpoint store.

### 17.2 Pilot Phase (Weeks 1-2)
5. Run all playbooks in **simulation mode** using tabletop incident scenarios.
6. Validate approval workflows, notifications, and audit log completeness.
7. Conduct rollback tests for every reversible action type.

### 17.3 Production Rollout
8. Enable live execution for P1/P2 incidents with mandatory approval gates.
9. Monitor execution metrics and approval cycle times daily.

### 17.4 Ongoing Operations
10. Review action success rates and rollback reasons weekly.
11. Update playbooks through change-approval process as threat landscape evolves.

---

## 18. Acceptance Criteria

| ID    | Criterion                                                                    | Validation Method      |
|-------|------------------------------------------------------------------------------|------------------------|
| AC-01 | Approved P1 containment actions execute within SLA in >= 95% of cases.       | Execution log analysis |
| AC-02 | Zero unauthorized action executions during red-team validation.              | Red team report        |
| AC-03 | Rollback succeeds for 100% of reversible actions in test scenarios.          | Rollback test suite    |
| AC-04 | 100% of actions recorded with actor, timestamp, target, and result.         | Audit log verification |
| AC-05 | Simulation mode produces identical decision path without side effects.       | Diff analysis          |

---

## 19. KPIs and Success Metrics

| KPI                              | Baseline Target       | Measurement Cadence |
|----------------------------------|----------------------|---------------------|
| Mean Time to Respond (MTTR)      | < 15 minutes         | Daily               |
| Containment Success Rate         | >= 98%               | Weekly              |
| Approval Cycle Time (p95)        | < 10 minutes         | Daily               |
| Rollback Rate                    | < 5%                 | Weekly              |
| Playbook Coverage (incident types)| >= 80% of P1/P2 types| Monthly             |

---

## Revision History

| Version | Date       | Author              | Changes                          |
|---------|------------|----------------------|----------------------------------|
| 1.0     | 2026-03-07 | AI Engineering Team  | Initial SRS creation             |
| 2.0     | 2026-03-07 | AI Engineering Team  | Production-ready refinement      |
