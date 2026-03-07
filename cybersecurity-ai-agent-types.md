# Cybersecurity AI Agent Types and Goals

This document outlines practical types of AI agents that can be created for cybersecurity programs.

## 1. Threat Detection Agent
- Goal: Detect suspicious behavior and potential attacks in near real time.
- What it does:
  - Monitors logs, network traffic, endpoint telemetry, and cloud events.
  - Uses anomaly detection and attack-pattern matching.
  - Flags high-risk events for SOC analysts.
- Typical outputs: Alerts with severity, confidence score, and affected assets.

## 2. Incident Triage Agent
- Goal: Reduce analyst workload by prioritizing and enriching alerts.
- What it does:
  - Correlates alerts across SIEM, EDR, IAM, and ticketing systems.
  - Adds context: user role, asset criticality, geolocation, and threat intelligence.
  - Suggests likely false positives vs. true incidents.
- Typical outputs: Ranked incident queue with recommended next actions.

## 3. Automated Response (SOAR) Agent
- Goal: Contain threats quickly and consistently.
- What it does:
  - Executes playbooks such as isolate host, disable account, block IP/domain, revoke tokens.
  - Requests human approval for high-impact actions.
  - Tracks every action for audit and rollback.
- Typical outputs: Response actions executed, timeline, and post-action status.

## 4. Vulnerability Management Agent
- Goal: Prioritize and reduce exploitable weaknesses.
- What it does:
  - Ingests scanner results and maps CVEs to business-critical assets.
  - Calculates risk using exploit availability, exposure, and asset importance.
  - Recommends patching order and compensating controls.
- Typical outputs: Risk-prioritized remediation plan and SLA tracking.

## 5. Phishing Defense Agent
- Goal: Identify and block phishing and social-engineering attacks.
- What it does:
  - Analyzes email headers, sender reputation, language cues, URLs, and attachments.
  - Detects impersonation attempts and suspicious intent.
  - Triggers quarantine, warning banners, or user verification flows.
- Typical outputs: Phishing verdict, confidence score, and blocked indicators.

## 6. Identity and Access Monitoring Agent
- Goal: Prevent account takeover and privilege abuse.
- What it does:
  - Monitors login patterns, MFA behavior, impossible travel, and privilege changes.
  - Detects risky entitlement combinations and unusual access requests.
  - Recommends least-privilege adjustments.
- Typical outputs: Risky identity events and access remediation suggestions.

## 7. Cloud Security Posture Agent
- Goal: Continuously enforce secure cloud configurations.
- What it does:
  - Reviews IaC templates and cloud resources for misconfigurations.
  - Validates against CIS benchmarks and internal policies.
  - Detects public exposure, excessive permissions, and missing encryption.
- Typical outputs: Misconfiguration findings with fix steps and policy exceptions.

## 8. Malware Analysis Agent
- Goal: Speed up malware classification and impact assessment.
- What it does:
  - Performs static and behavioral analysis in sandboxed environments.
  - Extracts indicators of compromise (IOCs), tactics, and malware family traits.
  - Suggests containment and eradication steps.
- Typical outputs: Malware report, IOCs, YARA suggestions, and severity rating.

## 9. Threat Intelligence Agent
- Goal: Turn external threat data into actionable internal defense.
- What it does:
  - Ingests feeds, reports, dark web chatter, and vendor advisories.
  - Maps intelligence to MITRE ATT&CK and internal asset exposure.
  - Produces organization-specific risk insights.
- Typical outputs: Prioritized threat briefs and detection rule recommendations.

## 10. Compliance and Audit Agent
- Goal: Automate evidence collection for regulatory and policy compliance.
- What it does:
  - Collects control evidence across systems (logs, access records, configs).
  - Maps controls to frameworks (ISO 27001, NIST CSF, SOC 2, PCI DSS, HIPAA).
  - Highlights gaps and remediation deadlines.
- Typical outputs: Audit-ready evidence packs and compliance gap reports.

## 11. Security Code Review Agent (AppSec)
- Goal: Find security weaknesses early in software development.
- What it does:
  - Scans code and pull requests for insecure patterns and secrets.
  - Validates dependencies for known vulnerabilities.
  - Suggests secure code fixes with developer-friendly explanations.
- Typical outputs: Prioritized findings with fix snippets and policy checks.

## 12. Deception and Honeypot Agent
- Goal: Detect lateral movement and attacker behavior early.
- What it does:
  - Manages decoy assets, fake credentials, and monitored trap services.
  - Detects interaction with deception artifacts.
  - Correlates attacker behavior to likely objectives.
- Typical outputs: High-confidence intrusion alerts and attacker TTP profile.

## Quick Starter Recommendation
If starting from scratch, prioritize these in order:
1. Incident Triage Agent
2. Threat Detection Agent
3. Automated Response Agent
4. Vulnerability Management Agent

This order usually delivers the fastest SOC efficiency and risk-reduction impact.
