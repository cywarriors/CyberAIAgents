# CyberAIAgents

Production deployment and usage guide for the cybersecurity AI agents in this repository.

## Overview

This repository contains a set of production-oriented cybersecurity AI agents implemented in Python under `src/` and designed around a common pattern:

- `config.py` for runtime settings
- `graph.py` for the agent workflow
- `main.py` for the entry point
- `api/`, `gui/`, `integrations/`, `monitoring/`, `models/`, `nodes/`, and `rules/` for runtime capabilities
- Docker and Kubernetes assets in a matching deployment folder

Each implemented agent is a full-stack service with:

- a backend in `api/` and `main.py` for orchestration, APIs, health checks, metrics, and integrations
- a frontend in `gui/` for dashboards, analyst workflows, and operational views

The current codebase includes 12 implemented agents and one additional agent defined at the SRS level but not yet implemented in `src/`.

## Implemented Agents

| Agent | Package | Deployment Assets | Local Run Command |
|------|---------|-------------------|-------------------|
| Threat Detection Agent | `threat_detection_agent` | `src/deploy/` | `python -m threat_detection_agent.main` |
| Incident Triage Agent | `incident_triage_agent` | `src/deploy_triage/` | `python -m incident_triage_agent.main` |
| Vulnerability Management Agent | `vulnerability_mgmt_agent` | `src/deploy_vm/` | `python -m vulnerability_mgmt_agent.main` |
| Phishing Defense Agent | `phishing_defense_agent` | `src/deploy_phishing/` | `python -m phishing_defense_agent.main` |
| Identity Access Agent | `identity_access_agent` | `src/deploy_identity/` | `python -m identity_access_agent.main` |
| Cloud Security Agent | `cloud_security_agent` | `src/deploy_cspm/` | `python -m cloud_security_agent.main` |
| Malware Analysis Agent | `malware_analysis_agent` | `src/deploy_malware/` | `python -m malware_analysis_agent.main` |
| Threat Intelligence Agent | `threat_intelligence_agent` | `src/deploy_threat_intel/` | `python -m threat_intelligence_agent.main` |
| Compliance Audit Agent | `compliance_audit_agent` | `src/deploy_compliance/` | `python -m compliance_audit_agent.main` |
| Security Code Review Agent | `security_code_review_agent` | `src/deploy_code_review/` | `python -m security_code_review_agent.main` |
| Deception Honeypot Agent | `deception_honeypot_agent` | `src/deploy_deception/` | `python -m deception_honeypot_agent.main` |
| VAPT Agent | `vapt_agent` | `src/deploy_vapt/` | `python -m vapt_agent.main` |

## SRS-Only Agent

The repository also includes an Automated Response / SOAR agent in the requirements documents under `srs/`, but there is no matching implementation package in `src/` at the time of writing.

## Repository Layout

```text
CyberAIAgents/
|-- README.md
|-- cybersecurity-ai-agent-types.md
|-- srs/
|-- src/
|   |-- requirements.txt
|   |-- pyproject.toml
|   |-- <agent>_agent/
|   |-- deploy/
|   |-- deploy_triage/
|   |-- deploy_vm/
|   |-- deploy_vapt/
|   |-- deploy_phishing/
|   |-- deploy_identity/
|   |-- deploy_cspm/
|   |-- deploy_malware/
|   |-- deploy_threat_intel/
|   |-- deploy_compliance/
|   |-- deploy_code_review/
|   |-- deploy_deception/
|   |-- tests/
|   |-- tests_triage/
|   |-- tests_vm/
|   |-- tests_vapt/
|   |-- tests_phishing/
|   |-- tests_identity/
|   |-- tests_cspm/
|   |-- tests_malware/
|   |-- tests_threat_intel/
|   |-- tests_compliance/
|   |-- tests_security_code_review/
|   `-- tests_deception/
`-- Leadership Doc/
```

## Production Prerequisites

Before deploying any agent, have the following in place:

- Python 3.11+
- Node.js 18+ and npm for GUI development and frontend builds
- Docker and Docker Compose
- Kubernetes cluster for production rollout
- Container registry for agent images
- Secret management for API keys, database credentials, tokens, and certificates
- Messaging and data dependencies required by the target agent, such as Kafka, Redis, PostgreSQL, SIEM APIs, EDR APIs, cloud APIs, or ticketing integrations

## Local Setup

Install the shared dependencies from the `src` directory:

```bash
cd src
python -m pip install -r requirements.txt
```

Create an environment file from the example and set values for the services your selected agent depends on:

```bash
cd src
copy .env.example .env
```

If you are using PowerShell, the repository already appears to use a local virtual environment:

```powershell
& ".\.venv\Scripts\Activate.ps1"
cd .\src
python -m pip install -r requirements.txt
```

## Backend Architecture and Usage

Each agent backend follows the same operational pattern:

- `main.py` starts the agent runtime, workflow graph, and supporting services
- `api/app.py` exposes the FastAPI application used by the GUI and external callers
- `api/routes/` contains domain-specific endpoints
- `monitoring/` exposes health and metrics endpoints for production observability
- `integrations/` contains connectors for SIEM, EDR, IAM, scanners, ticketing, messaging, and other systems

The backend stack is primarily:

- FastAPI for HTTP APIs
- Uvicorn for serving API and health endpoints
- LangGraph for workflow orchestration
- Prometheus-compatible metrics and health probes for operations

Run a backend from `src/` with the package entry point:

```bash
python -m threat_detection_agent.main
python -m incident_triage_agent.main
python -m vulnerability_mgmt_agent.main
python -m phishing_defense_agent.main
python -m identity_access_agent.main
python -m cloud_security_agent.main
python -m malware_analysis_agent.main
python -m threat_intelligence_agent.main
python -m compliance_audit_agent.main
python -m security_code_review_agent.main
python -m deception_honeypot_agent.main
python -m vapt_agent.main
```

In most cases this starts the agent processing pipeline plus the backend API and health endpoints required by the frontend and deployment platform.

## Frontend Architecture and Usage

Each implemented agent also has a GUI under `src/<agent>/gui/`.

The frontend stack is consistent across agents:

- React for the UI layer
- TypeScript for frontend code
- Vite for development and production builds
- Axios or similar API clients for backend communication

The frontend is intended for:

- dashboards and summary metrics
- investigation and analyst workflows
- processing status views
- administrative and operational controls

To run a frontend locally, open the GUI directory for the agent you want to work on and install dependencies:

```bash
cd src/threat_detection_agent/gui
npm install
npm run dev
```

Build a production-ready frontend bundle with:

```bash
npm run build
```

The Vite configuration in each agent GUI typically proxies `/api` to the local backend, so frontend development should be done while the matching backend is running.

## Full-Stack Local Development

For the best local development workflow:

1. Start the backend for the target agent from `src/`.
2. In a second terminal, move into that agent's `gui/` directory.
3. Run `npm install` if dependencies are not already present.
4. Start the frontend with `npm run dev`.
5. Open the Vite development URL in the browser.

Example:

```bash
cd src
python -m threat_detection_agent.main
```

In another terminal:

```bash
cd src/threat_detection_agent/gui
npm install
npm run dev
```

## Running Agents Locally

Run an individual agent from the `src` directory:

```bash
cd src
python -m threat_detection_agent.main
python -m incident_triage_agent.main
python -m vulnerability_mgmt_agent.main
python -m phishing_defense_agent.main
python -m identity_access_agent.main
python -m cloud_security_agent.main
python -m malware_analysis_agent.main
python -m threat_intelligence_agent.main
python -m compliance_audit_agent.main
python -m security_code_review_agent.main
python -m deception_honeypot_agent.main
python -m vapt_agent.main
```

In practice, you should run only the specific agent you are testing or operating, not all of them at once from the same terminal session.

If you need the GUI, start the corresponding frontend separately from that agent's `gui/` directory.

## Test Execution

The repository keeps tests segmented by agent. From `src/`, common examples are:

```bash
python -m pytest tests -v
python -m pytest tests_triage -v
python -m pytest tests_vm -v
python -m pytest tests_vapt -v
python -m pytest tests_phishing -v
python -m pytest tests_identity -v
python -m pytest tests_cspm -v
python -m pytest tests_malware -v
python -m pytest tests_threat_intel -v
python -m pytest tests_compliance -v
python -m pytest tests_security_code_review -v
python -m pytest tests_deception -v
```

Run the tests for the target agent before building a production image.

## Docker Usage

Each implemented agent has a dedicated Dockerfile in its deployment folder. Build the image for the agent you want to release.

Examples:

```bash
docker build -f src/deploy/Dockerfile -t cyberai/threat-detection:latest src
docker build -f src/deploy_triage/Dockerfile -t cyberai/incident-triage:latest src
docker build -f src/deploy_vm/Dockerfile -t cyberai/vulnerability-mgmt:latest src
docker build -f src/deploy_vapt/Dockerfile -t cyberai/vapt:latest src
docker build -f src/deploy_phishing/Dockerfile -t cyberai/phishing-defense:latest src
docker build -f src/deploy_identity/Dockerfile -t cyberai/identity-access:latest src
docker build -f src/deploy_cspm/Dockerfile -t cyberai/cloud-security:latest src
docker build -f src/deploy_malware/Dockerfile -t cyberai/malware-analysis:latest src
docker build -f src/deploy_threat_intel/Dockerfile -t cyberai/threat-intelligence:latest src
docker build -f src/deploy_compliance/Dockerfile -t cyberai/compliance-audit:latest src
docker build -f src/deploy_code_review/Dockerfile -t cyberai/security-code-review:latest src
docker build -f src/deploy_deception/Dockerfile -t cyberai/deception-honeypot:latest src
```

To run a local integration stack for an agent that includes a Docker Compose file:

```bash
docker compose -f src/deploy/docker-compose.yml up --build
docker compose -f src/deploy_triage/docker-compose.yml up --build
docker compose -f src/deploy_vm/docker-compose.yml up --build
docker compose -f src/deploy_vapt/docker-compose.yml up --build
```

Use the compose file from the deployment folder that matches the agent you are validating.

Where the deployment assets include both backend services and frontend hosting, treat the backend API and the frontend bundle as separate deployable concerns unless the deployment folder explicitly combines them.

## Kubernetes Deployment

Each deployment folder contains a `k8s/` directory with the manifests for cluster rollout. A standard deployment flow is:

```bash
kubectl apply -f src/deploy/k8s/
kubectl apply -f src/deploy_triage/k8s/
kubectl apply -f src/deploy_vm/k8s/
kubectl apply -f src/deploy_vapt/k8s/
kubectl apply -f src/deploy_phishing/k8s/
kubectl apply -f src/deploy_identity/k8s/
kubectl apply -f src/deploy_cspm/k8s/
kubectl apply -f src/deploy_malware/k8s/
kubectl apply -f src/deploy_threat_intel/k8s/
kubectl apply -f src/deploy_compliance/k8s/
kubectl apply -f src/deploy_code_review/k8s/
kubectl apply -f src/deploy_deception/k8s/
```

For production, replace direct `kubectl apply` with your normal GitOps or CI/CD promotion flow.

## Frontend and Backend Production Deployment Model

Use a clear separation of concerns in production:

- Backend services run the agent workflow, integrations, APIs, health endpoints, and metrics exporters.
- Frontend applications serve analyst dashboards and call the backend through the published API surface.
- Ingress, TLS termination, authentication, and routing should be managed centrally.

Recommended production model:

1. Build and publish the backend container from the matching `deploy*` folder.
2. Build the frontend bundle from the agent `gui/` directory.
3. Serve the frontend through your preferred static hosting layer, reverse proxy, or frontend container.
4. Route frontend API calls to the matching backend service.
5. Restrict backend API exposure to only the required consumers and networks.

At minimum, production deployment should define:

- frontend base URL
- backend API base URL
- allowed CORS origins
- trusted hosts
- authentication and session handling
- observability and audit logging

## Recommended Production Release Process

1. Select the target agent and deployment folder.
2. Review the matching SRS document in `srs/` and confirm operational scope.
3. Set backend environment variables, secrets, and integration credentials.
4. Build the frontend bundle and verify its API target configuration.
5. Run the agent-specific backend tests and any frontend build validation.
6. Build and scan the container image.
7. Push the image to the container registry.
8. Update Kubernetes manifests or Helm values with the approved image tag.
9. Promote to a non-production environment first.
10. Validate frontend access, backend health endpoints, metrics, logs, and downstream integrations.
11. Roll out to production using a controlled deployment strategy.

## Production Operating Guidance

Use the same baseline controls for every agent:

- Run as non-root containers.
- Store secrets outside source control.
- Enable readiness and liveness probes.
- Export logs and Prometheus metrics to the central observability platform.
- Apply resource requests and limits per workload.
- Restrict egress to only required integrations.
- Version detection rules, prompts, model settings, and policy artifacts.
- Use human approval gates for high-impact or destructive actions.
- Keep rollback-ready image tags and deployment manifests.
- Lock down frontend-to-backend access with explicit CORS and host allowlists.
- Publish only the frontend and the minimum required backend routes externally.

## Choosing the Right Agent

Use this repository as a modular platform. Pick the agent that matches the primary operating problem:

- `threat_detection_agent` for event-driven threat detection and alert generation
- `incident_triage_agent` for alert enrichment and prioritization
- `vulnerability_mgmt_agent` for remediation prioritization and SLA tracking
- `phishing_defense_agent` for email and URL threat analysis
- `identity_access_agent` for risky access monitoring and identity misuse detection
- `cloud_security_agent` for cloud posture and CSPM-style findings
- `malware_analysis_agent` for sample triage and behavior analysis
- `threat_intelligence_agent` for IOC and threat context enrichment
- `compliance_audit_agent` for evidence collection and control assessment
- `security_code_review_agent` for AppSec review and code risk findings
- `deception_honeypot_agent` for honeypot telemetry and deception workflows
- `vapt_agent` for vulnerability assessment and penetration testing orchestration

## Related Documentation

- `cybersecurity-ai-agent-types.md` for the high-level catalog of cybersecurity AI agent types
- `srs/README.md` for the SRS index
- `src/README.md` for the detailed Threat Detection Agent implementation guide
- `src/<agent>/api/app.py` for backend API definitions
- `src/<agent>/gui/package.json` and `src/<agent>/gui/vite.config.ts` for frontend build and local dev settings

## Current State Summary

- Implemented in `src/`: 12 agents
- Documented in `srs/`: broader program of cybersecurity agents
- Not yet implemented in `src/`: Automated Response / SOAR agent

This README is intended to be the starting point for production deployment and day-to-day usage across the implemented agent set.