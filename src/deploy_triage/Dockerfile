FROM python:3.11-slim AS base

LABEL maintainer="Cybersecurity AI Engineering Team"
LABEL description="Incident Triage Agent (SRS-02)"

WORKDIR /app

# Install OS-level deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY incident_triage_agent/ incident_triage_agent/
COPY tests_triage/ tests_triage/

# Non-root user for production
RUN useradd --create-home appuser
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8081/healthz || exit 1

EXPOSE 8081

ENTRYPOINT ["python", "-m", "incident_triage_agent.main"]
