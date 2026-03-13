FROM python:3.11-slim AS base

LABEL maintainer="Cybersecurity AI Engineering Team"
LABEL description="Identity & Access Monitoring Agent (SRS-06)"

WORKDIR /app

# Install OS-level deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY identity_access_agent/ identity_access_agent/
COPY tests_identity/ tests_identity/

# Non-root user for production
RUN useradd --create-home appuser
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8086/healthz || exit 1

EXPOSE 8006 8086 9096

ENTRYPOINT ["python", "-m", "identity_access_agent.main"]
