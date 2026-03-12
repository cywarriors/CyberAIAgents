FROM python:3.11-slim AS base

LABEL maintainer="CyberAIAgents" \
      srs="SRS-CYBER-13" \
      agent="vapt-agent"

WORKDIR /app

# System deps for potential scanner integrations
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vapt_agent/ vapt_agent/

ENV PYTHONUNBUFFERED=1 \
    AGENT_ENV=production

EXPOSE 8083 9091

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8083/healthz || exit 1

ENTRYPOINT ["python", "-m", "vapt_agent.main"]
