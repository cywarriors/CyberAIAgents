# Multi-stage build for Vulnerability Management Agent

# Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY ../requirements.txt .

# Install Python dependencies
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 appuser

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY ../vulnerability_mgmt_agent ./vulnerability_mgmt_agent
COPY ../pyproject.toml .

# Set environment
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    VM_AGENT_API_HOST=0.0.0.0 \
    VM_AGENT_API_PORT=8003 \
    LOG_LEVEL=info

# Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8003/api/v1/admin/health')" || exit 1

# Run API
CMD ["uvicorn", "vulnerability_mgmt_agent.api.app:app", "--host", "0.0.0.0", "--port", "8003"]
