# Multi-stage build for Cloud Security Posture Management Agent

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
COPY ../cloud_security_agent ./cloud_security_agent
COPY ../pyproject.toml .

# Set environment
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    CSPM_API_HOST=0.0.0.0 \
    CSPM_API_PORT=8006 \
    LOG_LEVEL=info

# Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check (use stdlib, no external dependencies)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8006/api/v1/admin/health')" || exit 1

EXPOSE 8006

# Run API
CMD ["uvicorn", "cloud_security_agent.api.app:app", "--host", "0.0.0.0", "--port", "8006", "--no-access-log"]
