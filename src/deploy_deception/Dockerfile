FROM python:3.11-slim AS base
WORKDIR /app
RUN addgroup --system appgroup && adduser --system --ingroup appgroup --uid 1000 appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY deception_honeypot_agent/ ./deception_honeypot_agent/
USER appuser
EXPOSE 8012 8092
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8012/healthz')"
CMD ["python", "-m", "deception_honeypot_agent.main"]
