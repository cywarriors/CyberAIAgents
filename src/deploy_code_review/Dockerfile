FROM python:3.11-slim AS base
WORKDIR /app
RUN addgroup --system appgroup && adduser --system --ingroup appgroup --uid 1000 appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY security_code_review_agent/ ./security_code_review_agent/
USER appuser
EXPOSE 8011 8091
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8011/healthz')"
CMD ["python", "-m", "security_code_review_agent.main"]
