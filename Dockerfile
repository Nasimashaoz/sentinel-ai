# Sentinel AI — Multi-stage Docker build
# Stage 1: build dependencies
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir build && \
    pip install --no-cache-dir \
      aiohttp aiofiles anthropic python-dotenv \
      psutil watchdog prometheus-client \
      google-cloud-logging google-auth \
      azure-identity azure-mgmt-monitor \
      boto3 kubernetes requests

# Stage 2: runtime image
FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="Sentinel AI" \
      org.opencontainers.image.description="24/7 AI-powered security monitoring agent" \
      org.opencontainers.image.source="https://github.com/Nasimashaoz/sentinel-ai" \
      org.opencontainers.image.licenses="MIT"

# Non-root user for security
RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source
COPY --chown=sentinel:sentinel . .

# Data directory for persistent storage
RUN mkdir -p /app/data && chown sentinel:sentinel /app/data

USER sentinel

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090/health')" || exit 1

CMD ["python", "-m", "core.agent"]
