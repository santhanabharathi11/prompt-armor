# syntax=docker/dockerfile:1
# Multi-arch: linux/amd64 + linux/arm64 (Apple Silicon, AWS Graviton)

ARG PYTHON_VERSION=3.12

# ── Builder ───────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir build \
    && pip install --no-cache-dir -e "."

# ── Runtime ───────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

# Security: run as non-root
RUN groupadd -r armor --gid=1001 \
    && useradd -r -g armor --uid=1001 --home-dir=/app --shell=/sbin/nologin armor

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/ ./src/
COPY config/ ./config/

# Audit log directory owned by armor user
RUN mkdir -p /var/log/prompt-armor && chown armor:armor /var/log/prompt-armor

USER armor

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

EXPOSE 8000

# Liveness probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

# 4 workers per container — scale horizontally with replicas behind ALB
CMD ["python", "-m", "uvicorn", "prompt_armor.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "4", \
     "--no-access-log", "--timeout-keep-alive", "30"]
