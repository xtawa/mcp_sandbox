# syntax=docker/dockerfile:1.7
# Hardened image for the MCP sandbox. Builds as root, runs as UID 10001.
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# bubblewrap is required at runtime for the bwrap sandbox.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bubblewrap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast, reproducible dependency resolution.
COPY --from=ghcr.io/astral-sh/uv:0.4.18 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev
COPY src/ ./src/
COPY policies/ ./policies/
RUN uv sync --frozen --no-dev

# ---- runtime stage ---------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        bubblewrap ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 mcp \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin mcp \
    && mkdir -p /app /data /workspace/_sandbox /data/transfer \
    && chown -R 10001:10001 /app /data /workspace

COPY --from=builder --chown=10001:10001 /app /app
COPY policies/ /app/policies/

USER 10001:10001
WORKDIR /app
EXPOSE 8765

# tini reaps zombies; --read-only + tmpfs are set in docker-compose.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "mcp_sandbox"]
