#!/usr/bin/env bash
# Run the MCP server locally with reload for development.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p /tmp/mcp-data /tmp/mcp-ws /tmp/mcp-transfer
export WORKSPACE_ROOT="${WORKSPACE_ROOT:-/tmp/mcp-ws}"
export DATA_ROOT="${DATA_ROOT:-/tmp/mcp-data}"
export TRANSFER_DIR="${TRANSFER_DIR:-/tmp/mcp-transfer}"
export AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-/tmp/mcp-data/audit.jsonl}"
export CATALOG_DB_PATH="${CATALOG_DB_PATH:-/tmp/mcp-data/catalog.db}"
export MCP_HTTP_HOST="${MCP_HTTP_HOST:-127.0.0.1}"
export MCP_HTTP_PORT="${MCP_HTTP_PORT:-8765}"
exec uv run python -m mcp_sandbox
