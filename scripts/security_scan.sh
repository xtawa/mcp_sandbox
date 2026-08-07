#!/usr/bin/env bash
# Run static analysis + dependency audit + the security test suite.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> ruff"
uv run ruff check src tests

echo "==> bandit"
# -lll gates the exit code on HIGH severity only (the project bar). The
# medium/low findings (B404/B108/B603) are expected: this codebase's purpose
# is to run sandboxed subprocesses via bwrap, and the "/tmp" hits are in-jail
# tmpfs mounts, not the host /tmp. They are documented as false positives.
uv run bandit -r src -q -lll

echo "==> pip-audit (runtime deps only — the container ships with --no-dev)"
# Audit only the dependencies that actually ship in the runtime image. The
# container Dockerfile installs with `uv sync --no-dev`, so dev-only packages
# (pytest, bandit, ruff, ...) never reach production and are out of scope for
# the supply-chain gate. We export runtime deps (excluding the local project
# itself via --no-emit-project) and audit that lockfile.
REQS="$(mktemp)"
trap 'rm -f "$REQS"' EXIT
uv export --no-dev --no-emit-project --format requirements-txt -o "$REQS"
uv run pip-audit -r "$REQS"

echo "==> security tests"
uv run pytest tests/security/ -v
