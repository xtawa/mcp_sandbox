"""Entrypoint: `python -m mcp_sandbox` serves the MCP HTTP transport."""
from __future__ import annotations

import uvicorn

from .config import load_settings
from .security.policy import SecurityPolicy
from .server import build_app_with_policy
from .transports.streamable_http import create_http_app


def main() -> None:
    settings = load_settings()
    policy = SecurityPolicy.load(settings.policies_dir / "default_policy.yaml")
    app = build_app_with_policy(policy, settings)
    http_app = create_http_app(app)
    uvicorn.run(http_app, host=settings.http_host, port=settings.http_port,
                log_level="info", access_log=False)


if __name__ == "__main__":
    main()
