"""Runner: launch an installed MCP as a jailed subprocess and proxy tool calls.

For v1 we use a simple request/response protocol over stdio: each call writes
one JSON line of arguments to the child stdin and reads one JSON line of
result from stdout. The child is launched via bwrap so it has no host FS
visibility and no network beyond the container egress policy.

The runner enforces an allowed_tools allowlist per MCP so the AI can only
invoke tools the operator explicitly approved at install time.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..config import Settings
from ..security.audit import AuditLogger
from ..security.policy import SecurityPolicy
from ..security.sandbox import _READONLY_BINDS, SandboxRunner
from .catalog import Catalog, InstalledMCP


class McpRunner:
    def __init__(
        self,
        settings: Settings,
        policy: SecurityPolicy,
        audit: AuditLogger,
        catalog: Catalog,
        sandbox: SandboxRunner,
    ) -> None:
        self._settings = settings
        self._policy = policy
        self._audit = audit
        self._catalog = catalog
        self._sandbox = sandbox

    def _build_argv(self, mcp: InstalledMCP) -> list[str]:
        # Reuse the sandbox runner's confinement by asking it to exec the
        # MCP entrypoint. We construct the argv directly so we can attach
        # the per-MCP venv path.
        entry = Path(mcp.venv_path) / "bin" / mcp.entrypoint
        argv: list[str] = [
            self._settings.bwrap_bin,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", str(self._settings.workspace_root),
            "--tmpfs", "/tmp",  # noqa: S108 - fresh isolated tmpfs inside the jail
            "--ro-bind", mcp.venv_path, mcp.venv_path,
            "--uid", str(self._settings.run_as_uid),
            "--gid", str(self._settings.run_as_gid),
            "--cap-drop", "ALL",
            "--clearenv",
            "--setenv", "PATH", f"{mcp.venv_path}/bin:/usr/bin:/bin",
        ]
        # Selective read-only binds of minimal host paths (binaries, libraries,
        # TLS trust store). We never bind "/" wholesale: that would expose
        # /etc/shadow, /data catalog DBs, source code under /workspace/src,
        # audit logs, and other secrets to untrusted MCP code. Sources that do
        # not exist on the host are silently skipped.
        for src, dst in _READONLY_BINDS:
            if Path(src).exists():
                argv += ["--ro-bind", src, dst]
        argv.append(str(entry))
        return argv

    def call_tool(self, name: str, tool: str, args: dict[str, Any]) -> dict:
        mcp = self._catalog.get(name)
        if mcp is None:
            raise KeyError(name)
        if mcp.allowed_tools and tool not in mcp.allowed_tools:
            self._audit.record(
                tool="call_mcp_tool", actor="ai",
                args={"mcp": name, "tool": tool}, outcome="denied",
                detail="tool not in allowed_tools",
            )
            raise PermissionError(f"tool {tool!r} not allowed for MCP {name!r}")
        argv = self._build_argv(mcp)
        proc = subprocess.run(  # noqa: S603 - argv is built from operator-approved MCP
            # entrypoints and confined via bwrap; payload is JSON over stdin
            argv,
            input=json.dumps({"tool": tool, "args": args}) + "\n",
            capture_output=True,
            text=True,
            timeout=self._policy.exec_timeout_seconds,
            check=False,
        )
        if proc.returncode != 0:
            self._audit.record(
                tool="call_mcp_tool", actor="ai",
                args={"mcp": name, "tool": tool}, outcome="error",
                detail=proc.stderr[:500],
            )
            raise RuntimeError(f"MCP {name} failed: {proc.stderr}")
        result = json.loads(proc.stdout)
        self._audit.record(
            tool="call_mcp_tool", actor="ai",
            args={"mcp": name, "tool": tool}, outcome="ok",
            detail=str(result)[:200],
        )
        return result

    def uninstall(self, name: str) -> None:
        mcp = self._catalog.get(name)
        if mcp is None:
            raise KeyError(name)
        shutil.rmtree(mcp.venv_path, ignore_errors=True)
        self._catalog.remove(name)
        self._audit.record(tool="uninstall_mcp", actor="ai",
                           args={"name": name}, outcome="ok", detail="removed")
