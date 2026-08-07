"""End-to-end: install a fixture MCP and proxy a tool call to it.

The fixture MCP is a tiny Python script that reads one JSON line {tool, args}
from stdin and writes one JSON line result back. It stands in for any real
third-party MCP.
"""
from pathlib import Path

import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.mcp_registry.catalog import Catalog, InstalledMCP
from mcp_sandbox.mcp_registry.runner import McpRunner
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.policy import SecurityPolicy

FIXTURE = """\
#!/usr/bin/env python3
import json, sys
line = sys.stdin.readline()
req = json.loads(line)
if req["tool"] == "echo":
    print(json.dumps({"echoed": req["args"]["msg"]}))
else:
    print(json.dumps({"error": "unknown tool"}))
"""


class NoOpSandbox:
    """Skips bwrap so the integration test runs without bubblewrap installed."""

    def run(self, command, *, timeout):
        from mcp_sandbox.security.sandbox import SandboxResult
        return SandboxResult(0, "", "")


@pytest.fixture
def runner(tmp_path, monkeypatch) -> McpRunner:
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("DATA_ROOT", str(tmp_path / "data"))
    s = Settings()
    pol_yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 10, max_concurrent_tools: 2}
command_allowlist: []
egress_allowlist: []
mcp_sources: [pip]
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(pol_yaml)
    return McpRunner(
        settings=s, policy=SecurityPolicy.load(p),
        audit=AuditLogger(tmp_path / "a.jsonl"), catalog=Catalog(tmp_path / "c.db"),
        sandbox=NoOpSandbox(),
    )


def _register_echo_mcp(runner, tmp_path, monkeypatch):
    # Build a fake installed MCP: a venv dir with a bin/echo_mcp script.
    venv = tmp_path / "venv"
    bindir = venv / "bin"
    bindir.mkdir(parents=True)
    entry = bindir / "echo_mcp"
    entry.write_text(FIXTURE)
    entry.chmod(0o755)

    # monkeypatch McpRunner._build_argv to skip bwrap and call the entrypoint
    # directly, so the test runs without bubblewrap installed.
    def direct_argv(self, mcp):
        return [str(Path(mcp.venv_path) / "bin" / mcp.entrypoint)]

    monkeypatch.setattr(McpRunner, "_build_argv", direct_argv)

    mcp = InstalledMCP(
        name="echo", source="pip://echo@1.0", version="1.0", venv_path=str(venv),
        entrypoint="echo_mcp", status="installed", sha256="fix",
        allowed_tools=("echo",),
    )
    runner._catalog.register(mcp)
    return mcp


def test_install_and_call_echo_mcp(runner, tmp_path, monkeypatch):
    _register_echo_mcp(runner, tmp_path, monkeypatch)
    result = runner.call_tool("echo", "echo", {"msg": "hello"})
    assert result == {"echoed": "hello"}


def test_call_disallowed_tool_blocked(runner, tmp_path, monkeypatch):
    _register_echo_mcp(runner, tmp_path, monkeypatch)
    with pytest.raises(PermissionError):
        runner.call_tool("echo", "dangerous_tool", {})
