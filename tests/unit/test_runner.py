import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.mcp_registry.catalog import Catalog, InstalledMCP
from mcp_sandbox.mcp_registry.runner import McpRunner
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.policy import SecurityPolicy
from mcp_sandbox.security.sandbox import SandboxResult


@pytest.fixture
def runner(tmp_path, monkeypatch) -> McpRunner:
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    s = Settings()
    pol_yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: []
egress_allowlist: []
mcp_sources: []
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(pol_yaml)
    return McpRunner(
        settings=s, policy=SecurityPolicy.load(p),
        audit=AuditLogger(tmp_path / "a.jsonl"), catalog=Catalog(tmp_path / "c.db"),
        sandbox=FakeSandbox(),
    )


class FakeSandbox:
    def run(self, command, *, timeout):
        return SandboxResult(returncode=0, stdout="{}", stderr="")


def test_build_argv_uses_venv_entrypoint(runner, tmp_path):
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "mcp-foo").write_text("#!/bin/sh\necho hi")
    mcp = InstalledMCP(name="foo", source="pip://foo", version="1", venv_path=str(venv),
                      entrypoint="mcp-foo", status="installed", sha256="x")
    argv = runner._build_argv(mcp)
    assert argv[-1] == str(venv / "bin" / "mcp-foo")
    # bwrap confinement present
    assert "--unshare-all" in argv
    # CRITICAL: full host root must NOT be exposed (selective binds only).
    # Assert that "--ro-bind / /" triple is NOT present.
    for i, arg in enumerate(argv):
        if arg == "--ro-bind" and i + 2 < len(argv):
            assert not (argv[i + 1] == "/" and argv[i + 2] == "/"), \
                "full host root exposed via --ro-bind / /"


def test_call_tool_unknown_mcp_rejected(runner):
    with pytest.raises(KeyError):
        runner.call_tool("nope", "some_tool", {})


def test_call_tool_disallowed_tool_rejected(runner, tmp_path):
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    mcp = InstalledMCP(
        name="foo", source="pip://foo", version="1", venv_path=str(venv),
        entrypoint="mcp-foo", status="installed", sha256="x",
        allowed_tools=("safe_tool",),
    )
    runner._catalog.register(mcp)
    with pytest.raises(PermissionError):
        runner.call_tool("foo", "dangerous_tool", {})
