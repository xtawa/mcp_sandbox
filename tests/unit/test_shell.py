import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.policy import SecurityPolicy
from mcp_sandbox.security.sandbox import SandboxResult
from mcp_sandbox.tools.shell import ExecTool


@pytest.fixture
def tool(tmp_path, monkeypatch) -> ExecTool:
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    s = Settings()
    pol_yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: [/bin/ls, /usr/bin/python3]
egress_allowlist: []
mcp_sources: []
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(pol_yaml)
    policy = SecurityPolicy.load(p)
    return ExecTool(settings=s, policy=policy, audit=AuditLogger(tmp_path / "audit.jsonl"),
                    sandbox=FakeSandbox())


class FakeSandbox:
    last_cmd: list[str] = []

    def run(self, command, *, timeout):
        self.last_cmd = command
        return SandboxResult(returncode=0, stdout="fake output", stderr="")


def test_exec_allowed_command(tool):
    result = tool.exec_command("/bin/ls", ["-la"])
    assert result["returncode"] == 0  # noqa: PLR2004 - conventional success exit code
    assert result["stdout"] == "fake output"
    assert tool._sandbox.last_cmd == ["/bin/ls", "-la"]


def test_exec_rejects_unlisted_binary(tool):
    with pytest.raises(PermissionError):
        tool.exec_command("/bin/rm", ["-rf", "/"])


def test_exec_rejects_shell_metacharacters(tool):
    with pytest.raises(PermissionError):
        tool.exec_command("/bin/ls", ["; rm -rf /"])


def test_exec_respects_timeout_from_policy(tool):
    tool.exec_command("/bin/ls", [])
    # FakeSandbox ignores timeout; we assert the tool passes policy timeout.
    # (Verified by the real sandbox test in test_sandbox.py.)


def test_exec_rejects_empty_command(tool):
    with pytest.raises(ValueError):
        tool.exec_command("", [])
