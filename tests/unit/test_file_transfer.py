import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.policy import SecurityPolicy
from mcp_sandbox.tools.file_transfer import FileTransferTool


@pytest.fixture
def tool(tmp_path, monkeypatch) -> FileTransferTool:
    ws = tmp_path / "ws"
    transfer = tmp_path / "transfer"
    monkeypatch.setenv("WORKSPACE_ROOT", str(ws))
    monkeypatch.setenv("TRANSFER_DIR", str(transfer))
    s = Settings()
    pol_yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: [/bin/ls]
egress_allowlist: []
mcp_sources: []
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(pol_yaml)
    return FileTransferTool(settings=s, policy=SecurityPolicy.load(p),
                            audit=AuditLogger(tmp_path / "audit.jsonl"))


def test_transfer_in_copies_host_to_workspace(tool, tmp_path):
    (tmp_path / "transfer" / "host.txt").write_text("from host")
    tool.transfer_file("host.txt", "in", dest="copied.txt")
    assert (tmp_path / "ws" / "copied.txt").read_text() == "from host"


def test_transfer_out_copies_workspace_to_host(tool, tmp_path):
    (tmp_path / "ws" / "result.txt").write_text("from sandbox")
    tool.transfer_file("result.txt", "out", dest="exported.txt")
    assert (tmp_path / "transfer" / "exported.txt").read_text() == "from sandbox"


def test_transfer_rejects_traversal_in_dest(tool):
    with pytest.raises(PermissionError):
        tool.transfer_file("x", "in", dest="../../escape.txt")


def test_transfer_unknown_direction_rejected(tool):
    with pytest.raises(ValueError):
        tool.transfer_file("x", "sideways")
