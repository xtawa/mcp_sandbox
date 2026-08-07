import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.policy import SecurityPolicy
from mcp_sandbox.tools.file_write import FileWriteTools


@pytest.fixture
def tools(tmp_path, monkeypatch) -> FileWriteTools:
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
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
    return FileWriteTools(
        settings=s,
        policy=SecurityPolicy.load(p),
        audit=AuditLogger(tmp_path / "audit.jsonl"),
    )


def test_write_file_creates_file(tools, tmp_path):
    tools.write_file("out.txt", "hello")
    assert (tmp_path / "out.txt").read_text() == "hello"


def test_write_file_rejects_oversized_payload(tools):
    with pytest.raises(ValueError):
        tools.write_file("big.txt", "x" * 2048)


def test_write_file_rejects_traversal(tools):
    with pytest.raises(PermissionError):
        tools.write_file("../escape.txt", "nope")


def test_make_directory(tools, tmp_path):
    tools.make_directory("a/b/c")
    assert (tmp_path / "a/b/c").is_dir()


def test_delete_file(tools, tmp_path):
    (tmp_path / "gone.txt").write_text("x")
    tools.delete_file("gone.txt")
    assert not (tmp_path / "gone.txt").exists()


def test_delete_file_cannot_escape_workspace(tools):
    with pytest.raises(PermissionError):
        tools.delete_file("../../etc/passwd")
