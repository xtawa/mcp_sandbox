import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.policy import SecurityPolicy
from mcp_sandbox.tools.file_read import FileReadTools


@pytest.fixture
def tools(tmp_path, monkeypatch) -> FileReadTools:
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
    return FileReadTools(
        settings=s,
        policy=SecurityPolicy.load(p),
        audit=AuditLogger(tmp_path / "audit.jsonl"),
    )


def test_read_file_returns_contents(tools, tmp_path):
    (tmp_path / "hello.txt").write_text("hello world")
    result = tools.read_file("hello.txt")
    assert result == "hello world"


def test_read_file_rejects_traversal(tools):
    with pytest.raises(PermissionError):
        tools.read_file("../../etc/passwd")


def test_read_file_enforces_size_limit(tools, tmp_path):
    (tmp_path / "big.txt").write_bytes(b"x" * 2048)
    with pytest.raises(ValueError):
        tools.read_file("big.txt")


def test_list_directory(tools, tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "a.txt").write_text("a")
    (sub / "b").mkdir()
    entries = tools.list_directory("sub")
    names = sorted(e["name"] for e in entries)
    assert names == ["a.txt", "b"]


def test_stat_file(tools, tmp_path):
    content = "abc"
    (tmp_path / "f.txt").write_text(content)
    info = tools.stat_file("f.txt")
    assert info["size"] == len(content)
    assert info["is_file"] is True
