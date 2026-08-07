import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.network import EgressClient
from mcp_sandbox.security.policy import SecurityPolicy
from mcp_sandbox.tools.file_export import FileExportTool


@pytest.fixture
def tool(tmp_path, monkeypatch) -> FileExportTool:
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    s = Settings()
    pol_yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: [/bin/ls]
egress_allowlist: [pypi.org]
mcp_sources: []
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(pol_yaml)
    policy = SecurityPolicy.load(p)
    return FileExportTool(
        settings=s, policy=policy, audit=AuditLogger(tmp_path / "audit.jsonl"),
        egress=EgressClient(policy, timeout=5),
    )


def test_export_uploads_to_allowlisted_host(tool, tmp_path, monkeypatch):
    (tmp_path / "out.bin").write_bytes(b"payload")

    class FakeResp:
        status_code = 200
        text = "ok"

    def fake_post(self, url, *, body, headers=None):
        assert url == "https://pypi.org/upload"
        assert body == b"payload"
        return FakeResp()

    monkeypatch.setattr(EgressClient, "post", fake_post)
    result = tool.export_file("out.bin", "https://pypi.org/upload")
    assert result["status"] == 200  # noqa: PLR2004 - conventional HTTP success status code


def test_export_rejects_non_allowlisted_host(tool, tmp_path):
    (tmp_path / "out.bin").write_bytes(b"payload")
    with pytest.raises(PermissionError):
        tool.export_file("out.bin", "https://evil.example.com/u")


def test_export_rejects_traversal(tool):
    with pytest.raises(PermissionError):
        tool.export_file("../../etc/passwd", "https://pypi.org/u")
