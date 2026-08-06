import pytest

from mcp_sandbox.security.network import EgressClient
from mcp_sandbox.security.policy import SecurityPolicy


@pytest.fixture
def policy(tmp_path) -> SecurityPolicy:
    yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: [/bin/ls]
egress_allowlist: [pypi.org]
mcp_sources: [pip]
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(yaml)
    return SecurityPolicy.load(p)


def test_get_rejects_non_allowlisted_host(policy, monkeypatch):
    client = EgressClient(policy, timeout=5)
    with pytest.raises(PermissionError):
        client.get("https://evil.example.com/x")


def test_get_rejects_private_ip(policy):
    client = EgressClient(policy, timeout=5)
    with pytest.raises(PermissionError):
        client.get("http://127.0.0.1/secret")


def test_post_size_capped(policy, monkeypatch):
    client = EgressClient(policy, timeout=5, max_body_bytes=8)
    with pytest.raises(ValueError):
        client.post("https://pypi.org/x", body=b"x" * 100)
