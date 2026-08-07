import pytest

from mcp_sandbox.security.network import EgressClient
from mcp_sandbox.security.policy import SecurityPolicy


@pytest.fixture
def policy(tmp_path) -> SecurityPolicy:
    yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: []
egress_allowlist: [pypi.org, github.com]
mcp_sources: []
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(yaml)
    return SecurityPolicy.load(p)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x",
    "http://localhost/x",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/x",
    "http://192.168.1.1/x",
    "ftp://pypi.org/x",
    "https://evil.example.com/x",
])
def test_blocked_urls(policy, url):
    client = EgressClient(policy, timeout=5)
    with pytest.raises(PermissionError):
        client.get(url)


def test_allowed_url_passes_check(policy):
    client = EgressClient(policy, timeout=5)
    # Should raise only because no real network, not because denied.
    # We assert the URL is permitted by calling _check directly.
    client._check("https://pypi.org/simple/", None)  # no exception
