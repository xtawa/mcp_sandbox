import pytest

from mcp_sandbox.security.policy import SecurityPolicy


@pytest.fixture
def policy(tmp_path) -> SecurityPolicy:
    yaml = """\
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
    p.write_text(yaml)
    return SecurityPolicy.load(p)


@pytest.mark.parametrize("args", [
    ["; rm -rf /"],
    ["$(cat /etc/passwd)"],
    ["`id`"],
    ["foo && bar"],
    ["foo || bar"],
    ["foo\nbar"],
    ["foo > /etc/cron.d/x"],
    ["foo|bar"],
])
def test_metacharacter_args_rejected(policy, args):
    d = policy.check_command("/bin/ls", args)
    assert not d.allowed


def test_unlisted_binary_rejected(policy):
    d = policy.check_command("/bin/sh", ["-c", "id"])
    assert not d.allowed
    assert "not in allowlist" in d.reason


def test_literal_args_allowed(policy):
    d = policy.check_command("/bin/ls", ["-la", "/tmp"])  # noqa: S108 - literal arg in a test
    assert d.allowed
