
import pytest

from mcp_sandbox.security.policy import SecurityPolicy


@pytest.fixture
def policy(tmp_path) -> SecurityPolicy:
    yaml = """\
version: 1
limits:
  max_file_bytes: 1024
  exec_timeout_seconds: 5
  max_concurrent_tools: 2
command_allowlist:
  - /usr/bin/python3
  - /bin/ls
egress_allowlist:
  - pypi.org
mcp_sources:
  - pip
tool_policy:
  read_file: true
  write_file: true
  list_directory: true
  stat_file: true
  delete_file: true
  make_directory: true
  transfer_file: true
  export_file: true
  exec_command: true
  list_tools: true
  sandbox_status: true
"""
    p = tmp_path / "policy.yaml"
    p.write_text(yaml)
    return SecurityPolicy.load(p)


def test_command_allowed(policy):
    d = policy.check_command("/usr/bin/python3", ["--version"])
    assert d.allowed
    assert d.reason == ""


def test_command_not_in_allowlist(policy):
    d = policy.check_command("/bin/rm", ["-rf", "/"])
    assert not d.allowed
    assert "not in allowlist" in d.reason


def test_command_rejects_shell_metacharacters(policy):
    d = policy.check_command("/usr/bin/python3", ["-c", "import os; os.system('rm -rf /')"])
    assert not d.allowed


def test_egress_allowed(policy):
    assert policy.check_egress("https://pypi.org/simple/").allowed


def test_egress_blocked(policy):
    d = policy.check_egress("https://evil.example.com/x")
    assert not d.allowed
    assert "evil.example.com" in d.reason


def test_egress_blocks_private_ranges(policy):
    d = policy.check_egress("http://169.254.169.254/latest/meta-data/")
    assert not d.allowed
    assert "non-global" in d.reason.lower() or "multicast" in d.reason.lower()


def test_mcp_source_allowed(policy):
    assert policy.check_mcp_source("pip://mcp-server-foo@1.0.0").allowed


def test_mcp_source_blocked(policy):
    d = policy.check_mcp_source("file:///etc/passwd")
    assert not d.allowed


def test_mcp_source_rejects_ssh_git_url(policy):
    # SSH-style git URLs (git@host:path) lack "://" and "+", so the scheme
    # extraction yields the whole string, which is never in the allowlist.
    # This locks in the security property after the git@ substring check was
    # narrowed to startswith (it was dead code for this case but the test
    # prevents future regressions).
    d = policy.check_mcp_source("git@github.com:evil/repo.git")
    assert not d.allowed
    assert "not allowed" in d.reason


def test_tool_enabled(policy):
    assert policy.is_tool_enabled("read_file")
    assert not policy.is_tool_enabled("format_disk")
