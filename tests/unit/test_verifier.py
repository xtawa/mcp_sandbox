import hashlib

import pytest

from mcp_sandbox.mcp_registry.verifier import SourceVerifier, VerificationError
from mcp_sandbox.security.policy import SecurityPolicy


@pytest.fixture
def policy(tmp_path) -> SecurityPolicy:
    yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: []
egress_allowlist: [pypi.org, github.com]
mcp_sources: [pip, git+https]
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(yaml)
    return SecurityPolicy.load(p)


def test_parses_pip_source(policy):
    v = SourceVerifier(policy)
    spec = v.parse("pip://mcp-server-foo@1.2.3")
    assert spec.scheme == "pip"
    assert spec.package == "mcp-server-foo"
    assert spec.version == "1.2.3"


def test_parses_git_source(policy):
    v = SourceVerifier(policy)
    spec = v.parse("git+https://github.com/o/r.git@abc123")
    assert spec.scheme == "git+https"
    assert spec.url == "https://github.com/o/r.git"
    assert spec.ref == "abc123"


def test_rejects_disallowed_scheme(policy):
    v = SourceVerifier(policy)
    with pytest.raises(VerificationError):
        v.parse("file:///etc/passwd")


def test_verify_download_hash_matches(policy, tmp_path):
    payload = b"package bytes"
    digest = hashlib.sha256(payload).hexdigest()
    v = SourceVerifier(policy)
    v.verify_hash(payload, digest)  # should not raise


def test_verify_download_hash_mismatch(policy):
    v = SourceVerifier(policy)
    with pytest.raises(VerificationError):
        v.verify_hash(b"data", "0" * 64)
