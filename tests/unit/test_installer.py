import pytest

from mcp_sandbox.config import Settings
from mcp_sandbox.mcp_registry.catalog import Catalog
from mcp_sandbox.mcp_registry.installer import Installer
from mcp_sandbox.mcp_registry.verifier import SourceSpec
from mcp_sandbox.security.audit import AuditLogger
from mcp_sandbox.security.policy import SecurityPolicy
from mcp_sandbox.security.sandbox import SandboxResult


@pytest.fixture
def installer(tmp_path, monkeypatch) -> Installer:
    monkeypatch.setenv("DATA_ROOT", str(tmp_path / "data"))
    s = Settings()
    pol_yaml = """\
version: 1
limits: {max_file_bytes: 1024, exec_timeout_seconds: 5, max_concurrent_tools: 2}
command_allowlist: []
egress_allowlist: [pypi.org]
mcp_sources: [pip]
tool_policy: {read_file: true, write_file: true, list_directory: true, stat_file: true,
  delete_file: true, make_directory: true, transfer_file: true, export_file: true,
  exec_command: true, list_tools: true, sandbox_status: true}
"""
    p = tmp_path / "p.yaml"
    p.write_text(pol_yaml)
    policy = SecurityPolicy.load(p)
    return Installer(
        settings=s, policy=policy, audit=AuditLogger(tmp_path / "a.jsonl"),
        catalog=Catalog(tmp_path / "cat.db"), runner=FakeRunner(),
    )


class FakeRunner:
    def __init__(self) -> None:
        self.calls = []

    def run(self, command, *, timeout):
        self.calls.append(command)
        return SandboxResult(returncode=0, stdout="", stderr="")


def test_install_creates_venv_and_registers(installer, tmp_path):
    spec = SourceSpec(scheme="pip", package="mcp-server-foo", version="1.0.0")
    record = installer.install(spec, sha256="abc", entrypoint="mcp-server-foo")
    assert record.name == "mcp-server-foo"
    assert record.status == "installed"
    assert record.sha256 == "abc"
    # venv path under data root
    assert record.venv_path.startswith(str(tmp_path / "data"))
    # catalog has it
    assert installer._catalog.get("mcp-server-foo") is not None


def test_install_rejects_empty_entrypoint(installer):
    spec = SourceSpec(scheme="pip", package="mcp-server-foo", version="1.0.0")
    with pytest.raises(ValueError):
        installer.install(spec, sha256="abc", entrypoint="")


def test_install_re_runs_pip_in_sandbox(installer):
    spec = SourceSpec(scheme="pip", package="mcp-server-foo", version="1.0.0")
    installer.install(spec, sha256="abc", entrypoint="mcp-server-foo")
    # FakeRunner captured the pip command
    assert any("pip" in " ".join(c) for c in installer._runner.calls)
