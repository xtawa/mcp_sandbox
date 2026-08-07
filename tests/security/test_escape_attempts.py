"""Tests that try to break out of the sandbox. They must all be denied at the
application layer, independent of whether bwrap is installed."""
import pytest

from mcp_sandbox.mcp_registry.verifier import VerificationError
from mcp_sandbox.server import build_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TRANSFER_DIR", str(tmp_path / "transfer"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("CATALOG_DB_PATH", str(tmp_path / "cat.db"))
    return build_app()


def test_read_file_traversal_denied(app):
    with pytest.raises(PermissionError):
        app.call_tool("read_file", {"path": "../../../../etc/passwd"})


def test_write_file_traversal_denied(app):
    with pytest.raises(PermissionError):
        app.call_tool("write_file", {"path": "/etc/cron.d/pwn", "content": "x"})


def test_exec_command_not_in_allowlist_denied(app):
    with pytest.raises(PermissionError):
        app.call_tool("exec_command", {"binary": "/bin/sh", "args": ["-c", "id"]})


def test_exec_command_shell_metachar_denied(app):
    with pytest.raises((PermissionError, ValueError)):
        app.call_tool("exec_command",
                      {"binary": "/bin/ls", "args": ["; cat /etc/passwd"]})


def test_export_file_to_private_ip_denied(app, tmp_path):
    (tmp_path / "ws").mkdir(exist_ok=True)
    (tmp_path / "ws" / "x").write_text("x")
    with pytest.raises(PermissionError):
        app.call_tool("export_file", {"path": "x", "url": "http://169.254.169.254/x"})


def test_install_mcp_disallowed_source_denied(app):
    with pytest.raises(VerificationError):
        app.call_tool("install_mcp", {"source": "file:///etc/passwd",
                                      "sha256": "0" * 64, "entrypoint": "x"})


def test_call_mcp_tool_disallowed_tool_denied(app):
    # No MCP installed; the catalog lookup raises KeyError before any exec.
    with pytest.raises(KeyError):
        app.call_tool("call_mcp_tool", {"mcp": "nope", "tool": "x", "args": {}})


def test_transfer_file_cannot_escape(app):
    with pytest.raises(PermissionError):
        app.call_tool("transfer_file", {"name": "../../etc/passwd", "direction": "in"})
