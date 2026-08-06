import pytest

from mcp_sandbox.server import build_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TRANSFER_DIR", str(tmp_path / "transfer"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("CATALOG_DB_PATH", str(tmp_path / "cat.db"))
    return build_app()


def test_app_exposes_all_required_tools(app):
    names = {t.name for t in app.list_tools()}
    required = {
        "read_file", "write_file", "list_directory", "stat_file",
        "delete_file", "make_directory", "transfer_file", "export_file",
        "exec_command", "list_tools", "sandbox_status",
        "install_mcp", "call_mcp_tool", "uninstall_mcp",
    }
    assert required.issubset(names)


def test_read_file_via_app(app, tmp_path):
    (tmp_path / "ws").mkdir(exist_ok=True)
    (tmp_path / "ws" / "hello.txt").write_text("hi")
    result = app.call_tool("read_file", {"path": "hello.txt"})
    assert "hi" in result


def test_disabled_tool_not_listed(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TRANSFER_DIR", str(tmp_path / "transfer"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("CATALOG_DB_PATH", str(tmp_path / "cat.db"))
    # Edit the policy in-memory by pointing policies_dir at a custom file.
    import yaml
    pol = tmp_path / "p.yaml"
    pol.write_text(yaml.safe_dump({
        "version": 1,
        "limits": {"max_file_bytes": 1024, "exec_timeout_seconds": 5,
                   "max_concurrent_tools": 2},
        "command_allowlist": ["/bin/ls"],
        "egress_allowlist": [],
        "mcp_sources": ["pip"],
        "tool_policy": {"read_file": True, "write_file": False,
                        "list_directory": True, "stat_file": True,
                        "delete_file": True, "make_directory": True,
                        "transfer_file": True, "export_file": True,
                        "exec_command": True, "list_tools": True,
                        "sandbox_status": True},
    }))
    from mcp_sandbox.security.policy import SecurityPolicy
    from mcp_sandbox.server import build_app_with_policy
    app = build_app_with_policy(SecurityPolicy.load(pol))
    names = {t.name for t in app.list_tools()}
    assert "write_file" not in names
    assert "read_file" in names
