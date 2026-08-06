import pytest
from mcp_sandbox.config import Settings


def test_defaults_are_secure(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    s = Settings()
    assert s.workspace_root == tmp_path
    assert s.run_as_uid == 10001
    assert s.run_as_gid == 10001
    assert s.max_file_bytes == 10 * 1024 * 1024
    assert s.exec_timeout_seconds == 30
    assert s.egress_allowlist_path.name == "egress_allowlist.txt"
    assert s.audit_log_path.parent.exists()


def test_unknown_env_keys_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(Exception):
        Settings(extra_field="nope")  # type: ignore[call-arg]
