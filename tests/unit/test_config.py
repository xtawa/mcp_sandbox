import pytest
from pydantic import ValidationError

from mcp_sandbox.config import Settings

# Magic values below mirror the secure defaults hardcoded in Settings; they
# are not configurable magic numbers but the contract being asserted.
_DEFAULT_UID = 10001
_DEFAULT_GID = 10001
_DEFAULT_EXEC_TIMEOUT = 30


def test_defaults_are_secure(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    s = Settings()
    assert s.workspace_root == tmp_path
    assert s.run_as_uid == _DEFAULT_UID
    assert s.run_as_gid == _DEFAULT_GID
    assert s.max_file_bytes == 10 * 1024 * 1024
    assert s.exec_timeout_seconds == _DEFAULT_EXEC_TIMEOUT
    assert s.egress_allowlist_path.name == "egress_allowlist.txt"
    assert s.audit_log_path.parent.exists()


def test_unknown_env_keys_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValidationError):
        Settings(extra_field="nope")  # type: ignore[call-arg]
