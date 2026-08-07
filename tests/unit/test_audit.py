import json

from mcp_sandbox.security.audit import AuditLogger


def test_log_writes_jsonl_line(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)
    logger.record(
        tool="read_file",
        actor="ai",
        args={"path": "foo.txt"},
        outcome="ok",
        detail="read 12 bytes",
    )
    lines = log_path.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tool"] == "read_file"
    assert entry["outcome"] == "ok"
    assert "ts" in entry
    assert entry["args"] == {"path": "foo.txt"}


def test_log_denied_action(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)
    logger.record(tool="exec_command", actor="ai", args={"cmd": "/bin/rm"}, outcome="denied",
                  detail="not in allowlist")
    entry = json.loads(log_path.read_text().splitlines()[0])
    assert entry["outcome"] == "denied"


def test_log_is_append_only(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    AuditLogger(log_path).record(tool="t", actor="a", args={}, outcome="ok", detail="")
    AuditLogger(log_path).record(tool="t2", actor="a", args={}, outcome="ok", detail="")
    # Two records written by two independent AuditLogger instances against the
    # same path must both appear (O_APPEND semantics).
    assert len(log_path.read_text().splitlines()) == 2  # noqa: PLR2004 - record count
