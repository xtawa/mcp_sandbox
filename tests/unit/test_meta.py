from mcp_sandbox.tools.meta import MetaTools


def test_list_tools_returns_enabled_set():
    tools = MetaTools(enabled_tools={"read_file", "write_file", "exec_command"})
    names = {t["name"] for t in tools.list_tools()}
    assert names == {"read_file", "write_file", "exec_command"}


def test_sandbox_status_reports_policy_version():
    tools = MetaTools(enabled_tools=set())
    status = tools.sandbox_status(policy_version="1", workspace="/ws", uid=10001)
    assert status["policy_version"] == "1"
    assert status["uid"] == 10001  # noqa: PLR2004 - conventional unprivileged UID asserted in test
    assert status["workspace"] == "/ws"
    assert status["containerized"] is True
