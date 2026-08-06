import pytest

from mcp_sandbox.transports.streamable_http import create_http_app

HTTP_OK = 200


@pytest.fixture
def http_app(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TRANSFER_DIR", str(tmp_path / "transfer"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("CATALOG_DB_PATH", str(tmp_path / "cat.db"))
    from mcp_sandbox.server import build_app
    return create_http_app(build_app())


def test_tools_list_endpoint(http_app):
    from starlette.testclient import TestClient
    client = TestClient(http_app)
    resp = client.post(
        "/mcp", headers={"Mcp-Method": "tools/list"}, json={"jsonrpc": "2.0", "id": 1}
    )
    assert resp.status_code == HTTP_OK
    body = resp.json()
    names = {t["name"] for t in body["result"]["tools"]}
    assert "read_file" in names


def test_tool_call_endpoint(http_app, tmp_path):
    from starlette.testclient import TestClient
    (tmp_path / "ws").mkdir(exist_ok=True)
    (tmp_path / "ws" / "x.txt").write_text("yo")
    client = TestClient(http_app)
    resp = client.post(
        "/mcp",
        headers={"Mcp-Method": "tools/call", "Mcp-Name": "read_file"},
        json={
            "jsonrpc": "2.0", "id": 2,
            "params": {"name": "read_file", "arguments": {"path": "x.txt"}},
        },
    )
    assert resp.status_code == HTTP_OK
    assert "yo" in resp.json()["result"]["content"][0]["text"]


def test_unknown_method_returns_jsonrpc_error(http_app):
    from starlette.testclient import TestClient
    client = TestClient(http_app)
    resp = client.post(
        "/mcp", headers={"Mcp-Method": "bogus/method"}, json={"jsonrpc": "2.0", "id": 3}
    )
    body = resp.json()
    assert "error" in body
