"""Streamable HTTP transport for the MCP 2026-07-28 stateless spec.

Each request is a self-describing POST /mcp with:
  - Mcp-Method header (e.g. tools/list, tools/call)
  - Mcp-Name header (tool name, for tools/call)
  - JSON-RPC 2.0 body

There is no initialize handshake and no session id; any instance can serve
any request. We use Starlette directly (a hard dep of the MCP SDK) so the
transport has zero extra dependencies and is trivially testable with
starlette.testclient.TestClient.
"""
from __future__ import annotations

import json
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..server import SandboxApp


def _jsonrpc(result: Any, req_id: int | str | None) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(code: int, message: str, req_id: int | str | None) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


async def _handle_mcp(request: Request) -> JSONResponse:
    app: SandboxApp = request.app.state.app
    method = request.headers.get("Mcp-Method", "")
    try:
        body = await request.json()
    except Exception:
        body = {}
    req_id = body.get("id")
    try:
        if method == "tools/list":
            tools = [
                {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
                for t in app.list_tools()
            ]
            return JSONResponse(_jsonrpc({"tools": tools}, req_id))
        if method == "tools/call":
            params = body.get("params", {})
            name = params.get("name") or request.headers.get("Mcp-Name", "")
            args = params.get("arguments", {})
            result = app.call_tool(name, args)
            text = result if isinstance(result, str) else json.dumps(result, default=str)
            return JSONResponse(_jsonrpc({"content": [{"type": "text", "text": text}]}, req_id))
        return JSONResponse(_jsonrpc_error(-32601, f"unknown method {method!r}", req_id))
    except PermissionError as exc:
        return JSONResponse(_jsonrpc_error(-32603, f"denied: {exc}", req_id))
    except KeyError as exc:
        return JSONResponse(_jsonrpc_error(-32602, f"not found: {exc}", req_id))
    except Exception as exc:  # pragma: no cover - last-resort guard
        return JSONResponse(_jsonrpc_error(-32603, str(exc), req_id))


def create_http_app(app: SandboxApp) -> Starlette:
    routes = [Route("/mcp", _handle_mcp, methods=["POST"])]
    starlette = Starlette(routes=routes)
    starlette.state.app = app
    return starlette
