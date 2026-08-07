# Architecture

```
+----------------------------------------------------------+
|  Host (operator machine)                                 |
|                                                          |
|  +----------------------------------------------------+  |
|  | OCI container (mcp-sandbox)  UID 10001, no caps   |  |
|  |  read-only rootfs, tmpfs /tmp + workspace          |  |
|  |  seccomp profile, no-new-privileges                |  |
|  |                                                    |  |
|  |  +-----------------------+   /data/transfer <----> |  | host volume
|  |  | MCP gateway (Python)  |   /data        <----> |  | host volume
|  |  |  streamable HTTP      |                         |  |
|  |  |  :8765                |                         |  |
|  |  +-----------+-----------+                         |  |
|  |              |                                     |  |
|  |   +----------+----------+   +-------------------+  |  |
|  |   | Built-in tools       |   | bwrap jail        |  |  |
|  |   |  read/write/list/    |   |  (per exec / MCP) |  |  |
|  |   |  stat/delete/mkdir/  |   |  own namespaces   |  |  |
|  |   |  transfer/export/    |   |  no host FS       |  |  |
|  |   |  exec/meta           |   |  no net (or       |  |  |
|  |   +----------------------+   |   filtered)       |  |  |
|  |                              +-------------------+  |  |
|  |   +-------------------------------------------+     |  |
|  |   | Security core: policy / paths / network / |     |  |
|  |   | sandbox / audit  (single arbiters)        |     |  |
|  |   +-------------------------------------------+     |  |
|  +----------------------------------------------------+  |
+----------------------------------------------------------+
```

## Request flow (tools/call)

1. AI client POSTs `/mcp` with `Mcp-Method: tools/call`, `Mcp-Name: <tool>`, JSON-RPC body.
2. `transports/streamable_http.py` parses the stateless request (no session).
3. `server.SandboxApp.call_tool(name, args)` dispatches to the tool handler.
4. The handler resolves paths via `security/paths.py`, checks the decision via
   `security/policy.py`, performs the action (possibly via `security/sandbox.py`
   for exec / `security/network.py` for egress), and writes an audit record.
5. The result is wrapped as MCP `content` and returned as JSON-RPC.

## Third-party MCP flow (install_mcp -> call_mcp_tool)

1. `install_mcp` parses the source via `verifier.py` (allowlist + scheme).
2. `installer.py` creates an isolated venv at `/data/mcps/<name>/venv` and
   runs `pip install` inside the bwrap jail.
3. The catalog records the MCP with its SHA-256, entrypoint, and allowed tools.
4. `call_mcp_tool` looks up the MCP, checks the per-MCP tool allowlist,
   spawns the entrypoint in a fresh bwrap jail, and proxies one JSON-RPC
   line over stdio.
5. `uninstall_mcp` removes the venv and catalog entry.

## Why bubblewrap (not Docker-in-Docker)

bwrap is unprivileged, ~200 KB, and works inside our non-root container
without `--privileged` or socket mounting. It gives us namespace isolation
(PID, mount, net, user) per exec and per MCP process, which is sufficient
given the container already provides the outer boundary. gVisor (`runsc`)
is offered as an optional outer runtime for sites that want kernel-level
syscall filtering on top.
