# Security Policy

## Threat model

The sandbox runs code an AI generated or selected. We assume that code is
**untrusted**: it may be buggy or adversarial (prompt injection, poisoned
dependencies). The sandbox must confine that code so it cannot:

1. Read or modify files outside its workspace.
2. Execute binaries not on the operator-approved allowlist.
3. Reach network endpoints not on the egress allowlist (SSRF, data exfil).
4. Escalate privileges or persist across container restarts.
5. Exhaust host resources (CPU, memory, PIDs, disk).

## Defense in depth (5 layers)

| Layer | Control | Where |
|-------|---------|-------|
| Container | non-root UID 10001, read-only rootfs, tmpfs writes, `no-new-privileges`, all caps dropped, seccomp profile, optional gVisor (`runsc`) | `Dockerfile`, `docker-compose.yml` |
| Process | `bubblewrap` jail: unshared PID/mount/net/user/ipc/uts namespaces, read-only host bind, tmpfs workspace, dropped caps, die-with-parent | `security/sandbox.py` |
| Application | path traversal prevention, command allowlist, egress allowlist + SSRF guard, request size limits, per-tool timeouts | `security/policy.py`, `security/paths.py`, `security/network.py` |
| Supply chain | MCP source allowlist (pip/git+https), SHA-256 pinning, isolated venv per MCP, per-MCP tool allowlist | `mcp_registry/verifier.py`, `mcp_registry/installer.py`, `mcp_registry/runner.py` |
| Audit | append-only JSONL log of every tool call, policy decision, and MCP lifecycle event | `security/audit.py` |

## What the AI CANNOT do

- Touch any path outside `/workspace/_sandbox` (file tools reject traversal).
- Run `sh`, `bash`, `curl`, `wget`, or any binary not in `policies/command_allowlist.txt`.
- Contact localhost, private IPs, link-local, or any host not in `policies/egress_allowlist.txt`.
- Install an MCP from `file://`, `http://`, or unsigned git sources.
- Call a tool on an installed MCP that the operator did not allowlist at install time.
- Gain root (UID 10001, no caps, no-new-privileges).

## Reporting a vulnerability

Open a private advisory. Do not file a public issue for security problems.
