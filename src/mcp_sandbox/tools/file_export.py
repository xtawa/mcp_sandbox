"""export_file: upload a workspace file to an external HTTP endpoint.

The destination URL MUST pass the egress allowlist + SSRF checks enforced by
EgressClient. This is the only sanctioned path for an AI to send data out of
the sandbox beyond the transfer volume.
"""
from __future__ import annotations

from ..config import Settings
from ..security.audit import AuditLogger
from ..security.network import EgressClient
from ..security.paths import SafePathError, resolve_safe_path
from ..security.policy import SecurityPolicy


class FileExportTool:
    def __init__(
        self,
        settings: Settings,
        policy: SecurityPolicy,
        audit: AuditLogger,
        egress: EgressClient,
    ) -> None:
        self._root = settings.workspace_root
        self._policy = policy
        self._audit = audit
        self._egress = egress

    def export_file(self, path: str, url: str) -> dict:
        try:
            p = resolve_safe_path(self._root, path)
        except SafePathError as exc:
            self._audit.record(tool="export_file", actor="ai",
                               args={"path": path, "url": url}, outcome="denied",
                               detail=str(exc))
            raise PermissionError(str(exc)) from exc
        if not p.exists():
            raise FileNotFoundError(str(p))
        if p.stat().st_size > self._policy.max_file_bytes:
            raise ValueError("file exceeds max_file_bytes")
        body = p.read_bytes()
        resp = self._egress.post(url, body=body)
        self._audit.record(
            tool="export_file", actor="ai",
            args={"path": path, "url": url}, outcome="ok",
            detail=f"HTTP {resp.status_code}",
        )
        return {"status": resp.status_code, "url": url, "bytes": len(body)}
