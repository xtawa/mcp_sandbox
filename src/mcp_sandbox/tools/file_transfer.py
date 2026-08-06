"""transfer_file: bidirectional copy between the sandbox workspace and the
host-mounted transfer volume.

The transfer volume is the ONLY host path the sandbox may read/write besides
its workspace. Both endpoints are confined by resolve_safe_path so an AI
cannot use the transfer tool to escape either boundary.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..config import Settings
from ..security.audit import AuditLogger
from ..security.paths import SafePathError, resolve_safe_path
from ..security.policy import SecurityPolicy


class FileTransferTool:
    def __init__(self, settings: Settings, policy: SecurityPolicy, audit: AuditLogger) -> None:
        self._workspace = settings.workspace_root
        self._transfer = settings.transfer_dir
        self._policy = policy
        self._audit = audit
        self._transfer.mkdir(parents=True, exist_ok=True)

    def _safe(self, root: Path, user_path: str) -> Path:
        try:
            return resolve_safe_path(root, user_path)
        except SafePathError as exc:
            raise PermissionError(str(exc)) from exc

    def transfer_file(self, name: str, direction: str, dest: str | None = None) -> str:
        dest = dest or name
        if direction == "in":
            src = self._safe(self._transfer, name)
            dst = self._safe(self._workspace, dest)
        elif direction == "out":
            src = self._safe(self._workspace, name)
            dst = self._safe(self._transfer, dest)
        else:
            raise ValueError(f"unknown direction {direction!r}; use 'in' or 'out'")
        if not src.exists():
            raise FileNotFoundError(str(src))
        if src.stat().st_size > self._policy.max_file_bytes:
            raise ValueError("file exceeds max_file_bytes")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        self._audit.record(
            tool="transfer_file", actor="ai",
            args={"name": name, "direction": direction, "dest": dest},
            outcome="ok", detail=f"{src} -> {dst}",
        )
        return str(dst)
