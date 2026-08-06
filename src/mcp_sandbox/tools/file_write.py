"""File write tools: write_file, delete_file, make_directory.

Every write is confined to the workspace root via resolve_safe_path and
capped at policy.max_file_bytes so an AI cannot exhaust disk with one call.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..config import Settings
from ..security.audit import AuditLogger
from ..security.paths import SafePathError, resolve_safe_path
from ..security.policy import SecurityPolicy


class FileWriteTools:
    def __init__(self, settings: Settings, policy: SecurityPolicy, audit: AuditLogger) -> None:
        self._root = settings.workspace_root
        self._policy = policy
        self._audit = audit

    def _safe(self, user_path: str) -> Path:
        try:
            return resolve_safe_path(self._root, user_path)
        except SafePathError as exc:
            self._audit.record(tool="write_file", actor="ai", args={"path": user_path},
                               outcome="denied", detail=str(exc))
            raise PermissionError(str(exc)) from exc

    def write_file(self, path: str, content: str) -> str:
        if len(content.encode("utf-8")) > self._policy.max_file_bytes:
            self._audit.record(tool="write_file", actor="ai", args={"path": path},
                               outcome="denied", detail="payload exceeds size limit")
            raise ValueError("content exceeds max_file_bytes")
        p = self._safe(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self._audit.record(tool="write_file", actor="ai", args={"path": path},
                           outcome="ok", detail=f"{len(content)} chars")
        return str(p)

    def make_directory(self, path: str) -> str:
        p = self._safe(path)
        p.mkdir(parents=True, exist_ok=True)
        self._audit.record(tool="make_directory", actor="ai", args={"path": path},
                           outcome="ok", detail=str(p))
        return str(p)

    def delete_file(self, path: str) -> str:
        p = self._safe(path)
        if not p.exists():
            raise FileNotFoundError(str(p))
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        self._audit.record(tool="delete_file", actor="ai", args={"path": path},
                           outcome="ok", detail="deleted")
        return str(p)
