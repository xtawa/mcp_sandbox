"""File read tools: read_file, list_directory, stat_file.

All paths are resolved through security.paths.resolve_safe_path so traversal
is impossible regardless of the argument the AI passes.
"""
from __future__ import annotations

from pathlib import Path

from ..config import Settings
from ..security.audit import AuditLogger
from ..security.paths import SafePathError, resolve_safe_path
from ..security.policy import SecurityPolicy


class FileReadTools:
    def __init__(self, settings: Settings, policy: SecurityPolicy, audit: AuditLogger) -> None:
        self._root = settings.workspace_root
        self._policy = policy
        self._audit = audit

    def _safe(self, user_path: str) -> Path:
        try:
            return resolve_safe_path(self._root, user_path)
        except SafePathError as exc:
            self._audit.record(
                tool="read_file", actor="ai", args={"path": user_path},
                outcome="denied", detail=str(exc),
            )
            raise PermissionError(str(exc)) from exc

    def read_file(self, path: str) -> str:
        p = self._safe(path)
        if not p.exists():
            self._audit.record(tool="read_file", actor="ai", args={"path": path},
                               outcome="denied", detail="not found")
            raise FileNotFoundError(str(p))
        if p.stat().st_size > self._policy.max_file_bytes:
            self._audit.record(tool="read_file", actor="ai", args={"path": path},
                               outcome="denied", detail="exceeds size limit")
            raise ValueError(f"file exceeds max {self._policy.max_file_bytes} bytes")
        text = p.read_text(encoding="utf-8", errors="replace")
        self._audit.record(tool="read_file", actor="ai", args={"path": path},
                           outcome="ok", detail=f"{len(text)} chars")
        return text

    def list_directory(self, path: str) -> list[dict]:
        p = self._safe(path)
        if not p.is_dir():
            raise NotADirectoryError(str(p))
        entries = []
        for entry in sorted(p.iterdir()):
            entries.append({
                "name": entry.name,
                "is_file": entry.is_file(),
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else 0,
            })
        self._audit.record(tool="list_directory", actor="ai", args={"path": path},
                           outcome="ok", detail=f"{len(entries)} entries")
        return entries

    def stat_file(self, path: str) -> dict:
        p = self._safe(path)
        if not p.exists():
            raise FileNotFoundError(str(p))
        st = p.stat()
        self._audit.record(tool="stat_file", actor="ai", args={"path": path},
                           outcome="ok", detail=str(st.st_size))
        return {
            "path": str(p),
            "size": st.st_size,
            "is_file": p.is_file(),
            "is_dir": p.is_dir(),
            "mtime": st.st_mtime,
            "mode": oct(st.st_mode),
        }
