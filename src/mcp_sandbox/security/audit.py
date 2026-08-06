"""Append-only structured audit log.

Every tool call, policy decision, and MCP lifecycle event is written here as
one JSON line per record. The file is opened with O_APPEND so concurrent
writers do not corrupt each other's lines. Rotation is out of scope for v1;
the container mounts /data as a volume the operator can rotate.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Open once, line-buffered, append-only. Keep the handle for the
        # lifetime of the process.
        self._fh = open(self._path, "a", encoding="utf-8")
        self._lock = threading.Lock()

    def record(
        self,
        *,
        tool: str,
        actor: str,
        args: dict[str, Any],
        outcome: str,
        detail: str = "",
    ) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "tool": tool,
            "actor": actor,
            "args": args,
            "outcome": outcome,
            "detail": detail,
        }
        line = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        with self._lock:
            self._fh.close()
