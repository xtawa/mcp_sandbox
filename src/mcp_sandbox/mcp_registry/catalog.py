"""SQLite-backed catalog of installed third-party MCPs.

The catalog is the source of truth for what is installed, where its venv
lives, and whether it is currently running. SQLite is used (not a flat file)
so concurrent tool calls cannot corrupt the store.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class InstalledMCP:
    name: str
    source: str
    version: str
    venv_path: str
    entrypoint: str
    status: str          # installed | running | stopped | error
    sha256: str
    allowed_tools: tuple[str, ...] = ()


class Catalog:
    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mcps (
                name TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def register(self, mcp: InstalledMCP) -> None:
        data = json.dumps(asdict(mcp), sort_keys=True)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO mcps (name, data) VALUES (?, ?)",
                (mcp.name, data),
            )
            self._conn.commit()

    def get(self, name: str) -> InstalledMCP | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM mcps WHERE name = ?", (name,)
            ).fetchone()
        if row is None:
            return None
        d = json.loads(row[0])
        d["allowed_tools"] = tuple(d.get("allowed_tools", ()))
        return InstalledMCP(**d)

    def list_all(self) -> list[InstalledMCP]:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM mcps ORDER BY name").fetchall()
        out = []
        for (raw,) in rows:
            d = json.loads(raw)
            d["allowed_tools"] = tuple(d.get("allowed_tools", ()))
            out.append(InstalledMCP(**d))
        return out

    def update_status(self, name: str, status: str) -> None:
        mcp = self.get(name)
        if mcp is None:
            raise KeyError(name)
        from dataclasses import replace
        self.register(replace(mcp, status=status))

    def remove(self, name: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM mcps WHERE name = ?", (name,))
            self._conn.commit()
