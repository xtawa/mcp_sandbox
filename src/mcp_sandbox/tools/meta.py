"""Meta tools: list_tools and sandbox_status.

These let the AI inspect what it can do without poking at the runtime
directly. They never touch the filesystem or network.
"""
from __future__ import annotations


class MetaTools:
    def __init__(self, enabled_tools: set[str]) -> None:
        self._enabled = sorted(enabled_tools)

    def list_tools(self) -> list[dict]:
        return [{"name": n, "enabled": True} for n in self._enabled]

    def sandbox_status(
        self,
        *,
        policy_version: str,
        workspace: str,
        uid: int,
    ) -> dict:
        return {
            "policy_version": policy_version,
            "workspace": workspace,
            "uid": uid,
            "containerized": True,
            "enabled_tools": list(self._enabled),
        }
