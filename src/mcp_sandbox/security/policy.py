"""Security policy: single arbiter for all allow/deny decisions.

Tools and the MCP registry MUST route every privilege check through
SecurityPolicy. No other module decides whether a command, host, or source
is allowed. This keeps the trust boundary in one auditable place.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

_SHELL_METACHARS = re.compile(r"[;&|`$\n\r<>]")


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class SecurityPolicy:
    """Loaded once at startup from default_policy.yaml."""

    def __init__(
        self,
        command_allowlist: frozenset[str],
        egress_allowlist: frozenset[str],
        mcp_sources: frozenset[str],
        tool_policy: dict[str, bool],
        max_file_bytes: int,
        exec_timeout_seconds: int,
        max_concurrent_tools: int,
    ) -> None:
        self._commands = command_allowlist
        self._egress = egress_allowlist
        self._sources = mcp_sources
        self._tools = dict(tool_policy)
        self.max_file_bytes = max_file_bytes
        self.exec_timeout_seconds = exec_timeout_seconds
        self.max_concurrent_tools = max_concurrent_tools

    @classmethod
    def load(cls, path: Path) -> "SecurityPolicy":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(
            command_allowlist=frozenset(raw["command_allowlist"]),
            egress_allowlist=frozenset(raw["egress_allowlist"]),
            mcp_sources=frozenset(raw["mcp_sources"]),
            tool_policy=raw["tool_policy"],
            max_file_bytes=int(raw["limits"]["max_file_bytes"]),
            exec_timeout_seconds=int(raw["limits"]["exec_timeout_seconds"]),
            max_concurrent_tools=int(raw["limits"]["max_concurrent_tools"]),
        )

    def is_tool_enabled(self, name: str) -> bool:
        return self._tools.get(name, False)

    def check_command(self, binary: str, args: list[str]) -> PolicyDecision:
        if binary not in self._commands:
            return PolicyDecision(False, f"binary {binary!r} not in allowlist")
        for arg in args:
            if _SHELL_METACHARS.search(arg):
                return PolicyDecision(
                    False, "argument contains shell metacharacters; pass literal args only"
                )
        return PolicyDecision(True)

    def check_egress(self, url: str) -> PolicyDecision:
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            return PolicyDecision(False, f"unparseable URL: {exc}")
        if parsed.scheme not in ("http", "https"):
            return PolicyDecision(False, f"scheme {parsed.scheme!r} not allowed")
        host = parsed.hostname or ""
        if not host:
            return PolicyDecision(False, "missing host")
        # Resolve and reject private/link-local/loopback addresses (SSRF guard).
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return PolicyDecision(False, f"cannot resolve host {host!r}")
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return PolicyDecision(
                    False, f"host {host!r} resolves to private/link-local address {ip}"
                )
        if host not in self._egress:
            return PolicyDecision(False, f"host {host!r} not in egress allowlist")
        return PolicyDecision(True)

    def check_mcp_source(self, source: str) -> PolicyDecision:
        scheme = source.split("://", 1)[0] if "://" in source else source.split("+", 1)[0]
        if scheme not in self._sources:
            return PolicyDecision(False, f"source scheme {scheme!r} not allowed")
        if scheme == "git+https":
            rest = source[len("git+https") :]
            if not rest.startswith("://") or "git@" in source:
                return PolicyDecision(False, "only public https git URLs are allowed")
        return PolicyDecision(True)
