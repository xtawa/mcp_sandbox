"""Egress HTTP client that enforces the security policy on every request.

All outbound HTTP from the sandbox (installer downloads, export_file uploads)
MUST go through EgressClient. It re-checks the host allowlist and SSRF guards
immediately before opening the socket, so a DNS rebinding attempt between
policy load and request time is still blocked.
"""
from __future__ import annotations

import httpx

from .policy import SecurityPolicy


class EgressClient:
    def __init__(
        self,
        policy: SecurityPolicy,
        *,
        timeout: int,
        max_body_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self._policy = policy
        self._timeout = timeout
        self._max_body = max_body_bytes

    def _check(self, url: str, body: bytes | None) -> None:
        decision = self._policy.check_egress(url)
        if not decision:
            raise PermissionError(decision.reason)
        if body is not None and len(body) > self._max_body:
            raise ValueError(f"body exceeds max {self._max_body} bytes")

    def get(self, url: str) -> httpx.Response:
        self._check(url, None)
        with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
            return client.get(url)

    def post(
        self, url: str, *, body: bytes, headers: dict[str, str] | None = None
    ) -> httpx.Response:
        self._check(url, body)
        with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
            return client.post(url, content=body, headers=headers or {})
