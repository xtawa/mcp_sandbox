"""Source verifier: parse + allowlist + integrity check for third-party MCPs.

install_mcp never executes code from an unverified source. The verifier:
  1. Parses the source URI into a typed spec.
  2. Confirms the scheme is on the policy allowlist.
  3. Verifies the SHA-256 of the downloaded payload against a pinned digest.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..security.policy import SecurityPolicy


class VerificationError(Exception):
    pass


@dataclass(frozen=True)
class SourceSpec:
    scheme: str
    package: str = ""
    version: str = ""
    url: str = ""
    ref: str = ""


class SourceVerifier:
    def __init__(self, policy: SecurityPolicy) -> None:
        self._policy = policy

    def parse(self, source: str) -> SourceSpec:
        decision = self._policy.check_mcp_source(source)
        if not decision:
            raise VerificationError(decision.reason)
        if source.startswith("pip://"):
            rest = source[len("pip://") :]
            if "@" in rest:
                pkg, version = rest.rsplit("@", 1)
            else:
                pkg, version = rest, ""
            return SourceSpec(scheme="pip", package=pkg, version=version)
        if source.startswith("git+https://"):
            rest = source[len("git+https://") :]
            url = "https://" + rest
            ref = ""
            if "@" in rest:
                url_part, ref = url.rsplit("@", 1)
                url = url_part
            return SourceSpec(scheme="git+https", url=url, ref=ref)
        raise VerificationError(f"unsupported source {source!r}")

    def verify_hash(self, payload: bytes, expected_sha256: str) -> None:
        actual = hashlib.sha256(payload).hexdigest()
        if actual.lower() != expected_sha256.lower():
            raise VerificationError(
                f"hash mismatch: expected {expected_sha256}, got {actual}"
            )
