"""exec_command: run an allowlisted binary inside the bwrap sandbox.

The tool NEVER invokes a shell. The binary and its argument list are passed
verbatim to SandboxRunner, which wraps them in bwrap. Shell metacharacters
in arguments are rejected so an AI cannot smuggle shell syntax past the
allowlist.
"""
from __future__ import annotations

from ..config import Settings
from ..security.audit import AuditLogger
from ..security.policy import SecurityPolicy
from ..security.sandbox import SandboxRunner


class ExecTool:
    def __init__(
        self,
        settings: Settings,
        policy: SecurityPolicy,
        audit: AuditLogger,
        sandbox: SandboxRunner,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._sandbox = sandbox

    def exec_command(self, binary: str, args: list[str]) -> dict:
        if not binary:
            raise ValueError("binary is required")
        decision = self._policy.check_command(binary, args)
        if not decision:
            self._audit.record(tool="exec_command", actor="ai",
                               args={"binary": binary, "args": args},
                               outcome="denied", detail=decision.reason)
            raise PermissionError(decision.reason)
        result = self._sandbox.run(
            [binary, *args],
            timeout=self._policy.exec_timeout_seconds,
        )
        self._audit.record(tool="exec_command", actor="ai",
                           args={"binary": binary, "args": args},
                           outcome="ok" if result.returncode == 0 else "error",
                           detail=f"rc={result.returncode}")
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
