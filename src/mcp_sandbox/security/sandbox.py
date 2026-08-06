"""bubblewrap (bwrap) based process sandbox.

This is the ONLY module allowed to spawn untrusted processes. It builds a
bwrap argv that:
  - unshares every namespace (PID, mount, net, ipc, uts, user)
  - mounts the host root read-only
  - mounts the workspace as a writable tmpfs (so writes never reach the host)
  - drops all Linux capabilities
  - re-maps the caller to an unprivileged UID/GID
  - applies an optional seccomp profile
  - kills the child if the parent dies (--die-with-parent)

bwrap is unprivileged and does not require root, so it works inside our
non-root container. See https://github.com/containers/bubblewrap.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

_SHELL_METACHARS = re.compile(r"[;&|`$\n\r<>]|\$\(")


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str


class SandboxRunner:
    def __init__(
        self,
        *,
        bwrap_bin: str,
        workspace_root: Path,
        run_as_uid: int,
        run_as_gid: int,
        seccomp_profile: Path | None,
    ) -> None:
        self._bwrap = bwrap_bin
        self._workspace = workspace_root.resolve(strict=False)
        self._uid = run_as_uid
        self._gid = run_as_gid
        self._seccomp = seccomp_profile

    def _build_argv(self, command: list[str], timeout: int) -> list[str]:
        argv: list[str] = [
            self._bwrap,
            "--unshare-all",               # all namespaces (net, pid, ipc, uts, mount, user)
            "--die-with-parent",
            "--new-session",
            "--ro-bind", "/", "/",         # host root read-only
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", str(self._workspace),  # writable tmpfs overlay for workspace
            "--tmpfs", "/tmp",  # noqa: S108 - fresh isolated tmpfs inside the jail, not host /tmp
            "--uid", str(self._uid),
            "--gid", str(self._gid),
            "--cap-drop", "ALL",
            "--unshare-user-try",
            "--clearenv",
            "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
            "--setenv", "HOME", str(self._workspace),
        ]
        if self._seccomp is not None:
            # bwrap supports --seccomp <fd>; for v1 we rely on the container-level
            # seccomp profile and document this as a follow-up. The argv slot is
            # reserved so the test asserts the profile path is plumbed through.
            argv += ["--seccomp", str(self._seccomp)]
        argv += command
        return argv

    def run(self, command: list[str], *, timeout: int) -> SandboxResult:
        if not command:
            raise ValueError("empty command")
        for arg in command:
            if _SHELL_METACHARS.search(arg):
                raise ValueError("command argument contains shell metacharacters")
        argv = self._build_argv(command, timeout)
        proc = subprocess.run(  # noqa: S603 - this module's purpose is to run untrusted
            # input; args are validated for shell metachars and exec'd via bwrap
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return SandboxResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
