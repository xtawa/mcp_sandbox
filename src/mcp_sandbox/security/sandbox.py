"""bubblewrap (bwrap) based process sandbox.

This is the ONLY module allowed to spawn untrusted processes. It builds a
bwrap argv that:
  - unshares every namespace (PID, mount, net, ipc, uts, user)
  - binds a minimal curated set of host paths (binaries, libraries, TLS trust
    store) read-only
  - mounts the workspace as a writable tmpfs (so writes never reach the host)
  - drops all Linux capabilities
  - re-maps the caller to an unprivileged UID/GID
  - relies on container-level seccomp (see policies/seccomp-profile.json)
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

# UTF-8 byte-classification masks used by _truncate to walk back to a leading
# byte boundary. Continuation bytes are 0b10xxxxxx; the top two bits of a
# leading byte are anything other than 0b10.
_UTF8_CONT_MASK = 0xC0
_UTF8_CONT_TAG = 0x80

# Minimal curated set of host paths bound read-only into the jail. We never
# bind "/" wholesale: that would expose /etc/shadow, /data catalog DBs, source
# code under /workspace/src, audit logs, and other secrets to untrusted code.
# Each source is checked for existence at argv build time so absent paths
# (e.g. /lib64 on merged-usr systems) are silently skipped.
_READONLY_BINDS: tuple[tuple[str, str], ...] = (
    ("/usr", "/usr"),
    ("/bin", "/bin"),
    ("/lib", "/lib"),
    ("/lib64", "/lib64"),
    ("/etc/ssl/certs", "/etc/ssl/certs"),
    ("/etc/passwd", "/etc/passwd"),  # minimal passwd for name resolution
    ("/etc/nsswitch.conf", "/etc/nsswitch.conf"),
    ("/etc/resolv.conf", "/etc/resolv.conf"),
)


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str


def _truncate(s: str, limit: int) -> str:
    """Truncate ``s`` to at most ``limit`` UTF-8 bytes, appending a marker if cut.

    Counts bytes (not characters) so the ``max_output_bytes`` budget is
    honoured exactly for multi-byte output (CJK, emoji). The cut position is
    walked back to the last UTF-8 leading byte at or before ``limit`` so the
    returned string never contains a partial multi-byte sequence (which would
    otherwise be replaced by ``U+FFFD`` and could exceed the byte budget).
    """
    encoded = s.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return s
    cut = limit
    # Walk back over UTF-8 continuation bytes (0b10xxxxxx) to a leading byte.
    while cut > 0 and (encoded[cut] & _UTF8_CONT_MASK) == _UTF8_CONT_TAG:
        cut -= 1
    marker = f"\n[truncated: output exceeded {limit} bytes]\n"
    return encoded[:cut].decode("utf-8", errors="replace") + marker


class SandboxRunner:
    def __init__(  # noqa: PLR0913 - stable public API; params cannot be collapsed
        self,
        *,
        bwrap_bin: str,
        workspace_root: Path,
        run_as_uid: int,
        run_as_gid: int,
        seccomp_profile: Path | None,
        max_output_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        """Configure the sandbox runner.

        Note on seccomp: the sandbox runner does NOT apply its own seccomp
        filter at v1. ``bwrap --seccomp`` expects a file descriptor to a
        compiled BPF filter, not a path to a JSON profile, and BPF compilation
        inside the runner would add a pyseccomp dependency that is out of scope.
        Seccomp enforcement therefore happens at the container level (see
        ``policies/seccomp-profile.json`` and the Dockerfile). The
        ``seccomp_profile`` parameter is reserved for future use when
        pyseccomp is available and is otherwise ignored.
        """
        self._bwrap = bwrap_bin
        self._workspace = workspace_root.resolve(strict=False)
        self._uid = run_as_uid
        self._gid = run_as_gid
        self._seccomp = seccomp_profile
        self._max_output_bytes = max_output_bytes

    def _build_argv(self, command: list[str], timeout: int) -> list[str]:
        argv: list[str] = [
            self._bwrap,
            "--unshare-all",  # all namespaces (net, pid, ipc, uts, mount, user)
            "--die-with-parent",
            "--new-session",
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
        # Selective read-only binds of a minimal curated set of host paths.
        # Sources that do not exist on the host are skipped.
        for src, dst in _READONLY_BINDS:
            if Path(src).exists():
                argv += ["--ro-bind", src, dst]
        argv += command
        return argv

    def run(self, command: list[str], *, timeout: int) -> SandboxResult:
        if not command:
            raise ValueError("empty command")
        for arg in command:
            if _SHELL_METACHARS.search(arg):
                raise ValueError("command argument contains shell metacharacters")
        argv = self._build_argv(command, timeout)
        try:
            proc = subprocess.run(  # noqa: S603 - this module's purpose is to run untrusted
                # input; args are validated for shell metachars and exec'd via bwrap
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            # Honour the run() contract: always return a SandboxResult rather
            # than letting TimeoutExpired propagate to the caller.
            partial_stdout = exc.stdout or ""
            partial_stderr = exc.stderr or ""
            if isinstance(partial_stdout, bytes):
                partial_stdout = partial_stdout.decode("utf-8", errors="replace")
            if isinstance(partial_stderr, bytes):
                partial_stderr = partial_stderr.decode("utf-8", errors="replace")
            return SandboxResult(
                returncode=-1,
                stdout=_truncate(partial_stdout, self._max_output_bytes),
                stderr=_truncate(
                    f"sandbox: command timed out after {timeout}s\n" + partial_stderr,
                    self._max_output_bytes,
                ),
            )
        except FileNotFoundError:
            # bwrap not installed (e.g. dev environments without bubblewrap).
            return SandboxResult(
                returncode=127,
                stdout="",
                stderr=f"sandbox: bwrap binary not found at {self._bwrap}\n",
            )
        return SandboxResult(
            returncode=proc.returncode,
            stdout=_truncate(proc.stdout, self._max_output_bytes),
            stderr=_truncate(proc.stderr, self._max_output_bytes),
        )
