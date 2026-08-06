"""Path resolution that confines every user-supplied path under a base dir.

This is the ONLY module allowed to translate a tool argument into a real
filesystem path. It defeats traversal (..), absolute paths, null bytes, and
symlinks that escape the workspace root. Based on OWASP File Upload /
path traversal guidance.

TOCTOU limitation:
    This resolver validates the path at resolution time. If an attacker can
    create or modify filesystem entries (e.g., symlinks) between resolution
    and the caller's open()/read()/write(), the path could escape the root.
    Callers MUST mitigate this by:
    - Opening files with O_NOFOLLOW on the final component, OR
    - Operating via file descriptors (open first, then fstat/read/write), OR
    - Using openat() with O_NOFOLLOW per path component.
    The resolver provides path validation; callers provide race-free access.
"""
from __future__ import annotations

from pathlib import Path


class SafePathError(ValueError):
    """Raised when a user-supplied path would escape its allowed root."""


def resolve_safe_path(root: Path, user_path: str) -> Path:
    """Return an absolute, resolved path guaranteed to live under ``root``.

    Raises SafePathError if the path escapes ``root`` via traversal, absolute
    path, symlink, or contains a null byte.
    """
    if "\x00" in user_path:
        raise SafePathError("null byte in path")
    if not user_path:
        raise SafePathError("empty path")

    root_resolved = root.resolve(strict=False)
    # Resolve the joined path, following symlinks to their real targets.
    # If a symlink points outside root, the resolved path will fail the
    # containment check below.
    try:
        real = (root_resolved / Path(user_path)).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SafePathError(f"cannot resolve path: {exc}") from exc

    # Containment check: the resolved path must be root itself or a descendant.
    if real != root_resolved and root_resolved not in real.parents:
        raise SafePathError(f"path escapes workspace root: {user_path!r}")
    return real
