"""Path resolution that confines every user-supplied path under a base dir.

This is the ONLY module allowed to translate a tool argument into a real
filesystem path. It defeats traversal (..), absolute paths, null bytes, and
symlinks that escape the workspace root. Based on OWASP File Upload /
path traversal guidance.
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
    # Join then resolve; do NOT follow symlinks yet so we can detect escapes.
    candidate = (root_resolved / Path(user_path)).resolve(strict=False)

    # Check containment using the resolved real path of the parent (symlink check).
    # If the target exists, .resolve() follows symlinks; if it escapes, reject.
    try:
        real = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SafePathError(f"cannot resolve path: {exc}") from exc

    if real != root_resolved and root_resolved not in real.parents:
        raise SafePathError(f"path escapes workspace root: {user_path!r}")
    return real
