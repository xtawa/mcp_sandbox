from pathlib import Path

import pytest

from mcp_sandbox.security.paths import resolve_safe_path, SafePathError


def test_normal_path_inside_workspace(tmp_path):
    p = resolve_safe_path(tmp_path, "sub/file.txt")
    assert p == (tmp_path / "sub" / "file.txt").resolve()
    assert str(p).startswith(str(tmp_path.resolve()))


def test_traversal_rejected(tmp_path):
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "../../etc/passwd")


def test_absolute_path_outside_rejected(tmp_path):
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "/etc/passwd")


def test_symlink_escape_rejected(tmp_path):
    target = tmp_path.parent / "outside.txt"
    target.write_text("nope")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "link")


def test_null_byte_rejected(tmp_path):
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "foo\0bar")


def test_empty_path_rejected(tmp_path):
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "")


def test_dot_returns_root(tmp_path):
    p = resolve_safe_path(tmp_path, ".")
    assert p == tmp_path.resolve()


def test_traversal_staying_inside_ok(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "file.txt").write_text("ok")
    # sub/../file.txt should resolve to tmp_path/file.txt (inside root)
    p = resolve_safe_path(tmp_path, "sub/../file.txt")
    assert p == (tmp_path / "file.txt").resolve()


def test_broken_symlink_escape_rejected(tmp_path):
    link = tmp_path / "broken"
    link.symlink_to(tmp_path.parent / "nonexistent_outside")
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "broken")
