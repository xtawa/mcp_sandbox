import pytest

from mcp_sandbox.security.paths import SafePathError, resolve_safe_path


@pytest.mark.parametrize("evil", [
    "../../etc/passwd",
    "/etc/passwd",
    "//etc/passwd",
    "foo/../../../etc/shadow",
    "foo/./../../bar",
    "a/b/../../../../../../../../etc",
    "foo\0bar",
    "",
])
def test_traversal_rejected(tmp_path, evil):
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, evil)


def test_symlink_escape_rejected(tmp_path):
    outside = tmp_path.parent / "outside_secret"
    outside.write_text("secret")
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "link")


def test_normal_subpath_ok(tmp_path):
    p = resolve_safe_path(tmp_path, "sub/dir/file.txt")
    assert str(p).startswith(str(tmp_path.resolve()))


def test_url_encoded_separator_not_decoded(tmp_path):
    # Paths arrive as raw JSON strings from the MCP transport, never as URL
    # query parameters, so there is no URL-decoding layer to reverse. A
    # literal "%2f" is therefore a valid filename component, not a path
    # separator, and must NOT be treated as traversal. (Decoding it would
    # corrupt legitimate filenames containing '%' and would address a threat
    # vector that does not exist for this transport.)
    p = resolve_safe_path(tmp_path, "..%2f..%2fetc/passwd")
    assert str(p).startswith(str(tmp_path.resolve()))
    assert "%2f" in p.name or p.parent.name == "..%2f..%2fetc"
