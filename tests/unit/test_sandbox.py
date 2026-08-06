import pytest

from mcp_sandbox.security.sandbox import SandboxResult, SandboxRunner


def test_build_argv_confines_to_workspace(tmp_path):
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=10001,
        run_as_gid=10001,
        seccomp_profile=None,
    )
    argv = runner._build_argv(["/bin/ls", "-la"], timeout=10)
    # Read-only root, tmpfs workspace, no network, drop caps, die-with-parent.
    assert "--unshare-all" in argv
    assert "--share-net" not in argv
    assert "--die-with-parent" in argv
    assert "--ro-bind" in argv
    assert "--tmpfs" in argv
    assert "--uid" in argv
    assert "--gid" in argv
    assert "--cap-drop" in argv or any(a == "--cap-drop" for a in argv)
    # The command tail must be the last elements.
    assert argv[-2:] == ["/bin/ls", "-la"]


def test_run_executes_echo_when_bwrap_available(tmp_path):
    # bwrap may not be available in the unit test env; skip if so.
    pytest.importorskip("shutil")
    import shutil
    if shutil.which("bwrap") is None:
        pytest.skip("bwrap not installed")
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=1000,
        run_as_gid=1000,
        seccomp_profile=None,
    )
    result = runner.run(["/bin/echo", "hello"], timeout=5)
    assert isinstance(result, SandboxResult)
    assert result.returncode == 0
    assert "hello" in result.stdout


def test_run_rejects_shell_metacharacters_in_args(tmp_path):
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=1000,
        run_as_gid=1000,
        seccomp_profile=None,
    )
    with pytest.raises(ValueError):
        runner.run(["/bin/ls", "; rm -rf /"], timeout=5)
