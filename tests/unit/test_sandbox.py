import subprocess
from pathlib import Path

import pytest

from mcp_sandbox.security.sandbox import SandboxResult, SandboxRunner, _truncate


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


def test_build_argv_uses_selective_binds_not_full_root(tmp_path):
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=10001,
        run_as_gid=10001,
        seccomp_profile=None,
    )
    argv = runner._build_argv(["/bin/ls"], timeout=10)
    # The full host root must never be bound.
    for i in range(len(argv) - 2):
        assert argv[i : i + 3] != ["--ro-bind", "/", "/"]
    # A selective bind of /usr is present (assuming /usr exists on the host).
    if Path("/usr").exists():
        for i in range(len(argv) - 2):
            if argv[i : i + 3] == ["--ro-bind", "/usr", "/usr"]:
                break
        else:
            pytest.fail("--ro-bind /usr /usr not found in argv")
    # Sensitive host directories must not be exposed anywhere in argv.
    assert not any("/data" in a for a in argv)
    assert not any("/workspace/src" in a for a in argv)


def test_build_argv_omits_seccomp_flag_at_v1(tmp_path):
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=10001,
        run_as_gid=10001,
        seccomp_profile=tmp_path / "seccomp.json",
    )
    argv = runner._build_argv(["/bin/ls"], timeout=10)
    assert "--seccomp" not in argv


def test_run_returns_timeout_result_on_timeout_expired(tmp_path, monkeypatch):
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=1000,
        run_as_gid=1000,
        seccomp_profile=None,
    )

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["bwrap"], timeout=1)

    monkeypatch.setattr(subprocess, "run", _raise_timeout)
    result = runner.run(["/bin/ls"], timeout=1)
    assert result.returncode == -1
    assert "timed out" in result.stderr


def test_run_returns_127_when_bwrap_missing(tmp_path, monkeypatch):
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=1000,
        run_as_gid=1000,
        seccomp_profile=None,
    )

    def _raise_missing(*args, **kwargs):
        raise FileNotFoundError(2, "No such file", "bwrap")

    monkeypatch.setattr(subprocess, "run", _raise_missing)
    result = runner.run(["/bin/ls"], timeout=5)
    assert result.returncode == 127  # noqa: PLR2004 - conventional "command not found" exit code
    assert "bwrap binary not found" in result.stderr


def test_truncate_helper_limits_output():
    marker = "\n[truncated: output exceeded 10 bytes]\n"
    truncated = _truncate("a" * 100, 10)
    assert len(truncated) <= 10 + len(marker)
    assert "truncated" in truncated
    # Short input passes through unchanged.
    assert _truncate("short", 10) == "short"


def test_run_truncates_large_stdout(tmp_path, monkeypatch):
    runner = SandboxRunner(
        bwrap_bin="bwrap",
        workspace_root=tmp_path,
        run_as_uid=1000,
        run_as_gid=1000,
        seccomp_profile=None,
        max_output_bytes=4096,
    )

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0] if args else None,
            returncode=0,
            stdout="x" * 1_000_000,
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = runner.run(["/bin/ls"], timeout=5)
    marker = "\n[truncated: output exceeded 4096 bytes]\n"
    assert len(result.stdout) <= 4096 + len(marker)
    assert "truncated" in result.stdout
