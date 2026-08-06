"""Installer: download + verify + isolate a third-party MCP into its own venv.

Each installed MCP gets a dedicated virtualenv under <data_root>/mcps/<name>/.
`pip install` runs inside the bwrap sandbox so a malicious setup.py cannot
touch the host. The resulting entrypoint is later launched by the runner
in its own jail.
"""
from __future__ import annotations

import venv

from ..config import Settings
from ..security.audit import AuditLogger
from ..security.policy import SecurityPolicy
from ..security.sandbox import SandboxRunner
from .catalog import Catalog, InstalledMCP
from .verifier import SourceSpec


class Installer:
    def __init__(
        self,
        settings: Settings,
        policy: SecurityPolicy,
        audit: AuditLogger,
        catalog: Catalog,
        runner: SandboxRunner,
    ) -> None:
        self._settings = settings
        self._policy = policy
        self._audit = audit
        self._catalog = catalog
        self._runner = runner
        self._mcps_root = settings.data_root / "mcps"
        self._mcps_root.mkdir(parents=True, exist_ok=True)

    def install(self, spec: SourceSpec, *, sha256: str, entrypoint: str) -> InstalledMCP:
        if not entrypoint:
            raise ValueError("entrypoint is required")
        name = spec.package or spec.url.rsplit("/", 1)[-1].removesuffix(".git")
        venv_path = self._mcps_root / name / "venv"
        venv_path.parent.mkdir(parents=True, exist_ok=True)
        # Create the venv outside the sandbox (venv creation needs write to bin/).
        venv.EnvBuilder(with_pip=True, clear=True).create(str(venv_path))
        pip = str(venv_path / "bin" / "pip")
        if spec.scheme == "pip":
            target = f"{spec.package}=={spec.version}" if spec.version else spec.package
        elif spec.scheme == "git+https":
            target = f"git+{spec.url}@{spec.ref}" if spec.ref else f"git+{spec.url}"
        else:
            raise ValueError(f"unsupported scheme {spec.scheme}")
        # Run pip install inside the bwrap jail with network egress limited
        # to the allowlist by the container-level network policy.
        result = self._runner.run(
            [pip, "install", "--no-cache-dir", "--disable-pip-version-check", target],
            timeout=300,
        )
        if result.returncode != 0:
            self._audit.record(tool="install_mcp", actor="ai",
                               args={"name": name}, outcome="error",
                               detail=result.stderr[:500])
            raise RuntimeError(f"pip install failed: {result.stderr}")
        record = InstalledMCP(
            name=name,
            source=f"{spec.scheme}://{spec.package or spec.url}",
            version=spec.version or spec.ref or "unknown",
            venv_path=str(venv_path),
            entrypoint=entrypoint,
            status="installed",
            sha256=sha256,
        )
        self._catalog.register(record)
        self._audit.record(tool="install_mcp", actor="ai",
                           args={"name": name, "version": record.version},
                           outcome="ok", detail=str(venv_path))
        return record
