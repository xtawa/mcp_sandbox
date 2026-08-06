"""Assembly: wire every tool into a single MCP application.

build_app() loads Settings + the default policy and returns an object whose
.list_tools() and .call_tool() methods the transport layer (Task 19) binds
to the MCP SDK. Keeping assembly here means the transport is trivially
swappable and the tool surface is testable without a network.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .config import Settings, load_settings
from .mcp_registry.catalog import Catalog
from .mcp_registry.installer import Installer
from .mcp_registry.runner import McpRunner
from .mcp_registry.verifier import SourceVerifier
from .security.audit import AuditLogger
from .security.network import EgressClient
from .security.policy import SecurityPolicy
from .security.sandbox import SandboxRunner
from .tools.file_export import FileExportTool
from .tools.file_read import FileReadTools
from .tools.file_transfer import FileTransferTool
from .tools.file_write import FileWriteTools
from .tools.meta import MetaTools
from .tools.shell import ExecTool


@dataclass
class ToolEntry:
    name: str
    description: str
    handler: Callable[[dict], Any]
    input_schema: dict


class SandboxApp:
    def __init__(self, tools: list[ToolEntry]) -> None:
        self._tools = {t.name: t for t in tools}

    def list_tools(self) -> list[ToolEntry]:
        return list(self._tools.values())

    def call_tool(self, name: str, args: dict) -> Any:
        if name not in self._tools:
            raise KeyError(name)
        return self._tools[name].handler(args)


def build_app_with_policy(policy: SecurityPolicy, settings: Settings | None = None) -> SandboxApp:
    settings = settings or load_settings()
    audit = AuditLogger(settings.audit_log_path)
    catalog = Catalog(settings.catalog_db_path)
    sandbox = SandboxRunner(
        bwrap_bin=settings.bwrap_bin,
        workspace_root=settings.workspace_root,
        run_as_uid=settings.run_as_uid,
        run_as_gid=settings.run_as_gid,
        seccomp_profile=settings.seccomp_profile_path
        if settings.seccomp_profile_path.exists() else None,
    )
    egress = EgressClient(policy, timeout=settings.exec_timeout_seconds)
    verifier = SourceVerifier(policy)
    installer = Installer(settings, policy, audit, catalog, sandbox)
    runner = McpRunner(settings, policy, audit, catalog, sandbox)

    fr = FileReadTools(settings, policy, audit)
    fw = FileWriteTools(settings, policy, audit)
    ft = FileTransferTool(settings, policy, audit)
    fe = FileExportTool(settings, policy, audit, egress)
    ex = ExecTool(settings, policy, audit, sandbox)
    meta = MetaTools({n for n, on in policy._tools.items() if on})

    tools: list[ToolEntry] = []
    if policy.is_tool_enabled("read_file"):
        tools.append(ToolEntry("read_file", "Read a file from the workspace.",
                               lambda a: fr.read_file(a["path"]),
                               {"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}))
    if policy.is_tool_enabled("write_file"):
        tools.append(ToolEntry("write_file", "Write content to a workspace file.",
                               lambda a: fw.write_file(a["path"], a["content"]),
                               {"type": "object",
                                "properties": {"path": {"type": "string"},
                                               "content": {"type": "string"}},
                                "required": ["path", "content"]}))
    if policy.is_tool_enabled("list_directory"):
        tools.append(ToolEntry("list_directory", "List directory entries.",
                               lambda a: fr.list_directory(a["path"]),
                               {"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}))
    if policy.is_tool_enabled("stat_file"):
        tools.append(ToolEntry("stat_file", "Stat a file.", lambda a: fr.stat_file(a["path"]),
                               {"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}))
    if policy.is_tool_enabled("delete_file"):
        tools.append(ToolEntry("delete_file", "Delete a file or directory.",
                               lambda a: fw.delete_file(a["path"]),
                               {"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}))
    if policy.is_tool_enabled("make_directory"):
        tools.append(ToolEntry("make_directory", "Create a directory.",
                               lambda a: fw.make_directory(a["path"]),
                               {"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}))
    if policy.is_tool_enabled("transfer_file"):
        tools.append(ToolEntry("transfer_file",
                               "Copy a file between workspace and host transfer volume.",
                               lambda a: ft.transfer_file(a["name"], a["direction"], a.get("dest")),
                               {"type": "object",
                                "properties": {"name": {"type": "string"},
                                               "direction": {"enum": ["in", "out"]},
                                               "dest": {"type": "string"}},
                                "required": ["name", "direction"]}))
    if policy.is_tool_enabled("export_file"):
        tools.append(ToolEntry("export_file",
                               "Upload a workspace file to an allowlisted HTTP endpoint.",
                               lambda a: fe.export_file(a["path"], a["url"]),
                               {"type": "object",
                                "properties": {"path": {"type": "string"},
                                               "url": {"type": "string"}},
                                "required": ["path", "url"]}))
    if policy.is_tool_enabled("exec_command"):
        tools.append(ToolEntry("exec_command",
                               "Run an allowlisted binary in the sandbox.",
                               lambda a: ex.exec_command(a["binary"], a.get("args", [])),
                               {"type": "object",
                                "properties": {
                                    "binary": {"type": "string"},
                                    "args": {"type": "array",
                                             "items": {"type": "string"}}},
                                "required": ["binary"]}))

    def install_mcp(a: dict) -> dict:
        spec = verifier.parse(a["source"])
        record = installer.install(spec, sha256=a["sha256"], entrypoint=a["entrypoint"])
        return {"name": record.name, "version": record.version, "status": record.status}

    def call_mcp_tool(a: dict) -> dict:
        return runner.call_tool(a["mcp"], a["tool"], a.get("args", {}))

    def uninstall_mcp(a: dict) -> dict:
        runner.uninstall(a["mcp"])
        return {"removed": a["mcp"]}

    tools.append(ToolEntry("install_mcp",
                           "Install a third-party MCP from an allowlisted source.",
                           install_mcp,
                           {"type": "object",
                            "properties": {"source": {"type": "string"},
                                           "sha256": {"type": "string"},
                                           "entrypoint": {"type": "string"}},
                            "required": ["source", "sha256", "entrypoint"]}))
    tools.append(ToolEntry("call_mcp_tool", "Invoke a tool on an installed MCP.",
                           call_mcp_tool,
                           {"type": "object",
                            "properties": {"mcp": {"type": "string"},
                                           "tool": {"type": "string"},
                                           "args": {"type": "object"}},
                            "required": ["mcp", "tool"]}))
    tools.append(ToolEntry("uninstall_mcp", "Remove an installed MCP.", uninstall_mcp,
                           {"type": "object", "properties": {"mcp": {"type": "string"}},
                            "required": ["mcp"]}))
    if policy.is_tool_enabled("list_tools"):
        tools.append(ToolEntry("list_tools", "List enabled tools.",
                               lambda a: [t.name for t in tools], {"type": "object"}))
    if policy.is_tool_enabled("sandbox_status"):
        tools.append(ToolEntry("sandbox_status", "Report sandbox status.",
                               lambda a: meta.sandbox_status(policy_version="1",
                                                             workspace=str(settings.workspace_root),
                                                             uid=settings.run_as_uid),
                               {"type": "object"}))

    return SandboxApp(tools)


def build_app() -> SandboxApp:
    settings = load_settings()
    policy = SecurityPolicy.load(settings.policies_dir / "default_policy.yaml")
    return build_app_with_policy(policy, settings)
