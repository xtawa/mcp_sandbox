"""Application configuration loaded from environment.

All security-relevant limits live here and are validated at startup so a
misconfiguration fails closed instead of silently weakening the sandbox.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent / "policies"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="forbid",
        case_sensitive=False,
    )

    workspace_root: Path = Field(
        default=Path("/workspace/_sandbox"),
        description="Writable workspace exposed to AI tools; paths are confined here.",
    )
    data_root: Path = Field(
        default=Path("/data"),
        description="Persistent data root (installed MCPs, catalog, audit log).",
    )
    transfer_dir: Path = Field(
        default=Path("/data/transfer"),
        description="Bidirectional transfer volume between sandbox and host.",
    )

    run_as_uid: int = Field(default=10001, ge=1)
    run_as_gid: int = Field(default=10001, ge=1)

    max_file_bytes: int = Field(default=10 * 1024 * 1024, ge=1)
    exec_timeout_seconds: int = Field(default=30, ge=1, le=600)
    max_concurrent_tools: int = Field(default=8, ge=1)

    policies_dir: Path = Field(default=_DEFAULT_POLICIES_DIR)
    command_allowlist_path: Path = Field(default=_DEFAULT_POLICIES_DIR / "command_allowlist.txt")
    egress_allowlist_path: Path = Field(default=_DEFAULT_POLICIES_DIR / "egress_allowlist.txt")
    seccomp_profile_path: Path = Field(default=_DEFAULT_POLICIES_DIR / "seccomp-profile.json")

    audit_log_path: Path = Field(default=Path("/data/audit/audit.jsonl"))
    catalog_db_path: Path = Field(default=Path("/data/mcps/catalog.db"))

    http_host: str = Field(default="127.0.0.1")
    http_port: int = Field(default=8765, ge=1, le=65535)

    allow_network_egress: bool = Field(default=True)
    bwrap_bin: str = Field(default="bwrap")

    @field_validator("workspace_root", "data_root", "transfer_dir")
    @classmethod
    def _ensure_dirs_exist(cls, v: Path) -> Path:
        v.mkdir(parents=True, exist_ok=True)
        return v

    @field_validator("audit_log_path")
    @classmethod
    def _ensure_audit_dir(cls, v: Path) -> Path:
        v.parent.mkdir(parents=True, exist_ok=True)
        return v

    @field_validator("catalog_db_path")
    @classmethod
    def _ensure_catalog_dir(cls, v: Path) -> Path:
        v.parent.mkdir(parents=True, exist_ok=True)
        return v


def load_settings() -> Settings:
    """Load settings from environment, creating required directories."""
    return Settings()
