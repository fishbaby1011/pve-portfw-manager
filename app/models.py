from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


PUBLIC_IP = _env("PVE_PORTFW_PUBLIC_IP", "203.0.113.10")
EXTERNAL_INTERFACE = _env("PVE_PORTFW_EXTERNAL_INTERFACE", "vmbr0")
INTERNAL_INTERFACE = _env("PVE_PORTFW_INTERNAL_INTERFACE", "vmbr20")
INTERNAL_SUBNET = _env("PVE_PORTFW_INTERNAL_SUBNET", "10.10.10.0/24")
INTERNAL_GATEWAY = _env("PVE_PORTFW_INTERNAL_GATEWAY", "10.10.10.1")
NFT_TABLE_FAMILY = "ip"
NFT_TABLE_NAME = "pve_portfw"
PROTECTED_PORTS_TEXT = _env("PVE_PORTFW_PROTECTED_PORTS", "22, 8006, 3128, 5900-5999")
ROLLBACK_SECONDS = 120
PANEL_LISTEN = _env("PVE_PORTFW_PANEL_LISTEN", "127.0.0.1:8088")
HOST_HELPER_COMMAND = _env("PVE_PORTFW_HOST_HELPER_COMMAND", "/usr/local/sbin/pve-portfw-host-helper")


class Paths(BaseModel):
    data_dir: Path = Path("/etc/pve-portfw")
    rules_json: Path = Path("/etc/pve-portfw/rules.json")
    generated_nft: Path = Path("/etc/pve-portfw/generated.nft")
    backups_dir: Path = Path("/etc/pve-portfw/backups")
    apply_state_json: Path = Path("/etc/pve-portfw/apply-state.json")
    audit_log: Path = Path("/etc/pve-portfw/audit.log")
    last_confirmed_rules_json: Path = Path("/etc/pve-portfw/last-confirmed.rules.json")
    last_confirmed_nft: Path = Path("/etc/pve-portfw/last-confirmed.nft")


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(max_length=80)
    name: str = Field(max_length=120)
    enabled: bool = True
    proto: Literal["tcp", "udp"]
    external_port: int = Field(..., ge=1, le=65535)
    dest_ip: str
    dest_port: int = Field(..., ge=1, le=65535)
    note: str = Field(default="", max_length=1000)


class ConfigResponse(BaseModel):
    previewMode: bool = False
    publicIp: str
    externalInterface: str
    internalInterface: str
    internalSubnet: str
    gateway: str
    protectedPorts: str
    webListen: str = PANEL_LISTEN
    architecture: str = "CT panel -> restricted SSH -> PVE host helper"
    hostHelperCommand: str = HOST_HELPER_COMMAND


class HelperConfig(BaseModel):
    ssh_target: str = f"pve-portfw-helper@{INTERNAL_GATEWAY}"
    ssh_key: str = "/etc/pve-portfw/ssh/host-helper"
    ssh_known_hosts: str = "/etc/pve-portfw/ssh/known_hosts"
    ssh_port: int = Field(default=22, ge=1, le=65535)
    connect_timeout: int = Field(default=8, ge=1, le=30)
    helper_command: str = HOST_HELPER_COMMAND


class SafetyCheck(BaseModel):
    label: str
    ok: bool


class ApplyState(BaseModel):
    host_generation: int = -1
    operation_id: str | None = None
    phase: str = "never_applied"
    last_applied_at: datetime | None = None
    last_error: str | None = None
    rollback_armed_until: datetime | None = None
    rollback_unit: str = "pve-portfw-watchdog.timer"
    last_apply_result: str = "Never applied"
    last_apply_log: list[str] = Field(default_factory=list)
    last_confirmed_at: datetime | None = None
    pending_rules: list[Rule] | None = None
    pending_generated_nft: str | None = None


class CommandResult(BaseModel):
    label: str
    status: Literal["ok", "warn", "error", "unknown"]
    command: list[str] | None = None
    stdout: str = ""
    stderr: str = ""
    detail: str = ""
    cause: str = ""
    suggestion: str = ""
    scope: str = "host"


class BackupInfo(BaseModel):
    id: str
    path: str
    size: int
    mtime: float


class ApplyResponse(BaseModel):
    ok: bool
    log: list[str]
    stdout: str = ""
    stderr: str = ""
    rollbackSeconds: int = ROLLBACK_SECONDS
