from __future__ import annotations

import os
import subprocess
import re
from dataclasses import dataclass

from .models import HOST_HELPER_COMMAND, INTERNAL_GATEWAY, HelperConfig


ALLOWED_HELPER_ACTIONS = {
    "dry-run",
    "apply",
    "confirm",
    "rollback",
    "diagnostics",
    "status",
}


@dataclass
class HostResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def load_helper_config() -> HelperConfig:
    return HelperConfig(
        ssh_target=os.environ.get("PVE_PORTFW_HOST_SSH_TARGET", f"pve-portfw-helper@{INTERNAL_GATEWAY}"),
        ssh_key=os.environ.get("PVE_PORTFW_HOST_SSH_KEY", "/etc/pve-portfw/ssh/host-helper"),
        ssh_known_hosts=os.environ.get("PVE_PORTFW_HOST_KNOWN_HOSTS", "/etc/pve-portfw/ssh/known_hosts"),
        ssh_port=int(os.environ.get("PVE_PORTFW_HOST_SSH_PORT", "22")),
        connect_timeout=int(os.environ.get("PVE_PORTFW_HOST_CONNECT_TIMEOUT", "8")),
        helper_command=os.environ.get("PVE_PORTFW_HOST_HELPER_COMMAND", HOST_HELPER_COMMAND),
    )


class HostHelperClient:
    def __init__(self, config: HelperConfig | None = None):
        self.config = config or load_helper_config()
        if not re.fullmatch(r"[A-Za-z0-9_-]+@[A-Za-z0-9][A-Za-z0-9.:-]*", self.config.ssh_target):
            raise ValueError("SSH target must be user@hostname or user@IPv4, without options or shell characters")
        if self.config.helper_command != "/usr/local/sbin/pve-portfw-host-helper":
            raise ValueError("only the fixed restricted helper command is allowed")

    def run(self, action: str, payload: str | None = None, timeout: int = 30) -> HostResult:
        if action not in ALLOWED_HELPER_ACTIONS:
            raise ValueError(f"helper action not allowed: {action}")
        command = self._ssh_command(action)
        try:
            completed = subprocess.run(
                command,
                input=payload,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return HostResult(completed.returncode, completed.stdout, completed.stderr)
        except FileNotFoundError as exc:
            return HostResult(127, "", str(exc))
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            return HostResult(124, stdout, "Host helper timed out. Its result is unknown; refresh host status before retrying.")

    def _ssh_command(self, action: str) -> list[str]:
        return [
            "ssh",
            "-i",
            self.config.ssh_key,
            "-p",
            str(self.config.ssh_port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.config.ssh_known_hosts}",
            "-o",
            f"ConnectTimeout={self.config.connect_timeout}",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            "--",
            self.config.ssh_target,
            self.config.helper_command,
            action,
        ]
