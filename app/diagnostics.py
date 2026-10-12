from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Sequence

from .host_client import HostHelperClient
from .models import CommandResult, Rule


def run_diagnostics(rules: Sequence[Rule], host_client: HostHelperClient | None = None) -> list[CommandResult]:
    host = host_client or HostHelperClient()
    result = host.run("diagnostics", timeout=30)
    results = []
    try:
        if result.returncode:
            raise ValueError(result.stderr or "Restricted SSH helper failed")
        payload = json.loads(result.stdout)
        if not isinstance(payload, list):
            raise ValueError("Host diagnostics must return a checks array")
        results = [CommandResult.model_validate(item) for item in payload]
    except ValueError as exc:
        results.append(CommandResult(label="Host helper connection", status="error", detail="Host checks could not be completed.",
                                     stderr=str(exc), cause="SSH, helper version or host permissions may be incorrect.",
                                     suggestion="Run the read-only preflight and follow the SSH troubleshooting guide."))
    enabled = [rule for rule in rules if rule.enabled]
    with ThreadPoolExecutor(max_workers=8) as executor:
        results += list(executor.map(check_destination, enabled))
    results.append(CommandResult(label="Internet → VM/CT", status="unknown", scope="external",
                                 detail="External reachability has not been tested.",
                                 cause="CT target checks and nft syntax checks do not test the ISP, upstream firewall or guest firewall.",
                                 suggestion="Test the public IP and external port from a separate Internet connection. Existing conntrack sessions may retain old NAT mappings."))
    return results


def check_destination(rule: Rule) -> CommandResult:
    target = f"{rule.dest_ip}:{rule.dest_port}"
    if rule.proto == "udp":
        return CommandResult(label=f"{rule.name} / UDP", status="unknown", scope="ct-to-target",
                             detail=f"UDP service at {target} has not been tested.",
                             suggestion="Use a protocol-specific client from an external connection. A UDP socket alone cannot prove delivery.")
    try:
        with socket.create_connection((rule.dest_ip, rule.dest_port), timeout=2):
            return CommandResult(label=f"{rule.name} / TCP", status="ok", scope="ct-to-target",
                                 detail=f"The CT established a TCP connection to {target}.",
                                 suggestion="Check external reachability separately. This result only covers the CT-to-target path.")
    except OSError as exc:
        return CommandResult(label=f"{rule.name} / TCP", status="warn", scope="ct-to-target",
                             detail=f"The CT could not connect to {target}.", stderr=str(exc),
                             cause="The service may not be listening, the target IP may have changed, or a firewall may block this path.",
                             suggestion="Check the guest IP, listening service and guest/PVE forwarding firewall. Do not restart host networking as a first step.")
