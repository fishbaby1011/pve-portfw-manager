from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass


MAX_RULES = 500
DEFAULT_PROTECTED = "22, 8006, 3128, 5900-5999"


def port_ranges(value: str) -> list[tuple[int, int]]:
    ranges = []
    for part in value.split(","):
        match = re.fullmatch(r"\s*(\d+)(?:\s*-\s*(\d+))?\s*", part)
        if not match:
            raise ValueError("invalid protected ports configuration")
        start, end = int(match[1]), int(match[2] or match[1])
        if not 1 <= start <= end <= 65535:
            raise ValueError("invalid protected ports range")
        ranges.append((start, end))
    return ranges


@dataclass(frozen=True)
class Settings:
    publicIp: str = "203.0.113.10"
    externalInterface: str = "vmbr0"
    internalInterface: str = "vmbr20"
    internalSubnet: str = "10.10.10.0/24"
    gateway: str = "10.10.10.1"
    protectedPorts: str = DEFAULT_PROTECTED

    def __post_init__(self):
        ipaddress.IPv4Address(self.publicIp)
        subnet = ipaddress.IPv4Network(self.internalSubnet)
        gateway = ipaddress.IPv4Address(self.gateway)
        if gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address):
            raise ValueError("gateway must be a usable address in the internal subnet")
        for interface in (self.externalInterface, self.internalInterface):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
                raise ValueError("invalid interface name")
        if self.externalInterface == self.internalInterface:
            raise ValueError("external and internal interfaces must differ")
        port_ranges(self.protectedPorts)

    def to_dict(self) -> dict:
        return asdict(self)


def validate_rules(raw: object, settings: Settings) -> list[dict]:
    if not isinstance(raw, list):
        raise ValueError('expected a rules array or {"rules": [...]}')
    if len(raw) > MAX_RULES:
        raise ValueError(f"at most {MAX_RULES} rules are allowed")
    subnet = ipaddress.IPv4Network(settings.internalSubnet)
    protected = port_ranges(settings.protectedPorts)
    ids, ports, rules = set(), set(), []
    for index, item in enumerate(raw):
        prefix = f"rule[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{prefix}: expected an object")
        rule = dict(item)
        if set(rule) - {"id", "name", "enabled", "proto", "external_port", "dest_ip", "dest_port", "note"}:
            raise ValueError(f"{prefix}: unknown fields")
        rule.setdefault("enabled", True)
        rule.setdefault("note", "")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", rule_id):
            raise ValueError(f"{prefix}: id must contain letters, numbers, dash or underscore (max 80)")
        prefix = rule_id
        for field, limit in (("name", 120), ("note", 1000)):
            if not isinstance(rule.get(field), str) or len(rule[field]) > limit:
                raise ValueError(f"{prefix}: invalid {field} (max {limit} characters)")
        if not rule["name"].strip():
            raise ValueError(f"{prefix}: name is required")
        if type(rule["enabled"]) is not bool:
            raise ValueError(f"{prefix}: enabled must be a boolean")
        if rule.get("proto") not in ("tcp", "udp"):
            raise ValueError(f"{prefix}: proto must be tcp or udp")
        for field in ("external_port", "dest_port"):
            if type(rule.get(field)) is not int or not 1 <= rule[field] <= 65535:
                raise ValueError(f"{prefix}: {field} must be an integer from 1 to 65535")
        if not isinstance(rule.get("dest_ip"), str):
            raise ValueError(f"{prefix}: dest_ip must be an IPv4 address string")
        try:
            ip = ipaddress.IPv4Address(rule.get("dest_ip", ""))
        except (ValueError, TypeError):
            raise ValueError(f"{prefix}: invalid destination IPv4 address") from None
        if ip not in subnet or ip in (subnet.network_address, subnet.broadcast_address) or str(ip) == settings.gateway:
            raise ValueError(f"{prefix}: dest_ip must be a VM/CT address inside {subnet}, not the host gateway")
        if any(start <= rule["external_port"] <= end for start, end in protected):
            raise ValueError(f"{prefix}: external_port {rule['external_port']} is protected")
        key = (rule["proto"], rule["external_port"])
        if rule_id in ids:
            raise ValueError(f"{prefix}: id must be unique")
        if key in ports:
            raise ValueError(f"{prefix}: proto + external_port duplicates another rule")
        ids.add(rule_id)
        ports.add(key)
        rules.append(rule)
    return rules


def revision(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def render_nft(rules: list[dict], settings: Settings) -> str:
    rules = validate_rules(rules, settings)
    enabled = [rule for rule in rules if rule["enabled"]]
    lines = ["table ip pve_portfw {", "  chain prerouting {", "    type nat hook prerouting priority dstnat; policy accept;"]
    for rule in enabled:
        lines.append(f'    iifname "{settings.externalInterface}" ip daddr {settings.publicIp} '
                     f'{rule["proto"]} dport {rule["external_port"]} dnat to {rule["dest_ip"]}:{rule["dest_port"]}')
    lines += ["  }", "  chain postrouting {", "    type nat hook postrouting priority srcnat; policy accept;",
              f'    oifname "{settings.externalInterface}" ip saddr {settings.internalSubnet} masquerade',
              "  }", "  chain forward {", "    type filter hook forward priority filter; policy accept;",
              "    ct state established,related accept"]
    for rule in enabled:
        lines.append(f'    iifname "{settings.externalInterface}" oifname "{settings.internalInterface}" '
                     f'ip daddr {rule["dest_ip"]} {rule["proto"]} dport {rule["dest_port"]} accept')
    lines += [f'    iifname "{settings.internalInterface}" oifname "{settings.externalInterface}" '
              f"ip saddr {settings.internalSubnet} accept", "  }", "}", ""]
    return "\n".join(lines)
