"""Mock kernel and restricted SSH transport. Never execute nft, SSH or systemd."""

import json
from types import SimpleNamespace

from app.host_client import HostResult
from portfw.host import HostEngine, NFT, SYSTEMCTL
from portfw.policy import Settings


def rule(rule_id="ubuntu-ssh", port=2222, **overrides):
    item = {"id": rule_id, "name": rule_id, "enabled": True, "proto": "tcp", "external_port": port,
            "dest_ip": "10.10.10.100", "dest_port": 22, "note": ""}
    item.update(overrides)
    return item


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeKernel:
    def __init__(self, settings=None):
        self.settings = settings or Settings()
        self.table = None
        self.other_tables = {"inet pve-firewall": "untouched", "ip ct_internet": "untouched"}
        self.calls = []
        self.fail_apply = 0
        self.fail_syntax = False
        self.watchdog_failure = False
        self.forwarding = "1"
        self.interfaces_up = True
        self.recovery_enabled = False
        self.watchdog_enabled = False
        self.handle = 1

    def run(self, args, payload=None):
        self.calls.append((args, payload))
        ok = lambda text="": SimpleNamespace(returncode=0, stdout=text, stderr="")
        fail = lambda text: SimpleNamespace(returncode=1, stdout="", stderr=text)
        if args[0] == NFT:
            if args[1:] == ["-j", "list", "tables"]:
                tables = [{"table": {"family": "inet", "name": "pve-firewall"}}]
                if self.table is not None:
                    tables += [{"table": {"family": "ip", "name": "pve_portfw"}}]
                return ok(json.dumps({"nftables": tables}))
            if args[1:] == ["-j", "list", "table", "ip", "pve_portfw"]:
                return ok(json.dumps({"nftables": [{"metainfo": {"version": "mock"}},
                    {"table": {"family": "ip", "name": "pve_portfw", "handle": self.handle}},
                    {"rule": {"family": "ip", "table": "pve_portfw", "chain": "mock", "handle": self.handle,
                              "expr": [{"mockGeneratedText": self.table}]}}]}))
            if args[1:] == ["list", "table", "ip", "pve_portfw"]:
                return ok(self.table)
            if args[1:] == ["-c", "-f", "-"]:
                return fail("syntax check failed") if self.fail_syntax else ok()
            if args[1:] == ["-f", "-"]:
                if self.fail_apply:
                    self.fail_apply -= 1
                    return fail("atomic apply failed")
                text = payload.removeprefix("delete table ip pve_portfw\n")
                self.table = text or None
                self.handle += 1
                return ok()
            raise AssertionError(f"Unexpected nft command: {args}")
        if args[0] == SYSTEMCTL:
            if args[1] == "stop":
                return ok()
            if args[1:3] == ["enable", "--now"]:
                if self.watchdog_failure:
                    return fail("watchdog unavailable")
                self.watchdog_enabled = True
                return ok()
            if args[1] == "is-enabled":
                return ok("enabled") if self.recovery_enabled else fail("disabled")
        if args[0].endswith("/ip"):
            address = self.settings.publicIp if args[-1] == self.settings.externalInterface else self.settings.gateway
            return ok(json.dumps([{"flags": ["UP"] if self.interfaces_up else [], "addr_info": [{"local": address}]}]))
        if args[0].endswith("/sysctl"):
            return ok(self.forwarding)
        raise AssertionError(f"Unexpected external command: {args}")


class FakeHostClient:
    def __init__(self, engine):
        self.engine = engine
        self.calls = []
        self.offline = False
        self.lose_apply_response = False

    def run(self, action, payload=None, timeout=30):
        self.calls.append((action, payload, timeout))
        if self.offline:
            return HostResult(255, stderr="SSH connection unavailable (mock)")
        try:
            handler = getattr(self.engine, action.replace("-", "_"))
            data = handler(json.loads(payload)) if payload else handler()
            if action == "apply" and self.lose_apply_response:
                return HostResult(124, stderr="SSH response lost after apply (mock)")
            return HostResult(0, json.dumps(data))
        except Exception as exc:
            return HostResult(1, json.dumps({"version": 2, "ok": False, "error": str(exc)}), str(exc))


def environment(tmp_path):
    clock = Clock()
    kernel = FakeKernel()
    root = tmp_path / "host"
    root.mkdir()
    engine = HostEngine(root, kernel.settings, kernel.run, clock, clock, "boot-one")
    return engine, kernel, clock, FakeHostClient(engine)
