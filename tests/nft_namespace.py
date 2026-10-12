"""Opt-in real nft checks, guarded by a fresh Linux network namespace."""

import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from portfw.host import HostEngine, NFT, SYSTEMCTL, table_fingerprint
from portfw.policy import Settings
from tests.fakes import rule


def main():
    if sys.platform != "linux":
        raise SystemExit("This optional test requires Linux and unshare.")
    if len(sys.argv) == 1:
        parent_namespace = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            child = subprocess.run(["/usr/bin/unshare", "-Urn", sys.executable, str(Path(__file__).resolve()), "--inside", str(parent_namespace)],
                                   pass_fds=(parent_namespace,))
        finally:
            os.close(parent_namespace)
        raise SystemExit(child.returncode)
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--inside":
            raise ValueError("invalid namespace arguments")
        parent_namespace = int(sys.argv[2])
        if not os.readlink(f"/proc/self/fd/{parent_namespace}").startswith("net:["):
            raise ValueError("an inherited network namespace descriptor is required")
        isolated = os.stat("/proc/self/ns/net").st_ino != os.fstat(parent_namespace).st_ino
    except (OSError, ValueError):
        isolated = False
    if not isolated:
        raise SystemExit("Refusing to run: a fresh network namespace is required.")
    os.close(parent_namespace)
    # Also refuse to use a pre-existing namespace containing any table.
    def nft(args, payload=None):
        return subprocess.run(args, input=payload, text=True, capture_output=True, check=False, timeout=10)
    current = nft([NFT, "-j", "list", "tables"])
    if current.returncode or any("table" in item for item in json.loads(current.stdout)["nftables"]):
        raise SystemExit("Refusing to run: namespace must have an empty nft ruleset and allow nft access.")
    def runner(args, payload=None):
        if args[0] == NFT:
            return nft(args, payload)
        if args[0] == SYSTEMCTL:
            return SimpleNamespace(returncode=0, stdout="mock timer", stderr="")
        raise AssertionError(f"Unexpected command: {args}")
    sentinel = "table inet test_sentinel {\n  chain guard {\n    type filter hook input priority filter; policy accept;\n  }\n}\n"
    sentinel_result = nft([NFT, "-f", "-"], sentinel)
    assert sentinel_result.returncode == 0, sentinel_result.stderr
    sentinel_before = table_fingerprint(json.loads(nft([NFT, "-j", "list", "table", "inet", "test_sentinel"]).stdout))
    with tempfile.TemporaryDirectory(prefix="portfw-nft-namespace-") as directory:
        settings = Settings()
        engine = HostEngine(Path(directory), settings, runner, boot_id="isolated-test")
        # This check covers the actual nft parser/kernel only, not interface readiness or real traffic.
        engine.require_ready = lambda: None
        def payload(rules):
            return {"version": 2, "settings": settings.to_dict(), "rules": rules, "operationId": str(uuid.uuid4())}
        first = payload([rule()])
        engine.apply(first)
        engine.confirm({"operationId": first["operationId"]})
        baseline = engine.inspect()["fingerprint"]
        second = payload([rule("web", 8080, dest_port=80), rule("udp", 19132, proto="udp", dest_port=19132)])
        engine.apply(second)
        engine.dry_run(first)
        assert engine.status()["activeRules"] == second["rules"]
        engine.rollback()
        assert engine.inspect()["fingerprint"] == baseline
        # A failed batch must not execute its preceding delete command.
        bad = nft([NFT, "-f", "-"], "delete table ip pve_portfw\nthis is invalid nft syntax\n")
        assert bad.returncode != 0
        assert engine.inspect()["fingerprint"] == baseline
        assert nft([NFT, "delete", "table", "ip", "pve_portfw"]).returncode == 0
        engine.recover()
        assert engine.inspect()["fingerprint"] == baseline
        sentinel_after = table_fingerprint(json.loads(nft([NFT, "-j", "list", "table", "inet", "test_sentinel"]).stdout))
        assert sentinel_after == sentinel_before
    print(json.dumps({"namespace": os.readlink("/proc/self/ns/net"), "nftVersion": nft([NFT, "--version"]).stdout.strip(),
                      "passed": ["actual generated nft syntax", "atomic replacement", "dry-run snapshot isolation", "confirm / rollback fingerprint",
                                 "failed batch preserves table", "confirmed table recovery", "unrelated table unchanged"],
                      "notTested": ["real systemd timers", "PVE firewall interaction", "Internet traffic", "real host reboot"]}, indent=2))


if __name__ == "__main__":
    main()
