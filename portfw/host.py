from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import signal
from pathlib import Path

from .policy import Settings, render_nft, revision, validate_rules


PROTOCOL = 2
NFT = "/usr/sbin/nft"
IP = "/usr/sbin/ip"
SYSTEMCTL = "/usr/bin/systemctl"
HELPER_DIR = Path("/etc/pve-portfw-host-helper")
MAX_PAYLOAD = 2 * 1024 * 1024


class HelperError(RuntimeError):
    pass


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".state-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        if os.name == "posix":
            dir_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_settings(path: Path) -> Settings:
    mapping = {"PVE_PORTFW_PUBLIC_IP": "publicIp", "PVE_PORTFW_EXTERNAL_INTERFACE": "externalInterface",
               "PVE_PORTFW_INTERNAL_INTERFACE": "internalInterface", "PVE_PORTFW_INTERNAL_SUBNET": "internalSubnet",
               "PVE_PORTFW_INTERNAL_GATEWAY": "gateway", "PVE_PORTFW_PROTECTED_PORTS": "protectedPorts"}
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        tokens = shlex.split(line, comments=True)
        if not tokens:
            continue
        if len(tokens) != 1 or "=" not in tokens[0]:
            raise ValueError("host config must contain KEY=value lines; shell code is not accepted")
        key, value = tokens[0].split("=", 1)
        if key not in mapping:
            raise ValueError(f"unknown host setting: {key}")
        values[mapping[key]] = value
    return Settings(**values)


def run_command(args: list[str], payload: str | None = None, timeout: int = 15):
    return subprocess.run(args, input=payload, text=True, capture_output=True, timeout=timeout, check=False,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})


def table_fingerprint(document: dict) -> str:
    # Kernel handles change on every load; metainfo describes the nft client, not the table.
    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if key not in ("handle", "index")}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    entries = [clean(item) for item in document["nftables"] if "metainfo" not in item]
    return revision(entries)


class HostEngine:
    def __init__(self, root: Path, settings: Settings, runner=run_command, clock=time.time,
                 monotonic=time.monotonic, boot_id: str | None = None):
        self.root, self.settings, self.run, self.clock, self.monotonic = root, settings, runner, clock, monotonic
        self.boot_id = boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.state_path = root / "state.json"

    def load(self) -> dict:
        if not self.state_path.exists():
            return {"version": PROTOCOL, "phase": "never_applied", "confirmed": None, "pending": None}
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        if state.get("version") != PROTOCOL:
            raise HelperError("unsupported host state version")
        return state

    def save(self, state: dict, event: str) -> None:
        state["generation"] = int(state.get("generation", 0)) + 1
        atomic_json(self.state_path, state)
        with (self.root / "audit.log").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"at": self.clock(), "event": event, "phase": state["phase"],
                                     "operationId": state.get("operationId"), "error": state.get("error")}) + "\n")

    def command(self, args: list[str], payload: str | None = None):
        try:
            return self.run(args, payload)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HelperError(f"command failed: {args[0]}: {exc}") from exc

    def inspect(self) -> dict:
        result = self.command([NFT, "-j", "list", "tables"])
        if result.returncode:
            raise HelperError(result.stderr or "cannot read nft tables")
        data = json.loads(result.stdout)
        exists = any(item.get("table", {}).get("family") == "ip" and item["table"].get("name") == "pve_portfw"
                     for item in data["nftables"])
        if not exists:
            return {"present": False, "fingerprint": None, "nft": ""}
        result = self.command([NFT, "-j", "list", "table", "ip", "pve_portfw"])
        if result.returncode:
            raise HelperError(result.stderr or "cannot inspect pve_portfw")
        fingerprint = table_fingerprint(json.loads(result.stdout))
        text = self.command([NFT, "list", "table", "ip", "pve_portfw"])
        if text.returncode:
            raise HelperError(text.stderr or "cannot back up pve_portfw")
        return {"present": True, "fingerprint": fingerprint, "nft": text.stdout}

    def remaining(self, pending: dict | None) -> int:
        if not pending or pending["bootId"] != self.boot_id:
            return 0
        return max(0, int(pending["monotonicDeadline"] - self.monotonic() + 0.999))

    def status(self) -> dict:
        state, table = self.load(), self.inspect()
        pending, confirmed = state.get("pending"), state.get("confirmed")
        expected = pending or confirmed
        verified = bool(expected and table["present"] and expected.get("fingerprint") == table["fingerprint"])
        recovery = self.command([SYSTEMCTL, "is-enabled", "pve-portfw-recover.service"])
        return {"version": PROTOCOL, "phase": state["phase"], "operationId": state.get("operationId"),
                "generation": state.get("generation", 0),
                "rollbackArmed": bool(pending), "remainingSeconds": self.remaining(pending),
                "rollbackDeadline": pending["deadline"] if pending else None,
                "tablePresent": table["present"], "tableVerified": verified,
                "activeRules": expected["rules"] if verified else None,
                "pendingRules": pending["rules"] if pending else None,
                "confirmedRules": confirmed["rules"] if confirmed else None,
                "confirmedNft": confirmed["nft"] if confirmed else None,
                "lastConfirmedAt": confirmed["confirmedAt"] if confirmed else None,
                "lastAppliedAt": state.get("lastAppliedAt"), "error": state.get("error"),
                "settings": self.settings.to_dict(), "recoveryEnabled": recovery.returncode == 0}

    def preflight(self) -> list[dict]:
        checks = []
        for interface, address, label in ((self.settings.externalInterface, self.settings.publicIp, "External interface"),
                                           (self.settings.internalInterface, self.settings.gateway, "Internal interface")):
            result = self.command([IP, "-j", "addr", "show", "dev", interface])
            try:
                devices = json.loads(result.stdout) if result.returncode == 0 else []
                good = any("UP" in device.get("flags", []) and any(info.get("local") == address for info in device.get("addr_info", []))
                           for device in devices)
            except (ValueError, TypeError):
                good = False
            checks.append({"label": label, "status": "ok" if good else "error", "command": [IP, "-j", "addr", "show", "dev", interface],
                           "detail": f"{interface} must be UP with {address}", "stdout": result.stdout[:4000], "stderr": result.stderr[:4000],
                           "cause": "The configured interface/address may not match the host." if not good else "",
                           "suggestion": "Compare the host bridge addresses with the panel and helper configuration. Do not change routing from this panel.", "scope": "host"})
        result = self.command(["/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward"])
        good = result.returncode == 0 and result.stdout.strip() == "1"
        checks.append({"label": "IPv4 forwarding", "status": "ok" if good else "error", "command": ["/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward"],
                       "detail": "Host IPv4 forwarding is enabled." if good else "Host IPv4 forwarding is disabled or unreadable.",
                       "stdout": result.stdout, "stderr": result.stderr, "cause": "Routing requires net.ipv4.ip_forward=1." if not good else "",
                       "suggestion": "Review your host sysctl configuration manually; no sysctl setting is changed by this tool.", "scope": "host"})
        return checks

    def require_ready(self):
        failed = [check["label"] for check in self.preflight() if check["status"] == "error"]
        if failed:
            raise HelperError("host preflight failed: " + ", ".join(failed))

    def payload_rules(self, payload: dict) -> list[dict]:
        if payload.get("version") != PROTOCOL or set(payload) - {"version", "rules", "settings", "operationId"}:
            raise HelperError("helper protocol v2 required; arbitrary nft or shell input is not accepted")
        if payload.get("settings") != self.settings.to_dict():
            raise HelperError("panel and host helper settings differ; update both configurations")
        return validate_rules(payload.get("rules"), self.settings)

    def batch(self, nft: str, table: dict) -> str:
        return ("delete table ip pve_portfw\n" if table["present"] else "") + nft

    def syntax_check(self, batch: str):
        result = self.command([NFT, "-c", "-f", "-"], batch)
        if result.returncode:
            raise HelperError(result.stderr or "nft syntax check failed")

    def replace_table(self, nft: str):
        table = self.inspect()
        if not nft and not table["present"]:
            return
        batch = self.batch(nft, table)
        self.syntax_check(batch)
        result = self.command([NFT, "-f", "-"], batch)
        if result.returncode:
            raise HelperError(result.stderr or "nft atomic transaction failed")

    def dry_run(self, payload: dict) -> dict:
        rules = self.payload_rules(payload)
        self.require_ready()
        self.syntax_check(self.batch(render_nft(rules, self.settings), self.inspect()))
        return {"version": PROTOCOL, "ok": True, "log": ["validate rules", "generate nft", "nft syntax check"],
                "message": "Syntax and host prerequisites passed; Internet reachability has not been tested."}

    def apply(self, payload: dict) -> dict:
        rules = self.payload_rules(payload)
        operation = payload.get("operationId", "")
        if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9-]{36}", operation):
            raise HelperError("valid operationId required")
        state = self.load()
        if state.get("operationId") == operation:
            if state["phase"] not in ("pending_confirmation", "confirmed"):
                raise HelperError("this operation has already finished; do not replay it")
            snapshot = state.get("pending") or state.get("confirmed")
            if snapshot["rules"] != rules:
                raise HelperError("operationId already belongs to a different rules snapshot")
            return self.status()
        if state.get("pending"):
            raise HelperError("an apply is already awaiting confirmation or rollback")
        self.require_ready()
        nft, table = render_nft(rules, self.settings), self.inspect()
        if state.get("confirmed") and table["present"] and state["confirmed"]["fingerprint"] != table["fingerprint"]:
            raise HelperError("the host table changed outside this tool; inspect it before applying")
        self.syntax_check(self.batch(nft, table))
        before = state.get("confirmed") or {"nft": table["nft"], "fingerprint": table["fingerprint"], "rules": None}
        atomic_json(self.root / "backups" / f"{operation}.json", {"before": before, "candidate": rules, "at": self.clock()})
        # Start the host-owned watchdog before recording any transaction that can modify nft.
        result = self.command([SYSTEMCTL, "enable", "--now", "pve-portfw-watchdog.timer"])
        if result.returncode:
            raise HelperError(result.stderr or "cannot arm the host rollback watchdog")
        state.update(operationId=operation, phase="applying", error=None, pending={
            "operationId": operation, "rules": rules, "nft": nft, "before": before, "fingerprint": None,
            "deadline": self.clock() + 120, "monotonicDeadline": self.monotonic() + 120, "bootId": self.boot_id})
        self.save(state, "rollback-armed")
        try:
            self.replace_table(nft)
            state["pending"]["fingerprint"] = self.inspect()["fingerprint"]
            if not state["pending"]["fingerprint"]:
                raise HelperError("applied table could not be verified")
            state.update(phase="pending_confirmation", lastAppliedAt=self.clock())
            self.save(state, "applied")
        except Exception as exc:
            state.update(phase="apply_failed", error=str(exc))
            self.save(state, "apply-failed")
            try:
                self.rollback()
            except Exception as rollback_exc:
                state.update(phase="recovery_failed", error=f"{exc}; rollback: {rollback_exc}")
                self.save(state, "rollback-failed")
            raise HelperError(f"apply failed: {exc}; inspect host status before retrying") from exc
        return self.status()

    def confirm(self, payload: dict) -> dict:
        state = self.load()
        pending = state.get("pending")
        if not pending:
            if state.get("confirmed") and payload.get("operationId") == state["confirmed"]["operationId"]:
                return self.status()
            raise HelperError("no pending apply to confirm")
        if payload.get("operationId") != pending["operationId"]:
            raise HelperError("confirmation does not match the pending operation")
        if not self.remaining(pending):
            raise HelperError("confirmation window expired; wait for host rollback")
        if not pending["fingerprint"] or self.inspect()["fingerprint"] != pending["fingerprint"]:
            raise HelperError("pending table does not match the running host table")
        confirmed = {key: pending[key] for key in ("operationId", "rules", "nft", "fingerprint")}
        confirmed["confirmedAt"] = self.clock()
        state.update(confirmed=confirmed, pending=None, phase="confirmed", error=None)
        self.save(state, "confirmed")
        self.command([SYSTEMCTL, "stop", "pve-portfw-watchdog.timer"])
        return self.status()

    def rollback(self, payload: dict | None = None) -> dict:
        state = self.load()
        if payload and payload.get("operationId") != state.get("operationId"):
            raise HelperError("rollback does not match the current operation")
        pending = state.get("pending")
        target = pending["before"] if pending else state.get("confirmed")
        if not target:
            raise HelperError("no host-owned rollback snapshot exists")
        try:
            self.replace_table(target["nft"])
            actual = self.inspect()
            if actual["fingerprint"] != target["fingerprint"]:
                raise HelperError("rollback table verification failed")
        except Exception as exc:
            state.update(phase="recovery_failed", error=str(exc))
            self.save(state, "rollback-failed")
            raise
        state.update(pending=None, phase="rolled_back", error=None)
        self.save(state, "rolled-back")
        self.command([SYSTEMCTL, "stop", "pve-portfw-watchdog.timer"])
        return self.status()

    def expire(self) -> dict:
        state = self.load()
        if state.get("pending") and not self.remaining(state["pending"]):
            return self.rollback()
        if not state.get("pending"):
            self.command([SYSTEMCTL, "stop", "pve-portfw-watchdog.timer"])
        return {"ok": True, "message": "No expired apply."}

    def recover(self) -> dict:
        state = self.load()
        if state.get("pending"):
            # A pending transaction must never be promoted to confirmed on a host reboot.
            return self.rollback() if state["pending"]["bootId"] != self.boot_id else self.expire()
        confirmed = state.get("confirmed")
        if not confirmed:
            return {"ok": True, "message": "No v2 confirmed snapshot. No table created."}
        table = self.inspect()
        if table["present"]:
            if table["fingerprint"] != confirmed["fingerprint"]:
                raise HelperError("existing pve_portfw differs from confirmed snapshot; refusing to overwrite")
            return {"ok": True, "message": "Confirmed table already present; no change."}
        self.require_ready()
        self.replace_table(confirmed["nft"])
        if self.inspect()["fingerprint"] != confirmed["fingerprint"]:
            raise HelperError("boot recovery verification failed")
        state.update(phase="confirmed", error=None)
        self.save(state, "boot-recovered")
        return {"ok": True, "message": "Restored verified last confirmed table."}

    def diagnostics(self) -> list[dict]:
        checks = self.preflight()
        status = self.status()
        checks.append({"label": "Running forwarding table", "status": "ok" if status["tableVerified"] else "warn",
                       "stdout": json.dumps({key: status[key] for key in ("phase", "tablePresent", "tableVerified", "operationId", "generation")}),
                       "detail": "Host table matches the recorded rules." if status["tableVerified"] else "No verified project table is running.",
                       "cause": "The host may have rebooted, rules may never have been applied, or another tool changed the table.",
                       "suggestion": "Check Apply status and the host recovery journal. A CT restart does not restore host nftables.", "scope": "host"})
        checks.append({"label": "Boot recovery", "status": "ok" if status["recoveryEnabled"] else "warn",
                       "command": [SYSTEMCTL, "is-enabled", "pve-portfw-recover.service"],
                       "stdout": "enabled" if status["recoveryEnabled"] else "disabled",
                       "detail": "Opt-in host recovery is enabled." if status["recoveryEnabled"] else "Host recovery is not enabled.",
                       "suggestion": "After a verified confirm, review and manually enable pve-portfw-recover.service on the host.", "scope": "host"})
        return checks


@contextlib.contextmanager
def host_lock(root: Path):
    import fcntl
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / "helper.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def main():
    try:
        def deadline_expired(_signum, _frame):
            raise HelperError("helper action time limit reached; inspect Host status")
        signal.signal(signal.SIGALRM, deadline_expired)
        signal.alarm(60)
        if os.geteuid() != 0:
            raise HelperError("helper must run as root through the restricted sudo allow-list")
        if len(sys.argv) != 2 or sys.argv[1] not in {"status", "diagnostics", "dry-run", "apply", "confirm", "rollback", "expire", "recover"}:
            raise HelperError("unsupported helper action")
        action = sys.argv[1]
        payload = {}
        if action in {"dry-run", "apply", "confirm", "rollback"}:
            raw = sys.stdin.buffer.read(MAX_PAYLOAD + 1)
            if len(raw) > MAX_PAYLOAD:
                raise HelperError("payload too large")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise HelperError("payload must be a JSON object")
            if action in {"confirm", "rollback"} and (payload.get("version") != PROTOCOL or set(payload) != {"version", "operationId"}):
                raise HelperError("confirm / rollback require protocol v2 and an operationId")
        with host_lock(HELPER_DIR):
            engine = HostEngine(HELPER_DIR, load_settings(HELPER_DIR / "config"))
            handler = getattr(engine, action.replace("-", "_"))
            result = handler(payload) if action in {"dry-run", "apply", "confirm", "rollback"} else handler()
        print(json.dumps(result))
    except Exception as exc:
        print(json.dumps({"version": PROTOCOL, "ok": False, "error": str(exc)}))
        print(str(exc), file=sys.stderr)
        sys.exit(1)
