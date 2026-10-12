"""Local preview with an in-memory mock nft kernel. Never opens SSH or executes commands."""

import argparse
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# This process always uses synthetic settings, even when launched from a
# deployment shell. Production application defaults remain unchanged.
os.environ.update({
    "PVE_PORTFW_PUBLIC_IP": "203.0.113.10",
    "PVE_PORTFW_EXTERNAL_INTERFACE": "vmbr0",
    "PVE_PORTFW_INTERNAL_INTERFACE": "vmbr42",
    "PVE_PORTFW_INTERNAL_SUBNET": "10.42.0.0/24",
    "PVE_PORTFW_INTERNAL_GATEWAY": "10.42.0.1",
    "PVE_PORTFW_HOST_SSH_TARGET": "pve-portfw-helper@10.42.0.1",
})

import uvicorn
from fastapi import Body, Depends
from app import main
from app.storage import Storage, get_paths
from app.models import CommandResult
from portfw.host import HostEngine
from tests.fakes import FakeHostClient, FakeKernel, rule


class PreviewWorld:
    def __init__(self):
        self.lock = threading.RLock()
        self.offset = 0
        self.reset()

    def now(self):
        return time.time() + self.offset

    def reset(self):
        with self.lock:
            parent = ROOT / ".preview-data"
            parent.mkdir(exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="preview-", dir=parent))
            host_dir = self.directory / "host"
            host_dir.mkdir()
            self.offset = 0
            self.kernel = FakeKernel(main.panel_settings())
            self.kernel.recovery_enabled = True
            self.engine = HostEngine(host_dir, self.kernel.settings, self.kernel.run, self.now, self.now, "preview-boot")
            self.host = PreviewClient(self.engine, self.lock)
            self.store = Storage(get_paths(self.directory / "panel"))
            initial = [rule("ubuntu-ssh", 2222, name="Ubuntu SSH", dest_ip="10.42.0.100", note="Example VM"),
                       rule("web", 8080, name="Web service", dest_ip="10.42.0.101", dest_port=80, note="Example application")]
            operation = {"version": 2, "operationId": str(uuid.uuid4()),
                         "settings": self.kernel.settings.to_dict(), "rules": initial}
            self.engine.apply(operation)
            self.engine.confirm({"version": 2, "operationId": operation["operationId"]})
            self.store.save_rules(initial)
            main.ApplyManager(self.store, self.host).status()

    def tick(self):
        while True:
            time.sleep(0.5)
            with self.lock:
                self.engine.expire()


class PreviewClient(FakeHostClient):
    def __init__(self, engine, lock):
        super().__init__(engine)
        self.lock = lock

    def run(self, action, payload=None, timeout=30):
        with self.lock:
            return super().run(action, payload, timeout)


world = PreviewWorld()
main.storage = lambda: world.store
main.host_client = lambda: world.host
main.app.state.preview_mode = True


def mock_diagnostics(rules, host_client):
    checks = [CommandResult.model_validate(item) for item in world.engine.diagnostics()]
    for item in rules:
        if item.enabled:
            checks.append(CommandResult(label=f"{item.name} / {item.proto.upper()}",
                          status="ok" if item.proto == "tcp" else "unknown", scope="ct-to-target",
                          detail="Mock result only. No connection was opened.",
                          suggestion="Verify this path on your own isolated test environment."))
    checks.append(CommandResult(label="Internet → VM/CT", status="unknown", scope="external",
                               detail="External reachability has not been tested.",
                               suggestion="Test the real deployment from a separate Internet connection."))
    return checks


main.run_diagnostics = mock_diagnostics


@main.app.post("/__mock__/reset", dependencies=[Depends(main.require_mutation_access)])
def mock_reset():
    world.reset()
    return {"ok": True}


@main.app.post("/__mock__/advance", dependencies=[Depends(main.require_mutation_access)])
def mock_advance(payload: dict = Body(...)):
    with world.lock:
        world.offset += int(payload.get("seconds", 121))
        world.engine.expire()
    return {"ok": True}


@main.app.post("/__mock__/offline", dependencies=[Depends(main.require_mutation_access)])
def mock_offline(payload: dict = Body(...)):
    world.host.offline = bool(payload.get("offline"))
    return {"ok": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8089)
    args = parser.parse_args()
    threading.Thread(target=world.tick, daemon=True).start()
    uvicorn.run(main.app, host="127.0.0.1", port=args.port)
