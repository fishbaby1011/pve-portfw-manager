from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from .audit import write_audit
from .config import panel_settings
from .host_client import HostHelperClient, HostResult
from .models import ApplyResponse, ApplyState, Rule
from .nftgen import assert_safe_nft, generate_nft
from .storage import StateConflict, Storage
from portfw.policy import revision


def timestamp(value) -> datetime | None:
    return datetime.fromtimestamp(value, timezone.utc) if value is not None else None


class ApplyManager:
    def __init__(self, storage: Storage | None = None, host_client: HostHelperClient | None = None):
        self.storage = storage or Storage()
        self.host = host_client or HostHelperClient()

    def payload(self, rules: list[Rule], operation: str | None = None) -> str:
        data = {"version": 2, "rules": [rule.model_dump() for rule in rules], "settings": panel_settings().to_dict()}
        if operation:
            data["operationId"] = operation
        return json.dumps(data)

    @staticmethod
    def parse_host(result: HostResult) -> dict:
        if result.returncode:
            raise ValueError(result.stderr or "Restricted host helper failed")
        try:
            data = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise ValueError("Host helper protocol v2 is required. Upgrade the host helper before applying.") from exc
        if not isinstance(data, dict) or data.get("version") != 2:
            raise ValueError("Host helper protocol v2 is required. Upgrade both host helper and CT panel.")
        return data

    def dry_run(self, expected_revision: str | None = None) -> ApplyResponse:
        with self.storage.transaction():
            self.storage.check_revision(expected_revision)
            rules = self.storage.load_rules()
            nft = generate_nft(rules)
            assert_safe_nft(nft)
            result = self.host.run("dry-run", self.payload(rules), timeout=30)
            try:
                data = self.parse_host(result)
                response = ApplyResponse(ok=bool(data.get("ok")), log=data.get("log", []),
                                         stdout=data.get("message", ""), stderr=data.get("error", ""))
            except ValueError as exc:
                response = ApplyResponse(ok=False, log=["validate rules", "generate nft"], stderr=str(exc))
            write_audit("dry-run", {"ok": response.ok, "revision": self.storage.rules_revision()}, self.storage)
            return response

    def apply(self, expected_revision: str | None = None) -> ApplyResponse:
        with self.storage.transaction():
            self.storage.check_revision(expected_revision)
            state = self.storage.load_apply_state()
            if state.pending_rules is not None:
                raise StateConflict("A previous apply result is still pending. Refresh Host status before applying again.")
            rules = self.storage.load_rules()
            nft = generate_nft(rules)
            assert_safe_nft(nft)
            self.storage.backup_current_files("pre-apply")
            state.operation_id = str(uuid.uuid4())
            state.phase = "applying"
            state.pending_rules, state.pending_generated_nft = rules, nft
            state.last_apply_log = ["validate rules", "generate nft", "send restricted host apply"]
            state.last_apply_result = "Apply result pending"
            state.last_error = None
            self.storage.save_apply_state(state)
            result = self.host.run("apply", self.payload(rules, state.operation_id), timeout=45)
            try:
                data = self.parse_host(result)
                self.reconcile(data)
                ok = data.get("phase") == "pending_confirmation" and bool(data.get("tableVerified"))
                log = ["validate rules", "generate nft", "nft syntax check", "backup current table",
                       "atomic apply pve_portfw", "host rollback armed"] if ok else state.last_apply_log
                state = self.storage.load_apply_state()
                state.last_apply_log = log
                self.storage.save_apply_state(state)
                response = ApplyResponse(ok=ok, log=log, stderr=data.get("error") or "")
            except ValueError as exc:
                state.last_apply_result = "Apply result unknown; check Host status"
                state.last_error = str(exc)
                state.last_apply_log += [str(exc)]
                self.storage.save_apply_state(state)
                response = ApplyResponse(ok=False, log=state.last_apply_log, stderr=str(exc))
            write_audit("apply", {"ok": response.ok, "operationId": state.operation_id, "returncode": result.returncode}, self.storage)
            return response

    def confirm(self) -> ApplyState:
        with self.storage.transaction():
            state = self.storage.load_apply_state()
            if not state.operation_id:
                raise StateConflict("There is no pending operation to confirm.")
            result = self.host.run("confirm", json.dumps({"version": 2, "operationId": state.operation_id}), timeout=20)
            try:
                data = self.parse_host(result)
                if data.get("phase") != "confirmed":
                    raise ValueError(data.get("error") or "Host did not confirm this apply")
                state = self.reconcile(data)
            except ValueError as exc:
                state.last_error = str(exc)
                self.storage.save_apply_state(state)
                raise StateConflict(f"Confirmation failed: {exc}") from exc
            write_audit("confirm", {"operationId": state.operation_id}, self.storage)
            return state

    def rollback(self) -> ApplyResponse:
        with self.storage.transaction():
            state = self.storage.load_apply_state()
            result = self.host.run("rollback", json.dumps({"version": 2, "operationId": state.operation_id}), timeout=45)
            try:
                data = self.parse_host(result)
                if data.get("phase") != "rolled_back":
                    raise ValueError(data.get("error") or "Host did not complete rollback")
                self.reconcile(data)
                response = ApplyResponse(ok=True, log=["restore host-owned rollback snapshot", "verify running table", "reconcile CT state"])
            except ValueError as exc:
                state.last_error = str(exc)
                state.last_apply_result = "Rollback failed; Host state is unverified"
                self.storage.save_apply_state(state)
                response = ApplyResponse(ok=False, log=["request host rollback"], stderr=str(exc))
            write_audit("rollback", {"ok": response.ok, "returncode": result.returncode}, self.storage)
            return response

    def restore_backup(self, backup_id: str) -> list[Rule]:
        with self.storage.transaction():
            self.storage.backup_current_files("pre-restore")
            rules = self.storage.restore_rules_from_backup(backup_id)
            self.storage.write_generated_nft(generate_nft(rules))
            write_audit("restore-backup", {"backup_id": backup_id, "applied": False}, self.storage)
            return rules

    def reconcile(self, host: dict) -> ApplyState:
        state = self.storage.load_apply_state()
        generation = host.get("generation", 0)
        if generation < state.host_generation:
            return state
        state.host_generation = generation
        old_pending = state.pending_rules
        state.phase = host.get("phase", "unknown")
        state.operation_id = host.get("operationId")
        state.last_error = host.get("error")
        state.rollback_armed_until = timestamp(host.get("rollbackDeadline")) if host.get("rollbackArmed") else None
        state.last_applied_at = timestamp(host.get("lastAppliedAt"))
        state.last_confirmed_at = timestamp(host.get("lastConfirmedAt"))
        labels = {"confirmed": "Confirmed", "pending_confirmation": "Applied / Pending Confirmation",
                  "rolled_back": "Rolled back to last confirmed rules", "never_applied": "Never applied",
                  "apply_failed": "Apply failed", "recovery_failed": "Host recovery failed", "applying": "Apply in progress"}
        state.last_apply_result = labels.get(state.phase, state.phase)
        confirmed = host.get("confirmedRules")
        if confirmed is not None:
            rules = [Rule.model_validate(item) for item in confirmed]
            # This snapshot comes from the host, never from the current editable rules.json.
            self.storage.save_last_confirmed(rules, host.get("confirmedNft") or generate_nft(rules), state)
        if host.get("rollbackArmed"):
            if host.get("pendingRules") is not None:
                state.pending_rules = [Rule.model_validate(item) for item in host["pendingRules"]]
        else:
            if state.phase == "rolled_back":
                target = confirmed if confirmed is not None else ([] if not host.get("tablePresent") else None)
                current = [rule.model_dump() for rule in self.storage.load_rules()]
                pending_raw = [rule.model_dump() for rule in old_pending] if old_pending is not None else None
                if target is not None and (current == pending_raw or current == confirmed):
                    self.storage.backup_current_files("pre-rollback-sync")
                    self.storage.save_rules(target)
                    self.storage.write_generated_nft(generate_nft(self.storage.load_rules()))
                # Preserve edits saved after apply; the UI will show them as pending changes.
            state.pending_rules = None
            state.pending_generated_nft = None
        self.storage.save_apply_state(state)
        return state

    def status(self) -> dict:
        # SSH reads must not hold the CT write lock or block a user confirmation.
        result = self.host.run("status", timeout=15)
        with self.storage.transaction():
            try:
                host = self.parse_host(result)
                local = self.storage.load_apply_state()
                if host.get("generation", 0) < local.host_generation:
                    raise ValueError("Host status snapshot is older than the last operation. Refresh status.")
                state = self.reconcile(host)
                reachable, error = True, None
            except ValueError as exc:
                host, state = {}, self.storage.load_apply_state()
                reachable, error = False, str(exc)
            saved = [rule.model_dump() for rule in self.storage.load_rules()]
            active = host.get("activeRules")
            pending_count = None if active is None else count_changes(saved, active)
            workflow = state.phase
            if reachable and not host.get("rollbackArmed") and (pending_count or (active is None and saved)):
                workflow = "saved_pending_apply"
            return {"phase": workflow, "hostPhase": host.get("phase", "unknown"), "helperConnected": reachable,
                    "hostError": error, "rollbackArmed": host.get("rollbackArmed", False),
                    "remainingSeconds": host.get("remainingSeconds", 0), "operationId": state.operation_id,
                    "lastApplyResult": state.last_apply_result, "lastApplyLog": state.last_apply_log,
                    "lastConfirmedAt": host.get("lastConfirmedAt"), "lastAppliedAt": host.get("lastAppliedAt"),
                    "tablePresent": host.get("tablePresent"), "tableVerified": host.get("tableVerified", False),
                    "activeRules": active, "activeRuleCount": sum(rule["enabled"] for rule in active) if active is not None else None,
                    "pendingChanges": pending_count, "savedRules": saved, "rulesRevision": revision(saved),
                    "recoveryEnabled": host.get("recoveryEnabled", False), "hostSettings": host.get("settings"),
                    "lastError": error or host.get("error") or state.last_error}


def count_changes(current: list[dict], baseline: list[dict]) -> int:
    before, after = {rule["id"]: rule for rule in baseline}, {rule["id"]: rule for rule in current}
    return sum(before.get(key) != after.get(key) for key in before.keys() | after.keys())
