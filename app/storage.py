from __future__ import annotations

import json
import os
import tempfile
import time
import contextlib
import threading
import uuid
from pathlib import Path
from typing import Any

from .models import ApplyState, BackupInfo, Paths, Rule
from .validation import validate_rule_list
from portfw.policy import revision


class StateConflict(ValueError):
    pass


_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def get_paths(data_dir: str | Path | None = None) -> Paths:
    root = Path(data_dir or os.environ.get("PVE_PORTFW_DATA_DIR", "/etc/pve-portfw"))
    return Paths(
        data_dir=root,
        rules_json=root / "rules.json",
        generated_nft=root / "generated.nft",
        backups_dir=root / "backups",
        apply_state_json=root / "apply-state.json",
        audit_log=root / "audit.log",
        last_confirmed_rules_json=root / "last-confirmed.rules.json",
        last_confirmed_nft=root / "last-confirmed.nft",
    )


class Storage:
    def __init__(self, paths: Paths | None = None):
        self.paths = paths or get_paths()

    def ensure_dirs(self) -> None:
        self.paths.data_dir.mkdir(parents=True, exist_ok=True)
        self.paths.backups_dir.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def transaction(self, wait_timeout: float = 1.0):
        self.ensure_dirs()
        key = str(self.paths.data_dir.resolve())
        with _locks_guard:
            lock = _locks.setdefault(key, threading.Lock())
        deadline = time.monotonic() + wait_timeout
        if not lock.acquire(timeout=wait_timeout):
            raise StateConflict("Another operation is in progress. Refresh status and retry.")
        try:
            with (self.paths.data_dir / "panel.lock").open("a+b") as handle:
                # Queue briefly behind a status write, but never wait indefinitely behind SSH mutations.
                while True:
                    try:
                        if os.name == "posix":
                            import fcntl
                            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        else:
                            import msvcrt
                            handle.seek(0)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except (BlockingIOError, OSError) as exc:
                        if time.monotonic() >= deadline:
                            raise StateConflict("Another panel process is updating state.") from exc
                        time.sleep(0.01)
                try:
                    yield
                finally:
                    if os.name == "posix":
                        fcntl.flock(handle, fcntl.LOCK_UN)
                    else:
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            lock.release()

    def rules_revision(self) -> str:
        return revision([rule.model_dump() for rule in self.load_rules()])

    def check_revision(self, expected: str | None) -> None:
        if expected and expected.strip('"') != self.rules_revision():
            raise StateConflict("Saved rules changed in another session. Reload before overwriting.")

    def load_rules(self) -> list[Rule]:
        self.ensure_dirs()
        if not self.paths.rules_json.exists():
            self.save_rules([])
            return []
        data = self._read_json(self.paths.rules_json)
        if not isinstance(data, list):
            raise ValueError("rules.json must contain a JSON array")
        return validate_rule_list(data)

    def save_rules(self, raw_rules: list[dict[str, Any]] | list[Rule]) -> list[Rule]:
        rules = validate_rule_list(raw_rules)
        self.ensure_dirs()
        self._atomic_write_json(self.paths.rules_json, [rule.model_dump() for rule in rules])
        return rules

    def import_rules(self, payload: Any) -> list[Rule]:
        if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
            raw_rules = payload["rules"]
        elif isinstance(payload, list):
            raw_rules = payload
        else:
            raise ValueError('payload must be a rules array or an object with a "rules" array')
        return self.save_rules(raw_rules)

    def write_generated_nft(self, nft_text: str) -> None:
        self.ensure_dirs()
        self._atomic_write_text(self.paths.generated_nft, nft_text)

    def load_apply_state(self) -> ApplyState:
        self.ensure_dirs()
        if not self.paths.apply_state_json.exists():
            return ApplyState()
        data = self._read_json(self.paths.apply_state_json)
        return ApplyState.model_validate(data)

    def save_apply_state(self, state: ApplyState) -> None:
        self.ensure_dirs()
        self._atomic_write_json(self.paths.apply_state_json, state.model_dump(mode="json"))

    def save_last_confirmed(self, rules: list[Rule], nft_text: str, state: ApplyState) -> ApplyState:
        self._atomic_write_json(self.paths.last_confirmed_rules_json, [rule.model_dump() for rule in rules])
        self._atomic_write_text(self.paths.last_confirmed_nft, nft_text)
        self.save_apply_state(state)
        return state

    def backup_current_files(self, reason: str) -> Path:
        self.ensure_dirs()
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        backup_dir = self.paths.backups_dir / f"{timestamp}-{reason}-{uuid.uuid4().hex[:8]}"
        backup_dir.mkdir(parents=True, exist_ok=False)
        for source in [
            self.paths.rules_json,
            self.paths.generated_nft,
            self.paths.apply_state_json,
            self.paths.last_confirmed_rules_json,
            self.paths.last_confirmed_nft,
        ]:
            if source.exists():
                (backup_dir / source.name).write_bytes(source.read_bytes())
        return backup_dir

    def list_backups(self) -> list[BackupInfo]:
        self.ensure_dirs()
        backups = []
        for path in sorted(self.paths.backups_dir.iterdir(), reverse=True):
            if path.is_dir():
                stat = path.stat()
                size = sum(file.stat().st_size for file in path.rglob("*") if file.is_file())
                backups.append(BackupInfo(id=path.name, path=str(path), size=size, mtime=stat.st_mtime))
        return backups

    def restore_rules_from_backup(self, backup_id: str) -> list[Rule]:
        backup = self._resolve_backup_dir(backup_id)
        rules_path = backup / "rules.json"
        if not rules_path.exists():
            raise ValueError(f"backup {backup_id} does not contain rules.json")
        data = self._read_json(rules_path)
        return self.save_rules(data)

    def _resolve_backup_dir(self, backup_id: str) -> Path:
        import re
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", backup_id):
            raise ValueError("invalid backup id")
        backup = (self.paths.backups_dir / backup_id).resolve()
        root = self.paths.backups_dir.resolve()
        if root not in backup.parents or not backup.is_dir():
            raise ValueError("invalid backup id")
        return backup

    @staticmethod
    def _read_json(path: Path) -> Any:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    @staticmethod
    def _atomic_write_json(path: Path, data: Any) -> None:
        text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        Storage._atomic_write_text(path, text)

    @staticmethod
    def _atomic_write_text(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            if os.name == "posix":
                directory_fd = os.open(path.parent, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except Exception:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise
