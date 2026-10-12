import json
from threading import Event, Thread

from app.apply import ApplyManager
from app.models import ApplyState
from app.nftgen import generate_nft, safety_checks
from app.storage import Storage, get_paths
from app.validation import validate_rule_list
from tests.fakes import environment, rule
from tests.test_host_engine import confirmed, payload


def test_host_helper_scope_and_safety():
    nft = generate_nft(validate_rule_list([rule()]))
    assert all(check.ok for check in safety_checks(nft))
    assert "hook input" not in nft and "hook output" not in nft
    assert nft.count("table ip pve_portfw") == 1


def setup(tmp_path):
    engine, kernel, clock, client = environment(tmp_path)
    store = Storage(get_paths(tmp_path / "panel"))
    return store, ApplyManager(store, client), engine, kernel, clock, client


def test_rollback_restores_last_confirmed_rules(tmp_path):
    store, manager, engine, _, _, _ = setup(tmp_path)
    confirmed(engine, [rule("confirmed", 2222)])
    store.save_rules([rule("confirmed", 2222)])
    manager.status()
    store.save_rules([rule("pending", 2223)])
    assert manager.apply().ok
    assert manager.rollback().ok
    assert [item.id for item in store.load_rules()] == ["confirmed"]


def test_confirm_uses_applied_snapshot_not_new_saved_edits(tmp_path):
    store, manager, engine, _, _, _ = setup(tmp_path)
    store.save_rules([rule("applied", 2222)])
    assert manager.apply().ok
    store.save_rules([rule("edited-after-apply", 8080)])
    assert manager.confirm().phase == "confirmed"
    confirmed_json = json.loads(store.paths.last_confirmed_rules_json.read_text())
    assert confirmed_json[0]["id"] == "applied"
    assert engine.status()["activeRules"][0]["id"] == "applied"
    assert store.load_rules()[0].id == "edited-after-apply"
    assert manager.status()["phase"] == "saved_pending_apply"


def test_auto_rollback_reconciles_after_ct_restart(tmp_path):
    store, manager, engine, _, clock, client = setup(tmp_path)
    confirmed(engine, [rule("confirmed")])
    store.save_rules([rule("pending", 8080)])
    manager.status()
    assert manager.apply().ok
    clock.advance(121)
    engine.expire()
    fresh = ApplyManager(Storage(store.paths), client)
    assert fresh.status()["phase"] == "rolled_back"
    assert store.load_rules()[0].id == "confirmed"


def test_rollback_preserves_later_saved_edits(tmp_path):
    store, manager, engine, _, _, _ = setup(tmp_path)
    confirmed(engine)
    store.save_rules([rule("pending", 8080)])
    manager.status()
    manager.apply()
    store.save_rules([rule("later", 8081)])
    assert manager.rollback().ok
    assert store.load_rules()[0].id == "later"
    assert manager.status()["phase"] == "saved_pending_apply"


def test_failed_rollback_does_not_change_ct_rules_or_claim_success(tmp_path):
    store, manager, engine, kernel, _, _ = setup(tmp_path)
    confirmed(engine)
    store.save_rules([rule("pending", 8080)])
    manager.status()
    manager.apply()
    kernel.fail_apply = 1
    response = manager.rollback()
    assert not response.ok
    assert store.load_rules()[0].id == "pending"
    assert store.load_apply_state().pending_rules is not None
    assert "failed" in store.load_apply_state().last_apply_result.lower()


def test_lost_ssh_response_reconciles_from_host_without_reapply(tmp_path):
    store, manager, _, _, _, client = setup(tmp_path)
    store.save_rules([rule()])
    client.lose_apply_response = True
    assert not manager.apply().ok
    assert manager.status()["rollbackArmed"]
    assert manager.confirm().phase == "confirmed"
    assert len([call for call in client.calls if call[0] == "apply"]) == 1


def test_host_unavailable_does_not_report_saved_rules_as_active(tmp_path):
    store, manager, _, _, _, client = setup(tmp_path)
    store.save_rules([rule()])
    client.offline = True
    status = manager.status()
    assert not status["helperConnected"]
    assert status["activeRules"] is None
    assert status["activeRuleCount"] is None
    assert status["pendingChanges"] is None


def test_save_and_import_never_update_last_confirmed(tmp_path):
    store, manager, engine, _, _, _ = setup(tmp_path)
    confirmed(engine)
    store.save_rules([rule()])
    manager.status()
    baseline = store.paths.last_confirmed_rules_json.read_bytes()
    store.save_rules([rule("different", 8080)])
    store.import_rules([rule("imported", 8081)])
    assert store.paths.last_confirmed_rules_json.read_bytes() == baseline


def test_stale_host_status_cannot_undo_a_confirmation(tmp_path):
    store, manager, engine, _, _, _ = setup(tmp_path)
    store.save_rules([rule()])
    manager.apply()
    stale = engine.status()
    manager.confirm()
    state = manager.reconcile(stale)
    assert state.phase == "confirmed"
    assert state.pending_rules is None
    assert state.host_generation > stale["generation"]


def test_status_transport_does_not_hold_the_ct_write_lock(tmp_path, monkeypatch):
    store, manager, _, _, _, client = setup(tmp_path)
    received, release = Event(), Event()
    original = client.run
    errors = []

    def delayed(action, *args, **kwargs):
        result = original(action, *args, **kwargs)
        if action == "status":
            received.set()
            assert release.wait(5)
        return result

    def poll():
        try:
            manager.status()
        except Exception as exc:
            errors.append(exc)

    monkeypatch.setattr(client, "run", delayed)
    thread = Thread(target=poll)
    thread.start()
    try:
        assert received.wait(5)
        with store.transaction():
            store.save_rules([rule()])
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not errors


def test_confirmation_queues_behind_a_short_status_write(tmp_path):
    store, manager, _, _, _, _ = setup(tmp_path)
    store.save_rules([rule()])
    manager.apply()
    errors, phases = [], []
    started = Event()

    def confirm():
        started.set()
        try:
            phases.append(manager.confirm().phase)
        except Exception as exc:
            errors.append(exc)

    with store.transaction():
        thread = Thread(target=confirm)
        thread.start()
        assert started.wait(5)
        thread.join(0.05)
        assert thread.is_alive(), "Confirmation should queue instead of failing on a short polling write"
    thread.join(5)
    assert not thread.is_alive() and not errors
    assert phases == ["confirmed"]
