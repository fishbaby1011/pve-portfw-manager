import copy
import uuid

import pytest

from portfw.host import HelperError, HostEngine, NFT, load_settings
from portfw.policy import Settings, render_nft, validate_rules
from tests.fakes import environment, rule


def payload(engine, rules=None, operation=None):
    return {"version": 2, "rules": rules if rules is not None else [rule()], "settings": engine.settings.to_dict(),
            "operationId": operation or str(uuid.uuid4())}


def confirmed(engine, rules=None):
    data = payload(engine, rules)
    engine.apply(data)
    engine.confirm({"operationId": data["operationId"]})
    return data


def test_atomic_apply_and_only_project_table(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    confirmed(engine)
    before = copy.deepcopy(kernel.other_tables)
    engine.apply(payload(engine, [rule("web", 8080, dest_port=80)]))
    batches = [text for args, text in kernel.calls if args == [NFT, "-f", "-"]]
    assert batches[-1].startswith("delete table ip pve_portfw\ntable ip pve_portfw {")
    assert kernel.other_tables == before
    assert not any(args == [NFT, "delete", "table", "ip", "pve_portfw"] for args, _ in kernel.calls)


def test_dry_run_cannot_change_pending_snapshot(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    pending = payload(engine)
    engine.apply(pending)
    before, table = copy.deepcopy(engine.load()), kernel.table
    engine.dry_run(payload(engine, [rule("web", 8080)]))
    assert engine.load() == before
    assert kernel.table == table
    engine.confirm({"operationId": pending["operationId"]})
    assert engine.status()["confirmedRules"] == pending["rules"]


def test_timeout_restores_confirmed_not_pending(tmp_path):
    engine, kernel, clock, _ = environment(tmp_path)
    baseline = confirmed(engine)
    table = kernel.table
    engine.apply(payload(engine, [rule("pending", 8080)]))
    clock.advance(121)
    engine.expire()
    status = engine.status()
    assert status["phase"] == "rolled_back"
    assert status["activeRules"] == baseline["rules"]
    assert kernel.table == table
    assert not status["rollbackArmed"]


def test_first_unconfirmed_apply_rolls_back_to_no_table(tmp_path):
    engine, kernel, clock, _ = environment(tmp_path)
    engine.apply(payload(engine))
    clock.advance(121)
    engine.expire()
    assert kernel.table is None
    assert engine.load()["confirmed"] is None


def test_confirmation_expiry_or_wrong_operation_rejected(tmp_path):
    engine, _, clock, _ = environment(tmp_path)
    request = payload(engine)
    engine.apply(request)
    with pytest.raises(HelperError, match="does not match"):
        engine.confirm({"operationId": str(uuid.uuid4())})
    clock.advance(121)
    with pytest.raises(HelperError, match="expired"):
        engine.confirm({"operationId": request["operationId"]})
    assert engine.load()["pending"]


def test_duplicate_apply_idempotent_and_new_apply_rejected(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    request = payload(engine)
    engine.apply(request)
    calls = len([args for args, _ in kernel.calls if args == [NFT, "-f", "-"]])
    engine.apply(request)
    assert calls == len([args for args, _ in kernel.calls if args == [NFT, "-f", "-"]])
    with pytest.raises(HelperError, match="already awaiting"):
        engine.apply(payload(engine))
    with pytest.raises(HelperError, match="different rules"):
        engine.apply(payload(engine, [rule("other", 8080)], request["operationId"]))


def test_boot_recovery_independent_of_ct_and_idempotent(tmp_path):
    engine, kernel, clock, _ = environment(tmp_path)
    baseline = confirmed(engine)
    kernel.table = None
    fresh = HostEngine(engine.root, engine.settings, kernel.run, clock, clock, "boot-two")
    assert not fresh.status()["tablePresent"]
    fresh.recover()
    assert fresh.status()["activeRules"] == baseline["rules"]
    changes = len([args for args, _ in kernel.calls if args == [NFT, "-f", "-"]])
    fresh.recover()
    assert changes == len([args for args, _ in kernel.calls if args == [NFT, "-f", "-"]])


@pytest.mark.parametrize("phase", ["confirmed", "rolled_back"])
def test_boot_recovery_restores_durable_three_rule_snapshot(tmp_path, phase):
    engine, kernel, clock, _ = environment(tmp_path)
    baseline = confirmed(engine, [rule("ssh"), rule("web-tcp", 8080, dest_port=8080),
                                  rule("web-udp", 8080, proto="udp", dest_port=8080)])
    if phase == "rolled_back":
        engine.apply(payload(engine, [rule("unconfirmed", 8443, dest_port=443)]))
        clock.advance(121)
        engine.expire()
    snapshot = copy.deepcopy(engine.load()["confirmed"])
    other_tables = copy.deepcopy(kernel.other_tables)
    kernel.table = None
    kernel.calls.clear()
    fresh = HostEngine(engine.root, engine.settings, kernel.run, clock, clock, "boot-two")

    assert fresh.load()["phase"] == phase
    assert fresh.load()["confirmed"] == snapshot
    assert fresh.load()["pending"] is None
    assert not fresh.status()["tablePresent"]
    assert fresh.recover()["message"] == "Restored verified last confirmed table."

    status = fresh.status()
    assert status["phase"] == "confirmed"
    assert status["tablePresent"] and status["tableVerified"]
    assert status["activeRules"] == baseline["rules"]
    assert not status["rollbackArmed"]
    assert fresh.load()["confirmed"] == snapshot
    assert kernel.table == snapshot["nft"]
    assert kernel.other_tables == other_tables
    assert [text for args, text in kernel.calls if args == [NFT, "-f", "-"]] == [snapshot["nft"]]

    state = copy.deepcopy(fresh.load())
    assert fresh.recover()["message"] == "Confirmed table already present; no change."
    assert fresh.load() == state
    assert [text for args, text in kernel.calls if args == [NFT, "-f", "-"]] == [snapshot["nft"]]


def test_idle_watchdog_does_not_replace_opt_in_boot_recovery(tmp_path):
    engine, kernel, clock, _ = environment(tmp_path)
    confirmed(engine)
    assert not engine.status()["recoveryEnabled"]
    state = engine.state_path.read_bytes()
    kernel.table = None
    kernel.calls.clear()
    fresh = HostEngine(engine.root, engine.settings, kernel.run, clock, clock, "boot-two")

    assert fresh.expire()["message"] == "No expired apply."
    assert kernel.table is None
    assert fresh.state_path.read_bytes() == state
    assert fresh.status()["confirmedRules"]
    assert not fresh.status()["recoveryEnabled"]
    assert not any(args == [NFT, "-f", "-"] for args, _ in kernel.calls)


@pytest.mark.parametrize("failure", ["bridge", "forwarding"])
def test_boot_recovery_readiness_failure_preserves_snapshot_for_retry(tmp_path, failure):
    engine, kernel, clock, _ = environment(tmp_path)
    baseline = confirmed(engine)
    state = engine.state_path.read_bytes()
    kernel.table = None
    kernel.calls.clear()
    if failure == "bridge":
        kernel.interfaces_up = False
    else:
        kernel.forwarding = "0"
    fresh = HostEngine(engine.root, engine.settings, kernel.run, clock, clock, "boot-two")

    with pytest.raises(HelperError, match="preflight"):
        fresh.recover()
    assert kernel.table is None
    assert fresh.state_path.read_bytes() == state
    assert not any(args == [NFT, "-f", "-"] for args, _ in kernel.calls)

    kernel.interfaces_up, kernel.forwarding = True, "1"
    fresh.recover()
    assert fresh.status()["tableVerified"]
    assert fresh.status()["activeRules"] == baseline["rules"]


def test_host_reboot_during_pending_restores_confirmed(tmp_path):
    engine, kernel, clock, _ = environment(tmp_path)
    baseline = confirmed(engine)
    engine.apply(payload(engine, [rule("pending", 8080)]))
    kernel.table = None
    fresh = HostEngine(engine.root, engine.settings, kernel.run, clock, clock, "boot-two")
    fresh.recover()
    assert fresh.status()["activeRules"] == baseline["rules"]
    assert fresh.status()["phase"] == "rolled_back"


def test_boot_recovery_waits_for_ready_interfaces_and_never_overwrites_drift(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    confirmed(engine)
    kernel.table = None
    kernel.interfaces_up = False
    with pytest.raises(HelperError, match="preflight"):
        engine.recover()
    assert kernel.table is None
    kernel.interfaces_up = True
    engine.recover()
    kernel.table += "# externally changed\n"
    with pytest.raises(HelperError, match="refusing to overwrite"):
        engine.recover()


def test_failed_apply_restores_previous_and_does_not_confirm(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    baseline = confirmed(engine)
    kernel.fail_apply = 1
    with pytest.raises(HelperError, match="apply failed"):
        engine.apply(payload(engine, [rule("new", 8080)]))
    assert engine.status()["activeRules"] == baseline["rules"]
    assert engine.status()["phase"] == "rolled_back"


def test_failed_rollback_retains_pending_for_watchdog_retry(tmp_path):
    engine, kernel, clock, _ = environment(tmp_path)
    baseline = confirmed(engine)
    engine.apply(payload(engine, [rule("new", 8080)]))
    kernel.fail_apply = 1
    with pytest.raises(HelperError):
        engine.rollback()
    assert engine.load()["pending"]
    assert engine.status()["phase"] == "recovery_failed"
    clock.advance(121)
    engine.expire()
    assert engine.status()["activeRules"] == baseline["rules"]


def test_watchdog_failure_prevents_any_apply(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    kernel.watchdog_failure = True
    with pytest.raises(HelperError, match="watchdog"):
        engine.apply(payload(engine))
    assert kernel.table is None
    assert engine.load()["pending"] is None


def test_unmanaged_existing_table_is_restored_on_first_timeout(tmp_path):
    engine, kernel, clock, _ = environment(tmp_path)
    kernel.table = "table ip pve_portfw {\n}\n"
    initial = kernel.table
    engine.apply(payload(engine))
    clock.advance(121)
    engine.expire()
    assert kernel.table == initial
    assert engine.status()["activeRules"] is None


@pytest.mark.parametrize("port", [22, 8006, 3128, 5900, 5999])
def test_host_rejects_protected_ports_before_nft(tmp_path, port):
    engine, kernel, _, _ = environment(tmp_path)
    with pytest.raises(ValueError, match="protected"):
        engine.apply(payload(engine, [rule(port=port)]))
    assert kernel.calls == []


def test_raw_nft_and_config_injection_rejected(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    with pytest.raises(HelperError, match="arbitrary nft"):
        engine.apply({"version": 2, "nft": "delete table inet pve-firewall"})
    data = payload(engine)
    data["settings"]["externalInterface"] = 'vmbr0"; include "/tmp/evil"'
    with pytest.raises(HelperError, match="settings differ"):
        engine.apply(data)
    assert kernel.calls == []
    config = tmp_path / "config"
    config.write_text("PVE_PORTFW_INTERNAL_INTERFACE=$(touch /tmp/evil)\n")
    with pytest.raises(ValueError):
        load_settings(config)


def test_forwarding_zero_is_error_not_successful_command(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    kernel.forwarding = "0"
    assert engine.preflight()[-1]["status"] == "error"
    with pytest.raises(HelperError, match="preflight"):
        engine.dry_run(payload(engine))


def test_legacy_snapshot_not_implicitly_applied_on_boot(tmp_path):
    engine, kernel, _, _ = environment(tmp_path)
    (engine.root / "last-confirmed.nft").write_text(render_nft([rule()], Settings()))
    engine.recover()
    assert kernel.table is None


@pytest.mark.parametrize("overrides", [{"external_port": True}, {"external_port": "2222"}, {"enabled": "false"},
                                       {"dest_ip": "10.10.10.1"}, {"dest_ip": "10.10.10.0"}, {"dest_ip": "10.10.10.255"},
                                       {"dest_ip": 0x0A0A0A64}])
def test_policy_strict_input(overrides):
    with pytest.raises(ValueError):
        validate_rules([rule(**overrides)], Settings())
