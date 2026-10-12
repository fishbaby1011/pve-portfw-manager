import json

import pytest
from fastapi.testclient import TestClient

from app import main
from app.storage import StateConflict, Storage, get_paths
from tests.fakes import environment, rule


@pytest.fixture
def api(tmp_path, monkeypatch):
    engine, kernel, clock, host = environment(tmp_path)
    store = Storage(get_paths(tmp_path / "panel"))
    monkeypatch.setattr(main, "storage", lambda: store)
    monkeypatch.setattr(main, "host_client", lambda: host)
    with TestClient(main.app, base_url="http://localhost") as client:
        token = client.get("/api/session").json()["csrfToken"]
        client.headers["X-CSRF-Token"] = token
        yield client, store, host, engine, kernel, clock


def test_first_run_and_template_response(api):
    client, store, *_ = api
    response = client.get("/")
    assert response.status_code == 200
    assert "PVE Port Forward Manager" in response.text
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert client.get("/api/rules").json() == []
    assert client.get("/api/preflight").json()["ready"]
    assert client.get("/api/apply-status").json()["activeRuleCount"] is None


def test_rule_crud_saved_only_and_revision_conflict(api):
    client, store, _, _, kernel, _ = api
    initial = client.get("/api/rules").headers["etag"]
    created = client.put("/api/rules", json=[rule()], headers={"If-Match": initial})
    assert created.status_code == 200
    assert kernel.table is None
    assert client.put("/api/rules", json=[], headers={"If-Match": initial}).status_code == 409
    current = created.headers["etag"]
    edited = rule(name="Edited", enabled=False)
    assert client.put("/api/rules", json=[edited], headers={"If-Match": current}).status_code == 200
    assert store.load_rules()[0].name == "Edited"
    assert client.put("/api/rules", json=[]).status_code == 200
    assert client.get("/api/rules").json() == []


@pytest.mark.parametrize("payload", [{"wrong": []}, "not an array", [rule(port=22)], [rule(dest_ip="8.8.8.8")], [rule(), rule("duplicate")], [rule(external_port="2222")]])
def test_import_validation_never_overwrites_current_rules(api, payload):
    client, store, *_ = api
    store.save_rules([rule("existing", 8080)])
    response = client.post("/api/rules/import", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"]
    assert store.load_rules()[0].id == "existing"


def test_import_export_and_preview_do_not_apply(api):
    client, store, _, _, kernel, _ = api
    assert client.post("/api/rules/import", json={"rules": [rule()]}).status_code == 200
    assert client.get("/api/rules/export").json() == [rule()]
    preview = client.post("/api/preview", json=[rule("draft", 8080)]).json()
    assert "dport 8080" in preview["nft"]
    assert all(check["ok"] for check in preview["safetyChecks"])
    assert store.load_rules()[0].id == "ubuntu-ssh"
    assert kernel.table is None


def test_api_apply_confirm_and_rollback(api):
    client, store, _, _, _, _ = api
    client.put("/api/rules", json=[rule()])
    revision = client.get("/api/apply-status").json()["rulesRevision"]
    assert client.post("/api/dry-run", json={"revision": revision}).json()["ok"]
    assert client.post("/api/apply", json={"revision": revision}).json()["ok"]
    assert client.get("/api/apply-status").json()["rollbackArmed"]
    assert client.post("/api/apply").status_code == 409
    assert client.post("/api/confirm").json()["phase"] == "confirmed"
    client.put("/api/rules", json=[rule("new", 8080)])
    assert client.post("/api/apply").json()["ok"]
    assert client.post("/api/rollback").json()["ok"]
    assert store.load_rules()[0].id == "ubuntu-ssh"


def test_api_failed_confirm_not_reported_as_success(api):
    client, _, host, *_ = api
    client.put("/api/rules", json=[rule()])
    client.post("/api/apply")
    host.offline = True
    response = client.post("/api/confirm")
    assert response.status_code == 409
    assert "Confirmation failed" in response.json()["detail"]


def test_missing_csrf_cross_origin_and_untrusted_host_rejected(api):
    client, _, *_ = api
    token = client.headers.pop("X-CSRF-Token")
    assert client.put("/api/rules", json=[]).status_code == 403
    client.headers["X-CSRF-Token"] = token
    assert client.put("/api/rules", json=[], headers={"Origin": "http://attacker.example"}).status_code == 403
    assert client.get("/api/config", headers={"Host": "attacker.example"}).status_code == 400
    assert client.put("/api/rules", json=[], headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


@pytest.mark.parametrize("bad_cookie", [False, True])
def test_non_ascii_csrf_is_rejected_without_a_server_error(api, bad_cookie):
    client, *_ = api
    headers = {"X-CSRF-Token": b"\xff.\xff"}
    if bad_cookie:
        headers["Cookie"] = b"pve_portfw_csrf=\xff.\xff"
    assert client.put("/api/rules", json=[], headers=headers).status_code == 403


def test_transaction_conflict_and_duplicate_backup_names(api):
    client, store, *_ = api
    store.save_rules([rule()])
    first, second = store.backup_current_files("same"), store.backup_current_files("same")
    assert first != second
    with store.transaction():
        assert client.put("/api/rules", json=[]).status_code == 409


def test_path_traversal_and_streamed_payload_limit(api):
    client, store, *_ = api
    with pytest.raises(ValueError):
        store.restore_rules_from_backup("../../etc")
    response = client.post("/api/rules/import", content=(b"x" * 500000 for _ in range(5)), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_preflight_mismatch_disables_readiness(api):
    client, _, host, _, kernel, _ = api
    kernel.forwarding = "0"
    result = client.get("/api/preflight").json()
    assert not result["ready"]
    assert any(item["status"] == "error" and item["label"] == "IPv4 forwarding" for item in result["checks"])
