import json

import pytest

from app.storage import Storage, get_paths


def valid_rule(rule_id="ubuntu-ssh", port=2222):
    return {
        "id": rule_id,
        "name": rule_id,
        "enabled": True,
        "proto": "tcp",
        "external_port": port,
        "dest_ip": "10.10.10.100",
        "dest_port": 22,
        "note": "",
    }


def test_import_invalid_payload_does_not_overwrite_existing_rules(tmp_path):
    store = Storage(get_paths(tmp_path))
    store.save_rules([valid_rule()])

    with pytest.raises(ValueError):
        store.import_rules({"not_rules": []})

    assert [rule.id for rule in store.load_rules()] == ["ubuntu-ssh"]


def test_atomic_write_keeps_valid_json_and_no_temp_files(tmp_path):
    store = Storage(get_paths(tmp_path))
    store.save_rules([valid_rule()])
    store.save_rules([valid_rule("web", 8080)])

    data = json.loads(store.paths.rules_json.read_text(encoding="utf-8"))
    assert data[0]["id"] == "web"
    assert not list(tmp_path.glob(".rules.json.*.tmp"))
