from app.nftgen import generate_nft, safety_checks
from app.validation import validate_rule_list


def test_disabled_rule_does_not_generate_dnat():
    rules = validate_rule_list(
        [
            {
                "id": "disabled",
                "name": "Disabled",
                "enabled": False,
                "proto": "tcp",
                "external_port": 2222,
                "dest_ip": "10.10.10.100",
                "dest_port": 22,
                "note": "",
            }
        ]
    )
    nft = generate_nft(rules)
    assert "dnat to 10.10.10.100:22" not in nft


def test_nft_output_safety_rules():
    rules = validate_rule_list(
        [
            {
                "id": "ubuntu-ssh",
                "name": "Ubuntu SSH",
                "enabled": True,
                "proto": "tcp",
                "external_port": 2222,
                "dest_ip": "10.10.10.100",
                "dest_port": 22,
                "note": "",
            }
        ]
    )
    nft = generate_nft(rules)
    assert "flush ruleset" not in nft
    assert "hook input" not in nft
    assert "hook output" not in nft
    assert "policy drop" not in nft
    assert nft.count("table ip pve_portfw") == 1
    assert all(check.ok for check in safety_checks(nft))
