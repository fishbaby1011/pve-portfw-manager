import pytest

from app.validation import RuleValidationError, validate_rule_list


def valid_rule(**overrides):
    rule = {
        "id": "ubuntu-ssh",
        "name": "Ubuntu SSH",
        "enabled": True,
        "proto": "tcp",
        "external_port": 2222,
        "dest_ip": "10.10.10.100",
        "dest_port": 22,
        "note": "SSH",
    }
    rule.update(overrides)
    return rule


def test_valid_rule_passes():
    assert validate_rule_list([valid_rule()])[0].id == "ubuntu-ssh"


def test_invalid_proto_fails():
    with pytest.raises(RuleValidationError):
        validate_rule_list([valid_rule(proto="icmp")])


def test_external_port_out_of_range_fails():
    with pytest.raises(RuleValidationError):
        validate_rule_list([valid_rule(external_port=70000)])


def test_dest_port_out_of_range_fails():
    with pytest.raises(RuleValidationError):
        validate_rule_list([valid_rule(dest_port=0)])


def test_dest_ip_outside_internal_subnet_fails():
    with pytest.raises(RuleValidationError):
        validate_rule_list([valid_rule(dest_ip="10.20.20.100")])


@pytest.mark.parametrize("port", [22, 8006, 3128, 5900, 5999])
def test_forbidden_ports_fail(port):
    with pytest.raises(RuleValidationError):
        validate_rule_list([valid_rule(external_port=port)])


def test_duplicate_id_fails():
    with pytest.raises(RuleValidationError):
        validate_rule_list([valid_rule(), valid_rule(external_port=2223)])


def test_duplicate_proto_external_port_fails():
    with pytest.raises(RuleValidationError):
        validate_rule_list([valid_rule(), valid_rule(id="other")])
