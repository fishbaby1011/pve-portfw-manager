import pytest

from app.host_client import HostHelperClient
from app.models import HelperConfig


def test_host_client_rejects_unknown_action():
    client = HostHelperClient(HelperConfig())
    with pytest.raises(ValueError):
        client.run("rm -rf /")


def test_host_client_builds_fixed_ssh_command():
    client = HostHelperClient(
        HelperConfig(
            ssh_target="helper@pve",
            ssh_key="/etc/pve-portfw/ssh/host-helper",
            ssh_port=2222,
            helper_command="/usr/local/sbin/pve-portfw-host-helper",
        )
    )
    command = client._ssh_command("dry-run")
    assert command[:2] == ["ssh", "-i"]
    assert "helper@pve" in command
    assert command[-2:] == ["/usr/local/sbin/pve-portfw-host-helper", "dry-run"]
    assert "StrictHostKeyChecking=yes" in command
    assert "--" in command


@pytest.mark.parametrize("target", ["-oProxyCommand=evil", "helper@host;rm", "helper@$(id)", "helper@host extra"])
def test_host_client_rejects_ssh_option_or_remote_shell_injection(target):
    with pytest.raises(ValueError):
        HostHelperClient(HelperConfig(ssh_target=target))


def test_timeout_keeps_uncertainty_and_decodes_partial_stdout(monkeypatch):
    import subprocess
    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired("ssh", 30, output=b"partial")
    monkeypatch.setattr(subprocess, "run", timed_out)
    result = HostHelperClient().run("apply", "{}")
    assert result.returncode == 124
    assert result.stdout == "partial"
    assert "unknown" in result.stderr
