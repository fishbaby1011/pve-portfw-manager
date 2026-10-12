import json
from contextlib import nullcontext

from app.diagnostics import run_diagnostics
from app.host_client import HostResult
from app.models import Rule
from tests.fakes import rule


class DiagnosticClient:
    def __init__(self, result=None):
        self.result = result or HostResult(0, json.dumps([{
            "label": "Host check", "status": "ok", "detail": "Host prerequisite checked.", "scope": "host"
        }]))

    def run(self, action, timeout):
        assert action == "diagnostics" and timeout == 30
        return self.result


def test_tcp_success_is_only_ct_to_target_and_never_external(monkeypatch):
    calls = []

    def connect(address, timeout):
        calls.append((address, timeout))
        return nullcontext()

    monkeypatch.setattr("app.diagnostics.socket.create_connection", connect)
    results = run_diagnostics([Rule(**rule())], DiagnosticClient())
    assert calls == [(("10.10.10.100", 22), 2)]
    assert results[1].status == "ok" and results[1].scope == "ct-to-target"
    assert results[-1].status == "unknown" and results[-1].scope == "external"


def test_disabled_and_udp_destinations_do_not_open_tcp_sockets(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No socket should be opened")

    monkeypatch.setattr("app.diagnostics.socket.create_connection", forbidden)
    rules = [Rule(**rule(enabled=False)), Rule(**rule("udp", 19132, proto="udp", dest_port=19132))]
    results = run_diagnostics(rules, DiagnosticClient())
    assert len(results) == 3
    assert results[1].status == "unknown" and results[1].scope == "ct-to-target"


def test_tcp_failure_is_actionable_without_claiming_complete_network_failure(monkeypatch):
    def refused(*args, **kwargs):
        raise ConnectionRefusedError("mock connection refused")

    monkeypatch.setattr("app.diagnostics.socket.create_connection", refused)
    results = run_diagnostics([Rule(**rule())], DiagnosticClient())
    assert results[1].status == "warn" and results[1].scope == "ct-to-target"
    assert results[1].cause and results[1].suggestion and results[1].stderr
    assert results[-1].status == "unknown"


def test_invalid_host_response_is_an_error_not_a_healthy_result():
    results = run_diagnostics([], DiagnosticClient(HostResult(0, "not JSON")))
    assert results[0].status == "error"
    assert results[0].cause and results[0].suggestion
    assert results[-1].status == "unknown"
