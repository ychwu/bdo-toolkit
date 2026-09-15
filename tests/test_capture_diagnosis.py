"""Synthetic network discovery: no game, capture driver, or network required."""

import json
import subprocess

import pytest

from bdo_toolkit import CaptureDiagnosis, diagnose_capture, cli
from bdo_toolkit import capture_diagnosis as diagnosis


def connection(**changes):
    row = dict(process_id=12, local_ip="192.0.2.2", local_port=50000,
               remote_ip="198.51.100.1", remote_port=8889, peer_process=None)
    row.update(changes)
    return row


@pytest.fixture
def snapshot(monkeypatch):
    data = {"game_count": 1, "connections": [connection()]}
    monkeypatch.setattr(diagnosis.sys, "platform", "win32")
    monkeypatch.setattr(diagnosis, "_windows_snapshot", lambda timeout: data)
    monkeypatch.setattr(diagnosis, "_capture_adapters", lambda: [
        ("ethernet", ("192.0.2.2",)), (r"\Device\NPF_Loopback", ("127.0.0.1",)),
    ])
    return data


def test_direct_and_web_connections_are_distinguished(snapshot):
    snapshot["connections"].append(connection(remote_port=443, local_port=50001))
    result = diagnose_capture()
    assert result.status == "candidates"
    assert [c.kind for c in result.candidates] == ["game_port", "other_tcp"]
    options = result.candidates[0].to_live_options()
    assert (options.interface, options.local_ip, options.ports) == ("ethernet", "192.0.2.2", (8889,))
    assert json.loads(json.dumps(result.to_dict()))["status"] == "candidates"


def test_proxy_uses_current_peer_port_and_loopback(snapshot):
    snapshot["connections"] = [connection(local_ip="127.0.0.2", remote_ip="127.0.0.1",
                                          remote_port=53123, peer_process="ExitLag")]
    candidate, = diagnose_capture().candidates
    assert candidate.kind == "local_proxy"
    assert candidate.peer_process == "ExitLag"
    options = candidate.to_live_options()
    assert options.interface == r"\Device\NPF_Loopback"
    assert options.ports == (53123,)
    assert options.local_ip == "127.0.0.2"


def test_unidentified_proxy_still_has_evidence(snapshot):
    snapshot["connections"] = [connection(local_ip="127.0.0.1", remote_ip="127.0.0.1", remote_port=53000)]
    candidate, = diagnose_capture().candidates
    assert candidate.peer_process is None
    assert candidate.kind == "local_proxy"


def test_missing_adapter_does_not_fall_back_to_default(snapshot, monkeypatch):
    monkeypatch.setattr(diagnosis, "_capture_adapters", lambda: [])
    candidate, = diagnose_capture().candidates
    assert candidate.interface is None
    with pytest.raises(ValueError, match="No matching"):
        candidate.to_live_options()


def test_ambiguous_adapters_are_all_returned(snapshot, monkeypatch):
    monkeypatch.setattr(diagnosis, "_capture_adapters", lambda: [("a", ("192.0.2.2",)), ("b", ("192.0.2.2",))])
    result = diagnose_capture()
    assert [c.interface for c in result.candidates] == ["a", "b"]
    assert all("Multiple adapters" in c.explanation for c in result.candidates)


def test_ipv6_is_not_suggested(snapshot):
    snapshot["connections"] = [connection(local_ip="::1", remote_ip="::1")]
    result = diagnose_capture()
    assert result.status == "no_connections"
    assert not result.candidates
    assert any("IPv6" in m for m in result.messages)


def test_no_game_and_no_connections(snapshot):
    snapshot["game_count"] = 0
    assert diagnose_capture().status == "no_game"
    snapshot.update(game_count=1, connections=[])
    assert diagnose_capture().status == "no_connections"


@pytest.mark.parametrize("error", [OSError("denied"), subprocess.TimeoutExpired("powershell", 1), ValueError("bad JSON")])
def test_inspection_failure_is_structured(snapshot, monkeypatch, error):
    def fail(timeout):
        raise error
    monkeypatch.setattr(diagnosis, "_windows_snapshot", fail)
    result = diagnose_capture()
    assert result.status == "unavailable"
    assert result.messages


def test_adapter_failure_preserves_connection_evidence(snapshot, monkeypatch):
    def fail():
        raise RuntimeError("Npcap unavailable")
    monkeypatch.setattr(diagnosis, "_capture_adapters", fail)
    result = diagnose_capture()
    assert result.candidates[0].interface is None
    assert any("Npcap unavailable" in m for m in result.messages)


def test_other_platform_does_not_run_powershell(monkeypatch):
    monkeypatch.setattr(diagnosis.sys, "platform", "linux")
    assert diagnose_capture().status == "unavailable"


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
def test_invalid_timeout(timeout):
    with pytest.raises(ValueError):
        diagnose_capture(timeout=timeout)


def test_cli_json_and_text(snapshot, capsys):
    assert cli.main(["diagnose-capture", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["candidates"][0]["remote_port"] == 8889
    assert cli.main(["diagnose-capture"]) == 0
    output = capsys.readouterr().out
    assert "Interface: ethernet" in output
    assert "unverified" in output


def test_cli_unavailable_and_timeout_validation(monkeypatch, capsys):
    monkeypatch.setattr(cli, "diagnose_capture", lambda **kw: CaptureDiagnosis("unavailable"))
    assert cli.main(["diagnose-capture", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unavailable"
    with pytest.raises(SystemExit):
        cli.main(["diagnose-capture", "--timeout", "0"])


def test_windows_collector_uses_fixed_script_timeout_and_hidden_window(monkeypatch):
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    def run(argv, **kwargs):
        assert argv[-1] == diagnosis._WINDOWS_SNAPSHOT
        assert kwargs["timeout"] == 3.0
        assert kwargs["creationflags"] == 0x08000000
        assert "shell" not in kwargs
        return subprocess.CompletedProcess(argv, 0, '\ufeff' + json.dumps({"game_count": 1, "connections": [connection()]}))
    monkeypatch.setattr(subprocess, "run", run)
    assert diagnosis._windows_snapshot(3.0)["connections"][0]["remote_port"] == 8889


@pytest.mark.parametrize("payload", ["invalid", "[]", '{"connections":[]}',
    json.dumps({"game_count": 1, "connections": [connection(remote_port=0)]}),
    json.dumps({"game_count": 1, "connections": [connection(local_ip="bad")]}),
])
def test_windows_collector_rejects_malformed_snapshot(monkeypatch, payload):
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 0, payload))
    with pytest.raises(ValueError):
        diagnosis._windows_snapshot(1)


def test_windows_collector_failure_does_not_leak_command_output(monkeypatch):
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 1, "", "private command output"))
    with pytest.raises(RuntimeError, match="inspection failed") as error:
        diagnosis._windows_snapshot(1)
    assert "private" not in str(error.value)


def test_settings_proposals_merge_game_ports_but_not_web(snapshot):
    snapshot["connections"] = [connection(remote_port=p, local_port=50000+i)
                               for i, p in enumerate([8889, 8885, 8884, 443, 443])]
    result = diagnose_capture()
    game, web = result.proposals
    assert game.ports == (8884, 8885, 8889)
    assert game.to_live_options().ports == game.ports
    assert web.kind == "other_tcp" and web.ports == (443,)
    assert len(game.candidates) == 3 and len(web.candidates) == 2
    assert len(result.candidates) == 5
    assert result.to_dict()["proposals"][0]["ports"] == [8884, 8885, 8889]


@pytest.mark.parametrize("change", [dict(process_id=13), dict(local_ip="192.0.2.3"),
                                    dict(interface="another"), dict(kind="other_tcp")])
def test_proposal_group_boundaries(change):
    from dataclasses import replace
    from bdo_toolkit import CaptureCandidate
    first = CaptureCandidate(**connection(), interface="ethernet", kind="game_port", explanation="test")
    second = replace(first, **change)
    assert len(CaptureDiagnosis("candidates", (first, second)).proposals) == 2


def test_proxy_grouping_preserves_unknown_ownership_boundaries():
    from dataclasses import replace
    from bdo_toolkit import CaptureCandidate
    first = CaptureCandidate(**connection(local_ip="127.0.0.1", remote_ip="127.0.0.1", peer_process="ExitLag"),
                             interface="loopback", kind="local_proxy", explanation="test")
    second = replace(first, remote_port=53000)
    assert len(CaptureDiagnosis("candidates", (first, second)).proposals) == 1
    for other in [replace(second, peer_process="Other"), replace(second, remote_ip="127.0.0.2")]:
        assert len(CaptureDiagnosis("candidates", (first, other)).proposals) == 2
    unknown = (replace(first, peer_process=None), replace(second, peer_process=None))
    assert len(CaptureDiagnosis("candidates", unknown).proposals) == 2


def test_proposals_empty_and_missing_adapter(snapshot, monkeypatch):
    assert CaptureDiagnosis("no_game").proposals == ()
    monkeypatch.setattr(diagnosis, "_capture_adapters", lambda: [])
    with pytest.raises(ValueError, match="No matching"):
        diagnose_capture().proposals[0].to_live_options()


def test_cli_consolidates_ports(snapshot, capsys):
    snapshot["connections"] = [connection(remote_port=port) for port in (8889, 8885, 8884)]
    assert cli.main(["diagnose-capture"]) == 0
    output = capsys.readouterr().out
    assert output.count("Interface:") == 1
    assert "ports: 8884,8885,8889" in output
