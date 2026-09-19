"""Agris CLI contracts without opening a live adapter."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bdo_toolkit import cli


class FakeBalance:
    remaining_points = 99960
    maximum_points = 100000
    confidence = "inferred"

    def to_dict(self):
        return {"remaining_points": self.remaining_points,
                "maximum_points": self.maximum_points, "confidence": self.confidence}


class FakeSession:
    def __init__(self, *, state="tracking", balances=None):
        self.status = SimpleNamespace(status=state, reason="test evidence")
        self.health = SimpleNamespace(to_dict=lambda: {"tcp_gap_resets": 0})
        self.balances = list([FakeBalance()] if balances is None else balances)
        self.stopped = False
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = self.stopped = True

    def __iter__(self):
        return iter(self.balances)

    def poll(self, timeout):
        if self.balances:
            return self.balances.pop(0)
        self.stopped = True
        return None


@pytest.mark.parametrize("surface", [["live"], ["replay", "missing.pcapng"]])
@pytest.mark.parametrize("value", [None, "0", "-1", "4294967296", "1.5", "nan"])
def test_cap_required_and_validated_before_acquisition(surface, value, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("acquisition opened before cap validation")
    monkeypatch.setattr(cli, "LiveAgrisSession", forbidden)
    monkeypatch.setattr(cli, "replay_agris", forbidden)
    args = ["agris", *surface]
    if value is not None:
        args += ["--cap", value]
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2


def test_replay_jsonl_and_cap_forwarding(monkeypatch, capsys):
    observed = {}
    session = FakeSession()
    def replay(path, **kwargs):
        observed.update(path=path, **kwargs)
        return session
    monkeypatch.setattr(cli, "replay_agris", replay)
    assert cli.main(["agris", "replay", "capture.pcapng", "--cap", "100000",
                     "--jsonl", "--ports", "8884,8889"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == FakeBalance().to_dict()
    assert "agris tracking" in captured.err and "agris health" in captured.err
    assert "consumed" not in captured.out and "starting" not in captured.out
    assert observed["expected_maximum_points"] == 100000
    assert observed["path"] == Path("capture.pcapng")
    assert observed["ports"] == (8884, 8889)
    assert session.closed


def test_live_forwards_capture_controls_and_separates_output(monkeypatch, capsys):
    observed = {}
    session = FakeSession()
    def live(**kwargs):
        observed.update(kwargs)
        return session
    monkeypatch.setattr(cli, "LiveAgrisSession", live)
    assert cli.main(["agris", "live", "--cap", "100000", "--jsonl",
                     "--iface", "test", "--local-ip", "192.0.2.1", "--no-bpf",
                     "--capture-seconds", "10", "--save-pcap", "new.pcapng"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == FakeBalance().to_dict()
    assert "capture-ready" in captured.err
    options = observed["live_options"]
    assert options.interface == "test" and options.local_ip == "192.0.2.1"
    assert options.use_bpf is False
    assert observed["expected_maximum_points"] == 100000
    assert observed["capture_seconds"] == 10
    assert observed["save_pcap"] == Path("new.pcapng")
    assert session.closed


@pytest.mark.parametrize("state", ["searching", "settling", "ambiguous", "invalid"])
def test_unresolved_is_not_a_zero_balance(state, monkeypatch, capsys):
    monkeypatch.setattr(cli, "replay_agris", lambda *a, **k: FakeSession(state=state, balances=[]))
    assert cli.main(["agris", "replay", "unused.pcap", "--cap", "100000"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and state in captured.err


def test_operational_error_is_clean(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OSError("capture unavailable")
    monkeypatch.setattr(cli, "LiveAgrisSession", fail)
    assert cli.main(["agris", "live", "--cap", "100000"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "error: capture unavailable\n"


def test_console_balance_only(monkeypatch, capsys):
    monkeypatch.setattr(cli, "replay_agris", lambda *a, **k: FakeSession())
    assert cli.main(["agris", "replay", "unused.pcap", "--cap", "100000"]) == 0
    assert capsys.readouterr().out == "Agris remaining=99,960 maximum=100,000 confidence=inferred\n"
