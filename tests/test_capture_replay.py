"""Passive replay streaming and file ownership."""

from __future__ import annotations

from pathlib import Path

import pytest

from _support.packets import feed_engine, loot_preview_frame
from fixture_paths import JULY17_OPCODE_PROFILE

from bdo_toolkit import (
    BDOEvent,
    Flow,
    _capture_backend as capture_backend_module,
    capture as capture_module,
    replay_pcap,
)
from bdo_toolkit._capture_backend import import_scapy
from bdo_toolkit._engine import PacketEngine


def test_replay_yields_before_processing_the_next_packet(monkeypatch):
    progress: list[str] = []

    def fake_iter(path: Path, engine: PacketEngine):
        feed_engine(engine, 1000, loot_preview_frame(7003, 1))
        progress.append("first")
        yield None
        progress.append("second")
        feed_engine(engine, 2000, loot_preview_frame(7004, 1))
        yield None
        engine.finish()

    monkeypatch.setattr(capture_module, "iter_pcap_file", fake_iter)
    events = replay_pcap(
        "unused.pcapng", opcode_profile=JULY17_OPCODE_PROFILE
    )
    assert next(events).item_id == 7003
    assert progress == ["first"]
    events.close()


def test_callback_collector_does_not_retain_delivered_events():
    delivered: list[BDOEvent] = []
    collector = capture_module._EventCollector(
        server_ports=(8889,),
        opcode_profile=JULY17_OPCODE_PROFILE,
        on_event=delivered.append,
    )
    event = BDOEvent("test", 0.0, Flow("a", 1, "b", 2), 1, 1)

    collector._deliver(event)

    assert delivered == [event]
    assert list(collector.drain_events()) == []


def test_invalid_capture_is_value_error_and_does_not_remain_locked(tmp_path):
    capture = tmp_path / "invalid.pcapng"
    capture.write_bytes(b"not a capture")

    with pytest.raises(ValueError, match="Could not read capture"):
        list(replay_pcap(capture, opcode_profile=JULY17_OPCODE_PROFILE))

    capture.unlink()
    assert not capture.exists()


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_iter_pcap_file_preserves_consumer_exception_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error_type: type[Exception],
) -> None:
    capture = tmp_path / "synthetic-valid.pcapng"
    capture.write_bytes(b"reader input is supplied by the deterministic fake")
    expected = error_type("consumer sentinel")

    class FakeReader:
        def __init__(self, _source: object) -> None:
            self.closed = False
            self._packets = iter((object(),))
            readers.append(self)

        def __iter__(self) -> FakeReader:
            return self

        def __next__(self) -> object:
            return next(self._packets)

        def close(self) -> None:
            self.closed = True

    readers: list[FakeReader] = []

    class FakeEngine:
        def finish(self) -> None:
            raise AssertionError("failed consumer replay must not be finalized")

    def fail_consumer(_engine: object):
        def handle(_packet: object) -> None:
            raise expected

        return handle

    monkeypatch.setattr(
        capture_backend_module,
        "import_scapy",
        lambda: (object(), object(), object(), object(), FakeReader),
    )
    monkeypatch.setattr(capture_backend_module, "make_packet_handler", fail_consumer)

    with pytest.raises(error_type) as raised:
        list(capture_backend_module.iter_pcap_file(capture, FakeEngine()))

    assert raised.value is expected
    assert len(readers) == 1
    assert readers[0].closed


def test_import_scapy_does_not_mutate_global_ipv6_setting():
    from scapy.config import conf

    previous = conf.ipv6_enabled
    try:
        conf.ipv6_enabled = True
        import_scapy()
        assert conf.ipv6_enabled is True
    finally:
        conf.ipv6_enabled = previous
