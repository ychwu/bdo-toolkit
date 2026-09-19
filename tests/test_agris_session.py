"""Agris acquisition owns bounded queues, deadline, shutdown and failure state."""
from __future__ import annotations

from pathlib import Path
from threading import Event, Thread
import time

import pytest

from bdo_toolkit import CaptureIntegrityError, LiveCaptureOptions
from bdo_toolkit._capture_runtime import CaptureStats
from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.agris import AgrisDiscoveryOptions, LiveAgrisSession
from bdo_toolkit.agris import session as module


def frames(values=(99960, 99920, 99880, 99840, 99800, 99760)):
    flow = FlowKey('192.0.2.1', 8889, '192.0.2.2', 40000)
    for index, value in enumerate(values):
        data = bytearray([0xAB] * 37)
        data[:2] = (37).to_bytes(2, 'little')
        data[2] = 0
        data[3:5] = (0x1746).to_bytes(2, 'little')
        data[12:16] = (100000).to_bytes(4, 'little')
        data[33:37] = value.to_bytes(4, 'little')
        yield BDOFrame(index, bytes(data), PacketContext(time.time(), flow, flow_generation=1), index * 37)


class FakeCapture:
    def __init__(self, *, capture_options, on_packet):
        self.callback = on_packet
        self.running = False
        self.stopped = False
        self.cleanup_incomplete = False
        self.endpoint = None
        self.stats = CaptureStats(received=6, dropped=0, interface_dropped=0)
        self.error = None
        self.stop_calls = 0

    def start(self):
        self.running = True
        for frame in frames():
            try:
                self.callback(frame)
            except BaseException as exc:
                self.error = exc
                break

    def stop(self):
        self.stop_calls += 1
        self.running = False
        self.stopped = True
        self.cleanup_incomplete = False
        return self.stats

    def raise_if_failed(self):
        if self.error is not None:
            raise self.error

    def snapshot_stats(self):
        return self.stats


@pytest.fixture
def fake(monkeypatch):
    captures = []
    def factory(**kwargs):
        result = FakeCapture(**kwargs)
        captures.append(result)
        return result
    monkeypatch.setattr(module, 'LivePacketCapture', factory)
    monkeypatch.setattr(module, 'make_packet_handler', lambda manager: manager.tracker.observe)
    return captures


def session(**kwargs):
    return LiveAgrisSession(expected_maximum_points=100000,
                            discovery_options=AgrisDiscoveryOptions(settle_seconds=0), **kwargs)


def wait_stopped(owner):
    assert owner._worker_done.wait(2)


def test_live_latest_only_then_direct_updates_and_drain_on_stop(fake):
    owner = session(capture_seconds=0.08)
    owner.start()
    wait_stopped(owner)
    balances = list(owner.events())
    assert [b.remaining_points for b in balances] == [99800, 99760]
    assert owner.status.balance.remaining_points == 99760
    assert owner.stop_reason == 'duration'
    assert owner.health.packets_processed == 6
    assert fake[0].stop_calls == 1
    owner.stop()


def test_duration_stops_without_application_polling(fake):
    owner = session(capture_seconds=0.02)
    owner.start()
    wait_stopped(owner)
    assert owner.stopped
    assert owner.stop_reason == 'duration'


def test_stopping_drains_accepted_before_finish(fake):
    owner = session()
    owner.start()
    owner.stop()
    assert owner.health.packets_processed == 6
    assert [x.remaining_points for x in owner.events()] == [99800, 99760]


def test_cap_validation_happens_before_capture_factory(fake):
    for cap in (None, True, 0, -1, 1.0, 0x100000000):
        with pytest.raises((ValueError, TypeError)):
            LiveAgrisSession(expected_maximum_points=cap)
    with pytest.raises(TypeError):
        LiveAgrisSession()
    assert not fake


@pytest.mark.parametrize('value', [True, 0, -1, float('nan'), float('inf')])
def test_duration_validation(value, fake):
    with pytest.raises(ValueError):
        session(capture_seconds=value)
    assert not fake


def test_packet_queue_overflow_is_failure_even_during_startup(fake):
    owner = session(live_options=LiveCaptureOptions(packet_queue_size=1))
    with pytest.raises(CaptureIntegrityError, match='packet queue overflow'):
        owner.start()
    assert owner.stopped
    assert owner.health.packet_queue_overflows == 1
    assert owner.status.status == 'invalid'


def test_slow_balance_consumer_fails_closed(fake):
    owner = session(live_options=LiveCaptureOptions(event_queue_size=1))
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError, match='balance queue overflow'):
        owner.poll(0)
    assert owner.health.event_queue_overflows == 1
    assert owner.status.balance is None


def test_native_drops_withdraw_balance(fake, monkeypatch):
    monkeypatch.setattr(FakeCapture, 'snapshot_stats', lambda self: CaptureStats(dropped=1))
    owner = session()
    try:
        owner.start()
    except CaptureIntegrityError:
        pass
    wait_stopped(owner)
    with pytest.raises(CaptureIntegrityError, match='dropped packets'):
        owner.poll(0)
    assert owner.status.balance is None


def test_existing_raw_capture_is_preserved_before_opening_adapter(fake, tmp_path):
    path = tmp_path / 'existing.pcap'
    path.write_bytes(b'private evidence')
    owner = session(save_pcap=path)
    with pytest.raises(FileExistsError):
        owner.start()
    assert path.read_bytes() == b'private evidence'
    assert not fake


def test_raw_writer_writes_before_decode_failure_and_closes(fake, monkeypatch, tmp_path):
    events = []
    primary = ValueError('decode failed')
    class Writer:
        def write(self, packet):
            events.append('write')
        def close(self):
            events.append('close')
    def bad_decode(packet):
        events.append('decode')
        raise primary
    monkeypatch.setattr(module, 'open_packet_writer', lambda path: Writer())
    monkeypatch.setattr(module, 'make_packet_handler', lambda manager: bad_decode)
    owner = session(save_pcap=tmp_path / 'new.pcap')
    try:
        owner.start()
    except ValueError as exc:
        assert exc is primary
    wait_stopped(owner)
    with pytest.raises(ValueError) as failure:
        owner.stop()
    assert failure.value is primary
    assert events[:2] == ['write', 'decode']
    assert events[-1] == 'close'
    assert events.count('write') == 6


def test_incomplete_native_cleanup_can_be_retried(fake, monkeypatch):
    original = FakeCapture.stop
    def incomplete_once(self):
        if not getattr(self, 'retried', False):
            self.retried = True
            self.cleanup_incomplete = True
            raise OSError('stop failed')
        return original(self)
    monkeypatch.setattr(FakeCapture, 'stop', incomplete_once)
    owner = session(capture_seconds=0.02)
    owner.start()
    wait_stopped(owner)
    assert owner.cleanup_incomplete
    assert not owner.stopped
    with pytest.raises(OSError, match='stop failed'):
        owner.stop()
    assert owner.stopped
    assert not owner.cleanup_incomplete


def test_context_preserves_body_failure_over_stop_failure(fake, monkeypatch):
    owner = session()
    primary = LookupError('application failed')
    monkeypatch.setattr(FakeCapture, 'stop', lambda self: (_ for _ in ()).throw(OSError('cleanup failed')))
    with pytest.raises(LookupError) as caught:
        with owner:
            raise primary
    assert caught.value is primary
    assert getattr(primary, 'cleanup_owner', None) is owner
    # Release the fake owner explicitly to avoid leaving intentional test state.
    fake[0].stopped = True
    fake[0].cleanup_incomplete = False
    with pytest.raises(OSError):
        owner.stop()


def test_idle_poll_is_woken_by_stop(fake, monkeypatch):
    monkeypatch.setattr(FakeCapture, 'start', lambda self: setattr(self, 'running', True))
    owner = session()
    owner.start()
    done = Event()
    thread = Thread(target=lambda: (owner.poll(), done.set()))
    thread.start()
    owner.stop()
    assert done.wait(1)
    thread.join(1)


def test_invalid_timeout_is_rejected_even_after_stop(fake):
    owner = session()
    owner.start()
    owner.stop()
    for timeout in (-1, True, float('inf'), float('nan')):
        with pytest.raises(ValueError):
            owner.poll(timeout)


def test_fresh_session_requires_new_discovery(fake):
    owner = session(capture_seconds=0.02)
    owner.start()
    wait_stopped(owner)
    assert owner.status.status == 'tracking'
    assert session().status.status == 'searching'
    with pytest.raises(RuntimeError, match='single-use'):
        owner.start()


def test_failure_arriving_during_dequeue_takes_priority(fake, monkeypatch):
    owner = session(capture_seconds=0.02)
    owner.start()
    wait_stopped(owner)
    original = owner._events.get_nowait
    failure = CaptureIntegrityError('loss raced dequeue')
    def raced_get():
        value = original()
        owner._record_error(failure)
        return value
    monkeypatch.setattr(owner._events, 'get_nowait', raced_get)
    with pytest.raises(CaptureIntegrityError) as caught:
        owner.poll(0)
    assert caught.value is failure


def test_startup_timeout_stays_primary_and_keeps_cleanup_owner(fake, monkeypatch):
    gate = Event()
    original = FakeCapture.start
    def blocked_start(self):
        gate.wait(2)
        original(self)
    monkeypatch.setattr(FakeCapture, 'start', blocked_start)
    owner = session()
    owner._START_TIMEOUT = 0.01
    owner._JOIN_TIMEOUT = 0.01
    try:
        with pytest.raises(TimeoutError) as caught:
            owner.start()
        assert owner.error is caught.value
        assert caught.value.cleanup_owner is owner
    finally:
        gate.set()
    wait_stopped(owner)
    with pytest.raises(TimeoutError):
        owner.stop()
    assert owner.stopped
