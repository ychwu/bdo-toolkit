"""Controllable live-capture lifecycle and compatibility behavior."""

from __future__ import annotations

import time
from threading import Event, Thread

import pytest

from bdo_toolkit import (
    BDOEvent,
    CaptureIntegrityError,
    EventFilter,
    Flow,
    LiveCaptureOptions,
    LiveCaptureSession,
    PacketCaptureOptions,
)
from bdo_toolkit import _capture_runtime as capture_runtime
from bdo_toolkit import capture as capture_module


def _event(item_id: int) -> BDOEvent:
    return BDOEvent(
        event_type="item_received",
        timestamp=float(item_id),
        flow=Flow("203.0.113.1", 8889, "198.51.100.2", 50000),
        item_id=item_id,
        quantity=1,
    )


@pytest.fixture
def live_fakes(monkeypatch):
    class FakeEngine:
        def __init__(self, server_ports):
            self.server_ports = frozenset(server_ports)
            self.finish_calls = 0
            self.service_gap_calls = []
            self.tcp_gap_resets = 0
            self.flow_state_evictions = 0

        def finish(self):
            self.finish_calls += 1

        def service_gaps(self, now):
            self.service_gap_calls.append(now)
            return 0

    class FakeCollector:
        instances = []

        def __init__(self, *, server_ports, on_event, **kwargs):
            self.engine = FakeEngine(server_ports)
            self.on_event = on_event
            self.kwargs = kwargs
            self.final_event = None
            self.finalize_calls = 0
            self.flush_calls = 0
            self.__class__.instances.append(self)

        def emit(self, event):
            self.on_event(event)

        def flush_stale(self, now):
            self.flush_calls += 1

        def finalize(self):
            self.finalize_calls += 1
            if self.final_event is not None:
                self.on_event(self.final_event)

    class FakeSniffer:
        instances = []

        def __init__(self, *, prn, started_callback=None, **kwargs):
            self.prn = prn
            self.started_callback = started_callback
            self.kwargs = kwargs
            self.running = False
            self.exception = None
            self.stop_calls = 0
            self.__class__.instances.append(self)

        def start(self):
            self.running = True
            if self.started_callback is not None:
                self.started_callback()

        def stop(self):
            self.stop_calls += 1
            self.running = False

        def emit_packet(self, packet):
            try:
                self.prn(packet)
            except BaseException:
                # Scapy contains callback failures inside its capture thread.
                self.running = False

    monkeypatch.setattr(
        capture_runtime,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr(capture_runtime, "_is_windows", lambda: False)
    monkeypatch.setattr(capture_module, "_EventCollector", FakeCollector)
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeSniffer)
    return FakeCollector, FakeSniffer


def test_session_stop_wakes_a_quiet_blocking_consumer(live_fakes):
    _, FakeSniffer = live_fakes
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with pytest.raises(RuntimeError, match="not started"):
        session.stop()

    session.start()
    received = []
    consumer = Thread(target=lambda: received.extend(session.events()), daemon=True)
    consumer.start()

    session.stop()
    consumer.join(timeout=1.0)

    assert not consumer.is_alive()
    assert received == []
    assert session.stopped
    assert not session.running
    assert session.stop_reason == "requested"
    assert session.error is None
    assert FakeSniffer.instances[-1].stop_calls == 1

    # Stop is intentionally idempotent; a session itself remains single-use.
    session.stop()
    with pytest.raises(RuntimeError, match="already started"):
        session.start()


def test_live_session_defaults_to_activity_and_preserves_explicit_filters(live_fakes):
    FakeCollector, _ = live_fakes

    default_session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    default_session.start()
    assert FakeCollector.instances[-1].kwargs["event_filter"] == EventFilter.activity()
    default_session.stop()

    explicit_all = EventFilter()
    all_session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface"),
        event_filter=explicit_all,
    )
    all_session.start()
    assert FakeCollector.instances[-1].kwargs["event_filter"] is explicit_all
    all_session.stop()


def test_replay_none_keeps_the_unfiltered_offline_contract(monkeypatch):
    observed = {}

    class FakeCollector:
        def __init__(self, *, event_filter, **kwargs):
            del kwargs
            observed["event_filter"] = event_filter
            self.engine = object()

        def drain_events(self):
            return iter(())

        def finalize(self):
            pass

    monkeypatch.setattr(capture_module, "_EventCollector", FakeCollector)
    monkeypatch.setattr(capture_module, "iter_pcap_file", lambda path, engine: ())

    assert list(capture_module.replay_pcap("unused.pcapng")) == []
    assert observed["event_filter"] is None


def test_session_drains_queue_then_shutdown_tail_without_deadlock(live_fakes):
    FakeCollector, _ = live_fakes
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(
            interface="test-interface",
            event_queue_size=1,
        )
    )
    session.start()
    collector = FakeCollector.instances[-1]
    first = _event(1)
    finalized = _event(2)

    collector.emit(first)  # Fill the bounded queue before stop().
    collector.final_event = finalized
    session.stop()

    assert list(session.events()) == [first, finalized]
    assert collector.engine.finish_calls == 1
    assert collector.finalize_calls == 1
    assert session.poll(timeout=0) is None


def test_session_poll_supports_nonblocking_app_integration(live_fakes):
    FakeCollector, _ = live_fakes
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()
    collector = FakeCollector.instances[-1]

    assert session.poll(timeout=0) is None
    assert collector.flush_calls == 1
    collector.emit(_event(7))
    assert session.poll(timeout=0).item_id == 7

    with pytest.raises(ValueError, match="timeout"):
        session.poll(timeout=-1)
    session.stop()


def test_session_propagates_capture_thread_errors(live_fakes, monkeypatch):
    _, FakeSniffer = live_fakes

    def make_failing_handler(engine):
        def fail(packet):
            raise RuntimeError("decoder failed")

        return fail

    monkeypatch.setattr(capture_module, "make_packet_handler", make_failing_handler)
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()

    FakeSniffer.instances[-1].emit_packet(object())

    with pytest.raises(RuntimeError, match="decoder failed"):
        list(session.events())
    assert session.stopped
    assert session.stop_reason == "error"
    assert isinstance(session.error, RuntimeError)


def test_native_callback_hands_slow_decode_to_worker(live_fakes, monkeypatch):
    _, FakeSniffer = live_fakes
    decoder_entered = Event()
    decoder_release = Event()

    def make_slow_handler(engine):
        del engine

        def handle(packet):
            del packet
            decoder_entered.set()
            decoder_release.wait(timeout=1.0)

        return handle

    monkeypatch.setattr(capture_module, "make_packet_handler", make_slow_handler)
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()

    started = time.monotonic()
    FakeSniffer.instances[-1].emit_packet(object())
    callback_elapsed = time.monotonic() - started

    assert decoder_entered.wait(timeout=1.0)
    assert callback_elapsed < 0.1
    decoder_release.set()
    session.stop()
    assert session.health.packets_accepted == 1


def test_session_services_tcp_gap_clock_while_idle(live_fakes):
    FakeCollector, _ = live_fakes
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()
    engine = FakeCollector.instances[-1].engine

    deadline = time.monotonic() + 1.0
    while not engine.service_gap_calls and time.monotonic() < deadline:
        time.sleep(0.01)

    session.stop()
    assert engine.service_gap_calls


def test_packet_queue_overflow_fails_closed_and_reports_health(
    live_fakes,
    monkeypatch,
):
    _, FakeSniffer = live_fakes
    decoder_entered = Event()
    decoder_release = Event()

    def make_blocking_handler(engine):
        del engine

        def handle(packet):
            del packet
            decoder_entered.set()
            decoder_release.wait(timeout=2.0)

        return handle

    monkeypatch.setattr(capture_module, "make_packet_handler", make_blocking_handler)
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(
            interface="test-interface",
            packet_queue_size=1,
        )
    )
    session.start()
    sniffer = FakeSniffer.instances[-1]
    sniffer.emit_packet(object())
    assert decoder_entered.wait(timeout=1.0)
    sniffer.emit_packet(object())
    sniffer.emit_packet(object())

    health = session.health
    assert health.packet_queue_overflows == 1
    assert not health.capture_is_clean
    assert isinstance(session.error, CaptureIntegrityError)

    decoder_release.set()
    with pytest.raises(CaptureIntegrityError, match="packet queue overflowed"):
        list(session.events())
    assert session.stopped


def test_session_propagates_sniffer_thread_startup_errors(live_fakes):
    _, FakeSniffer = live_fakes
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()
    sniffer = FakeSniffer.instances[-1]
    sniffer.exception = OSError("adapter failed")
    sniffer.running = False

    with pytest.raises(OSError, match="adapter failed"):
        list(session.events())

    assert session.stop_reason == "error"
    assert session.error is sniffer.exception


def test_start_raises_async_sniffer_initialization_failure(live_fakes, monkeypatch):
    class FailingStartupSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self.exception = None
            self.thread = None

        def start(self):
            def fail_startup():
                self.running = True
                self.exception = OSError("Npcap adapter could not open")

            self.thread = Thread(target=fail_startup)
            self.thread.start()
            self.thread.join()

        def stop(self):
            raise self.exception

    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FailingStartupSniffer)
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with pytest.raises(OSError, match="Npcap adapter could not open"):
        session.start()
    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


def test_session_context_manager_starts_and_stops(live_fakes):
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with session:
        assert session.running

    assert session.stopped
    assert session.stop_reason == "requested"


def test_capture_live_remains_a_timed_blocking_wrapper(live_fakes):
    FakeCollector, FakeSniffer = live_fakes

    assert (
        list(
            capture_module.capture_live(
                live_options=LiveCaptureOptions(interface="test-interface"),
                capture_seconds=0,
            )
        )
        == []
    )

    assert FakeSniffer.instances[-1].stop_calls == 1
    assert FakeCollector.instances[-1].engine.finish_calls == 1
    assert FakeCollector.instances[-1].finalize_calls == 1


def test_capture_live_deadline_stops_while_consumer_is_suspended(monkeypatch):
    emitted = _event(99)

    class DeadlineSession:
        _POLL_INTERVAL_SECONDS = 0.2
        instances = []

        def __init__(self, **kwargs):
            del kwargs
            self.stopped = False
            self.delivered = False
            self.stop_at = None
            self.stopped_event = Event()
            self.__class__.instances.append(self)

        def start(self):
            pass

        def poll(self, timeout=None):
            del timeout
            if not self.delivered:
                self.delivered = True
                return emitted
            return None

        def _finish_stop(self, reason):
            assert reason == "timeout"
            self.stop_at = time.monotonic()
            self.stopped = True
            self.stopped_event.set()

        def stop(self):
            self.stopped = True
            self.stopped_event.set()

    monkeypatch.setattr(capture_module, "LiveCaptureSession", DeadlineSession)
    started = time.monotonic()
    events = capture_module.capture_live(capture_seconds=0.05)

    assert next(events) is emitted
    session = DeadlineSession.instances[-1]
    assert session.stopped_event.wait(timeout=0.5)
    assert session.stop_at is not None
    assert session.stop_at - started < 0.3
    events.close()


def test_closing_capture_live_stops_its_delegated_session(monkeypatch):
    emitted = _event(42)

    class FakeSession:
        _POLL_INTERVAL_SECONDS = 0.2
        instances = []

        def __init__(self, **kwargs):
            self.stopped = False
            self.delivered = False
            self.__class__.instances.append(self)

        def start(self):
            pass

        def poll(self, timeout=None):
            if not self.delivered:
                self.delivered = True
                return emitted
            return None

        def stop(self):
            self.stopped = True

    monkeypatch.setattr(capture_module, "LiveCaptureSession", FakeSession)
    events = capture_module.capture_live()

    assert next(events) is emitted
    events.close()

    assert FakeSession.instances[-1].stopped


def test_session_validates_configuration_before_capture_starts():
    with pytest.raises(ValueError, match="event_queue_size"):
        LiveCaptureOptions(event_queue_size=0)
    with pytest.raises(ValueError, match="IPv4"):
        LiveCaptureOptions(local_ip="not-an-ip")
    with pytest.raises(ValueError, match="packet_queue_size"):
        LiveCaptureOptions(packet_queue_size=0)
    with pytest.raises(ValueError, match="use_bpf"):
        PacketCaptureOptions(use_bpf="yes")


def test_live_options_extend_shared_packet_capture_options():
    options = LiveCaptureOptions(ports=(8889, 8889), event_queue_size=3)

    assert isinstance(options, PacketCaptureOptions)
    assert options.ports == (8889,)
    assert options.event_queue_size == 3


def test_live_options_use_positive_backend_controls(live_fakes):
    _, FakeSniffer = live_fakes
    session = LiveCaptureSession(
        live_options=LiveCaptureOptions(
            interface="test-interface",
            use_bpf=False,
            auto_local_ip=False,
            event_queue_size=3,
        )
    )

    session.start()
    sniffer = FakeSniffer.instances[-1]
    assert sniffer.kwargs["iface"] == "test-interface"
    assert sniffer.kwargs["filter"] is None
    assert callable(sniffer.kwargs["lfilter"])
    session.stop()

