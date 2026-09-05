"""Controllable live-capture lifecycle and compatibility behavior."""

from __future__ import annotations

import asyncio
import time
from threading import Event, Thread, get_ident
from types import SimpleNamespace

import pytest

from _support.capture import item_event as _event
from _support.framing import (
    feed_collector,
    finish_collector,
    framing_message,
    framing_profile,
)

from bdo_toolkit import (
    AsyncLiveCaptureSession,
    CaptureIntegrityError,
    EventFilter,
    LiveCaptureOptions,
    LiveCaptureSession,
    PacketCaptureOptions,
    _capture_runtime as capture_runtime,
    capture as capture_module,
)
from bdo_toolkit._reassembly import FlowManager
from bdo_toolkit.capture import _EventCollector


class _HealthFlowRace:
    """Hold real flow processing while another thread reads session health."""

    def __init__(self, session: LiveCaptureSession) -> None:
        self.session = session
        self.scanner_entered = Event()
        self.health_counter_entered = Event()
        self.release_scanner = Event()
        self.decoder_done = Event()
        self.health_done = Event()
        self.errors: list[BaseException] = []
        self.health_results = []
        race = self

        class BlockingScanner:
            def feed(self, data, context):
                del data, context
                race.scanner_entered.set()
                race.release_scanner.wait()
                race.session._enqueue(_event(1))

            def scan_standalone(self, data, context):
                del data, context

            def reset(self):
                pass

        self.manager = FlowManager(
            server_ports={8889},
            scanner_factory=BlockingScanner,
        )

        class Engine:
            @property
            def tcp_gap_resets(self):
                race.health_counter_entered.set()
                return race.manager.tcp_gap_resets

            @property
            def flow_state_evictions(self):
                return 0

            def finish(self):
                race.manager.finish()

        session._collector = SimpleNamespace(
            engine=Engine(),
            finalize=lambda: None,
            flush_stale=lambda _now: None,
        )

    def start_decoder(self) -> Thread:
        def decode() -> None:
            try:
                self.manager.process_tcp_segment(
                    source_ip="203.0.113.1",
                    source_port=8889,
                    destination_ip="198.51.100.2",
                    destination_port=50000,
                    sequence=100,
                    payload=b"x",
                    timestamp=1.0,
                    syn=True,
                )
            except BaseException as exc:
                self.errors.append(exc)
            finally:
                self.decoder_done.set()

        thread = Thread(target=decode, daemon=True)
        thread.start()
        return thread

    def start_health_reader(self) -> Thread:
        def read_health() -> None:
            try:
                self.health_results.append(self.session.health)
            except BaseException as exc:
                self.errors.append(exc)
            finally:
                self.health_done.set()

        thread = Thread(target=read_health, daemon=True)
        thread.start()
        return thread


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
        opcode_profile="opcodes.local",
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


def test_incomplete_backend_stop_retains_live_session_owners_for_retry(
    monkeypatch,
    live_fakes,
):
    FakeCollector, _ = live_fakes
    cleanup_failure = RuntimeError("live packet capture cleanup is incomplete")

    class RetryCapture:
        def __init__(self, **kwargs):
            del kwargs
            self.allow_cleanup = False
            self.cleanup_incomplete = False
            self.cleanup_error = None
            self.error = None
            self.endpoint = None
            self.buffer_error = None
            self.stats = capture_runtime.CaptureStats()
            self.stopped = False

        @property
        def running(self):
            return not self.stopped

        def start(self):
            return None

        def stop(self):
            if not self.allow_cleanup:
                self.cleanup_incomplete = True
                self.cleanup_error = cleanup_failure
                raise cleanup_failure
            self.cleanup_incomplete = False
            self.cleanup_error = None
            self.stopped = True
            return self.stats

        def snapshot_stats(self):
            return self.stats

    monkeypatch.setattr(capture_module, "LivePacketCapture", RetryCapture)
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()
    capture = session._capture
    collector = session._collector
    worker = session._packet_worker
    assert isinstance(capture, RetryCapture)
    assert collector is FakeCollector.instances[-1]
    assert worker is not None

    with pytest.raises(RuntimeError, match="cleanup is incomplete"):
        session.stop()

    assert not session.stopped
    assert session._capture is capture
    assert session._collector is collector
    assert session._packet_worker is worker
    assert collector.engine.finish_calls == 0
    assert collector.finalize_calls == 0

    capture.allow_cleanup = True
    session.stop()

    assert session.stopped
    assert collector.engine.finish_calls == 1
    assert collector.finalize_calls == 1
    with pytest.raises(RuntimeError) as retained:
        session.raise_if_failed()
    assert retained.value is cleanup_failure


def test_incomplete_start_cleanup_keeps_live_session_retryable(
    monkeypatch,
    live_fakes,
):
    FakeCollector, _ = live_fakes
    startup_failure = RuntimeError("adapter readiness timed out")

    class FailedStartCapture:
        def __init__(self, **kwargs):
            del kwargs
            self.allow_cleanup = False
            self.cleanup_incomplete = True
            self.cleanup_error = RuntimeError("cleanup is incomplete")
            self.error = startup_failure
            self.endpoint = None
            self.buffer_error = None
            self.stats = capture_runtime.CaptureStats()
            self.stopped = False

        @property
        def running(self):
            return not self.stopped

        def start(self):
            raise startup_failure

        def stop(self):
            if not self.allow_cleanup:
                raise self.cleanup_error
            self.cleanup_incomplete = False
            self.cleanup_error = None
            self.stopped = True
            return self.stats

        def snapshot_stats(self):
            return self.stats

    monkeypatch.setattr(capture_module, "LivePacketCapture", FailedStartCapture)
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with pytest.raises(RuntimeError) as started:
        session.start()

    assert started.value is startup_failure
    assert started.value.cleanup_owner is session
    capture = session._capture
    assert isinstance(capture, FailedStartCapture)
    assert session._collector is FakeCollector.instances[-1]
    assert session._packet_worker is not None
    assert not session.stopped

    capture.allow_cleanup = True
    session.stop()
    assert session.stopped
    with pytest.raises(RuntimeError) as retained:
        session.raise_if_failed()
    assert retained.value is startup_failure


def test_failed_start_retains_a_stuck_decoder_owner_for_retry(
    monkeypatch,
    live_fakes,
):
    FakeCollector, _ = live_fakes
    startup_failure = RuntimeError("adapter failed after its first callback")
    decoder_entered = Event()
    decoder_release = Event()

    def make_stuck_handler(engine):
        del engine

        def handle(packet):
            del packet
            decoder_entered.set()
            decoder_release.wait()

        return handle

    class PartialStartCapture:
        def __init__(self, *, on_packet, **kwargs):
            del kwargs
            self._on_packet = on_packet
            self.cleanup_incomplete = False
            self.cleanup_error = None
            self.error = startup_failure
            self.endpoint = None
            self.buffer_error = None
            self.stats = capture_runtime.CaptureStats()
            self.stopped = True
            self.running = False

        def start(self):
            self._on_packet(object())
            assert decoder_entered.wait(timeout=1.0)
            raise startup_failure

    monkeypatch.setattr(capture_module, "make_packet_handler", make_stuck_handler)
    monkeypatch.setattr(capture_module, "LivePacketCapture", PartialStartCapture)
    monkeypatch.setattr(
        LiveCaptureSession,
        "_DECODER_STOP_TIMEOUT_SECONDS",
        0.05,
    )
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with pytest.raises(RuntimeError) as started:
        session.start()

    assert started.value is startup_failure
    assert started.value.cleanup_owner is session
    assert session.cleanup_incomplete
    assert session._collector is FakeCollector.instances[-1]
    assert session._packet_worker is not None
    assert session._packet_worker.is_alive()

    decoder_release.set()
    session._packet_worker.join(timeout=1.0)
    session.stop()
    assert session.stopped
    assert not session.cleanup_incomplete


def test_decoder_thread_start_failure_rolls_back_to_not_started(
    monkeypatch,
    live_fakes,
):
    _, FakeSniffer = live_fakes
    real_thread = capture_module.Thread
    startup_failure = RuntimeError("decoder thread could not start")

    def thread_factory(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        if kwargs.get("name") == "bdo-toolkit-items":
            thread.start = lambda: (_ for _ in ()).throw(startup_failure)
        return thread

    monkeypatch.setattr(capture_module, "Thread", thread_factory)
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with pytest.raises(RuntimeError) as started:
        session.start()

    assert started.value is startup_failure
    assert not hasattr(startup_failure, "cleanup_owner")
    assert not session.cleanup_incomplete
    assert session._capture is None
    assert session._collector is None
    assert session._packet_worker is None
    assert FakeSniffer.instances == []
    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


def test_stop_monitor_thread_start_failure_stops_native_and_decoder(
    monkeypatch,
    live_fakes,
):
    _, FakeSniffer = live_fakes
    real_thread = capture_module.Thread
    startup_failure = RuntimeError("stop monitor could not start")
    created_workers = []

    def thread_factory(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        if kwargs.get("name") == "bdo-toolkit-items":
            created_workers.append(thread)
        elif kwargs.get("name") == "bdo-toolkit-items-stop":
            thread.start = lambda: (_ for _ in ()).throw(startup_failure)
        return thread

    monkeypatch.setattr(capture_module, "Thread", thread_factory)
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with pytest.raises(RuntimeError) as started:
        session.start()

    assert started.value is startup_failure
    assert not hasattr(startup_failure, "cleanup_owner")
    assert FakeSniffer.instances[-1].stop_calls == 1
    assert len(created_workers) == 1
    assert not created_workers[0].is_alive()
    assert not session.cleanup_incomplete
    assert session._capture is None
    assert session._collector is None
    assert session._packet_worker is None
    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


@pytest.mark.parametrize("control", ["stop", "poll"])
def test_control_waiting_on_failed_start_rechecks_rolled_back_lifecycle(
    monkeypatch,
    live_fakes,
    control,
):
    _, _ = live_fakes
    start_entered = Event()
    release_start = Event()
    startup_failure = RuntimeError("first native start failed")

    class RacingCapture:
        instances = []

        def __init__(self, **kwargs):
            del kwargs
            self.attempt = len(self.__class__.instances) + 1
            self.cleanup_incomplete = False
            self.cleanup_error = None
            self.error = None
            self.endpoint = None
            self.buffer_error = None
            self.stats = capture_runtime.CaptureStats()
            self.stopped = self.attempt == 1
            self.running = False
            self.__class__.instances.append(self)

        def start(self):
            if self.attempt == 1:
                start_entered.set()
                assert release_start.wait(timeout=2)
                raise startup_failure
            self.stopped = False
            self.running = True

        def stop(self):
            self.running = False
            self.stopped = True
            return self.stats

        def snapshot_stats(self):
            return self.stats

    monkeypatch.setattr(capture_module, "LivePacketCapture", RacingCapture)
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    start_errors = []
    control_errors = []

    def run_start():
        try:
            session.start()
        except BaseException as exc:
            start_errors.append(exc)

    def run_control():
        try:
            if control == "stop":
                session.stop()
            else:
                session.poll(timeout=0)
        except BaseException as exc:
            control_errors.append(exc)

    starter = Thread(target=run_start, daemon=True)
    starter.start()
    assert start_entered.wait(timeout=1)
    controller = Thread(target=run_control, daemon=True)
    controller.start()
    time.sleep(0.05)
    release_start.set()
    starter.join(timeout=2)
    controller.join(timeout=2)

    assert not starter.is_alive()
    assert not controller.is_alive()
    assert start_errors == [startup_failure]
    assert len(control_errors) == 1
    assert isinstance(control_errors[0], RuntimeError)
    assert "not started" in str(control_errors[0])
    assert not session.stopped

    session.start()
    assert session.running
    assert not session.stopped
    session.stop()
    assert session.stopped


def test_request_stop_cannot_cross_failed_start_rollback_into_retry(
    monkeypatch,
    live_fakes,
):
    _, _ = live_fakes
    start_entered = Event()
    release_start = Event()
    request_setting_stop = Event()
    allow_request_set = Event()
    startup_failure = RuntimeError("first native start failed")

    class RacingCapture:
        attempts = 0

        def __init__(self, **kwargs):
            del kwargs
            self.__class__.attempts += 1
            self.attempt = self.__class__.attempts
            self.cleanup_incomplete = False
            self.cleanup_error = None
            self.error = None
            self.endpoint = None
            self.buffer_error = None
            self.stats = capture_runtime.CaptureStats()
            self.stopped = self.attempt == 1
            self.running = False

        def start(self):
            if self.attempt == 1:
                start_entered.set()
                assert release_start.wait(timeout=2)
                raise startup_failure
            self.stopped = False
            self.running = True

        def stop(self):
            self.running = False
            self.stopped = True
            return self.stats

        def snapshot_stats(self):
            return self.stats

    monkeypatch.setattr(capture_module, "LivePacketCapture", RacingCapture)
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    original_stop_set = session._stop_requested.set
    first_set = True

    def gated_stop_set():
        nonlocal first_set
        if first_set:
            first_set = False
            request_setting_stop.set()
            assert allow_request_set.wait(timeout=2)
        original_stop_set()

    session._stop_requested.set = gated_stop_set
    start_errors = []
    request_errors = []

    def run_start():
        try:
            session.start()
        except BaseException as exc:
            start_errors.append(exc)

    def run_request():
        try:
            session.request_stop()
        except BaseException as exc:
            request_errors.append(exc)

    starter = Thread(target=run_start, daemon=True)
    starter.start()
    assert start_entered.wait(timeout=1)
    requester = Thread(target=run_request, daemon=True)
    requester.start()
    assert request_setting_stop.wait(timeout=1)

    release_start.set()
    allow_request_set.set()
    starter.join(timeout=2)
    requester.join(timeout=2)

    assert start_errors == [startup_failure]
    assert request_errors == []
    assert not session._stop_requested.is_set()
    assert not session._finalizing.is_set()
    assert not session.stopped

    session.start()
    time.sleep(0.05)
    assert session.running
    assert not session.stopped
    session.stop()
    assert session.stopped


def test_live_session_defaults_to_activity_and_preserves_explicit_filters(live_fakes):
    FakeCollector, _ = live_fakes

    default_session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    default_session.start()
    assert FakeCollector.instances[-1].kwargs["event_filter"] == EventFilter.activity()
    default_session.stop()

    explicit_all = EventFilter()
    all_session = LiveCaptureSession(
        opcode_profile="opcodes.local",
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

    assert list(
        capture_module.replay_pcap(
            "unused.pcapng", opcode_profile="opcodes.local"
        )
    ) == []
    assert observed["event_filter"] is None


def test_session_drains_queue_then_shutdown_tail_without_deadlock(live_fakes):
    FakeCollector, _ = live_fakes
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
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
        opcode_profile="opcodes.local",
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
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()

    FakeSniffer.instances[-1].emit_packet(object())

    with pytest.raises(RuntimeError, match="decoder failed"):
        list(session.events())
    assert session.stopped
    assert session.stop_reason == "error"
    assert isinstance(session.error, RuntimeError)


def test_health_does_not_wait_for_structural_flow_lock():
    session = LiveCaptureSession(opcode_profile="unused")
    race = _HealthFlowRace(session)
    decoder = race.start_decoder()
    assert race.scanner_entered.wait(timeout=1.0)
    reader = race.start_health_reader()

    try:
        assert race.health_counter_entered.wait(timeout=1.0)
        assert race.health_done.wait(timeout=1.0), (
            "health waited for the structural flow lock"
        )
    finally:
        race.release_scanner.set()

    decoder.join(timeout=1.0)
    reader.join(timeout=1.0)
    assert race.decoder_done.is_set()
    assert not decoder.is_alive()
    assert not reader.is_alive()
    assert race.errors == []
    assert len(race.health_results) == 1


def test_stop_remains_bounded_after_concurrent_health_and_flow_delivery():
    session = LiveCaptureSession(opcode_profile="unused")
    race = _HealthFlowRace(session)
    with session._state_lock:
        session._started = True
    decoder = race.start_decoder()
    session._packet_worker = decoder
    assert race.scanner_entered.wait(timeout=1.0)
    reader = race.start_health_reader()
    assert race.health_counter_entered.wait(timeout=1.0)

    race.release_scanner.set()
    event = session._queue.get(timeout=1.0)
    assert event.item_id == 1
    stop_done = Event()

    def stop_session() -> None:
        try:
            session.stop()
        except BaseException as exc:
            race.errors.append(exc)
        finally:
            stop_done.set()

    stopper = Thread(target=stop_session, daemon=True)
    stopper.start()
    assert stop_done.wait(timeout=1.0), "stop became unbounded after health sampling"

    decoder.join(timeout=1.0)
    reader.join(timeout=1.0)
    stopper.join(timeout=1.0)
    assert race.decoder_done.is_set()
    assert race.health_done.is_set()
    assert not decoder.is_alive()
    assert not reader.is_alive()
    assert not stopper.is_alive()
    assert race.errors == []
    assert session.stopped


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
        opcode_profile="opcodes.local",
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


def test_stuck_decoder_stop_is_bounded_and_retryable(live_fakes, monkeypatch):
    FakeCollector, FakeSniffer = live_fakes
    decoder_entered = Event()
    decoder_release = Event()

    def make_stuck_handler(engine):
        del engine

        def handle(packet):
            del packet
            decoder_entered.set()
            decoder_release.wait()

        return handle

    monkeypatch.setattr(capture_module, "make_packet_handler", make_stuck_handler)
    monkeypatch.setattr(
        LiveCaptureSession,
        "_DECODER_STOP_TIMEOUT_SECONDS",
        0.05,
    )
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()
    collector = FakeCollector.instances[-1]
    FakeSniffer.instances[-1].emit_packet(object())
    assert decoder_entered.wait(timeout=1.0)

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="decoder cleanup is incomplete"):
        session.stop()
    elapsed = time.monotonic() - started

    assert elapsed < 0.5
    assert session.cleanup_incomplete
    assert not session.stopped
    assert collector.engine.finish_calls == 0
    assert collector.finalize_calls == 0

    decoder_release.set()
    assert session._packet_worker is not None
    session._packet_worker.join(timeout=1.0)
    session.stop()

    assert session.stopped
    assert not session.cleanup_incomplete
    assert collector.engine.finish_calls == 1
    assert collector.finalize_calls == 1


def test_decoder_callback_uses_request_stop_instead_of_recursive_stop(
    live_fakes,
    monkeypatch,
):
    _, FakeSniffer = live_fakes
    callback_finished = Event()
    callback_errors = []
    sessions = []
    delivered = _event(909)

    def make_callback_handler(engine):
        del engine

        def handle(packet):
            del packet
            session = sessions[0]
            try:
                session.stop()
            except BaseException as exc:
                callback_errors.append(exc)
            session.request_stop()
            session._enqueue(delivered)
            callback_finished.set()

        return handle

    monkeypatch.setattr(
        capture_module,
        "make_packet_handler",
        make_callback_handler,
    )
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    sessions.append(session)
    session.start()
    FakeSniffer.instances[-1].emit_packet(object())

    assert callback_finished.wait(timeout=1.0)
    assert len(callback_errors) == 1
    assert isinstance(callback_errors[0], RuntimeError)
    assert "request_stop" in str(callback_errors[0])
    deadline = time.monotonic() + 1.0
    while not session.stopped and time.monotonic() < deadline:
        time.sleep(0.01)
    assert session.stopped
    assert list(session.events()) == [delivered]


def test_origin_observer_from_wall_clock_uses_request_stop_without_deadlock(
    live_fakes,
):
    FakeCollector, _ = live_fakes
    callback_done = Event()
    callback_errors = []
    sessions = []

    def stop_from_observer(_observation):
        try:
            sessions[0].stop()
        except BaseException as exc:
            callback_errors.append(exc)
        sessions[0].request_stop()
        callback_done.set()

    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface"),
        origin_observer=stop_from_observer,
    )
    sessions.append(session)
    session.start()
    collector = FakeCollector.instances[-1]
    wrapped_observer = collector.kwargs["origin_observer"]
    collector.engine.service_gaps = lambda _now: wrapped_observer(object())

    assert callback_done.wait(timeout=2), "wall-clock observer deadlocked"
    assert len(callback_errors) == 1
    assert "request_stop" in str(callback_errors[0])
    deadline = time.monotonic() + 2
    while not session.stopped and time.monotonic() < deadline:
        time.sleep(0.01)
    assert session.stopped


def test_origin_observer_from_poll_flush_uses_request_stop_without_deadlock(
    live_fakes,
):
    FakeCollector, _ = live_fakes
    callback_done = Event()
    callback_errors = []
    sessions = []

    def stop_from_observer(_observation):
        try:
            sessions[0].stop()
        except BaseException as exc:
            callback_errors.append(exc)
        sessions[0].request_stop()
        callback_done.set()

    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface"),
        origin_observer=stop_from_observer,
    )
    sessions.append(session)
    session.start()
    collector = FakeCollector.instances[-1]
    wrapped_observer = collector.kwargs["origin_observer"]
    collector.flush_stale = lambda _now: wrapped_observer(object())

    started = time.monotonic()
    assert session.poll(timeout=0) is None
    assert time.monotonic() - started < 1
    assert callback_done.is_set()
    assert len(callback_errors) == 1
    assert "request_stop" in str(callback_errors[0])
    deadline = time.monotonic() + 2
    while not session.stopped and time.monotonic() < deadline:
        time.sleep(0.01)
    assert session.stopped


def test_origin_observer_rejects_async_stop_from_another_thread(
    live_fakes,
):
    FakeCollector, _ = live_fakes

    async def scenario():
        loop = asyncio.get_running_loop()
        callback_done = Event()
        callback_errors = []
        sessions = []

        def stop_from_observer(_observation):
            stopping = asyncio.run_coroutine_threadsafe(
                sessions[0].stop(),
                loop,
            )
            try:
                stopping.result(timeout=1)
            except BaseException as exc:
                callback_errors.append(exc)
            sessions[0].request_stop()
            callback_done.set()

        session = AsyncLiveCaptureSession(
            opcode_profile="opcodes.local",
            origin_observer=stop_from_observer,
        )
        sessions.append(session)
        await session.start()
        collector = FakeCollector.instances[-1]
        wrapped_observer = collector.kwargs["origin_observer"]
        collector.engine.service_gaps = lambda _now: wrapped_observer(object())

        assert await asyncio.to_thread(callback_done.wait, 2)
        assert len(callback_errors) == 1
        assert isinstance(callback_errors[0], RuntimeError)
        assert "request_stop" in str(callback_errors[0])
        await asyncio.wait_for(session.stop(), timeout=2)
        assert session.stopped

    asyncio.run(scenario())


def test_origin_observer_cannot_block_on_direct_poll(live_fakes):
    FakeCollector, _ = live_fakes
    callback_done = Event()
    callback_errors = []
    sessions = []

    def poll_from_observer(_observation):
        try:
            sessions[0].poll()
        except BaseException as exc:
            callback_errors.append(exc)
        sessions[0].request_stop()
        callback_done.set()

    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface"),
        origin_observer=poll_from_observer,
    )
    sessions.append(session)
    session.start()
    collector = FakeCollector.instances[-1]
    wrapped_observer = collector.kwargs["origin_observer"]
    collector.engine.service_gaps = lambda _now: wrapped_observer(object())

    assert callback_done.wait(timeout=2), "observer poll deadlocked"
    assert len(callback_errors) == 1
    assert "cannot consume events" in str(callback_errors[0])
    session.stop()


def test_origin_observer_cannot_block_on_async_poll(live_fakes):
    FakeCollector, _ = live_fakes

    async def scenario():
        loop = asyncio.get_running_loop()
        callback_done = Event()
        callback_errors = []
        sessions = []

        def poll_from_observer(_observation):
            polling = asyncio.run_coroutine_threadsafe(
                sessions[0].poll(),
                loop,
            )
            try:
                polling.result(timeout=1)
            except BaseException as exc:
                callback_errors.append(exc)
            sessions[0].request_stop()
            callback_done.set()

        session = AsyncLiveCaptureSession(
            opcode_profile="opcodes.local",
            origin_observer=poll_from_observer,
        )
        sessions.append(session)
        await session.start()
        collector = FakeCollector.instances[-1]
        wrapped_observer = collector.kwargs["origin_observer"]
        collector.engine.service_gaps = lambda _now: wrapped_observer(object())

        assert await asyncio.to_thread(callback_done.wait, 2)
        assert len(callback_errors) == 1
        assert "cannot consume events" in str(callback_errors[0])
        await session.stop()

    asyncio.run(scenario())


def test_nested_origin_observers_keep_outer_session_guarded(live_fakes):
    FakeCollector, _ = live_fakes
    nested_done = Event()
    callback_errors = []
    sessions = []
    wrapped = {}

    def outer_observer(_observation):
        wrapped["inner"](object())
        sessions[0].request_stop()
        nested_done.set()

    def inner_observer(_observation):
        try:
            sessions[0].stop()
        except BaseException as exc:
            callback_errors.append(exc)

    outer = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface"),
        origin_observer=outer_observer,
    )
    inner = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface"),
        origin_observer=inner_observer,
    )
    sessions.extend((outer, inner))
    outer.start()
    outer_collector = FakeCollector.instances[-1]
    inner.start()
    inner_collector = FakeCollector.instances[-1]
    wrapped["inner"] = inner_collector.kwargs["origin_observer"]
    outer_wrapped = outer_collector.kwargs["origin_observer"]
    outer_collector.engine.service_gaps = lambda _now: outer_wrapped(object())

    assert nested_done.wait(timeout=2), "nested origin callback deadlocked"
    assert len(callback_errors) == 1
    assert "request_stop" in str(callback_errors[0])
    outer.stop()
    inner.stop()


def test_callback_request_stop_does_not_wait_on_concurrent_control_stop(
    live_fakes,
    monkeypatch,
):
    _, FakeSniffer = live_fakes
    observer_entered = Event()
    allow_request = Event()
    request_done = Event()
    sessions = []

    def make_observer_handler(engine):
        del engine

        def handle(_packet):
            observer = capture_module._EventCollector.instances[-1].kwargs[
                "origin_observer"
            ]
            observer(object())

        return handle

    def request_from_observer(_observation):
        observer_entered.set()
        assert allow_request.wait(timeout=1)
        sessions[0].request_stop()
        request_done.set()

    monkeypatch.setattr(capture_module, "make_packet_handler", make_observer_handler)
    monkeypatch.setattr(
        LiveCaptureSession,
        "_DECODER_STOP_TIMEOUT_SECONDS",
        0.5,
    )
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface"),
        origin_observer=request_from_observer,
    )
    sessions.append(session)
    session.start()
    FakeSniffer.instances[-1].emit_packet(object())
    assert observer_entered.wait(timeout=1)
    stop_errors = []

    def control_stop():
        try:
            session.stop()
        except BaseException as exc:
            stop_errors.append(exc)

    stopper = Thread(target=control_stop, daemon=True)
    stopper.start()
    deadline = time.monotonic() + 1
    while (
        FakeSniffer.instances[-1].stop_calls == 0
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert FakeSniffer.instances[-1].stop_calls == 1
    allow_request.set()

    assert request_done.wait(timeout=0.25), "request_stop waited on cleanup lock"
    stopper.join(timeout=1)
    assert not stopper.is_alive()
    assert stop_errors == []
    assert session.stopped


def test_session_services_tcp_gap_clock_while_idle(live_fakes):
    FakeCollector, _ = live_fakes
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )
    session.start()
    engine = FakeCollector.instances[-1].engine
    clock_threads = []

    def service_gaps(now):
        clock_threads.append(get_ident())
        engine.service_gap_calls.append(now)
        return 0

    engine.service_gaps = service_gaps

    deadline = time.monotonic() + 1.0
    while not clock_threads and time.monotonic() < deadline:
        time.sleep(0.01)

    session.stop()
    assert engine.service_gap_calls
    assert set(clock_threads) == {session._packet_worker.ident}


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
        opcode_profile="opcodes.local",
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
        opcode_profile="opcodes.local",
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
        opcode_profile="opcodes.local",
        live_options=LiveCaptureOptions(interface="test-interface")
    )

    with pytest.raises(OSError, match="Npcap adapter could not open"):
        session.start()
    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


def test_session_context_manager_starts_and_stops(live_fakes):
    session = LiveCaptureSession(
        opcode_profile="opcodes.local",
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
                opcode_profile="opcodes.local",
                live_options=LiveCaptureOptions(interface="test-interface"),
                capture_seconds=0,
            )
        )
        == []
    )

    assert FakeSniffer.instances[-1].stop_calls == 1
    assert FakeCollector.instances[-1].engine.finish_calls == 1
    assert FakeCollector.instances[-1].finalize_calls == 1


def test_capture_live_timer_start_failure_stops_started_session(monkeypatch):
    startup_failure = RuntimeError("deadline timer could not start")

    class StartedSession:
        instances = []

        def __init__(self, **kwargs):
            del kwargs
            self.stopped = False
            self.cleanup_incomplete = False
            self.__class__.instances.append(self)

        def start(self):
            return None

        def stop(self):
            self.stopped = True

    class FailedTimer:
        def __init__(self, *args, **kwargs):
            del args, kwargs
            self.name = ""
            self.daemon = False
            self.cancelled = False

        def start(self):
            raise startup_failure

        def cancel(self):
            self.cancelled = True

    monkeypatch.setattr(capture_module, "LiveCaptureSession", StartedSession)
    monkeypatch.setattr(capture_module, "Timer", FailedTimer)
    events = capture_module.capture_live(
        opcode_profile="opcodes.local", capture_seconds=1.0
    )

    with pytest.raises(RuntimeError) as started:
        next(events)

    assert started.value is startup_failure
    assert StartedSession.instances[-1].stopped


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
    events = capture_module.capture_live(
        opcode_profile="opcodes.local", capture_seconds=0.05
    )

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
    events = capture_module.capture_live(opcode_profile="opcodes.local")

    assert next(events) is emitted
    events.close()

    assert FakeSession.instances[-1].stopped


def test_capture_live_close_exposes_owner_when_cleanup_is_incomplete(
    monkeypatch,
):
    emitted = _event(43)
    cleanup_failure = RuntimeError("delegated cleanup is incomplete")

    class IncompleteSession:
        _POLL_INTERVAL_SECONDS = 0.2
        instances = []

        def __init__(self, **kwargs):
            del kwargs
            self.stopped = False
            self.cleanup_incomplete = False
            self.delivered = False
            self.__class__.instances.append(self)

        def start(self):
            return None

        def poll(self, timeout=None):
            del timeout
            if not self.delivered:
                self.delivered = True
                return emitted
            return None

        def stop(self):
            self.cleanup_incomplete = True
            raise cleanup_failure

    monkeypatch.setattr(capture_module, "LiveCaptureSession", IncompleteSession)
    events = capture_module.capture_live(opcode_profile="opcodes.local")
    assert next(events) is emitted

    with pytest.raises(RuntimeError) as closed:
        events.close()

    assert closed.value is cleanup_failure
    assert cleanup_failure.cleanup_owner is IncompleteSession.instances[-1]


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
        opcode_profile="opcodes.local",
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


def test_idle_gap_service_preserves_already_queued_missing_bytes():
    profile = framing_profile()
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    session = LiveCaptureSession(opcode_profile=profile)
    session._collector = collector
    message = framing_message(0x1111)
    old_timestamp = time.time() - 10
    feed_collector(collector, b"", sequence=99, timestamp=old_timestamp, syn=True)
    feed_collector(collector, message[:20], timestamp=old_timestamp)
    feed_collector(collector, message[60:], sequence=160, timestamp=old_timestamp)
    session._packet_queue.put(message[20:60])

    session._service_engine_clock()
    assert collector.engine.tcp_gap_resets == 0
    feed_collector(
        collector, session._packet_queue.get_nowait(),
        sequence=120, timestamp=old_timestamp,
    )
    session._service_engine_clock()
    assert collector.engine.tcp_gap_resets == 0
    assert [(event.event_type, event.item_id) for event in finish_collector(collector)] == [
        ("loot_preview", 7003)
    ]


def test_idle_gap_service_still_expires_a_truly_missing_segment():
    profile = framing_profile()
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    session = LiveCaptureSession(opcode_profile=profile)
    session._collector = collector
    old_timestamp = time.time() - 10
    feed_collector(collector, b"", sequence=99, timestamp=old_timestamp, syn=True)
    feed_collector(collector, framing_message(0x1111), sequence=120, timestamp=old_timestamp)
    session._service_engine_clock()
    assert collector.engine.tcp_gap_resets == 1
    assert len(finish_collector(collector)) == 1
