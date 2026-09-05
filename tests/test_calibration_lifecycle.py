"""Deterministic live-calibration acquisition lifecycle regressions."""

from __future__ import annotations

from bdo_toolkit._calibration import capture as calibration_capture
from threading import Event, Thread

import pytest

from bdo_toolkit import PacketCaptureOptions
from bdo_toolkit import _capture_backend as capture_backend
from bdo_toolkit import _capture_runtime as capture_runtime
from bdo_toolkit import calibration as calibration_module
from bdo_toolkit.calibration import (
    CalibrationRetention,
    CalibrationResult,
    CalibrationSession,
)


class _ReadySniffer:
    instances: list["_ReadySniffer"] = []

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.running = False
        self.exception: BaseException | None = None
        self.thread = None
        self.stop_calls = 0
        self.__class__.instances.append(self)

    def start(self) -> None:
        self.running = True
        callback = self.kwargs["started_callback"]
        assert callable(callback)
        callback()

    def stop(self) -> None:
        self.stop_calls += 1
        self.running = False


class _DelayedReadySniffer(_ReadySniffer):
    start_entered = Event()
    release_readiness = Event()

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._readiness_thread: Thread | None = None

    def start(self) -> None:
        self.running = True
        self.start_entered.set()

        def announce_ready() -> None:
            assert self.release_readiness.wait(timeout=2)
            callback = self.kwargs["started_callback"]
            assert callable(callback)
            callback()

        self._readiness_thread = Thread(target=announce_ready, daemon=True)
        self._readiness_thread.start()

    def stop(self) -> None:
        super().stop()
        if self._readiness_thread is not None:
            self._readiness_thread.join(timeout=2)


class _NeverReadySniffer(_ReadySniffer):
    def start(self) -> None:
        self.running = True


class _DeadThread:
    ident = 123

    @staticmethod
    def is_alive() -> bool:
        return False


class _DeadStartupSniffer(_ReadySniffer):
    def start(self) -> None:
        self.thread = _DeadThread()
        self.running = False


class _RaisingStopSniffer(_ReadySniffer):
    failure = OSError("capture stop failed")

    def stop(self) -> None:
        self.stop_calls += 1
        # Model a backend that has stopped its thread but fails while reporting
        # or completing shutdown. The session must still finish flow cleanup.
        self.running = False
        raise self.failure


class _ControlledThread:
    def __init__(self) -> None:
        self.ident = 1234
        self.alive = True
        self.join_calls: list[float | None] = []

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float | None = None) -> None:
        self.join_calls.append(timeout)


class _UncooperativeStopSniffer(_ReadySniffer):
    failure = OSError("capture stop request failed")

    def start(self) -> None:
        self.running = True
        self.thread = _ControlledThread()
        callback = self.kwargs["started_callback"]
        assert callable(callback)
        callback()

    def stop(self, join: bool = True) -> None:
        self.stop_calls += 1
        assert join is False
        raise self.failure


@pytest.fixture(autouse=True)
def live_runtime_fakes(monkeypatch):
    _ReadySniffer.instances.clear()
    _DelayedReadySniffer.start_entered.clear()
    _DelayedReadySniffer.release_readiness.clear()
    _RaisingStopSniffer.failure = OSError("capture stop failed")
    monkeypatch.setattr(
        capture_runtime,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr(capture_runtime, "_is_windows", lambda: False)
    monkeypatch.setattr(
        CalibrationSession,
        "_STARTUP_TIMEOUT_SECONDS",
        0.08,
    )


def _session() -> CalibrationSession:
    return CalibrationSession(
        item_id=7003,
        capture_options=PacketCaptureOptions(interface="test-interface"),
    )


def test_start_waits_for_delayed_capture_readiness(monkeypatch) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        _DelayedReadySniffer,
    )
    session = _session()
    errors: list[BaseException] = []

    def start() -> None:
        try:
            session.start()
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    thread = Thread(target=start)
    thread.start()
    assert _DelayedReadySniffer.start_entered.wait(timeout=1)
    assert thread.is_alive()

    _DelayedReadySniffer.release_readiness.set()
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert errors == []
    assert session.running
    result = session.stop()
    assert isinstance(result, CalibrationResult)
    assert _ReadySniffer.instances[-1].stop_calls == 1


def test_shared_capture_keeps_calibration_frame_delivery(monkeypatch) -> None:
    ip_layer = object()
    tcp_layer = object()
    monkeypatch.setattr(
        capture_runtime,
        "import_scapy",
        lambda: (ip_layer, tcp_layer, None, None, None),
    )
    monkeypatch.setattr(
        capture_backend,
        "import_scapy",
        lambda: (ip_layer, tcp_layer, None, None, None),
    )
    monkeypatch.setattr(capture_runtime, "_new_async_sniffer", _ReadySniffer)

    class IPLayer:
        src = "203.0.113.10"
        dst = "198.51.100.20"
        version = 4
        proto = 6
        ihl = 5
        flags = 0
        frag = 0

        def __init__(self, payload: bytes) -> None:
            self.len = 40 + len(payload)

        def __bytes__(self) -> bytes:
            return b"\x00" * self.len

    class TCPLayer:
        sport = 8889
        dport = 51000
        seq = 1000
        flags = 0
        dataofs = 5

        def __init__(self, payload: bytes) -> None:
            self.payload = payload

    class Packet:
        time = 1000.0

        def __init__(self, payload: bytes) -> None:
            self.layers = {
                ip_layer: IPLayer(payload),
                tcp_layer: TCPLayer(payload),
            }

        def __contains__(self, layer: object) -> bool:
            return layer in self.layers

        def __getitem__(self, layer: object):
            return self.layers[layer]

    frame = bytearray(13)
    frame[0:2] = len(frame).to_bytes(2, "little")
    frame[3:5] = (0x1234).to_bytes(2, "little")

    session = _session()
    session.start()
    callback = _ReadySniffer.instances[-1].kwargs["prn"]
    assert callable(callback)
    callback(Packet(bytes(frame)))

    assert session.frames_collected == 1
    result = session.stop()
    assert result.frames_scanned == 1


def test_never_fired_readiness_times_out_and_stops_backend(monkeypatch) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        _NeverReadySniffer,
    )
    session = _session()

    with pytest.raises(RuntimeError, match="timed out"):
        session.start()

    sniffer = _ReadySniffer.instances[-1]
    assert sniffer.stop_calls == 1
    assert not sniffer.running
    assert not session.running
    assert isinstance(session.error, RuntimeError)
    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


def test_stored_async_capture_exception_propagates_through_session(
    monkeypatch,
) -> None:
    monkeypatch.setattr(capture_runtime, "_new_async_sniffer", _ReadySniffer)
    session = _session()
    session.start()
    failure = ValueError("capture thread failed")
    sniffer = _ReadySniffer.instances[-1]
    sniffer.exception = failure

    with pytest.raises(ValueError) as caught:
        session.raise_if_failed()
    assert caught.value is failure

    with pytest.raises(ValueError) as caught:
        session.stop()
    assert caught.value is failure
    assert not session.running
    assert session.error is failure


def test_dead_capture_thread_fails_startup_without_orphan(monkeypatch) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        _DeadStartupSniffer,
    )
    session = _session()

    with pytest.raises(RuntimeError, match="ended during startup"):
        session.start()

    sniffer = _ReadySniffer.instances[-1]
    assert not sniffer.running
    assert not session.running
    assert isinstance(session.error, RuntimeError)


def test_immediate_concurrent_stop_cannot_orphan_starting_backend(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        _DelayedReadySniffer,
    )
    session = _session()
    start_errors: list[BaseException] = []
    stop_errors: list[BaseException] = []
    stop_result: list[CalibrationResult] = []
    stop_returned = Event()

    def start() -> None:
        try:
            session.start()
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            start_errors.append(exc)

    def stop() -> None:
        try:
            stop_result.append(session.stop())
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            stop_errors.append(exc)
        finally:
            stop_returned.set()

    start_thread = Thread(target=start)
    start_thread.start()
    assert _DelayedReadySniffer.start_entered.wait(timeout=1)
    stop_thread = Thread(target=stop)
    stop_thread.start()
    assert not stop_returned.wait(timeout=0.03)

    _DelayedReadySniffer.release_readiness.set()
    start_thread.join(timeout=2)
    stop_thread.join(timeout=2)

    assert not start_thread.is_alive()
    assert not stop_thread.is_alive()
    assert start_errors == []
    assert stop_errors == []
    assert len(stop_result) == 1
    sniffer = _ReadySniffer.instances[-1]
    assert sniffer.stop_calls == 1
    assert not sniffer.running
    assert not session.running


def test_raising_stop_is_observable_after_flow_cleanup(monkeypatch) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        _RaisingStopSniffer,
    )
    session = _session()
    session.start()
    manager = session._manager
    assert manager is not None
    finish_calls = 0
    original_finish = manager.finish

    def finish() -> None:
        nonlocal finish_calls
        finish_calls += 1
        original_finish()

    monkeypatch.setattr(manager, "finish", finish)

    with pytest.raises(OSError) as caught:
        session.stop()

    assert caught.value is _RaisingStopSniffer.failure
    assert finish_calls == 1
    assert session.error is _RaisingStopSniffer.failure
    assert not session.running
    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


def test_incomplete_capture_stop_keeps_calibration_flow_owner_for_retry(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        _UncooperativeStopSniffer,
    )
    session = _session()
    session.start()
    capture = session._capture
    manager = session._manager
    assert capture is not None
    assert manager is not None
    finish_calls = 0
    original_finish = manager.finish

    def finish() -> None:
        nonlocal finish_calls
        finish_calls += 1
        original_finish()

    monkeypatch.setattr(manager, "finish", finish)

    with pytest.raises(RuntimeError, match="cleanup is incomplete") as first:
        session.stop()

    sniffer = _ReadySniffer.instances[-1]
    thread = sniffer.thread
    assert isinstance(thread, _ControlledThread)
    assert first.value.__cause__ is _UncooperativeStopSniffer.failure
    assert thread.join_calls == [capture_runtime._CAPTURE_JOIN_TIMEOUT_SECONDS]
    assert finish_calls == 0
    assert session._capture is capture
    assert session._manager is manager
    assert session.cleanup_incomplete
    assert capture.cleanup_incomplete

    thread.alive = False
    sniffer.running = False
    with pytest.raises(RuntimeError) as retried:
        session.stop()

    assert retried.value is first.value
    assert finish_calls == 1
    assert session._capture is None
    assert session._manager is None
    assert not session.cleanup_incomplete
    assert capture.stopped


def test_incomplete_startup_cleanup_keeps_calibration_owner_until_stop_retry(
    monkeypatch,
) -> None:
    startup_failure = RuntimeError("capture startup timed out")

    class IncompleteStartupCapture:
        instances = []

        def __init__(self, **kwargs: object) -> None:
            self.running = True
            self.stopped = False
            self.cleanup_incomplete = True
            self.cleanup_error = RuntimeError("capture cleanup is incomplete")
            self.error = startup_failure
            self.__class__.instances.append(self)

        def start(self) -> None:
            raise startup_failure

        def stop(self) -> None:
            self.running = False
            self.stopped = True
            self.cleanup_incomplete = False
            self.cleanup_error = None

        def raise_if_failed(self) -> None:
            raise startup_failure

    monkeypatch.setattr(
        calibration_capture,
        "LivePacketCapture",
        IncompleteStartupCapture,
    )
    session = _session()

    with pytest.raises(RuntimeError) as started:
        session.start()

    capture = IncompleteStartupCapture.instances[-1]
    manager = session._manager
    assert started.value is startup_failure
    assert started.value.cleanup_owner is session
    assert session._capture is capture
    assert manager is not None
    assert session.cleanup_incomplete

    with pytest.raises(RuntimeError) as stopped:
        session.stop()

    assert stopped.value is startup_failure
    assert session._capture is None
    assert session._manager is None
    assert not session.cleanup_incomplete
    assert capture.stopped


def test_context_exit_stops_capture_and_preserves_block_exception(
    monkeypatch,
) -> None:
    monkeypatch.setattr(capture_runtime, "_new_async_sniffer", _ReadySniffer)
    session = _session()
    failure = LookupError("application failed")

    with pytest.raises(LookupError) as caught:
        with session:
            raise failure

    assert caught.value is failure
    sniffer = _ReadySniffer.instances[-1]
    assert sniffer.stop_calls == 1
    assert not sniffer.running
    assert not session.running


def test_context_cleanup_failure_is_retained_without_masking_block_error(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        capture_runtime,
        "_new_async_sniffer",
        _RaisingStopSniffer,
    )
    session = _session()
    block_failure = LookupError("application failed")

    with pytest.raises(LookupError) as caught:
        with session:
            raise block_failure

    assert caught.value is block_failure
    assert session.error is _RaisingStopSniffer.failure
    assert any(
        "context cleanup also failed" in note
        for note in caught.value.__notes__
    )
    assert not session.running


def test_calibrate_live_polls_and_propagates_background_failure(
    monkeypatch,
) -> None:
    failure = RuntimeError("background capture failed")
    state = {"entered": False, "exited": False, "stopped": False}

    class FakeSession:
        def __init__(self, **kwargs: object) -> None:
            pass

        def __enter__(self):
            state["entered"] = True
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            state["exited"] = True

        def raise_if_failed(self) -> None:
            raise failure

        def stop(self) -> CalibrationResult:
            state["stopped"] = True
            return CalibrationResult(
                (),
                (),
                0,
                retention=CalibrationRetention(0, 0, 0, 0, 0, 0),
            )

    monkeypatch.setattr(calibration_capture, "CalibrationSession", FakeSession)
    monkeypatch.setattr(
        "time.sleep",
        lambda seconds: pytest.fail("failure polling must precede waiting"),
    )

    with pytest.raises(RuntimeError) as caught:
        calibration_module.calibrate_live(item_id=7003, capture_seconds=30)

    assert caught.value is failure
    assert state == {"entered": True, "exited": True, "stopped": False}
