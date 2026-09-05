"""Asyncio facades preserve the synchronous sessions' lifecycle behavior."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue
from threading import Event

import pytest

from _support.capture import item_event as _event

from bdo_toolkit import (
    AsyncCalibrationSession,
    AsyncLiveCaptureSession,
    EventFilter,
    _async_sessions as async_module,
)


_END = object()


class FakeLiveCaptureSession:
    instances: list["FakeLiveCaptureSession"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self._running = False
        self.stopped = False
        self.stop_reason = None
        self.error = None
        self.start_error = None
        self.stop_error = None
        self.cleanup_incomplete = False
        self.start_calls = 0
        self.stop_calls = 0
        self.poll_calls = []
        self.start_entered = Event()
        self.start_release = Event()
        self.start_release.set()
        self.stop_entered = Event()
        self.stop_release = Event()
        self.stop_release.set()
        self.poll_entered = Event()
        self.final_event = None
        self._events = Queue()
        self.__class__.instances.append(self)

    @property
    def running(self):
        return self._running

    def start(self):
        self.start_calls += 1
        self.start_entered.set()
        self.start_release.wait()
        if self.start_error is not None:
            raise self.start_error
        if self.started:
            raise RuntimeError("live capture session was already started")
        self.started = True
        self._running = True

    def stop(self):
        if not self.started:
            raise RuntimeError("live capture session was not started")
        self.stop_calls += 1
        self.stop_entered.set()
        self.stop_release.wait()
        if self.stop_error is not None:
            raise self.stop_error
        if self.stopped:
            return
        self._running = False
        if self.final_event is not None:
            self._events.put(self.final_event)
        self.stopped = True
        self.stop_reason = "error" if self.error is not None else "requested"
        self._events.put(_END)

    def poll(self, timeout=None):
        if not self.started:
            raise RuntimeError("live capture session was not started")
        self.poll_calls.append(timeout)
        self.poll_entered.set()
        try:
            if timeout is None:
                value = self._events.get()
            else:
                value = self._events.get(timeout=timeout)
        except Empty:
            return None
        if value is _END:
            if self.error is not None:
                raise self.error
            return None
        return value

    def emit(self, event):
        self._events.put(event)

    def raise_if_failed(self):
        if self.error is not None:
            raise self.error


class FakeCalibrationSession:
    instances: list["FakeCalibrationSession"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self._running = False
        self.frames_collected = 0
        self.frames_observed = 0
        self.frames_retained = 0
        self.frames_discarded = 0
        self.bytes_observed = 0
        self.bytes_retained = 0
        self.bytes_discarded = 0
        self.retention_truncated = False
        self.retention = object()
        self.cleanup_incomplete = False
        self.stop_error = None
        self.abort_error = None
        self.start_calls = 0
        self.stop_calls = 0
        self.abort_calls = 0
        self.start_entered = Event()
        self.start_release = Event()
        self.start_release.set()
        self.stop_entered = Event()
        self.stop_release = Event()
        self.stop_release.set()
        self.abort_entered = Event()
        self.abort_release = Event()
        self.abort_release.set()
        self.result = object()
        self.__class__.instances.append(self)

    @property
    def running(self):
        return self._running

    def start(self):
        self.start_calls += 1
        self.start_entered.set()
        self.start_release.wait()
        if self._running:
            raise RuntimeError("calibration session is already running")
        self._running = True

    def stop(self):
        if not self._running:
            raise RuntimeError("calibration session was not started")
        self.stop_calls += 1
        self.stop_entered.set()
        self.stop_release.wait()
        if self.stop_error is not None:
            raise self.stop_error
        self._running = False
        self.cleanup_incomplete = False
        return self.result

    def __exit__(self, exc_type, exc_value, traceback):
        if self._running:
            self.abort_calls += 1
            self.abort_entered.set()
            self.abort_release.wait()
            if self.abort_error is not None:
                self.cleanup_incomplete = True
                raise self.abort_error
            self._running = False
            self.cleanup_incomplete = False


@pytest.fixture
def fake_async_sessions(monkeypatch):
    FakeLiveCaptureSession.instances.clear()
    FakeCalibrationSession.instances.clear()
    monkeypatch.setattr(
        async_module,
        "LiveCaptureSession",
        FakeLiveCaptureSession,
    )
    monkeypatch.setattr(
        async_module,
        "CalibrationSession",
        FakeCalibrationSession,
    )


def test_async_live_context_forwards_configuration_and_stops(fake_async_sessions):
    async def scenario():
        explicit_all = EventFilter()
        async with AsyncLiveCaptureSession(
            opcode_profile="opcodes.local",
            event_filter=explicit_all,
        ) as session:
            fake = FakeLiveCaptureSession.instances[-1]
            assert session.running
            assert not session.stopped
            assert fake.kwargs["opcode_profile"] == "opcodes.local"
            assert fake.kwargs["event_filter"] is explicit_all

        assert session.stopped
        assert session.stop_reason == "requested"
        assert fake.stop_calls == 1

    asyncio.run(scenario())


def test_async_live_poll_before_start_fails_without_starting_worker(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        fake = FakeLiveCaptureSession.instances[-1]

        with pytest.raises(RuntimeError, match="not started"):
            await session.poll()
        with pytest.raises(RuntimeError, match="not started"):
            await session.stop()
        assert not fake.poll_entered.is_set()
        assert fake.stop_calls == 0

    asyncio.run(scenario())


def test_async_live_iterator_drains_finalized_tail_after_external_stop(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        received = []

        async def consume():
            async for event in session:
                received.append(event)

        consumer = asyncio.create_task(consume())
        await asyncio.to_thread(fake.poll_entered.wait, 1.0)
        first = _event(1)
        finalized = _event(2)
        fake.emit(first)
        fake.final_event = finalized

        await session.stop()
        await asyncio.wait_for(consumer, 1.0)

        assert received == [first, finalized]

    asyncio.run(scenario())


def test_async_live_events_preserve_ready_event_order(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        expected = [_event(index) for index in range(3)]
        for event in expected:
            fake.emit(event)

        iterator = session.events()
        received = [await anext(iterator) for _ in expected]

        assert received == expected
        assert fake.poll_calls == [None, None, None]
        await iterator.aclose()
        await session.stop()

    asyncio.run(scenario())


def test_async_live_iterator_handoff_to_poll_preserves_ready_events(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        expected = [_event(index) for index in range(3)]
        for event in expected:
            fake.emit(event)

        iterator = session.events()
        assert await anext(iterator) is expected[0]
        assert await session.poll(timeout=0) is expected[1]
        assert await session.poll(timeout=0) is expected[2]
        assert fake.poll_calls == [None, 0, 0]

        await iterator.aclose()
        await session.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize("invalid_timeout", [-1, True, float("nan")])
def test_async_live_active_poll_validates_timeout_before_worker_submission(
    fake_async_sessions,
    invalid_timeout,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        with pytest.raises(ValueError, match="timeout"):
            await session.poll(timeout=invalid_timeout)

        assert fake.poll_calls == []
        await session.stop()

    asyncio.run(scenario())


def test_async_live_early_iterator_close_leaves_later_events_available(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        expected = [_event(index) for index in range(3)]
        for event in expected:
            fake.emit(event)

        iterator = session.events()
        assert await anext(iterator) is expected[0]
        await iterator.aclose()

        replacement = session.events()
        assert await anext(replacement) is expected[1]
        assert await anext(replacement) is expected[2]
        assert fake.poll_calls == [None, None, None]
        await replacement.aclose()
        await session.stop()

    asyncio.run(scenario())


def test_async_live_early_break_leaves_later_events_available_to_poll(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        expected = [_event(index) for index in range(3)]
        for event in expected:
            fake.emit(event)

        received = []
        async for event in session.events():
            received.append(event)
            break

        assert received == expected[:1]
        assert await session.poll(timeout=0) is expected[1]
        assert await session.poll(timeout=0) is expected[2]
        assert fake.poll_calls == [None, 0, 0]
        await session.stop()

    asyncio.run(scenario())


def test_async_live_consumer_cancellation_after_yield_leaves_later_events(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        expected = [_event(index) for index in range(3)]
        for event in expected:
            fake.emit(event)

        yielded = asyncio.Event()

        async def consume():
            async for event in session.events():
                assert event is expected[0]
                yielded.set()
                await asyncio.Future()

        consumer = asyncio.create_task(consume())
        await asyncio.wait_for(yielded.wait(), 1.0)
        consumer.cancel()
        with pytest.raises(asyncio.CancelledError):
            await consumer

        assert not session.stopped
        assert fake.stop_calls == 0
        assert await session.poll(timeout=0) is expected[1]
        assert await session.poll(timeout=0) is expected[2]
        await session.stop()

    asyncio.run(scenario())


def test_async_live_cancelled_iterator_next_preserves_settled_event(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        finalized = _event(9)
        fake.final_event = finalized
        iterator = session.events()

        pending = asyncio.create_task(anext(iterator))
        await asyncio.to_thread(fake.poll_entered.wait, 1.0)
        pending.cancel()

        with pytest.raises(asyncio.CancelledError):
            await pending

        assert session.stopped
        replacement = session.events()
        assert await anext(replacement) is finalized
        assert fake.poll_calls == [None]
        with pytest.raises(StopAsyncIteration):
            await anext(replacement)

    asyncio.run(scenario())


def test_async_live_cancelled_poll_preserves_settled_event(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        finalized = _event(9)
        fake.final_event = finalized

        pending = asyncio.create_task(session.poll())
        await asyncio.to_thread(fake.poll_entered.wait, 1.0)
        pending.cancel()

        with pytest.raises(asyncio.CancelledError):
            await pending

        assert session.stopped
        assert await session.poll(timeout=0) is finalized
        assert fake.poll_calls == [None]

    asyncio.run(scenario())


def test_async_live_stopped_session_drains_before_retained_error(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        expected = [_event(index) for index in range(3)]
        for event in expected:
            fake.emit(event)
        fake.error = OSError("decoder failed after buffered events")
        await session.stop()

        iterator = session.events()
        assert await anext(iterator) is expected[0]
        assert await session.poll(timeout=-1) is expected[1]
        assert await session.poll(timeout=-1) is expected[2]
        with pytest.raises(OSError, match="decoder failed after buffered events"):
            await session.poll(timeout=-1)
        await iterator.aclose()

    asyncio.run(scenario())


def test_async_live_background_error_surfaces_after_queued_event(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        emitted = _event(5)
        fake.emit(emitted)
        fake.error = OSError("decoder failed")

        received = []
        with pytest.raises(OSError, match="decoder failed"):
            async for event in session:
                received.append(event)
                await session.stop()

        assert received == [emitted]
        assert isinstance(session.error, OSError)
        with pytest.raises(OSError, match="decoder failed"):
            session.raise_if_failed()

    asyncio.run(scenario())


def test_cancelling_quiet_async_poll_stops_and_wakes_session(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        pending = asyncio.create_task(session.poll())
        await asyncio.to_thread(fake.poll_entered.wait, 1.0)
        pending.cancel()

        with pytest.raises(asyncio.CancelledError):
            await pending

        assert session.stopped
        assert fake.stop_calls == 1
        assert fake.poll_calls == [None]

    asyncio.run(scenario())


def test_async_live_rejects_concurrent_consumers(fake_async_sessions):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        first_consumer = asyncio.create_task(session.poll())
        await asyncio.to_thread(fake.poll_entered.wait, 1.0)
        with pytest.raises(RuntimeError, match="one consumer"):
            await session.poll(timeout=0)

        await session.stop()
        await first_consumer

    asyncio.run(scenario())


def test_async_live_rejects_poll_while_iterator_fetch_is_active(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        iterator = session.events()

        first_consumer = asyncio.create_task(anext(iterator))
        await asyncio.to_thread(fake.poll_entered.wait, 1.0)
        with pytest.raises(RuntimeError, match="one consumer"):
            await session.poll(timeout=0)

        await session.stop()
        with pytest.raises(StopAsyncIteration):
            await first_consumer

    asyncio.run(scenario())


def test_async_live_concurrent_stop_calls_share_one_shutdown(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        fake.stop_release.clear()

        first = asyncio.create_task(session.stop())
        await asyncio.to_thread(fake.stop_entered.wait, 1.0)
        second = asyncio.create_task(session.stop())
        first.cancel()
        fake.stop_release.set()

        with pytest.raises(asyncio.CancelledError):
            await first
        await second
        assert fake.stop_calls == 1

    asyncio.run(scenario())


def test_async_live_second_start_preserves_cleanup_executor(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        with pytest.raises(RuntimeError, match="already started"):
            await session.start()

        assert not session._executor_closed
        assert fake.start_calls == 1
        await session.stop()
        assert fake.stop_calls == 1
        assert session._executor_closed

    asyncio.run(scenario())


def test_async_live_stop_does_not_depend_on_host_default_executor_capacity(
    fake_async_sessions,
):
    async def scenario():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        pending = asyncio.create_task(session.poll())
        while not fake.poll_entered.is_set():
            await asyncio.sleep(0)

        await asyncio.wait_for(session.stop(), 1.0)
        assert await asyncio.wait_for(pending, 1.0) is None

    asyncio.run(scenario())


def test_async_live_cancelled_start_cleans_up_late_success(fake_async_sessions):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        fake = FakeLiveCaptureSession.instances[-1]
        fake.start_release.clear()

        start = asyncio.create_task(session.start())
        await asyncio.to_thread(fake.start_entered.wait, 1.0)
        start.cancel()
        fake.start_release.set()

        with pytest.raises(asyncio.CancelledError):
            await start
        assert fake.stopped
        assert fake.stop_calls == 1

    asyncio.run(scenario())


def test_async_live_failed_start_closes_wrapper_executor(fake_async_sessions):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        fake = FakeLiveCaptureSession.instances[-1]
        fake.start_error = OSError("adapter unavailable")

        with pytest.raises(OSError, match="adapter unavailable"):
            await session.start()

        assert session._executor_closed

    asyncio.run(scenario())


def test_cancelled_async_live_stop_keeps_cancellation_on_cleanup_failure(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        fake.stop_release.clear()
        fake.stop_error = OSError("cleanup failed")

        stopping = asyncio.create_task(session.stop())
        await asyncio.to_thread(fake.stop_entered.wait, 1.0)
        stopping.cancel()
        fake.stop_release.set()

        with pytest.raises(asyncio.CancelledError):
            await stopping
        assert session._executor_closed

    asyncio.run(scenario())


def test_async_live_incomplete_cleanup_can_be_retried(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        cleanup_error = OSError("native capture is still running")
        fake.cleanup_incomplete = True
        fake.stop_error = cleanup_error

        with pytest.raises(OSError) as raised:
            await session.stop()

        assert raised.value is cleanup_error
        assert session.cleanup_incomplete
        assert not session._executor_closed
        assert fake.stop_calls == 1

        fake.cleanup_incomplete = False
        fake.stop_error = None
        await session.stop()

        assert session.stopped
        assert session._executor_closed
        assert fake.stop_calls == 2

    asyncio.run(scenario())


def test_cancelled_async_live_incomplete_cleanup_retries_on_next_stop(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        cleanup_error = OSError("native capture is still running")
        fake.cleanup_incomplete = True
        fake.stop_error = cleanup_error
        fake.stop_release.clear()

        stopping = asyncio.create_task(session.stop())
        await asyncio.to_thread(fake.stop_entered.wait, 1.0)
        stopping.cancel()
        fake.stop_release.set()

        with pytest.raises(asyncio.CancelledError):
            await stopping

        assert session.cleanup_incomplete
        assert not session._executor_closed
        assert session._stop_future is None

        fake.cleanup_incomplete = False
        fake.stop_error = None
        await session.stop()

        assert session.stopped
        assert session._executor_closed
        assert fake.stop_calls == 2

    asyncio.run(scenario())


def test_async_live_poll_forwards_timeout(fake_async_sessions):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        assert await session.poll(timeout=0.01) is None
        assert fake.poll_calls == [0.01]
        await session.stop()

    asyncio.run(scenario())


def test_async_live_stopped_poll_ignores_timeout_while_draining(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession(opcode_profile="opcodes.local")
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]
        queued = _event(1)
        finalized = _event(2)
        fake.emit(queued)
        fake.final_event = finalized
        await session.stop()

        assert await session.poll(timeout=float("nan")) is queued
        assert await session.poll(timeout=float("nan")) is finalized
        assert await session.poll(timeout=float("nan")) is None
        assert fake.poll_calls == [0, 0, 0]

    asyncio.run(scenario())


def test_async_calibration_returns_result_without_context_abort(
    fake_async_sessions,
):
    async def scenario():
        async with AsyncCalibrationSession(item_id=7003, quantity=3) as session:
            fake = FakeCalibrationSession.instances[-1]
            fake.frames_collected = 12
            assert session.frames_collected == 12
            result = await session.stop()
            assert await session.stop() is result

        assert result is fake.result
        assert session.result is result
        assert fake.stop_calls == 1
        assert fake.abort_calls == 0

    asyncio.run(scenario())


def test_async_calibration_forwards_and_exposes_retention(fake_async_sessions):
    session = AsyncCalibrationSession(
        item_id=7003,
        max_retained_frames=321,
        max_retained_bytes=65_432,
    )
    fake = FakeCalibrationSession.instances[-1]

    assert fake.kwargs["max_retained_frames"] == 321
    assert fake.kwargs["max_retained_bytes"] == 65_432

    fake.frames_observed = 7
    fake.frames_retained = 5
    fake.frames_discarded = 2
    fake.bytes_observed = 700
    fake.bytes_retained = 500
    fake.bytes_discarded = 200
    fake.retention_truncated = True

    assert session.frames_observed == 7
    assert session.frames_retained == 5
    assert session.frames_discarded == 2
    assert session.bytes_observed == 700
    assert session.bytes_retained == 500
    assert session.bytes_discarded == 200
    assert session.retention_truncated
    assert session.retention is fake.retention


def test_async_calibration_context_aborts_when_no_result_requested(
    fake_async_sessions,
):
    async def scenario():
        async with AsyncCalibrationSession(item_id=7003) as session:
            assert session.running

        fake = FakeCalibrationSession.instances[-1]
        assert not session.running
        assert session.result is None
        assert fake.stop_calls == 0
        assert fake.abort_calls == 1

    asyncio.run(scenario())


def test_cancelled_async_calibration_stop_preserves_exact_result(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncCalibrationSession(item_id=7003)
        await session.start()
        fake = FakeCalibrationSession.instances[-1]
        fake.stop_release.clear()

        stopping = asyncio.create_task(session.stop())
        await asyncio.to_thread(fake.stop_entered.wait, 1.0)
        stopping.cancel()
        fake.stop_release.set()

        with pytest.raises(asyncio.CancelledError):
            await stopping

        assert session.result is fake.result
        assert await session.stop() is fake.result
        assert fake.stop_calls == 1

    asyncio.run(scenario())


def test_async_calibration_incomplete_cleanup_can_be_retried(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncCalibrationSession(item_id=7003)
        await session.start()
        fake = FakeCalibrationSession.instances[-1]
        cleanup_error = OSError("calibration capture is still running")
        fake.cleanup_incomplete = True
        fake.stop_error = cleanup_error

        with pytest.raises(OSError) as raised:
            await session.stop()

        assert raised.value is cleanup_error
        assert session.cleanup_incomplete
        assert session.running
        assert fake.stop_calls == 1

        fake.cleanup_incomplete = False
        fake.stop_error = None
        assert await session.stop() is fake.result

        assert session.result is fake.result
        assert not session.running
        assert fake.stop_calls == 2

    asyncio.run(scenario())


def test_async_calibration_abort_is_idempotent_and_prevents_stop(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncCalibrationSession(item_id=7003)
        await session.start()
        fake = FakeCalibrationSession.instances[-1]

        await session.abort()
        await session.abort()

        assert fake.abort_calls == 1
        with pytest.raises(RuntimeError, match="aborted"):
            await session.stop()

    asyncio.run(scenario())


def test_cancelled_async_calibration_abort_preserves_retryable_cleanup(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncCalibrationSession(item_id=7003)
        await session.start()
        fake = FakeCalibrationSession.instances[-1]
        cleanup_error = OSError("calibration capture is still running")
        fake.abort_error = cleanup_error
        fake.abort_release.clear()

        aborting = asyncio.create_task(session.abort())
        assert await asyncio.to_thread(fake.abort_entered.wait, 1.0)
        aborting.cancel()
        fake.abort_release.set()

        with pytest.raises(asyncio.CancelledError):
            await aborting

        assert session.cleanup_incomplete
        assert session.running
        assert fake.abort_calls == 1

        fake.abort_error = None
        await session.abort()
        assert not session.running
        assert fake.abort_calls == 2

    asyncio.run(scenario())


def test_async_calibration_cancelled_start_aborts_late_success(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncCalibrationSession(item_id=7003)
        fake = FakeCalibrationSession.instances[-1]
        fake.start_release.clear()

        starting = asyncio.create_task(session.start())
        await asyncio.to_thread(fake.start_entered.wait, 1.0)
        starting.cancel()
        fake.start_release.set()

        with pytest.raises(asyncio.CancelledError):
            await starting
        assert fake.abort_calls == 1
        assert not fake.running

    asyncio.run(scenario())


@pytest.mark.parametrize("prior_terminal", ["stop", "abort"])
def test_async_calibration_cancelled_reuse_exposes_current_run_for_retry(
    fake_async_sessions,
    prior_terminal,
):
    async def scenario():
        session = AsyncCalibrationSession(item_id=7003)
        fake = FakeCalibrationSession.instances[-1]
        first_result = object()
        second_result = object()
        fake.result = first_result

        await session.start()
        if prior_terminal == "stop":
            assert await session.stop() is first_result
        else:
            await session.abort()
        prior_stop_calls = fake.stop_calls
        prior_abort_calls = fake.abort_calls

        fake.result = second_result
        fake.start_entered.clear()
        fake.start_release.clear()
        cleanup_error = OSError("second calibration cleanup is incomplete")
        fake.abort_error = cleanup_error

        starting = asyncio.create_task(session.start())
        await asyncio.to_thread(fake.start_entered.wait, 1.0)
        starting.cancel()
        fake.start_release.set()

        with pytest.raises(asyncio.CancelledError) as cancelled:
            await starting

        assert cancelled.value.cleanup_owner is session
        assert session.cleanup_incomplete
        assert session.running
        assert session.result is None
        assert fake.abort_calls == prior_abort_calls + 1

        fake.abort_error = None
        fake.cleanup_incomplete = False
        assert await session.stop() is second_result
        assert fake.stop_calls == prior_stop_calls + 1
        assert not session.running
        assert session.result is second_result

    asyncio.run(scenario())
