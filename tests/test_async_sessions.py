"""Asyncio facades preserve the synchronous sessions' lifecycle behavior."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue
from threading import Event

import pytest

from bdo_toolkit import (
    AsyncCalibrationSession,
    AsyncLiveCaptureSession,
    BDOEvent,
    EventFilter,
    Flow,
)
from bdo_toolkit import _async_sessions as async_module


_END = object()


def _event(item_id: int) -> BDOEvent:
    return BDOEvent(
        event_type="item_received",
        timestamp=float(item_id),
        flow=Flow("203.0.113.1", 8889, "198.51.100.2", 50000),
        item_id=item_id,
        quantity=1,
    )


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
        self.start_calls = 0
        self.stop_calls = 0
        self.abort_calls = 0
        self.start_entered = Event()
        self.start_release = Event()
        self.start_release.set()
        self.stop_entered = Event()
        self.stop_release = Event()
        self.stop_release.set()
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
        self._running = False
        return self.result

    def __exit__(self, exc_type, exc_value, traceback):
        if self._running:
            self.abort_calls += 1
            self._running = False


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
        session = AsyncLiveCaptureSession()
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
        session = AsyncLiveCaptureSession()
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


def test_async_live_background_error_surfaces_after_queued_event(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession()
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
        session = AsyncLiveCaptureSession()
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
        session = AsyncLiveCaptureSession()
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        first_consumer = asyncio.create_task(session.poll())
        await asyncio.to_thread(fake.poll_entered.wait, 1.0)
        with pytest.raises(RuntimeError, match="one consumer"):
            await session.poll(timeout=0)

        await session.stop()
        await first_consumer

    asyncio.run(scenario())


def test_async_live_concurrent_stop_calls_share_one_shutdown(
    fake_async_sessions,
):
    async def scenario():
        session = AsyncLiveCaptureSession()
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


def test_async_live_stop_does_not_depend_on_host_default_executor_capacity(
    fake_async_sessions,
):
    async def scenario():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        session = AsyncLiveCaptureSession()
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
        session = AsyncLiveCaptureSession()
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
        session = AsyncLiveCaptureSession()
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
        session = AsyncLiveCaptureSession()
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


def test_async_live_poll_forwards_timeout(fake_async_sessions):
    async def scenario():
        session = AsyncLiveCaptureSession()
        await session.start()
        fake = FakeLiveCaptureSession.instances[-1]

        assert await session.poll(timeout=0.01) is None
        assert fake.poll_calls == [0.01]
        await session.stop()

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
