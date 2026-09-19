"""Agris async ownership and delivery, without opening a capture adapter."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue
from threading import Event

import pytest

from bdo_toolkit._capture_options import LiveCaptureOptions
from bdo_toolkit.agris import async_session as module


_END = object()


class FakeSession:
    instances: list[FakeSession] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.stopped = False
        self.cleanup_incomplete = False
        self.stop_reason = None
        self.error = None
        self.endpoint = object()
        self.status = object()
        self.health = object()
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
        self.poll_dequeued = Event()
        self.poll_release = Event()
        self.poll_release.set()
        self.queue = Queue()
        self.final_balance = None
        self.instances.append(self)

    def start(self):
        self.start_calls += 1
        self.start_entered.set()
        assert self.start_release.wait(3)
        if self.start_error is not None:
            raise self.start_error
        self.running = True

    def stop(self):
        self.stop_calls += 1
        self.stop_entered.set()
        assert self.stop_release.wait(3)
        if self.stop_error is not None:
            raise self.stop_error
        if not self.stopped:
            self.running = False
            self.stopped = True
            self.cleanup_incomplete = False
            self.stop_reason = "requested"
            if self.final_balance is not None:
                self.queue.put(self.final_balance)
            self.queue.put(_END)

    def poll(self, timeout=None):
        self.poll_calls.append(timeout)
        self.poll_entered.set()
        try:
            result = self.queue.get(timeout=timeout)
        except Empty:
            return None
        if result is _END:
            self.queue.put(_END)
            self.raise_if_failed()
            return None
        self.poll_dequeued.set()
        assert self.poll_release.wait(3)
        return result

    def raise_if_failed(self):
        if self.error is not None:
            raise self.error


@pytest.fixture
def fake_sessions(monkeypatch):
    FakeSession.instances.clear()
    monkeypatch.setattr(module, "LiveAgrisSession", FakeSession)


def test_required_cap_has_no_default(fake_sessions):
    with pytest.raises(TypeError, match="expected_maximum_points"):
        module.AsyncLiveAgrisSession()
    assert FakeSession.instances == []


def test_configuration_metadata_and_context_forwarding(fake_sessions, tmp_path):
    async def scenario():
        options = LiveCaptureOptions(event_queue_size=9, packet_queue_size=21)
        discovery = object()
        target = tmp_path / "capture.pcapng"
        async with module.AsyncLiveAgrisSession(
            expected_maximum_points=125_000,
            live_options=options,
            discovery_options=discovery,
            capture_seconds=30,
            save_pcap=target,
        ) as session:
            fake = FakeSession.instances[-1]
            assert fake.kwargs == {
                "expected_maximum_points": 125_000,
                "live_options": options,
                "discovery_options": discovery,
                "capture_seconds": 30,
                "save_pcap": target,
            }
            assert session.running
            assert not session.stopped
            assert session.endpoint is fake.endpoint
            assert session.status is fake.status
            assert session.health is fake.health
            assert session.error is None
            assert not session.cleanup_incomplete
        assert session.stopped
        assert not session.running
        assert session.stop_reason == "requested"
        assert fake.stop_calls == 1
        await session.stop()
        assert fake.stop_calls == 1

    asyncio.run(scenario())


def test_poll_and_stop_before_start_reject_without_worker(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        fake = FakeSession.instances[-1]
        with pytest.raises(RuntimeError, match="not started"):
            await session.poll()
        with pytest.raises(RuntimeError, match="not started"):
            await session.stop()
        assert fake.poll_calls == []
        assert fake.stop_calls == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("timeout", [-1, float("inf"), float("nan"), True, "1"])
def test_active_poll_rejects_invalid_timeout(fake_sessions, timeout):
    async def scenario():
        async with module.AsyncLiveAgrisSession(expected_maximum_points=100_000) as session:
            fake = FakeSession.instances[-1]
            with pytest.raises(ValueError, match="timeout"):
                await session.poll(timeout)
            assert fake.poll_calls == []

    asyncio.run(scenario())


def test_poll_timeout_remains_nonterminal_and_no_prefetch(fake_sessions):
    async def scenario():
        async with module.AsyncLiveAgrisSession(expected_maximum_points=100_000) as session:
            fake = FakeSession.instances[-1]
            assert await session.poll(timeout=0.01) is None
            assert session.running
            assert len(fake.poll_calls) == 1
            assert 0 <= fake.poll_calls[0] <= 0.01
            balance = object()
            fake.queue.put(balance)
            assert await session.poll(timeout=0) is balance
            count = len(fake.poll_calls)
            await asyncio.sleep(0.03)
            assert len(fake.poll_calls) == count

    asyncio.run(scenario())


def test_long_timeout_uses_bounded_slices(fake_sessions):
    async def scenario():
        async with module.AsyncLiveAgrisSession(expected_maximum_points=100_000) as session:
            fake = FakeSession.instances[-1]
            assert await session.poll(timeout=0.24) is None
            assert len(fake.poll_calls) >= 3
            assert all(0 <= value <= 0.1 for value in fake.poll_calls)

    asyncio.run(scenario())


def test_stop_wakes_poll_with_one_default_executor_worker(fake_sessions):
    async def scenario():
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        await session.start()
        fake = FakeSession.instances[-1]
        polling = asyncio.create_task(session.poll())
        assert await asyncio.to_thread(fake.poll_entered.wait, 1)
        await asyncio.wait_for(session.stop(), 1)
        assert await asyncio.wait_for(polling, 1) is None

    asyncio.run(scenario())


def test_only_one_poll_consumer(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        await session.start()
        fake = FakeSession.instances[-1]
        polling = asyncio.create_task(session.poll())
        assert await asyncio.to_thread(fake.poll_entered.wait, 1)
        with pytest.raises(RuntimeError, match="one consumer"):
            await session.poll(0)
        await session.stop()
        assert await polling is None

    asyncio.run(scenario())


def test_cancelled_poll_preserves_dequeued_balance_before_buffered_tail(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        await session.start()
        fake = FakeSession.instances[-1]
        first, second = object(), object()
        fake.queue.put(first)
        fake.queue.put(second)
        fake.poll_release.clear()
        polling = asyncio.create_task(session.poll())
        assert await asyncio.to_thread(fake.poll_dequeued.wait, 1)
        polling.cancel()
        assert await asyncio.to_thread(fake.stop_entered.wait, 1)
        fake.poll_release.set()
        with pytest.raises(asyncio.CancelledError):
            await polling
        assert session.stopped
        assert await session.poll(float("nan")) is first
        assert await session.poll(float("nan")) is second
        assert await session.poll(float("nan")) is None

    asyncio.run(scenario())


def test_cancelled_poll_failed_stop_retains_owner_and_does_not_wait_forever(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        await session.start()
        fake = FakeSession.instances[-1]
        fake.cleanup_incomplete = True
        fake.stop_error = OSError("native shutdown incomplete")
        polling = asyncio.create_task(session.poll())
        assert await asyncio.to_thread(fake.poll_entered.wait, 1)
        polling.cancel()
        with pytest.raises(asyncio.CancelledError) as raised:
            await asyncio.wait_for(polling, 1)
        assert raised.value.cleanup_owner is session
        assert session.cleanup_incomplete
        assert not session._executor_closed
        fake.stop_error = None
        await session.stop()
        assert session.stopped
        assert fake.stop_calls == 2

    asyncio.run(scenario())


def test_cancelled_start_stops_late_success(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        fake = FakeSession.instances[-1]
        fake.start_release.clear()
        starting = asyncio.create_task(session.start())
        assert await asyncio.to_thread(fake.start_entered.wait, 1)
        starting.cancel()
        fake.start_release.set()
        with pytest.raises(asyncio.CancelledError):
            await starting
        assert fake.stop_calls == 1
        assert session.stopped
        assert session._executor_closed

    asyncio.run(scenario())


def test_start_failure_exposes_retryable_owner(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        fake = FakeSession.instances[-1]
        failure = OSError("capture readiness failed")
        fake.start_error = failure
        fake.cleanup_incomplete = True
        with pytest.raises(OSError) as raised:
            await session.start()
        assert raised.value is failure
        assert failure.cleanup_owner is session
        assert not session._executor_closed
        await session.stop()
        assert session.stopped
        assert session._executor_closed

    asyncio.run(scenario())


def test_repeated_concurrent_start_keeps_first_owner(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        fake = FakeSession.instances[-1]
        fake.start_release.clear()
        starting = asyncio.create_task(session.start())
        assert await asyncio.to_thread(fake.start_entered.wait, 1)
        with pytest.raises(RuntimeError, match="already started"):
            await session.start()
        assert not session._executor_closed
        fake.start_release.set()
        await starting
        await session.stop()
        assert fake.start_calls == 1

    asyncio.run(scenario())


def test_cancelled_stop_keeps_cleanup_retryable(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        await session.start()
        fake = FakeSession.instances[-1]
        fake.cleanup_incomplete = True
        fake.stop_error = OSError("native shutdown incomplete")
        fake.stop_release.clear()
        stopping = asyncio.create_task(session.stop())
        assert await asyncio.to_thread(fake.stop_entered.wait, 1)
        stopping.cancel()
        fake.stop_release.set()
        with pytest.raises(asyncio.CancelledError) as raised:
            await stopping
        assert raised.value.cleanup_owner is session
        assert not session._executor_closed
        fake.stop_error = None
        await session.stop()
        assert fake.stop_calls == 2
        assert session._executor_closed

    asyncio.run(scenario())


def test_context_keeps_primary_exception_and_cleanup_owner(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        fake = FakeSession.instances[-1]
        primary = ValueError("consumer failure")
        fake.cleanup_incomplete = True
        fake.stop_error = OSError("native shutdown incomplete")
        with pytest.raises(ValueError) as raised:
            async with session:
                raise primary
        assert raised.value is primary
        assert primary.cleanup_owner is session
        assert any("cleanup also failed" in note for note in primary.__notes__)
        fake.stop_error = None
        await session.stop()

    asyncio.run(scenario())


def test_async_iterator_drains_final_balance(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        await session.start()
        fake = FakeSession.instances[-1]
        first, last = object(), object()
        fake.queue.put(first)
        fake.final_balance = last
        await session.stop()
        assert [balance async for balance in session] == [first, last]

    asyncio.run(scenario())


def test_retained_capture_failure_takes_precedence_over_buffered_observations(fake_sessions):
    async def scenario():
        session = module.AsyncLiveAgrisSession(expected_maximum_points=100_000)
        await session.start()
        fake = FakeSession.instances[-1]
        first = object()
        fake.queue.put(first)
        await session.stop()
        fake.error = OSError("packet loss")
        with pytest.raises(OSError, match="packet loss"):
            await session.poll()
        with pytest.raises(OSError, match="packet loss"):
            session.raise_if_failed()
        with pytest.raises(OSError, match="packet loss"):
            await session.stop()
        assert fake.queue.get_nowait() is first

    asyncio.run(scenario())


@pytest.mark.parametrize("cap", [0, -1, True, 1000.5])
def test_real_sync_validation_rejects_cap_before_executor(monkeypatch, cap):
    def unexpected_executor(**kwargs):
        pytest.fail("invalid cap must fail before allocating an async executor")

    monkeypatch.setattr(module, "ThreadPoolExecutor", unexpected_executor)
    with pytest.raises((TypeError, ValueError), match="maximum_points"):
        module.AsyncLiveAgrisSession(expected_maximum_points=cap)


def test_real_sync_worker_async_delivery_and_owned_duration(monkeypatch):
    """Exercise actual sync ownership under the facade, with only I/O mocked."""

    from bdo_toolkit._capture_runtime import CaptureStats
    from bdo_toolkit.agris import session as sync_module
    from bdo_toolkit.agris.models import AgrisBalance
    from bdo_toolkit.events import Flow

    balance = AgrisBalance(
        remaining_points=99960,
        maximum_points=100000,
        observed_at=123.0,
        flow=Flow("192.0.2.1", 8884, "192.0.2.2", 50000),
        connection_epoch=0,
    )

    class FakeCapture:
        def __init__(self, *, capture_options, on_packet):
            self.on_packet = on_packet
            self.running = False
            self.stopped = False
            self.cleanup_incomplete = False
            self.endpoint = None
            self.stats = CaptureStats()

        def start(self):
            self.running = True
            self.on_packet(balance)

        def stop(self):
            self.running = False
            self.stopped = True

        def snapshot_stats(self):
            return self.stats

        def raise_if_failed(self):
            pass

    monkeypatch.setattr(sync_module, "LivePacketCapture", FakeCapture)

    async def scenario():
        session = module.AsyncLiveAgrisSession(
            expected_maximum_points=100_000, capture_seconds=0.1
        )
        monkeypatch.setattr(
            sync_module, "make_packet_handler", lambda manager: session._session._publish
        )
        async with session:
            assert [event async for event in session] == [balance]
            assert session.stopped
            assert session.stop_reason == "duration"
            assert session.health.packets_accepted == 1
            assert session.health.packets_processed == 1
        assert session._executor_closed

    asyncio.run(scenario())
