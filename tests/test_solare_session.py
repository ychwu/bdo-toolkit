"""Lifecycle coverage for the synchronous and asyncio Solare sessions."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

import pytest

from bdo_toolkit._capture_runtime import CaptureEndpoint, CaptureStats
from bdo_toolkit.solare.async_session import AsyncLiveSolareSession
from bdo_toolkit.solare.models import (
    SolareCaptureHealth,
    SolareCaptureEndpoint,
    SolareCaptureResult,
    SolareClass,
    SolareDetectionStatus,
    SolareEvidence,
    SolareLeaderboardSnapshot,
    SolarePlayer,
    SolareUpdate,
    SolareUpdateKind,
    solare_snapshot_id,
)
from bdo_toolkit.solare.session import LiveSolareSession
from bdo_toolkit.solare import session as session_module


def _classified_result(
    health: SolareCaptureHealth,
    *,
    complete: bool,
) -> SolareCaptureResult:
    evidence = SolareEvidence(
        ranked_players=620 if complete else 0,
        overall_players=100 if complete else 0,
        exact_cross_check=100 if complete else 0,
        health=health,
    )
    if not complete:
        status = (
            SolareDetectionStatus.INCONCLUSIVE
            if health.payload_segments
            else SolareDetectionStatus.NO_TRAFFIC
        )
        return SolareCaptureResult(status=status, evidence=evidence)

    player = SolarePlayer(
        name="TestPlayer",
        global_rank=1,
        primary_class=SolareClass(0, "Warrior"),
    )
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id=solare_snapshot_id((player,)),
        observed_at=1234.5,
        players=(player,),
        evidence=evidence,
    )
    return SolareCaptureResult(
        status=SolareDetectionStatus.COMPLETE,
        evidence=evidence,
        snapshot=snapshot,
    )


def _generic_stream(first_opcode: int) -> bytes:
    return b"".join(
        (5).to_bytes(2, "little")
        + b"\x00"
        + opcode.to_bytes(2, "little")
        for opcode in range(first_opcode, first_opcode + 3)
    )


class _FakeWriter:
    instances: list["_FakeWriter"] = []

    def __init__(self, path: Path) -> None:
        self.path = path
        self.packets: list[object] = []
        self.flush_calls = 0
        self.closed = False
        self.__class__.instances.append(self)

    def write(self, packet: object) -> None:
        self.packets.append(packet)

    def flush(self) -> None:
        self.flush_calls += 1

    def close(self) -> None:
        self.closed = True


def _install_live_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    packets: tuple[bytes, ...] = (),
    complete_after: Optional[int] = None,
    runtime_error: Optional[BaseException] = None,
    confirmation_stats: Optional[CaptureStats] = None,
    final_stats: Optional[CaptureStats] = None,
    complete_on_refresh: bool = False,
) -> dict[str, Any]:
    state: dict[str, Any] = {"captures": [], "health": []}
    _FakeWriter.instances.clear()

    class FakeCapture:
        def __init__(self, **kwargs: Any) -> None:
            self.on_packet = kwargs["on_packet"]
            self.endpoint = CaptureEndpoint(
                interface="fake-interface",
                local_ip="192.0.2.50",
                bpf_filter="tcp",
            )
            self.running = False
            self.stopped = False
            self.stop_calls = 0
            state["captures"].append(self)

        @property
        def error(self) -> Optional[BaseException]:
            return runtime_error if self.running else None

        def start(self) -> None:
            self.running = True
            for packet in packets:
                self.on_packet(packet)

        def stop(self) -> CaptureStats:
            self.stop_calls += 1
            self.running = False
            self.stopped = True
            return final_stats or CaptureStats(
                received=len(packets),
                dropped=0,
                interface_dropped=0,
                capture_buffer_bytes=64 * 1024 * 1024,
            )

        def snapshot_stats(self) -> CaptureStats:
            return confirmation_stats or CaptureStats(
                received=len(packets),
                dropped=0,
                interface_dropped=0,
                capture_buffer_bytes=64 * 1024 * 1024,
            )

    class FakeTracker:
        def __init__(self, emit: Any) -> None:
            self._emit = emit
            self.observed = 0
            self.complete = False

        def _confirm(self) -> None:
            if self.complete:
                return
            self.complete = True
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.SNAPSHOT_CONFIRMED,
                    message="snapshot confirmed",
                    ranked_players=620,
                    overall_players=100,
                    exact_cross_check=100,
                )
            )

        def observe(self, _frame: object) -> None:
            self.observed += 1
            if self.observed == 1:
                self._emit(
                    SolareUpdate(
                        kind=SolareUpdateKind.RANKED_PROGRESS,
                        message="400 ranked players recovered",
                        ranked_players=400,
                    )
                )
            if (
                complete_after is not None
                and self.observed >= complete_after
                and not complete_on_refresh
            ):
                self._confirm()

        def refresh(self) -> None:
            if (
                complete_on_refresh
                and complete_after is not None
                and self.observed >= complete_after
            ):
                self._confirm()

    def fake_packet_handler(collector: Any):
        sequence = 10_000
        timestamp = 1000.0

        def handle(packet: object) -> None:
            nonlocal sequence, timestamp
            assert isinstance(packet, bytes)
            collector.process_tcp_segment(
                source_ip="198.51.100.10",
                source_port=collector.ports[0],
                destination_ip="192.0.2.50",
                destination_port=51000,
                sequence=sequence,
                payload=packet,
                timestamp=timestamp,
            )
            sequence += len(packet)
            timestamp += 1

        return handle

    def fake_build(
        _frames: object,
        health: SolareCaptureHealth,
    ) -> SolareCaptureResult:
        state["health"].append(health)
        return _classified_result(health, complete=complete_after is not None)

    def fake_open_writer(path: Path) -> _FakeWriter:
        return _FakeWriter(path)

    monkeypatch.setattr(session_module, "LivePacketCapture", FakeCapture)
    monkeypatch.setattr(session_module, "LiveSolareDiscoveryTracker", FakeTracker)
    monkeypatch.setattr(session_module, "make_packet_handler", fake_packet_handler)
    monkeypatch.setattr(session_module, "build_solare_result", fake_build)
    monkeypatch.setattr(
        LiveSolareSession,
        "_open_writer",
        staticmethod(fake_open_writer),
    )
    return state


def test_live_session_reports_progress_auto_stops_and_drains_packets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100), _generic_stream(0x2200)),
        complete_after=3,
    )
    callback_updates: list[SolareUpdate] = []
    session = LiveSolareSession(
        save_pcap="solare-session-test-output.pcapng",
        on_update=callback_updates.append,
    )

    session.start()
    assert session.endpoint == SolareCaptureEndpoint(
        interface="fake-interface",
        local_ip="192.0.2.50",
        bpf_filter="tcp",
    )
    result = session.wait(timeout=2)

    assert result is not None and result.complete
    assert session.stop_reason == "complete-snapshot"
    assert session.stopped and not session.running
    updates = list(session.updates())
    kinds = [update.kind for update in updates]
    assert kinds == [
        SolareUpdateKind.CAPTURE_READY,
        SolareUpdateKind.TRAFFIC,
        SolareUpdateKind.RANKED_PROGRESS,
        SolareUpdateKind.SNAPSHOT_CONFIRMED,
        SolareUpdateKind.FINISHED,
    ]
    assert [update.kind for update in callback_updates] == kinds
    assert updates[-1].result is result

    health = state["health"][0]
    # Result health is frozen at structural confirmation. The second queued
    # packet is still drained and written, but cannot mutate the snapshot.
    assert health.payload_segments == 1
    assert health.synchronized_messages == 3
    assert health.saved_packets == 1
    assert health.pcap_received == 2
    assert health.pcap_dropped == 0
    assert state["captures"][0].stop_calls == 1
    assert session.stop() is result

    writer = _FakeWriter.instances[0]
    assert writer.packets == [
        _generic_stream(0x1100),
        _generic_stream(0x2200),
    ]
    assert writer.closed


def test_live_session_manual_stop_returns_best_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)
    session = LiveSolareSession(stop_on_complete=False)
    session.start()

    ready = session.poll(timeout=0.5)
    assert ready is not None
    assert ready.kind is SolareUpdateKind.CAPTURE_READY
    result = session.stop()

    assert result.status is SolareDetectionStatus.NO_TRAFFIC
    assert session.stop_reason == "requested"
    assert state["captures"][0].stop_calls == 1
    finished = session.poll(timeout=0)
    assert finished is not None
    assert finished.kind is SolareUpdateKind.FINISHED
    assert session.poll(timeout=0) is None


def test_keep_listening_preserves_health_latched_at_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
        confirmation_stats=CaptureStats(
            received=1,
            dropped=0,
            interface_dropped=0,
            capture_buffer_bytes=64 * 1024 * 1024,
        ),
        final_stats=CaptureStats(
            received=50,
            dropped=7,
            interface_dropped=3,
            capture_buffer_bytes=64 * 1024 * 1024,
        ),
    )
    session = LiveSolareSession(stop_on_complete=False)
    session.start()

    while True:
        update = session.poll(timeout=2)
        assert update is not None
        if update.kind is SolareUpdateKind.SNAPSHOT_CONFIRMED:
            break

    assert session._collector is not None
    session._collector.tcp_gap_resets += 1
    result = session.stop()

    assert result.status is SolareDetectionStatus.COMPLETE
    health = state["health"][-1]
    assert health.capture_is_clean
    assert health.tcp_gap_resets == 0
    assert health.pcap_dropped == 0
    assert health.pcap_interface_dropped == 0


def test_live_session_auto_stops_when_idle_refresh_confirms_final_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
        complete_on_refresh=True,
    )
    session = LiveSolareSession()

    session.start()
    result = session.wait(timeout=2)

    assert result is not None and result.complete
    assert session.stopped
    assert session.stop_reason == "complete-snapshot"


def test_live_session_refuses_to_overwrite_existing_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_exists = Path.exists

    def fake_exists(path: Path) -> bool:
        if path.name == "already-present.pcapng":
            return True
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", fake_exists)
    session = LiveSolareSession(save_pcap="already-present.pcapng")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        session.start()
    assert not session.running


def test_writer_startup_failure_closes_capture_even_if_sniffer_already_ended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)

    def fail_writer(_path: Path) -> object:
        state["captures"][0].running = False
        raise OSError("writer failed")

    monkeypatch.setattr(
        LiveSolareSession,
        "_open_writer",
        staticmethod(fail_writer),
    )
    session = LiveSolareSession(save_pcap="writer-failure-test.pcapng")

    with pytest.raises(OSError, match="writer failed"):
        session.start()

    assert state["captures"][0].stop_calls == 1
    assert state["captures"][0].stopped
    assert not session.running


def test_live_capture_failure_is_retained_and_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = RuntimeError("capture thread failed")
    _install_live_fakes(monkeypatch, runtime_error=expected)
    session = LiveSolareSession()
    session.start()

    with pytest.raises(RuntimeError, match="capture thread failed") as raised:
        session.wait(timeout=2)

    assert raised.value is expected
    assert session.stopped
    assert session.error is expected
    assert session.stop_reason == "error"
    with pytest.raises(RuntimeError, match="capture thread failed"):
        session.stop()


def test_async_live_session_basic_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        async with AsyncLiveSolareSession(stop_on_complete=False) as session:
            ready = await session.poll(timeout=0.5)
            assert ready is not None
            assert ready.kind is SolareUpdateKind.CAPTURE_READY
            result = await session.stop()
            assert result.status is SolareDetectionStatus.NO_TRAFFIC
            assert session.stopped

    asyncio.run(scenario())


def test_async_live_session_rejects_second_start_without_closing_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()
        assert session.endpoint == SolareCaptureEndpoint(
            interface="fake-interface",
            local_ip="192.0.2.50",
            bpf_filter="tcp",
        )

        with pytest.raises(RuntimeError, match="already started"):
            await session.start()

        assert session.running
        assert not session._closed
        result = await session.stop()
        assert result.status is SolareDetectionStatus.NO_TRAFFIC
        assert session._closed
        assert state["captures"][0].stop_calls == 1

    asyncio.run(scenario())


def test_async_live_wait_timeout_keeps_session_reusable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()

        assert await session.wait(timeout=0) is None
        assert not session._closed
        assert await session.wait(timeout=0) is None
        assert not session._closed

        await session.stop()
        assert session._closed

    asyncio.run(scenario())


def test_async_stop_cleans_executor_after_session_auto_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
    )

    async def scenario() -> None:
        session = AsyncLiveSolareSession()
        await session.start()
        while not session.stopped:
            await asyncio.sleep(0)

        result = await session.stop()
        assert result.complete
        assert session._closed

    asyncio.run(scenario())


def test_async_wait_background_failure_closes_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(
        monkeypatch,
        runtime_error=RuntimeError("capture thread failed"),
    )

    async def scenario() -> None:
        session = AsyncLiveSolareSession()
        await session.start()

        with pytest.raises(RuntimeError, match="capture thread failed"):
            await session.wait(timeout=2)

        assert session.stopped
        assert session._closed

    asyncio.run(scenario())


def test_cancelling_async_poll_stops_and_settles_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        async with AsyncLiveSolareSession(stop_on_complete=False) as session:
            ready = await session.poll(timeout=0.5)
            assert ready is not None
            polling = asyncio.create_task(session.poll())
            await asyncio.sleep(0.05)
            polling.cancel()
            with pytest.raises(asyncio.CancelledError):
                await polling
            assert session.stopped
            assert session.stop_reason == "requested"

    asyncio.run(scenario())


def test_async_poll_wait_and_manual_stop_cannot_starve_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()
        ready = await session.poll(timeout=0.5)
        assert ready is not None

        polling = asyncio.create_task(session.poll())
        waiting = asyncio.create_task(session.wait())
        await asyncio.sleep(0.05)
        stopped_result = await asyncio.wait_for(session.stop(), timeout=2)
        update = await asyncio.wait_for(polling, timeout=2)
        waited_result = await asyncio.wait_for(waiting, timeout=2)

        assert stopped_result.status is SolareDetectionStatus.NO_TRAFFIC
        assert waited_result is stopped_result
        assert update is not None
        assert update.kind is SolareUpdateKind.FINISHED

    asyncio.run(scenario())


def test_async_session_rejects_a_second_concurrent_waiter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()
        first = asyncio.create_task(session.wait())
        await asyncio.sleep(0.05)
        with pytest.raises(RuntimeError, match="one waiter"):
            await session.wait(timeout=0.1)

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(first, timeout=2)
        assert session.stopped

    asyncio.run(scenario())
