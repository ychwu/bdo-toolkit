"""Lifecycle coverage for the synchronous and asyncio Solare sessions."""

from __future__ import annotations

import asyncio
from pathlib import Path
import time
from threading import Event as NativeEvent
from threading import Thread as NativeThread
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
    complete_on_candidate_idle: bool = False,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "captures": [],
        "health": [],
        "build_kwargs": [],
    }
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

    state["capture_class"] = FakeCapture

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
                and not complete_on_candidate_idle
            ):
                self._confirm()

        def refresh(self) -> None:
            if (
                complete_on_candidate_idle
                and complete_after is not None
                and self.observed >= complete_after
            ):
                self._confirm()

        def service_candidate_idle(self, _now: float) -> bool:
            if (
                complete_on_candidate_idle
                and complete_after is not None
                and self.observed >= complete_after
            ):
                self._confirm()
            return self.complete

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
        **kwargs: object,
    ) -> SolareCaptureResult:
        state["health"].append(health)
        state["build_kwargs"].append(kwargs)
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


def test_live_session_forwards_raw_retention_to_result_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
    )
    session = LiveSolareSession(retain_raw_extensions=True)

    session.start()
    result = session.wait(timeout=2)

    assert result is not None and result.complete
    assert state["build_kwargs"] == [{"retain_raw_extensions": True}]


@pytest.mark.parametrize("value", [None, 0, 1, "yes"])
def test_live_session_rejects_non_boolean_raw_retention(value: object) -> None:
    with pytest.raises(
        TypeError,
        match="retain_raw_extensions must be a boolean",
    ):
        LiveSolareSession(
            retain_raw_extensions=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("value", [None, 0, 1, "yes"])
def test_async_session_rejects_non_boolean_raw_retention(value: object) -> None:
    with pytest.raises(
        TypeError,
        match="retain_raw_extensions must be a boolean",
    ):
        AsyncLiveSolareSession(
            retain_raw_extensions=value,  # type: ignore[arg-type]
        )


def test_capture_convenience_forwards_raw_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _classified_result(SolareCaptureHealth(), complete=False)
    observed: dict[str, object] = {}

    class FakeSession:
        running = False

        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)

        def start(self) -> None:
            pass

        def stop(self) -> SolareCaptureResult:
            return expected

    monkeypatch.setattr(session_module, "LiveSolareSession", FakeSession)

    result = session_module.capture_solare_snapshot(
        capture_seconds=0,
        retain_raw_extensions=True,
    )

    assert result is expected
    assert observed["retain_raw_extensions"] is True


def test_capture_convenience_has_a_finite_default_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _classified_result(SolareCaptureHealth(), complete=False)
    stop_calls = 0

    class FakeSession:
        running = False

        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> None:
            pytest.fail(f"deadline should already be expired, got {timeout=}")

        def stop(self) -> SolareCaptureResult:
            nonlocal stop_calls
            stop_calls += 1
            return expected

    monotonic_values = iter((1_000.0, 1_121.0))
    monkeypatch.setattr(session_module, "LiveSolareSession", FakeSession)
    monkeypatch.setattr(
        session_module.time,
        "monotonic",
        lambda: next(monotonic_values),
    )

    result = session_module.capture_solare_snapshot()

    assert result is expected
    assert stop_calls == 1


def test_capture_convenience_exposes_hidden_owner_on_incomplete_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary_failure = RuntimeError("live wait failed")
    cleanup_failure = RuntimeError("live cleanup is incomplete")

    class IncompleteSession:
        instances: list["IncompleteSession"] = []

        def __init__(self, **kwargs: Any) -> None:
            del kwargs
            self.running = True
            self.cleanup_incomplete = False
            self.__class__.instances.append(self)

        def start(self) -> None:
            return None

        def wait(self, timeout: Optional[float] = None) -> None:
            del timeout
            raise primary_failure

        def stop(self) -> SolareCaptureResult:
            self.cleanup_incomplete = True
            raise cleanup_failure

    monkeypatch.setattr(session_module, "LiveSolareSession", IncompleteSession)

    with pytest.raises(RuntimeError) as failed:
        session_module.capture_solare_snapshot(capture_seconds=None)

    assert failed.value is primary_failure
    assert primary_failure.cleanup_owner is IncompleteSession.instances[-1]
    assert any("cleanup also failed" in note for note in primary_failure.__notes__)


def test_capture_convenience_allows_explicit_infinite_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _classified_result(SolareCaptureHealth(), complete=False)
    observed_timeouts: list[float | None] = []

    class FakeSession:
        running = False

        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def wait(
            self, timeout: float | None = None
        ) -> SolareCaptureResult:
            observed_timeouts.append(timeout)
            return expected

        def stop(self) -> SolareCaptureResult:
            pytest.fail("the completed session should not be stopped again")

    monkeypatch.setattr(session_module, "LiveSolareSession", FakeSession)

    result = session_module.capture_solare_snapshot(capture_seconds=None)

    assert result is expected
    assert observed_timeouts == [session_module._POLL_INTERVAL_SECONDS]


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


def test_preconfirmation_tcp_gap_emits_one_fail_closed_warning() -> None:
    session = LiveSolareSession()
    collector = session_module.SolareFrameCollector((8889,))
    collector.tcp_gap_resets = 2
    session._collector = collector

    session._announce_tcp_gap_loss()
    session._announce_tcp_gap_loss()

    update = session._update_queue.get_nowait()
    assert update.kind is SolareUpdateKind.WARNING
    assert "TCP reassembly reset 2 times" in update.message
    assert "remain fail-closed" in update.message
    assert "fresh capture" in update.message
    assert session._update_queue.empty()


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


def test_confirmation_health_is_latched_before_snapshot_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
    )
    sessions: list[LiveSolareSession] = []
    callback_health: list[SolareCaptureHealth] = []

    def add_post_confirmation_loss(update: SolareUpdate) -> None:
        if update.kind is not SolareUpdateKind.SNAPSHOT_CONFIRMED:
            return
        session = sessions[0]
        assert session._confirmed_health is not None
        callback_health.append(session._confirmed_health)
        with session._state_lock:
            session._packet_queue_overflows += 1
            session._stop_reason = "resource-limit"
        session._stop_requested.set()

    session = LiveSolareSession(
        stop_on_complete=False,
        on_update=add_post_confirmation_loss,
    )
    sessions.append(session)
    session.start()
    result = session.wait(timeout=2)

    assert result is not None and result.complete
    assert len(callback_health) == 1
    assert callback_health[0].capture_is_clean
    assert callback_health[0].packet_queue_overflows == 0
    assert result.evidence.health is callback_health[0]
    assert session.stop_reason == "resource-limit"
    assert "already-confirmed snapshot remains valid" in (result.message or "")


def test_live_session_auto_stops_when_candidate_idle_confirms_final_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
        complete_on_candidate_idle=True,
    )
    session = LiveSolareSession()

    session.start()
    result = session.wait(timeout=2)

    assert result is not None and result.complete
    assert session.stopped
    assert session.stop_reason == "complete-snapshot"


def test_drained_clock_service_waits_for_decoder_backlog() -> None:
    class RecordingCollector:
        def __init__(self) -> None:
            self.service_calls = 0
            self.tcp_gap_resets = 0

        def service_gaps(self, _now: float) -> int:
            self.service_calls += 1
            return 0

    class RecordingTracker:
        complete = False

        def __init__(self) -> None:
            self.service_calls = 0

        def service_candidate_idle(self, _now: float) -> bool:
            self.service_calls += 1
            return False

    session = LiveSolareSession()
    collector = RecordingCollector()
    tracker = RecordingTracker()
    session._collector = collector  # type: ignore[assignment]
    session._tracker = tracker  # type: ignore[assignment]
    session._packet_queue.put_nowait(object())

    session._service_drained_clocks()

    assert collector.service_calls == 0
    assert tracker.service_calls == 0

    session._packet_queue.get_nowait()
    session._service_drained_clocks()

    assert collector.service_calls == 1
    assert tracker.service_calls == 1


def test_drained_clock_services_quiet_tcp_gap_and_warns_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = LiveSolareSession()
    collector = session_module.SolareFrameCollector((8889,))
    session._collector = collector

    collector.process_tcp_segment(
        source_ip="198.51.100.10",
        source_port=8889,
        destination_ip="192.0.2.50",
        destination_port=51000,
        sequence=99,
        payload=b"",
        timestamp=100.0,
        syn=True,
    )
    collector.process_tcp_segment(
        source_ip="198.51.100.10",
        source_port=8889,
        destination_ip="192.0.2.50",
        destination_port=51000,
        sequence=101,
        payload=b"x",
        timestamp=100.1,
    )
    monkeypatch.setattr(session_module.time, "time", lambda: 102.0)

    session._service_drained_clocks()

    assert collector.tcp_gap_resets == 1
    warning = session._update_queue.get_nowait()
    assert warning.kind is SolareUpdateKind.WARNING
    assert "remain fail-closed" in warning.message


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
    state = _install_live_fakes(
        monkeypatch,
        packets=tuple(_generic_stream(0x1100 + index * 3) for index in range(25)),
    )

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
    assert session._packet_queue.empty()
    assert not session.running


def test_incomplete_solare_start_cleanup_retains_pipeline_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)
    base_capture = state["capture_class"]
    startup_failure = RuntimeError("Solare adapter readiness timed out")
    cleanup_failure = RuntimeError("Solare capture cleanup is incomplete")

    class FailedStartCapture(base_capture):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.allow_cleanup = False
            self.cleanup_error = cleanup_failure

        def start(self) -> None:
            self.running = True
            raise startup_failure

        def stop(self) -> CaptureStats:
            self.stop_calls += 1
            if not self.allow_cleanup:
                raise cleanup_failure
            self.running = False
            self.stopped = True
            return CaptureStats()

    monkeypatch.setattr(session_module, "LivePacketCapture", FailedStartCapture)
    session = LiveSolareSession()

    with pytest.raises(RuntimeError) as started:
        session.start()

    assert started.value is startup_failure
    assert started.value.cleanup_owner is session
    capture = state["captures"][0]
    assert isinstance(capture, FailedStartCapture)
    assert session.running
    assert not session.stopped
    assert session._capture is capture
    assert session._collector is not None
    assert session._tracker is not None
    with pytest.raises(RuntimeError) as waited:
        session.wait(timeout=0)
    assert waited.value is startup_failure

    capture.allow_cleanup = True
    with pytest.raises(RuntimeError) as stopped:
        session.stop()

    assert stopped.value is startup_failure
    assert session.stopped
    assert session._capture is None
    assert session._collector is None
    assert session._tracker is None


def test_incomplete_solare_stop_retains_pipeline_until_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)
    session = LiveSolareSession()
    session.start()
    capture = state["captures"][0]
    original_stop = capture.stop
    cleanup_failure = RuntimeError("Solare capture cleanup is incomplete")
    allow_cleanup = False

    def retryable_stop() -> CaptureStats:
        nonlocal allow_cleanup
        if not allow_cleanup:
            capture.cleanup_error = cleanup_failure
            capture.running = True
            capture.stopped = False
            raise cleanup_failure
        return original_stop()

    capture.stop = retryable_stop
    collector = session._collector
    tracker = session._tracker

    with pytest.raises(RuntimeError) as first:
        session.stop()

    assert first.value is cleanup_failure
    assert not session.stopped
    assert session._capture is capture
    assert session._collector is collector
    assert session._tracker is tracker

    allow_cleanup = True
    with pytest.raises(RuntimeError) as retried:
        session.stop()

    assert retried.value is cleanup_failure
    assert session.stopped
    assert session._capture is None
    assert session._collector is None
    assert session._tracker is None


def test_stuck_solare_worker_stop_is_bounded_and_retains_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
    )
    callback_entered = NativeEvent()
    release_callback = NativeEvent()

    def block_traffic(update: SolareUpdate) -> None:
        if update.kind is SolareUpdateKind.TRAFFIC:
            callback_entered.set()
            release_callback.wait()

    monkeypatch.setattr(
        LiveSolareSession,
        "_WORKER_STOP_TIMEOUT_SECONDS",
        0.05,
    )
    session = LiveSolareSession(
        stop_on_complete=False,
        on_update=block_traffic,
    )
    session.start()
    assert callback_entered.wait(timeout=1.0)
    collector = session._collector
    tracker = session._tracker

    started_at = time.monotonic()
    with pytest.raises(RuntimeError, match="worker cleanup is incomplete") as first:
        session.stop()
    elapsed = time.monotonic() - started_at

    assert elapsed < 0.5
    assert session.cleanup_incomplete
    assert not session.stopped
    assert session._collector is collector
    assert session._tracker is tracker
    assert state["captures"][0].stopped

    release_callback.set()
    assert session._stopped.wait(timeout=1.0)
    assert not session.cleanup_incomplete
    with pytest.raises(RuntimeError) as repeated:
        session.stop()
    assert repeated.value is first.value


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


def test_sync_context_exit_raises_an_already_stored_background_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = RuntimeError("capture failed before sync context exit")
    _install_live_fakes(monkeypatch, runtime_error=expected)
    escaped: list[BaseException] = []

    try:
        with LiveSolareSession() as session:
            assert session._stopped.wait(timeout=2)
            assert session.error is expected
    except BaseException as exc:
        escaped.append(exc)

    assert len(escaped) == 1
    assert escaped[0] is expected


def test_sync_context_body_exception_remains_primary_when_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)
    body_error = LookupError("user body failed")
    cleanup_error = OSError("capture cleanup failed")
    escaped: list[BaseException] = []

    try:
        with LiveSolareSession() as session:
            capture = state["captures"][0]

            def fail_stop() -> CaptureStats:
                capture.running = False
                capture.stopped = True
                raise cleanup_error

            capture.stop = fail_stop
            raise body_error
    except BaseException as exc:
        escaped.append(exc)

    assert len(escaped) == 1
    assert escaped[0] is body_error
    assert session.error is cleanup_error
    assert session.stopped


def test_worker_thread_start_failure_rolls_back_capture_and_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = _install_live_fakes(monkeypatch)
    expected = RuntimeError("worker thread could not start")

    class FailingThread:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            raise expected

    monkeypatch.setattr(session_module, "Thread", FailingThread)
    session = LiveSolareSession(save_pcap=tmp_path / "thread-start.pcapng")

    with pytest.raises(RuntimeError) as raised:
        session.start()

    assert raised.value is expected
    assert not session.running
    assert session.stopped
    assert state["captures"][0].stopped
    assert state["captures"][0].stop_calls == 1
    assert len(_FakeWriter.instances) == 1
    assert _FakeWriter.instances[0].closed


def test_first_failure_identity_survives_buffered_updates_and_all_accessors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = RuntimeError("first callback failure")

    def fail_ready(update: SolareUpdate) -> None:
        if update.kind is SolareUpdateKind.CAPTURE_READY:
            raise expected

    _install_live_fakes(monkeypatch)
    session = LiveSolareSession(on_update=fail_ready)
    session.start()
    assert session._stopped.wait(timeout=2)
    assert session.error is expected

    # Progress already queued before the failure remains consumable. Once it
    # is drained, every terminal accessor must expose the original object.
    buffered: list[SolareUpdate] = []
    with pytest.raises(RuntimeError) as raised:
        while True:
            update = session.poll(timeout=0)
            assert update is not None
            buffered.append(update)
    assert raised.value is expected
    assert buffered
    assert buffered[0].kind is SolareUpdateKind.CAPTURE_READY

    for operation in (lambda: session.wait(timeout=0), session.stop):
        with pytest.raises(RuntimeError) as raised:
            operation()
        assert raised.value is expected


@pytest.mark.parametrize("failure_site", ["writer", "decoder", "finalize"])
def test_worker_failures_stop_and_preserve_the_first_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_site: str,
) -> None:
    primary = RuntimeError(f"{failure_site} primary failure")
    secondary = RuntimeError("later final-result failure")
    save_pcap: Path | None = None

    state = _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),) if failure_site != "finalize" else (),
    )

    def fail_result(*_args: object, **_kwargs: object) -> SolareCaptureResult:
        raise secondary

    if failure_site == "writer":
        save_pcap = tmp_path / "writer-runtime-failure.pcapng"

        class FailingWriter(_FakeWriter):
            def write(self, packet: object) -> None:
                super().write(packet)
                raise primary

            def close(self) -> None:
                self.closed = True
                raise secondary

        monkeypatch.setattr(
            LiveSolareSession,
            "_open_writer",
            staticmethod(FailingWriter),
        )
    elif failure_site == "decoder":
        def fail_packet_handler(_collector: object):
            def handle(_packet: object) -> None:
                raise primary

            return handle

        monkeypatch.setattr(session_module, "make_packet_handler", fail_packet_handler)
        monkeypatch.setattr(
            session_module,
            "build_solare_result",
            fail_result,
        )
    else:
        def fail_finalize(_collector: object) -> None:
            raise primary

        monkeypatch.setattr(
            session_module.SolareFrameCollector,
            "finish",
            fail_finalize,
        )
        monkeypatch.setattr(
            session_module,
            "build_solare_result",
            fail_result,
        )

    session = LiveSolareSession(save_pcap=save_pcap)
    session.start()
    if failure_site == "finalize":
        session._stop_requested.set()

    assert session._stopped.wait(timeout=2)
    assert session.error is primary
    assert session.stop_reason == "error"
    assert state["captures"][0].stopped
    with pytest.raises(RuntimeError) as raised:
        session.stop()
    assert raised.value is primary


def test_decoder_failure_still_records_every_accepted_packet(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    packets = (_generic_stream(0x1100), _generic_stream(0x2200))
    expected = RuntimeError("decoder failed after capture accepted packets")
    _install_live_fakes(monkeypatch, packets=packets)

    def fail_packet_handler(_collector: object):
        def handle(_packet: object) -> None:
            raise expected

        return handle

    monkeypatch.setattr(session_module, "make_packet_handler", fail_packet_handler)
    session = LiveSolareSession(save_pcap=tmp_path / "decoder-evidence.pcapng")

    session.start()

    assert session._stopped.wait(timeout=2)
    assert session.error is expected
    assert session._saved_packets == len(packets)
    assert len(_FakeWriter.instances) == 1
    assert _FakeWriter.instances[0].packets == list(packets)
    assert _FakeWriter.instances[0].closed


def test_uncaught_finalization_stage_failure_still_marks_session_stopped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    expected = RuntimeError("health finalization failed")

    class DeferredThread:
        def __init__(self, *, target: Any, **_kwargs: object) -> None:
            self.target = target

        def start(self) -> None:
            pass

    def fail_health(
        _session: LiveSolareSession,
        _collector: object,
        _stats: object,
    ) -> SolareCaptureHealth:
        raise expected

    monkeypatch.setattr(session_module, "Thread", DeferredThread)
    monkeypatch.setattr(LiveSolareSession, "_collector_health", fail_health)
    session = LiveSolareSession()
    session.start()
    session._stop_requested.set()
    escaped: list[BaseException] = []

    try:
        session._run_worker()
    except BaseException as exc:
        escaped.append(exc)

    assert not escaped
    assert session.stopped
    assert not session.running
    assert session.error is expected
    assert session.stop_reason == "error"


def test_packet_queue_overflow_is_reported_and_rejects_preoverflow_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_module, "LIVE_PACKET_QUEUE_MAX", 2)
    state = _install_live_fakes(
        monkeypatch,
        packets=(
            _generic_stream(0x1100),
            _generic_stream(0x2200),
            _generic_stream(0x3300),
        ),
        complete_after=1,
    )

    def classify_with_integrity(
        _frames: object,
        health: SolareCaptureHealth,
        **_kwargs: object,
    ) -> SolareCaptureResult:
        state["health"].append(health)
        return _classified_result(health, complete=health.capture_is_clean)

    monkeypatch.setattr(
        session_module,
        "build_solare_result",
        classify_with_integrity,
    )
    session = LiveSolareSession()

    session.start()
    result = session.wait(timeout=2)

    assert result is not None
    assert not result.complete
    assert result.snapshot is None
    assert session.stop_reason == "resource-limit"
    assert result.evidence.health.packet_queue_peak == 2
    assert result.evidence.health.packet_queue_overflows == 1
    assert not result.evidence.health.capture_is_clean

    updates = list(session.updates())
    warnings = [
        update for update in updates if update.kind is SolareUpdateKind.WARNING
    ]
    finished = [
        update for update in updates if update.kind is SolareUpdateKind.FINISHED
    ]
    assert len(warnings) == 1
    assert "packet queue overflow" in warnings[0].message
    assert len(finished) == 1
    assert updates.index(warnings[0]) < updates.index(finished[0])
    assert finished[0].result is result
    assert not finished[0].result.complete


def test_flow_state_eviction_emits_one_actionable_warning_before_finished(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
    )
    session = LiveSolareSession(stop_on_complete=False)
    session.start()

    while True:
        update = session.poll(timeout=2)
        assert update is not None
        if update.kind is SolareUpdateKind.TRAFFIC:
            break

    assert session._collector is not None
    session._collector.flow_state_evictions = 2
    session.request_stop()
    result = session.wait(timeout=2)

    assert result is not None and not result.complete
    updates = list(session.updates())
    warnings = [
        update for update in updates if update.kind is SolareUpdateKind.WARNING
    ]
    assert len(warnings) == 1
    assert "forced flow-state eviction" in warnings[0].message
    assert "reducing capture load" in warnings[0].message
    assert updates.index(warnings[0]) < next(
        index
        for index, update in enumerate(updates)
        if update.kind is SolareUpdateKind.FINISHED
    )


def test_post_confirmation_resource_limit_preserves_snapshot_and_explains_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
    )
    session = LiveSolareSession(stop_on_complete=False)
    session.start()

    while True:
        update = session.poll(timeout=2)
        assert update is not None
        if update.kind is SolareUpdateKind.SNAPSHOT_CONFIRMED:
            break
    for _ in range(200):
        if session._confirmed_health is not None:
            break
        assert not session._stopped.wait(timeout=0.01)
    assert session._confirmed_health is not None
    assert session._confirmed_health.capture_is_clean

    # Model a packet callback hitting the already-tested bounded-queue path
    # after the clean snapshot was latched.  The worker is intentionally left
    # to perform normal finalization and update delivery.
    with session._state_lock:
        session._packet_queue_overflows += 1
        session._stop_reason = "resource-limit"
    session._stop_requested.set()
    result = session.wait(timeout=2)

    assert result is not None and result.complete
    assert result.snapshot is not None
    assert result.evidence.health.capture_is_clean
    assert result.evidence.health.packet_queue_overflows == 0
    assert session.stop_reason == "resource-limit"
    assert "already-confirmed snapshot remains valid" in (result.message or "")
    assert "continued capture ended due to resource pressure" in (
        result.message or ""
    )
    assert "packet queue overflow" in (result.message or "")

    updates = list(session.updates())
    terminal = [
        update
        for update in updates
        if update.kind in {SolareUpdateKind.WARNING, SolareUpdateKind.FINISHED}
    ]
    assert [update.kind for update in terminal] == [
        SolareUpdateKind.WARNING,
        SolareUpdateKind.FINISHED,
    ]
    assert "packet queue overflow" in terminal[0].message
    assert terminal[1].result is result


def test_update_queue_stays_bounded_and_keeps_finished_without_polling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_module, "LIVE_UPDATE_QUEUE_MAX", 2)
    _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
    )
    session = LiveSolareSession()

    session.start()
    result = session.wait(timeout=2)

    assert result is not None and result.complete
    assert session._update_queue.maxsize == 2
    assert session._update_queue.qsize() <= 2
    updates = list(session.updates())
    assert len(updates) <= 2
    assert updates[-1].kind is SolareUpdateKind.FINISHED
    assert updates[-1].result is result


def test_capture_ready_callback_can_request_stop_without_reentrant_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    sessions: list[LiveSolareSession] = []
    callback_kinds: list[SolareUpdateKind] = []
    inside_ready = False
    reentered = False
    start_errors: list[BaseException] = []

    def stop_when_ready(update: SolareUpdate) -> None:
        nonlocal inside_ready, reentered
        if inside_ready:
            reentered = True
        callback_kinds.append(update.kind)
        if update.kind is SolareUpdateKind.CAPTURE_READY:
            inside_ready = True
            sessions[0].request_stop()
            inside_ready = False

    session = LiveSolareSession(on_update=stop_when_ready)
    sessions.append(session)

    def start_session() -> None:
        try:
            session.start()
        except BaseException as exc:
            start_errors.append(exc)

    starter = NativeThread(target=start_session, daemon=True)
    starter.start()
    starter.join(timeout=2)

    assert not starter.is_alive(), "CAPTURE_READY callback did not return"
    assert not start_errors
    result = session.wait(timeout=2)
    assert result is session.result
    assert not reentered
    assert callback_kinds[0] is SolareUpdateKind.CAPTURE_READY
    assert callback_kinds[-1] is SolareUpdateKind.FINISHED
    assert session.stop_reason == "requested"


def test_blocking_control_from_progress_callback_fails_instead_of_deadlocking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    sessions: list[LiveSolareSession] = []

    def wait_when_ready(update: SolareUpdate) -> None:
        if update.kind is SolareUpdateKind.CAPTURE_READY:
            sessions[0].wait()

    session = LiveSolareSession(on_update=wait_when_ready)
    sessions.append(session)
    session.start()

    assert session._stopped.wait(timeout=2)
    assert isinstance(session.error, RuntimeError)
    assert "cannot block inside on_update" in str(session.error)


def test_recursive_start_from_finished_callback_fails_without_deadlocking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    sessions: list[LiveSolareSession] = []
    callback_errors: list[RuntimeError] = []

    def restart_when_finished(update: SolareUpdate) -> None:
        if update.kind is not SolareUpdateKind.FINISHED:
            return
        try:
            sessions[0].start()
        except RuntimeError as exc:
            callback_errors.append(exc)

    session = LiveSolareSession(on_update=restart_when_finished)
    sessions.append(session)
    session.start()
    session.request_stop()

    assert session._stopped.wait(timeout=2), "FINISHED callback deadlocked the worker"
    assert len(callback_errors) == 1
    assert "already started" in str(callback_errors[0])
    assert session.error is None
    assert session.wait(timeout=0) is session.result


@pytest.mark.parametrize(
    "terminal_kind",
    [SolareUpdateKind.WARNING, SolareUpdateKind.FINISHED],
)
def test_stop_from_terminal_callback_is_rejected_without_deadlocking(
    monkeypatch: pytest.MonkeyPatch,
    terminal_kind: SolareUpdateKind,
) -> None:
    _install_live_fakes(monkeypatch)
    sessions: list[LiveSolareSession] = []
    callback_errors: list[RuntimeError] = []

    def stop_when_terminal(update: SolareUpdate) -> None:
        if update.kind is not terminal_kind:
            return
        try:
            sessions[0].stop()
        except RuntimeError as exc:
            callback_errors.append(exc)

    session = LiveSolareSession(on_update=stop_when_terminal)
    sessions.append(session)
    session.start()
    if terminal_kind is SolareUpdateKind.WARNING:
        assert session._collector is not None
        session._collector.flow_state_evictions = 1
    session.request_stop()

    assert session._stopped.wait(timeout=2), (
        f"{terminal_kind.value} callback deadlocked finalization"
    )
    assert len(callback_errors) == 1
    assert "cannot block inside on_update" in str(callback_errors[0])
    assert session.error is None
    assert session.wait(timeout=0) is session.result


def test_callback_cannot_consume_the_public_update_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    sessions: list[LiveSolareSession] = []
    callback_errors: list[RuntimeError] = []

    def probe_poll(update: SolareUpdate) -> None:
        if update.kind is not SolareUpdateKind.CAPTURE_READY:
            return
        try:
            sessions[0].poll(timeout=0)
        except RuntimeError as exc:
            callback_errors.append(exc)
        sessions[0].request_stop()

    session = LiveSolareSession(on_update=probe_poll)
    sessions.append(session)
    session.start()
    result = session.wait(timeout=2)

    assert result is not None
    assert len(callback_errors) == 1
    assert "cannot consume updates inside on_update" in str(callback_errors[0])
    updates = list(session.updates())
    assert updates[0].kind is SolareUpdateKind.CAPTURE_READY
    assert updates[-1].kind is SolareUpdateKind.FINISHED
    assert session.error is None


def test_finalized_session_releases_capture_pipeline_but_keeps_public_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
    )
    session = LiveSolareSession()

    session.start()
    endpoint = session.endpoint
    result = session.wait(timeout=2)

    assert endpoint == SolareCaptureEndpoint(
        interface="fake-interface",
        local_ip="192.0.2.50",
        bpf_filter="tcp",
    )
    assert result is not None and result.complete
    assert session.endpoint == endpoint
    assert session.result is result
    assert session.stop() is result
    assert session._collector is None
    assert session._tracker is None
    assert session._capture is None
    assert session._packet_handler is None
    assert state["captures"][0].stopped


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


def test_async_solare_incomplete_cleanup_retains_executor_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)
    cleanup_failure = RuntimeError("Solare capture cleanup is incomplete")

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()
        capture = state["captures"][0]
        original_stop = capture.stop
        allow_cleanup = False

        def retryable_stop() -> CaptureStats:
            if not allow_cleanup:
                capture.cleanup_error = cleanup_failure
                capture.running = True
                capture.stopped = False
                raise cleanup_failure
            return original_stop()

        capture.stop = retryable_stop

        with pytest.raises(RuntimeError) as first:
            await session.stop()

        assert first.value is cleanup_failure
        assert session.cleanup_incomplete
        assert not session.stopped
        assert not session._closed
        assert session._stop_future is None

        allow_cleanup = True
        with pytest.raises(RuntimeError) as retried:
            await session.stop()

        assert retried.value is cleanup_failure
        assert session.stopped
        assert not session.cleanup_incomplete
        assert session._closed

    asyncio.run(scenario())


def test_async_request_stop_is_nonblocking_and_wait_returns_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()
        session.request_stop()
        result = await session.wait(timeout=2)
        assert result is not None
        assert result.status is SolareDetectionStatus.NO_TRAFFIC
        assert session.stop_reason == "requested"

    asyncio.run(scenario())


def test_async_capture_ready_callback_can_request_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        sessions: list[AsyncLiveSolareSession] = []

        def stop_when_ready(update: SolareUpdate) -> None:
            if update.kind is SolareUpdateKind.CAPTURE_READY:
                sessions[0].request_stop()

        session = AsyncLiveSolareSession(on_update=stop_when_ready)
        sessions.append(session)
        await session.start()
        result = await session.wait(timeout=2)
        assert result is not None
        assert result.status is SolareDetectionStatus.NO_TRAFFIC
        assert session.stop_reason == "requested"
        assert session.error is None

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["stop", "wait", "poll"])
def test_async_blocking_control_from_update_callback_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        callback_errors: list[BaseException] = []
        sessions: list[AsyncLiveSolareSession] = []

        def control_from_update(update: SolareUpdate) -> None:
            if update.kind is not SolareUpdateKind.TRAFFIC:
                return
            if operation == "stop":
                coroutine = sessions[0].stop()
            elif operation == "wait":
                coroutine = sessions[0].wait()
            else:
                coroutine = sessions[0].poll()
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
            try:
                future.result(timeout=1)
            except BaseException as exc:
                callback_errors.append(exc)

        session = AsyncLiveSolareSession(on_update=control_from_update)
        sessions.append(session)
        await session.start()
        await asyncio.to_thread(
            session._session._emit,
            SolareUpdate(
                kind=SolareUpdateKind.TRAFFIC,
                message="test callback context",
            ),
        )

        assert len(callback_errors) == 1
        assert isinstance(callback_errors[0], RuntimeError)
        if operation == "poll":
            assert "cannot consume updates" in str(callback_errors[0])
        else:
            assert "cannot block inside on_update" in str(callback_errors[0])
        assert not session.cleanup_incomplete
        await session.stop()

    asyncio.run(scenario())


def test_async_finished_poll_closes_executor_after_callback_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    callback_entered = NativeEvent()
    release_callback = NativeEvent()

    def gate_finished(update: SolareUpdate) -> None:
        if update.kind is SolareUpdateKind.FINISHED:
            callback_entered.set()
            assert release_callback.wait(timeout=2)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(on_update=gate_finished)
        await session.start()
        session.request_stop()

        finished: SolareUpdate | None = None
        while finished is None or finished.kind is not SolareUpdateKind.FINISHED:
            finished = await session.poll(timeout=2)
            assert finished is not None

        assert callback_entered.is_set()
        assert not session._closed
        assert not session.stopped
        release_callback.set()
        for _ in range(200):
            if session.stopped and session._closed:
                break
            await asyncio.sleep(0.01)
        assert session.stopped
        assert session._closed

    asyncio.run(scenario())


def test_async_stop_remains_available_after_finished_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    callback_entered = NativeEvent()
    release_callback = NativeEvent()

    def gate_finished(update: SolareUpdate) -> None:
        if update.kind is SolareUpdateKind.FINISHED:
            callback_entered.set()
            assert release_callback.wait(timeout=2)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(on_update=gate_finished)
        await session.start()
        session.request_stop()

        finished: SolareUpdate | None = None
        while finished is None or finished.kind is not SolareUpdateKind.FINISHED:
            finished = await session.poll(timeout=2)
            assert finished is not None

        assert callback_entered.is_set()
        stop_task = asyncio.create_task(session.stop())
        await asyncio.sleep(0)
        assert not stop_task.done()
        release_callback.set()

        result = await asyncio.wait_for(stop_task, timeout=2)
        assert result is session.result
        assert session.stopped
        assert session._closed

    asyncio.run(scenario())


def test_async_updates_ends_cleanly_after_finished(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession()
        await session.start()
        session.request_stop()

        kinds = [update.kind async for update in session.updates()]

        assert kinds[0] is SolareUpdateKind.CAPTURE_READY
        assert kinds[-1] is SolareUpdateKind.FINISHED
        assert session._closed

    asyncio.run(scenario())


def test_async_updates_checks_for_finished_callback_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_fakes(monkeypatch)
    expected = RuntimeError("terminal callback failed")

    def fail_finished(update: SolareUpdate) -> None:
        if update.kind is SolareUpdateKind.FINISHED:
            raise expected

    async def scenario() -> None:
        session = AsyncLiveSolareSession(on_update=fail_finished)
        await session.start()
        session.request_stop()

        observed: list[SolareUpdateKind] = []
        with pytest.raises(RuntimeError) as raised:
            async for update in session.updates():
                observed.append(update.kind)

        assert raised.value is expected
        assert observed[-1] is SolareUpdateKind.FINISHED
        assert session._closed

    asyncio.run(scenario())


def test_async_live_session_forwards_raw_retention_to_result_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(
        monkeypatch,
        packets=(_generic_stream(0x1100),),
        complete_after=1,
    )

    async def scenario() -> None:
        session = AsyncLiveSolareSession(retain_raw_extensions=True)
        await session.start()
        result = await session.wait(timeout=2)
        assert result is not None and result.complete

    asyncio.run(scenario())
    assert state["build_kwargs"] == [{"retain_raw_extensions": True}]


def test_async_context_exit_raises_an_already_stored_background_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = RuntimeError("capture failed before async context exit")
    _install_live_fakes(monkeypatch, runtime_error=expected)

    async def scenario() -> None:
        escaped: list[BaseException] = []
        try:
            async with AsyncLiveSolareSession() as session:
                while not session.stopped:
                    await asyncio.sleep(0)
                assert session.error is expected
        except BaseException as exc:
            escaped.append(exc)

        assert len(escaped) == 1
        assert escaped[0] is expected

    asyncio.run(scenario())


def test_async_context_body_exception_remains_primary_when_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_live_fakes(monkeypatch)
    body_error = LookupError("async user body failed")
    cleanup_error = OSError("async capture cleanup failed")

    async def scenario() -> None:
        escaped: list[BaseException] = []
        wrapper: AsyncLiveSolareSession | None = None
        try:
            async with AsyncLiveSolareSession() as wrapper:
                capture = state["captures"][0]

                def fail_stop() -> CaptureStats:
                    capture.running = False
                    capture.stopped = True
                    raise cleanup_error

                capture.stop = fail_stop
                raise body_error
        except BaseException as exc:
            escaped.append(exc)

        assert wrapper is not None
        assert len(escaped) == 1
        assert escaped[0] is body_error
        assert wrapper.error is cleanup_error
        assert wrapper.stopped

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


@pytest.mark.parametrize("invalid_timeout", [-1, True, float("nan")])
def test_async_solare_stopped_wait_ignores_timeout(
    monkeypatch: pytest.MonkeyPatch,
    invalid_timeout: Any,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()
        result = await session.stop()

        assert await session.wait(timeout=invalid_timeout) is result

    asyncio.run(scenario())


@pytest.mark.parametrize("invalid_timeout", [-1, True, float("nan")])
def test_async_solare_stopped_poll_ignores_timeout_while_draining(
    monkeypatch: pytest.MonkeyPatch,
    invalid_timeout: Any,
) -> None:
    _install_live_fakes(monkeypatch)

    async def scenario() -> None:
        session = AsyncLiveSolareSession(stop_on_complete=False)
        await session.start()
        ready = await session.poll(timeout=0.5)
        assert ready is not None
        assert ready.kind is SolareUpdateKind.CAPTURE_READY
        await session.stop()

        finished = await session.poll(timeout=invalid_timeout)
        assert finished is not None
        assert finished.kind is SolareUpdateKind.FINISHED
        assert await session.poll(timeout=invalid_timeout) is None

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
        with pytest.raises(RuntimeError, match="capture thread failed"):
            await session.wait(timeout=-1)

        drained = []
        with pytest.raises(RuntimeError, match="capture thread failed"):
            while (update := await session.poll(timeout=-1)) is not None:
                drained.append(update.kind)
        assert drained == [
            SolareUpdateKind.CAPTURE_READY,
            SolareUpdateKind.FINISHED,
        ]

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
            finished = await session.poll(timeout=-1)
            assert finished is not None
            assert finished.kind is SolareUpdateKind.FINISHED
            assert await session.poll(timeout=True) is None

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["wait", "poll"])
def test_async_cancellation_returns_after_bounded_incomplete_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    _install_live_fakes(monkeypatch)
    callback_entered = NativeEvent()
    release_callback = NativeEvent()

    def block_finished(update: SolareUpdate) -> None:
        if update.kind is SolareUpdateKind.FINISHED:
            callback_entered.set()
            assert release_callback.wait(timeout=2)

    monkeypatch.setattr(
        LiveSolareSession,
        "_WORKER_STOP_TIMEOUT_SECONDS",
        0.05,
    )

    async def scenario() -> None:
        loop_errors: list[dict[str, object]] = []
        asyncio.get_running_loop().set_exception_handler(
            lambda _loop, context: loop_errors.append(context)
        )
        session = AsyncLiveSolareSession(
            stop_on_complete=False,
            on_update=block_finished,
        )
        await session.start()
        ready = await session.poll(timeout=0.5)
        assert ready is not None
        assert ready.kind is SolareUpdateKind.CAPTURE_READY

        if operation == "wait":
            active = asyncio.create_task(session.wait())
        else:
            active = asyncio.create_task(session.poll())
        await asyncio.sleep(0.05)
        active.cancel()

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(active, timeout=1.0)

        assert await asyncio.to_thread(callback_entered.wait, 1)
        assert session.cleanup_incomplete
        assert not session.stopped
        assert not session._closed

        if operation == "poll":
            preserved = await session.poll(timeout=0)
            assert preserved is not None
            assert preserved.kind is SolareUpdateKind.FINISHED

        release_callback.set()
        for _ in range(200):
            if session.stopped:
                break
            await asyncio.sleep(0.01)
        assert session.stopped
        if operation == "poll":
            for _ in range(200):
                if session._closed:
                    break
                await asyncio.sleep(0.01)
            assert session._closed
        with pytest.raises(RuntimeError, match="worker cleanup is incomplete"):
            await session.stop()
        assert session._closed
        await asyncio.sleep(0)
        assert loop_errors == []

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
