from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.solare._constants import CLASS_NAMES
from bdo_toolkit.solare._replay_capture import SolareFrameCollector
from bdo_toolkit.solare._result import build_solare_result
from bdo_toolkit.solare._live_tracker import LiveSolareDiscoveryTracker
from bdo_toolkit.solare.models import (
    SolareCaptureHealth,
    SolareCaptureResult,
    SolareDetectionStatus,
    SolareEvidence,
    SolareUpdate,
    SolareUpdateKind,
)


FLOW = FlowKey("198.51.100.10", 8889, "192.0.2.20", 51000)


def _put_name(message: bytearray, offset: int, name: str) -> None:
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    message[offset : offset + len(encoded)] = encoded


def _message(
    *,
    length: int,
    opcode: int,
    stride: int,
    name_offset: int,
    rank_offset: int,
    rows: tuple[tuple[str, int, int], tuple[str, int, int]],
    class_offset: int | None = None,
) -> bytes:
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[2] = 0
    message[3:5] = opcode.to_bytes(2, "little")
    for record_index, (name, rank, class_code) in enumerate(rows):
        base = record_index * stride
        _put_name(message, base + name_offset, name)
        message[base + rank_offset : base + rank_offset + 4] = rank.to_bytes(
            4, "little"
        )
        if class_offset is not None:
            message[base + class_offset] = class_code
    return bytes(message)


def _complete_frames(
    *,
    rich_opcode: int = 0x4444,
    overall_opcode: int = 0x5555,
    include_overall: bool = True,
) -> tuple[BDOFrame, ...]:
    classes = tuple(CLASS_NAMES)
    rows = tuple(
        (f"Player{rank:04d}", rank, classes[(rank - 1) // 20])
        for rank in range(1, 621)
    )
    frames: list[BDOFrame] = []
    stream_sequence = 100_000

    for index in range(310):
        message = _message(
            length=8_410,
            opcode=rich_opcode,
            stride=4_200,
            name_offset=20,
            rank_offset=100,
            class_offset=104,
            rows=(rows[index * 2], rows[index * 2 + 1]),
        )
        frames.append(
            BDOFrame(
                index=len(frames),
                message=message,
                context=PacketContext(1_000.0 + index, FLOW),
                stream_sequence=stream_sequence,
            )
        )
        stream_sequence += len(message)

    if include_overall:
        for index in range(50):
            message = _message(
                length=8_430,
                opcode=overall_opcode,
                stride=4_210,
                name_offset=30,
                rank_offset=120,
                rows=(rows[index * 2], rows[index * 2 + 1]),
            )
            frames.append(
                BDOFrame(
                    index=len(frames),
                    message=message,
                    context=PacketContext(2_000.0 + index, FLOW),
                    stream_sequence=stream_sequence,
                )
            )
            stream_sequence += len(message)
    return tuple(frames)


def _health(frames: tuple[BDOFrame, ...]) -> SolareCaptureHealth:
    return SolareCaptureHealth(
        payload_segments=len(frames),
        payload_bytes=sum(frame.length for frame in frames),
        synchronized_messages=len(frames),
        retained_large_messages=len(frames),
    )


def _shift_frames(
    frames: tuple[BDOFrame, ...],
    *,
    sequence_delta: int,
    timestamp_delta: float,
) -> tuple[BDOFrame, ...]:
    return tuple(
        BDOFrame(
            index=frame.index + 10_000,
            message=frame.message,
            context=PacketContext(
                frame.context.timestamp + timestamp_delta,
                frame.context.flow,
            ),
            stream_sequence=(frame.stream_sequence or 0) + sequence_delta,
        )
        for frame in frames
    )


def test_complete_result_is_opcode_agnostic_and_falls_back_to_rankings() -> None:
    frames = _complete_frames(rich_opcode=0x7654, overall_opcode=0x3210)

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.complete
    assert result.snapshot is not None
    assert len(result.snapshot.players) == 620
    assert result.snapshot.players[0].name == "Player0001"
    assert result.snapshot.players[-1].global_rank == 620
    assert result.snapshot.capabilities == frozenset({"rankings"})
    assert result.snapshot.observed_at == pytest.approx(2_049.0)
    assert result.evidence.exact_cross_check == 100
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.opcode == 0x7654
    assert result.evidence.rich_layout.detail_layout_id is None
    assert result.evidence.overall_layout is not None
    assert result.evidence.overall_layout.opcode == 0x3210


def test_rich_table_without_overall_cross_check_never_exposes_snapshot() -> None:
    frames = _complete_frames(include_overall=False)

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.RICH_CANDIDATE
    assert result.snapshot is None
    assert result.evidence.ranked_players == 620
    assert result.evidence.overall_players == 0


def test_balanced_class_prefix_plus_overall_is_not_a_complete_snapshot() -> None:
    complete = _complete_frames()
    # Twenty complete class groups (400 records) can look balanced after a
    # capture gap. Keep the later overall table to prove that this tempting
    # prefix still must not become an atomic 620-player snapshot.
    frames = complete[:200] + complete[310:]

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.RANKED_PARTIAL
    assert result.snapshot is None
    assert result.evidence.ranked_players == 400


@pytest.mark.parametrize("second_frame_count", (1, 360))
def test_first_complete_snapshot_survives_a_later_same_flow_refresh(
    second_frame_count: int,
) -> None:
    first = _complete_frames()
    sequence_delta = sum(frame.length for frame in first) + 50_000
    second = _shift_frames(
        _complete_frames()[:second_frame_count],
        sequence_delta=sequence_delta,
        timestamp_delta=10_000.0,
    )
    frames = first + second

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert len(result.snapshot.players) == 620
    assert result.snapshot.observed_at == pytest.approx(2_049.0)


def test_first_complete_snapshot_survives_an_extra_overall_frame() -> None:
    first = _complete_frames()
    sequence_delta = sum(frame.length for frame in first) + 50_000
    extra_overall = _shift_frames(
        first[310:311],
        sequence_delta=sequence_delta,
        timestamp_delta=10_000.0,
    )
    frames = first + extra_overall

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert len(result.snapshot.players) == 620
    assert result.snapshot.observed_at == pytest.approx(2_049.0)


@pytest.mark.parametrize("stale_rich_count", (1, 266))
def test_complete_retry_survives_a_stale_same_family_prefix(
    stale_rich_count: int,
) -> None:
    complete = _complete_frames()
    stale_source = complete[1 : 1 + stale_rich_count]
    stale_bytes = sum(frame.length for frame in stale_source)
    stale = _shift_frames(
        stale_source,
        sequence_delta=-stale_bytes - 10_000,
        timestamp_delta=-10_000.0,
    )
    frames = stale + complete

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert len(result.snapshot.players) == 620
    assert result.snapshot.players[0].name == "Player0001"
    assert result.snapshot.observed_at == pytest.approx(2_049.0)


def test_live_tracker_confirms_complete_retry_after_stale_prefix() -> None:
    complete = _complete_frames()
    stale_source = complete[1:267]
    stale = _shift_frames(
        stale_source,
        sequence_delta=-sum(frame.length for frame in stale_source) - 10_000,
        timestamp_delta=-10_000.0,
    )
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in stale + complete:
        tracker.observe(frame)

    assert tracker.complete
    assert tracker.confirmed_frames is not None
    result = build_solare_result(
        tracker.confirmed_frames,
        _health(tracker.confirmed_frames),
    )
    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert result.snapshot.observed_at == pytest.approx(2_049.0)


def test_live_tracker_end_of_burst_refresh_recovers_offset_family_counts() -> None:
    first = _complete_frames()
    stale_rich = first[1:267]
    stale_overall = first[311:335]
    retry = _shift_frames(
        first,
        sequence_delta=sum(frame.length for frame in first) + 100_000,
        timestamp_delta=10_000.0,
    )
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in stale_rich + stale_overall + retry:
        tracker.observe(frame)

    # Totals are 576 rich and 74 overall frames. Neither exact retry end is a
    # normal ten-frame progress milestone, so live capture's idle-burst refresh
    # is what evaluates the final exact-size windows.
    assert not tracker.complete
    tracker.refresh()
    assert tracker.complete
    assert tracker.confirmed_frames is not None

    result = build_solare_result(
        tracker.confirmed_frames,
        _health(tracker.confirmed_frames),
    )
    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert result.snapshot.observed_at == pytest.approx(12_049.0)


def test_repeated_idle_refresh_without_new_frames_is_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bdo_toolkit.solare._live_tracker as tracker_module

    real_discover = tracker_module.discover_solare
    calls = 0

    def counted_discover(frames: object):
        nonlocal calls
        calls += 1
        return real_discover(frames)  # type: ignore[arg-type]

    monkeypatch.setattr(tracker_module, "discover_solare", counted_discover)
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)
    tracker.observe(_complete_frames()[0])

    tracker.refresh()
    first_result = tracker.result
    tracker.refresh()

    assert calls == 1
    assert tracker.result is first_result


def test_no_game_payload_is_reported_separately_from_inconclusive() -> None:
    result = build_solare_result((), SolareCaptureHealth(saved_packets=12))

    assert result.status is SolareDetectionStatus.NO_TRAFFIC
    assert result.snapshot is None
    assert "no inbound payload" in (result.message or "")


@pytest.mark.parametrize(
    ("health_change", "expected_field"),
    (
        ({"tcp_gap_resets": 1}, "tcp_gap_resets"),
        ({"pcap_dropped": 1}, "pcap_dropped"),
        ({"pcap_interface_dropped": 1}, "pcap_interface_dropped"),
    ),
)
def test_structural_match_with_unclean_capture_fails_closed(
    health_change: dict[str, int],
    expected_field: str,
) -> None:
    frames = _complete_frames()
    health = replace(_health(frames), **health_change)

    result = build_solare_result(frames, health)

    assert result.status is SolareDetectionStatus.DETECTED_INCOMPLETE
    assert result.snapshot is None
    assert result.evidence.exact_cross_check == 100
    assert not result.evidence.health.capture_is_clean
    assert getattr(result.evidence.health, expected_field) == 1
    assert "integrity" in (result.message or "")


def test_frame_collector_reassembles_generic_messages_and_tracks_health() -> None:
    observed: list[BDOFrame] = []
    collector = SolareFrameCollector((8889,), observed.append)
    stream = b"".join(
        (5).to_bytes(2, "little") + b"\x00" + opcode.to_bytes(2, "little")
        for opcode in (0x1111, 0x2222, 0x3333)
    )

    collector.process_tcp_segment(
        source_ip=FLOW.source_ip,
        source_port=FLOW.source_port,
        destination_ip=FLOW.destination_ip,
        destination_port=FLOW.destination_port,
        sequence=500,
        payload=stream,
        timestamp=1234.5,
    )
    collector.finish()

    assert [frame.opcode for frame in observed] == [0x1111, 0x2222, 0x3333]
    assert collector.frames == []
    assert collector.health().payload_segments == 1
    assert collector.health().payload_bytes == len(stream)
    assert collector.health().synchronized_messages == 3
    assert collector.health().retained_large_messages == 0


def test_collector_retention_is_bounded_after_snapshot_latch() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)
    collector = SolareFrameCollector((8889,), tracker.observe)
    complete = _complete_frames()
    for frame in complete:
        collector._accept_frame(frame)
    assert tracker.complete
    assert len(collector.frames) == len(complete)

    collector.stop_retaining()
    for frame in _shift_frames(
        complete,
        sequence_delta=sum(item.length for item in complete) + 50_000,
        timestamp_delta=10_000.0,
    ):
        collector._accept_frame(frame)

    health = collector.health()
    assert len(collector.frames) == len(complete)
    assert health.synchronized_messages == len(complete) * 2
    assert health.retained_large_messages == len(complete)


def test_replay_solare_counts_capture_packets_and_returns_builder_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bdo_toolkit.solare.replay as replay_module

    expected = SolareCaptureResult(
        status=SolareDetectionStatus.NO_TRAFFIC,
        evidence=SolareEvidence(),
    )
    observed: dict[str, object] = {}

    def fake_iter(_path: Path, collector: object):
        observed["collector"] = collector
        yield None
        yield None
        yield None

    def fake_build(frames: object, health: SolareCaptureHealth):
        observed["frames"] = frames
        observed["health"] = health
        return expected

    monkeypatch.setattr(replay_module, "iter_pcap_file", fake_iter)
    monkeypatch.setattr(replay_module, "build_solare_result", fake_build)

    assert replay_module.replay_solare("ignored.pcapng") is expected
    assert observed["frames"] == []
    health = observed["health"]
    assert isinstance(health, SolareCaptureHealth)
    assert health.saved_packets == 3


def test_live_tracker_emits_ranked_cross_check_and_confirmation_progress() -> None:
    updates: list[SolareUpdate] = []
    tracker = LiveSolareDiscoveryTracker(updates.append)

    for frame in _complete_frames():
        tracker.observe(frame)

    assert tracker.complete
    ranked_updates = [
        update.ranked_players
        for update in updates
        if update.kind is SolareUpdateKind.RANKED_PROGRESS
    ]
    assert ranked_updates == [400, 500, 600]
    assert any(
        update.kind is SolareUpdateKind.RICH_CANDIDATE for update in updates
    )
    cross_checks = [
        update.exact_cross_check
        for update in updates
        if update.kind is SolareUpdateKind.CROSS_CHECK
    ]
    assert cross_checks == [20]
    assert updates[-1].kind is SolareUpdateKind.SNAPSHOT_CONFIRMED
    assert updates[-1].exact_cross_check == 100

    first_window = tracker.confirmed_frames
    assert first_window is not None
    extra = _shift_frames(
        _complete_frames(),
        sequence_delta=sum(frame.length for frame in first_window) + 50_000,
        timestamp_delta=10_000.0,
    )
    for frame in extra:
        tracker.observe(frame)
    assert tracker.complete
    assert tracker.confirmed_frames is first_window
