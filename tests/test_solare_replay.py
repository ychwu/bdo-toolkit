from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.solare._constants import (
    CLASS_NAMES,
    DISCOVERY_RETENTION_MAX_BYTES,
    DISCOVERY_RETENTION_MAX_FRAMES,
    LIVE_CANDIDATE_IDLE_SECONDS,
)
from bdo_toolkit.solare._details import (
    SolareDetailDecode,
    SolareOverallDetailDecode,
)
from bdo_toolkit.solare._discovery import DiscoveredSolareFamily
from bdo_toolkit.solare._replay_capture import SolareFrameCollector
from bdo_toolkit.solare._result import build_solare_result
from bdo_toolkit.solare._live_tracker import LiveSolareDiscoveryTracker
from bdo_toolkit.solare.replay import replay_solare
from bdo_toolkit.solare.models import (
    SolareCaptureHealth,
    SolareCaptureResult,
    SolareClass,
    SolareClassPerformance,
    SolareDetectionStatus,
    SolareEvidence,
    SolareOverallEntry,
    SolarePlayer,
    SolareSpecialization,
    SolareUpdate,
    SolareUpdateKind,
    solare_snapshot_id,
)

FLOW = FlowKey("198.51.100.10", 8889, "192.0.2.20", 51000)
SECOND_FLOW = FlowKey("198.51.100.11", 8889, "192.0.2.20", 51001)


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
    name_prefix: str = "Player",
    rich_ranks: tuple[int, ...] | None = None,
    overall_name_overrides: dict[int, str] | None = None,
) -> tuple[BDOFrame, ...]:
    classes = tuple(CLASS_NAMES)
    if rich_ranks is None:
        rich_ranks = tuple(range(1, 621))
    assert len(rich_ranks) == 620
    rows = tuple(
        (f"{name_prefix}{rank:04d}", rank, classes[ordinal // 20])
        for ordinal, rank in enumerate(rich_ranks)
    )
    overall_name_overrides = overall_name_overrides or {}
    overall_rows = tuple(
        (overall_name_overrides.get(rank, f"{name_prefix}{rank:04d}"), rank, 0)
        for rank in range(1, 101)
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
                rows=(
                    overall_rows[index * 2],
                    overall_rows[index * 2 + 1],
                ),
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


def _menu_frames(*, opcode: int = 0x3333) -> tuple[BDOFrame, ...]:
    length = 8_410
    offsets = (100, 1_600, 3_100, 4_600, 6_100)
    frames: list[BDOFrame] = []
    stream_sequence = 50_000
    for frame_index in range(24):
        message = bytearray(length)
        message[0:2] = length.to_bytes(2, "little")
        message[2] = 0
        message[3:5] = opcode.to_bytes(2, "little")
        for slot, offset in enumerate(offsets):
            _put_name(message, offset, f"Menu{frame_index:02d}{slot}")
        frames.append(
            BDOFrame(
                index=frame_index,
                message=bytes(message),
                context=PacketContext(500.0 + frame_index, FLOW),
                stream_sequence=stream_sequence,
            )
        )
        stream_sequence += length
    return tuple(frames)


def _health(frames: tuple[BDOFrame, ...]) -> SolareCaptureHealth:
    return SolareCaptureHealth(
        payload_segments=len(frames),
        payload_bytes=sum(frame.length for frame in frames),
        synchronized_messages=len(frames),
        retained_large_messages=len(frames),
    )


def _non_solare_frames(
    count: int,
    *,
    start_index: int = 100_000,
    distinct_flows: bool = False,
) -> tuple[BDOFrame, ...]:
    """Return qualifying large frames that cannot satisfy ranked discovery."""

    length = 32 * 1024
    opcode = 0x7A7A
    message = (
        length.to_bytes(2, "little")
        + b"\x00"
        + opcode.to_bytes(2, "little")
        + bytes(length - 5)
    )
    return tuple(
        BDOFrame(
            index=start_index + ordinal,
            message=message,
            context=PacketContext(
                50_000.0 + ordinal,
                (
                    FlowKey(
                        "198.51.100.10",
                        10_000 + ordinal,
                        "192.0.2.20",
                        51_000,
                    )
                    if distinct_flows
                    else FLOW
                ),
            ),
            stream_sequence=10_000_000 + (ordinal * length),
        )
        for ordinal in range(count)
    )


def _shift_frames(
    frames: tuple[BDOFrame, ...],
    *,
    sequence_delta: int,
    timestamp_delta: float,
    flow: FlowKey | None = None,
    index_delta: int = 10_000,
) -> tuple[BDOFrame, ...]:
    return tuple(
        BDOFrame(
            index=frame.index + index_delta,
            message=frame.message,
            context=PacketContext(
                frame.context.timestamp + timestamp_delta,
                flow or frame.context.flow,
            ),
            stream_sequence=(frame.stream_sequence or 0) + sequence_delta,
        )
        for frame in frames
    )


def _expected_ranking_snapshot_id(name_prefix: str) -> str:
    classes = tuple(CLASS_NAMES)
    players = tuple(
        SolarePlayer(
            name=f"{name_prefix}{rank:04d}",
            global_rank=rank,
            primary_class=SolareClass(
                code=classes[(rank - 1) // 20],
                name=CLASS_NAMES[classes[(rank - 1) // 20]],
            ),
        )
        for rank in range(1, 621)
    )
    return solare_snapshot_id(players)


def _middle_refresh_frames() -> tuple[BDOFrame, ...]:
    """Return partial + complete + partial generations on one TCP flow."""

    stale = _complete_frames(name_prefix="Stale")
    generation_delta = sum(frame.length for frame in stale) + 100_000
    middle = _shift_frames(
        _complete_frames(name_prefix="Middle"),
        sequence_delta=generation_delta,
        timestamp_delta=10_000.0,
    )
    following = _shift_frames(
        _complete_frames(name_prefix="Following")[:1],
        sequence_delta=generation_delta * 2,
        timestamp_delta=20_000.0,
        index_delta=20_000,
    )
    # The stale response contributes only one non-reset rich frame but all 50
    # overall frames. Both family aggregates therefore have invalid first and
    # last edge windows even though ``middle`` is an exact complete response.
    return stale[1:2] + stale[310:] + middle + following


def _assert_selected_snapshot(
    result: SolareCaptureResult,
    *,
    name_prefix: str,
    observed_at: float,
) -> None:
    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert result.snapshot.players[0].name == f"{name_prefix}0001"
    assert result.snapshot.players[-1].name == f"{name_prefix}0620"
    assert result.snapshot.overall_top_100[0].name == f"{name_prefix}0001"
    assert result.snapshot.observed_at == pytest.approx(observed_at)
    assert result.snapshot.snapshot_id == _expected_ranking_snapshot_id(name_prefix)

    rich_layout = result.evidence.rich_layout
    overall_layout = result.evidence.overall_layout
    assert rich_layout is not None
    assert overall_layout is not None
    assert (
        rich_layout.opcode,
        rich_layout.message_count,
        rich_layout.record_stride,
        rich_layout.name_offset,
        rich_layout.rank_offset,
        rich_layout.class_offset,
    ) == (0x4444, 310, 4_200, 20, 100, 104)
    assert (
        overall_layout.opcode,
        overall_layout.message_count,
        overall_layout.record_stride,
        overall_layout.name_offset,
        overall_layout.rank_offset,
    ) == (0x5555, 50, 4_210, 30, 120)


def test_complete_result_is_opcode_agnostic_and_falls_back_to_rankings() -> None:
    frames = _complete_frames(rich_opcode=0x7654, overall_opcode=0x3210)

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.complete
    assert result.snapshot is not None
    assert len(result.snapshot.players) == 620
    assert result.snapshot.players[0].name == "Player0001"
    assert result.snapshot.players[-1].global_rank == 620
    assert result.snapshot.class_table_capabilities == frozenset({"rankings"})
    assert result.snapshot.overall_capabilities == frozenset({"rankings"})
    assert result.snapshot.capabilities == frozenset({"rankings"})
    assert all(
        entry.total_wins is None
        and entry.total_draws is None
        and entry.total_losses is None
        and entry.total_matches is None
        for entry in result.snapshot.overall_top_100
    )
    assert result.snapshot.observed_at == pytest.approx(2_049.0)
    assert result.evidence.exact_cross_check == 100
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.opcode == 0x7654
    assert result.evidence.rich_layout.detail_layout_id is None
    assert result.evidence.overall_layout is not None
    assert result.evidence.overall_layout.opcode == 0x3210


def test_direct_result_preserves_menu_context_after_repeated_responses() -> None:
    first = _menu_frames()
    response_bytes = sum(frame.length for frame in first)
    second = _shift_frames(
        first,
        sequence_delta=response_bytes + 10_000,
        timestamp_delta=100.0,
    )
    third = _shift_frames(
        first,
        sequence_delta=(response_bytes + 10_000) * 2,
        timestamp_delta=200.0,
        index_delta=20_000,
    )
    frames = first + second + third

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.MENU_CONTEXT
    assert result.snapshot is None
    assert result.evidence.candidate_families == ((0x3333, 8_410, 72),)


def test_complete_result_allows_one_overall_only_player() -> None:
    rich_ranks = (*range(1, 21), *range(22, 622))
    frames = _complete_frames(rich_ranks=rich_ranks)

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert len(result.snapshot.players) == 620
    assert len(result.snapshot.overall_top_100) == 100
    assert result.evidence.exact_cross_check == 99
    assert 21 not in {player.global_rank for player in result.snapshot.players}
    overall_only = result.snapshot.overall_top_100[20]
    assert (overall_only.global_rank, overall_only.name) == (21, "Player0021")
    assert overall_only.elo is None
    assert overall_only.classes_played == ()
    assert overall_only.total_wins is None
    assert overall_only.total_draws is None
    assert overall_only.total_losses is None
    assert overall_only.total_matches is None
    assert result.snapshot.class_table_capabilities == frozenset({"rankings"})
    assert result.snapshot.overall_capabilities == frozenset({"rankings"})


def test_overall_only_player_keeps_direct_overall_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Overall details survive even when no class-table row can be joined."""

    import bdo_toolkit.solare._result as result_module

    rich_ranks = (*range(1, 21), *range(22, 622))
    frames = _complete_frames(rich_ranks=rich_ranks)
    class_code = next(iter(CLASS_NAMES))
    player_class = SolareClass(class_code, CLASS_NAMES[class_code])
    specialization = SolareSpecialization(
        code=1,
        branch="advanced",
        name="Awakening",
    )

    def fake_decode_class(
        _frames: Sequence[BDOFrame],
        rich: DiscoveredSolareFamily,
        *,
        retain_raw_extensions: bool = False,
    ) -> SolareDetailDecode:
        assert retain_raw_extensions is False
        players = tuple(
            SolarePlayer(
                name=name,
                global_rank=rank,
                primary_class=SolareClass(
                    discovered_class,
                    CLASS_NAMES[discovered_class],
                ),
                elo=5_000 - rank,
            )
            for name, rank, discovered_class in zip(
                rich.names,
                rich.ranks,
                rich.class_codes,
            )
        )
        return SolareDetailDecode(
            layout_id="synthetic-class-v1",
            players=players,
            capabilities=frozenset({"rankings", "elo"}),
        )

    def fake_decode_overall(
        _frames: Sequence[BDOFrame],
        overall: DiscoveredSolareFamily,
        *,
        retain_raw_extensions: bool = False,
    ) -> SolareOverallDetailDecode:
        assert retain_raw_extensions is False
        entries = tuple(
            SolareOverallEntry(
                name=name,
                global_rank=rank,
                elo=4_000 - rank,
                classes_played=(
                    SolareClassPerformance(
                        slot=0,
                        primary=True,
                        player_class=player_class,
                        specialization=specialization,
                        matches=20,
                        wins=10,
                        draws=1,
                        losses=9,
                        recent_results_raw=(1, 0, 1),
                        recent_results_wire_text="1,0,1",
                    ),
                ),
                total_wins=15,
                total_draws=1,
                total_losses=4,
            )
            for name, rank in zip(overall.names, overall.ranks)
        )
        return SolareOverallDetailDecode(
            layout_id="synthetic-overall-v1",
            entries=entries,
            capabilities=frozenset(
                {
                    "rankings",
                    "elo",
                    "performance",
                    "aggregate_performance",
                }
            ),
        )

    monkeypatch.setattr(result_module, "decode_solare_details", fake_decode_class)
    monkeypatch.setattr(
        result_module,
        "decode_solare_overall_details",
        fake_decode_overall,
    )

    result = build_solare_result(frames, _health(frames))

    assert result.snapshot is not None
    overall_only = result.snapshot.overall_top_100[20]
    assert (overall_only.global_rank, overall_only.name) == (21, "Player0021")
    assert overall_only.elo == 3_979
    assert len(overall_only.classes_played) == 1
    performance = overall_only.classes_played[0]
    assert performance.player_class == player_class
    assert performance.matches == 20
    assert performance.record_is_balanced
    assert overall_only.total_wins == 15
    assert overall_only.total_draws == 1
    assert overall_only.total_losses == 4
    assert overall_only.total_matches == 20
    assert overall_only.total_matches == performance.matches
    assert (
        overall_only.total_wins,
        overall_only.total_draws,
        overall_only.total_losses,
    ) != (performance.wins, performance.draws, performance.losses)
    assert result.snapshot.get_player(overall_only.name) is None
    rich_overlap = result.snapshot.get_player("Player0001")
    overall_overlap = result.snapshot.get_overall_entry("Player0001")
    assert rich_overlap is not None
    assert overall_overlap is not None
    assert rich_overlap.elo == 4_999
    assert overall_overlap.elo == 3_999
    assert result.snapshot.class_table_capabilities == frozenset(
        {"rankings", "elo"}
    )
    assert result.snapshot.overall_capabilities == frozenset(
        {
            "rankings",
            "elo",
            "performance",
            "aggregate_performance",
        }
    )
    assert result.snapshot.capabilities == frozenset({"rankings", "elo"})
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.detail_layout_id == "synthetic-class-v1"
    assert result.evidence.overall_layout is not None
    assert (
        result.evidence.overall_layout.detail_layout_id
        == "synthetic-overall-v1"
    )


def test_class_details_never_populate_structural_overall_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid class decoder is not an enrichment source for overall rows."""

    import bdo_toolkit.solare._result as result_module

    frames = _complete_frames()

    def fake_decode_class(
        _frames: Sequence[BDOFrame],
        rich: DiscoveredSolareFamily,
        *,
        retain_raw_extensions: bool = False,
    ) -> SolareDetailDecode:
        assert retain_raw_extensions is False
        players = tuple(
            SolarePlayer(
                name=name,
                global_rank=rank,
                primary_class=SolareClass(
                    class_code,
                    CLASS_NAMES[class_code],
                ),
                elo=4_000 - rank,
            )
            for name, rank, class_code in zip(
                rich.names,
                rich.ranks,
                rich.class_codes,
            )
        )
        return SolareDetailDecode(
            layout_id="synthetic-class-v1",
            players=players,
            capabilities=frozenset({"rankings", "elo"}),
        )

    monkeypatch.setattr(
        result_module,
        "decode_solare_details",
        fake_decode_class,
    )

    result = build_solare_result(frames, _health(frames))

    assert result.snapshot is not None
    assert result.snapshot.players[0].elo == 3_999
    assert result.snapshot.overall_top_100[0].elo is None
    assert result.snapshot.overall_top_100[0].classes_played == ()
    assert result.snapshot.overall_top_100[0].total_wins is None
    assert result.snapshot.overall_top_100[0].total_draws is None
    assert result.snapshot.overall_top_100[0].total_losses is None
    assert result.snapshot.overall_top_100[0].total_matches is None
    assert result.snapshot.class_table_capabilities == frozenset(
        {"rankings", "elo"}
    )
    assert result.snapshot.overall_capabilities == frozenset({"rankings"})
    assert result.snapshot.capabilities == frozenset({"rankings"})
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.detail_layout_id == "synthetic-class-v1"
    assert result.evidence.overall_layout is not None
    assert result.evidence.overall_layout.detail_layout_id is None


def test_overall_details_survive_when_class_detail_decoder_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One table's detail failure cannot suppress the other table's decode."""

    import bdo_toolkit.solare._result as result_module

    frames = _complete_frames()
    class_code = next(iter(CLASS_NAMES))
    player_class = SolareClass(class_code, CLASS_NAMES[class_code])

    def fail_class_decode(
        _frames: Sequence[BDOFrame],
        _rich: DiscoveredSolareFamily,
        *,
        retain_raw_extensions: bool = False,
    ) -> None:
        assert retain_raw_extensions is False
        return None

    def decode_overall(
        _frames: Sequence[BDOFrame],
        overall: DiscoveredSolareFamily,
        *,
        retain_raw_extensions: bool = False,
    ) -> SolareOverallDetailDecode:
        assert retain_raw_extensions is False
        entries = tuple(
            SolareOverallEntry(
                name=name,
                global_rank=rank,
                elo=4_000 - rank,
                classes_played=(
                    SolareClassPerformance(
                        slot=0,
                        primary=True,
                        player_class=player_class,
                        matches=100,
                        wins=60,
                        draws=1,
                        losses=39,
                        recent_results_raw=(1, 0, 1),
                        recent_results_wire_text="1,0,1",
                    ),
                ),
                total_wins=63,
                total_draws=1,
                total_losses=36,
            )
            for name, rank in zip(overall.names, overall.ranks)
        )
        return SolareOverallDetailDecode(
            layout_id="synthetic-overall-v1",
            entries=entries,
            capabilities=frozenset(
                {
                    "rankings",
                    "elo",
                    "performance",
                    "aggregate_performance",
                }
            ),
        )

    monkeypatch.setattr(result_module, "decode_solare_details", fail_class_decode)
    monkeypatch.setattr(
        result_module,
        "decode_solare_overall_details",
        decode_overall,
    )

    result = build_solare_result(frames, _health(frames))

    assert result.snapshot is not None
    class_row = result.snapshot.players[0]
    assert class_row.elo is None
    assert class_row.classes_played == ()
    assert result.snapshot.class_table_capabilities == frozenset({"rankings"})
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.detail_layout_id is None

    overall_row = result.snapshot.overall_top_100[0]
    assert overall_row.elo == 3_999
    assert len(overall_row.classes_played) == 1
    assert overall_row.classes_played[0].record_is_balanced
    assert overall_row.total_wins == 63
    assert overall_row.total_draws == 1
    assert overall_row.total_losses == 36
    assert overall_row.total_matches == 100
    assert (
        overall_row.total_wins,
        overall_row.total_draws,
        overall_row.total_losses,
    ) != (
        overall_row.classes_played[0].wins,
        overall_row.classes_played[0].draws,
        overall_row.classes_played[0].losses,
    )
    assert result.snapshot.overall_capabilities == frozenset(
        {
            "rankings",
            "elo",
            "performance",
            "aggregate_performance",
        }
    )
    assert result.evidence.overall_layout is not None
    assert (
        result.evidence.overall_layout.detail_layout_id
        == "synthetic-overall-v1"
    )
    assert result.snapshot.capabilities == frozenset({"rankings"})


def test_complete_result_accepts_the_minimum_twenty_exact_overlaps() -> None:
    rich_ranks = (*range(1, 21), *range(101, 701))
    frames = _complete_frames(rich_ranks=rich_ranks)

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert len(result.snapshot.players) == 620
    assert len(result.snapshot.overall_top_100) == 100
    assert result.evidence.exact_cross_check == 20
    assert [entry.global_rank for entry in result.snapshot.overall_top_100] == list(
        range(1, 101)
    )


def test_nineteen_overlaps_cannot_confirm_a_snapshot() -> None:
    rich_ranks = (*range(1, 20), *range(101, 702))
    frames = _complete_frames(rich_ranks=rich_ranks)

    result = build_solare_result(frames, _health(frames))

    assert result.status is not SolareDetectionStatus.COMPLETE
    assert result.snapshot is None
    assert result.evidence.exact_cross_check == 0


@pytest.mark.parametrize(
    ("rich_ranks", "overall_name_overrides"),
    (
        (tuple(range(1, 621)), {21: "Contradiction0021"}),
        ((*range(1, 21), *range(22, 622)), {21: "Player0101"}),
    ),
)
def test_shared_rank_or_name_contradiction_fails_closed(
    rich_ranks: tuple[int, ...],
    overall_name_overrides: dict[int, str],
) -> None:
    frames = _complete_frames(
        rich_ranks=rich_ranks,
        overall_name_overrides=overall_name_overrides,
    )

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.RICH_CANDIDATE
    assert result.snapshot is None
    assert result.evidence.exact_cross_check == 0


def test_rich_table_without_overall_cross_check_never_exposes_snapshot() -> None:
    frames = _complete_frames(include_overall=False)

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.RICH_CANDIDATE
    assert result.snapshot is None
    assert result.evidence.ranked_players == 620
    assert result.evidence.overall_players == 0


def test_second_rich_generation_cannot_masquerade_as_overall_table() -> None:
    first_rich = _complete_frames(include_overall=False)
    second_rich = _shift_frames(
        _complete_frames(
            rich_opcode=0x6666,
            include_overall=False,
        ),
        sequence_delta=sum(frame.length for frame in first_rich) + 100_000,
        timestamp_delta=10_000.0,
    )

    result = build_solare_result(
        first_rich + second_rich,
        _health(first_rich + second_rich),
    )

    assert result.status is SolareDetectionStatus.RICH_CANDIDATE
    assert result.snapshot is None
    assert result.evidence.overall_players == 0


def test_live_rich_prefix_is_tentative_until_its_family_boundary() -> None:
    first_rich = _complete_frames(include_overall=False)
    second_rich = _shift_frames(
        _complete_frames(
            rich_opcode=0x6666,
            include_overall=False,
        ),
        sequence_delta=sum(frame.length for frame in first_rich) + 100_000,
        timestamp_delta=10_000.0,
    )
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in first_rich + second_rich[:50]:
        tracker.observe(frame)
    assert not tracker.complete

    # Candidate idleness alone cannot turn the exact top-100 prefix of another
    # class table into independent overall-table proof.
    assert tracker._last_candidate_activity_at is not None
    tracker.service_candidate_idle(
        tracker._last_candidate_activity_at
        + LIVE_CANDIDATE_IDLE_SECONDS
    )
    assert not tracker.complete

    interleaved = _shift_frames(
        _complete_frames(
            rich_opcode=0x7777,
            include_overall=False,
        )[:1],
        sequence_delta=sum(frame.length for frame in first_rich + second_rich)
        + 200_000,
        timestamp_delta=20_000.0,
        index_delta=20_000,
    )[0]
    tracker.observe(interleaved)
    tracker.refresh(end_of_burst=False)
    assert not tracker.complete

    # The next same-family frame proves that the 50-frame prefix was not an
    # independent overall response.  Even an ensuing idle finalization must
    # remain fail-closed.
    tracker.observe(second_rich[50])
    tracker.refresh()
    assert not tracker.complete


def test_subthreshold_idle_cannot_latch_before_delayed_same_family_frame() -> None:
    first_rich = _complete_frames(include_overall=False)
    second_rich = _shift_frames(
        _complete_frames(
            rich_opcode=0x6666,
            include_overall=False,
        ),
        sequence_delta=sum(frame.length for frame in first_rich) + 100_000,
        timestamp_delta=10_000.0,
    )
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in first_rich + second_rich[:50]:
        tracker.observe(frame)
    assert tracker._last_candidate_activity_at is not None
    last_candidate = tracker._last_candidate_activity_at

    # The old queue-idle path finalized after roughly 0.2 seconds. A frame
    # already delayed inside the decode queue could then be ignored forever.
    assert not tracker.service_candidate_idle(last_candidate + 0.2)
    assert not tracker.complete

    tracker.observe(second_rich[50])
    assert tracker._last_candidate_activity_at is not None
    assert not tracker.service_candidate_idle(
        tracker._last_candidate_activity_at
        + LIVE_CANDIDATE_IDLE_SECONDS
    )
    assert not tracker.complete


def test_candidate_idle_closes_overall_tail_amid_unrelated_traffic() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in _complete_frames():
        tracker.observe(frame)

    # The exact 50-frame tail is intentionally provisional during an active
    # candidate burst. Unrelated small game packets never reach this tracker,
    # so the session can service the candidate-specific clock while they keep
    # the global packet queue busy.
    assert not tracker.complete
    assert tracker._last_candidate_activity_at is not None
    # This monotonic-clock value reproduces a Linux float boundary where
    # ``(last_candidate + 1.5) - last_candidate`` rounds just below 1.5.
    last_candidate = 63.021708486
    tracker._last_candidate_activity_at = last_candidate
    assert not tracker.service_candidate_idle(
        last_candidate + LIVE_CANDIDATE_IDLE_SECONDS - 0.001
    )
    assert not tracker.complete
    assert tracker.service_candidate_idle(
        last_candidate + LIVE_CANDIDATE_IDLE_SECONDS
    )
    assert tracker.complete
    assert tracker.confirmed_frames is not None


def test_sequence_less_frames_use_ordinal_distance_units() -> None:
    frames = tuple(
        BDOFrame(
            index=frame.index,
            message=frame.message,
            context=frame.context,
            stream_sequence=None,
        )
        for frame in _complete_frames()
    )

    result = build_solare_result(frames, _health(frames))

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert result.snapshot.players[0].name == "Player0001"


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


def test_complete_middle_refresh_survives_partial_generations_on_both_edges() -> None:
    frames = _middle_refresh_frames()

    result = build_solare_result(frames, _health(frames))

    _assert_selected_snapshot(
        result,
        name_prefix="Middle",
        observed_at=12_049.0,
    )


def test_middle_refresh_structural_scan_work_stays_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bdo_toolkit.solare._discovery as discovery_module

    calls = {"rank": 0, "identifier": 0}
    original_rank_read = discovery_module._u32le
    original_identifier_read = discovery_module._read_player_identifier

    def counted_rank_read(*args: object, **kwargs: object) -> int:
        calls["rank"] += 1
        return original_rank_read(*args, **kwargs)  # type: ignore[arg-type]

    def counted_identifier_read(*args: object, **kwargs: object) -> str:
        calls["identifier"] += 1
        return original_identifier_read(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_module, "_u32le", counted_rank_read)
    monkeypatch.setattr(
        discovery_module,
        "_read_player_identifier",
        counted_identifier_read,
    )
    frames = _middle_refresh_frames()

    result = build_solare_result(frames, _health(frames))

    assert result.complete
    # The pre-hardening path performed roughly 40 million rank reads on this
    # 412-frame shape.  Operation-count ceilings are stable across CI hosts and
    # leave ample room for future validation gates without restoring that
    # quadratic failure mode.
    assert calls["rank"] < 20_000
    assert calls["identifier"] < 100_000


def test_first_of_two_distinct_complete_same_flow_snapshots_is_selected() -> None:
    first = _complete_frames(name_prefix="First")
    second = _shift_frames(
        _complete_frames(name_prefix="Second"),
        sequence_delta=sum(frame.length for frame in first) + 100_000,
        timestamp_delta=10_000.0,
    )
    frames = first + second

    result = build_solare_result(frames, _health(frames))

    _assert_selected_snapshot(
        result,
        name_prefix="First",
        observed_at=2_049.0,
    )


def test_first_complete_cross_flow_snapshot_ignores_tcp_sequence_origins() -> None:
    earlier = _shift_frames(
        _complete_frames(name_prefix="Earlier"),
        sequence_delta=50_000_000,
        timestamp_delta=0.0,
        flow=FLOW,
        index_delta=10_000,
    )
    later = _shift_frames(
        _complete_frames(name_prefix="Later"),
        sequence_delta=0,
        timestamp_delta=10_000.0,
        flow=SECOND_FLOW,
        index_delta=0,
    )
    # TCP sequence numbers and frame indexes are local to their producers. The
    # later flow deliberately has lower values for both; tuple ingestion order
    # is the only valid cross-flow chronology available to discovery.
    frames = earlier + later

    result = build_solare_result(frames, _health(frames))

    _assert_selected_snapshot(
        result,
        name_prefix="Earlier",
        observed_at=2_049.0,
    )


def test_live_tracker_confirms_a_complete_middle_refresh_at_burst_end() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in _middle_refresh_frames():
        tracker.observe(frame)

    # A 50-frame family remains tentative while traffic is actively arriving:
    # it could be the prefix of a second rich table.  The normal idle refresh
    # proves the burst boundary without depending on absolute family counts.
    tracker.refresh()
    assert tracker.complete
    assert tracker.confirmed_frames is not None
    result = build_solare_result(
        tracker.confirmed_frames,
        _health(tracker.confirmed_frames),
    )
    _assert_selected_snapshot(
        result,
        name_prefix="Middle",
        observed_at=12_049.0,
    )


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

    tracker.refresh()
    assert tracker.complete
    assert tracker.confirmed_frames is not None
    result = build_solare_result(
        tracker.confirmed_frames,
        _health(tracker.confirmed_frames),
    )
    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    assert result.snapshot.observed_at == pytest.approx(2_049.0)


def test_live_tracker_reset_milestones_recover_offset_family_counts() -> None:
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

    # Totals are 576 rich and 74 overall frames.  Absolute family-count
    # milestones miss both retry boundaries, but reset-relative milestones
    # still discover the rich retry.  The final overall family is confirmed at
    # the normal end-of-burst boundary.
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

    def counted_discover(frames: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return real_discover(frames, **kwargs)  # type: ignore[arg-type]

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
    ("health_change", "expected_message"),
    (
        ({"packet_queue_overflows": 2}, "packet queue overflow"),
        ({"flow_state_evictions": 3}, "forced flow-state eviction"),
    ),
)
def test_inconclusive_result_names_bounded_pipeline_loss(
    health_change: dict[str, int],
    expected_message: str,
) -> None:
    health = SolareCaptureHealth(payload_segments=1, **health_change)

    result = build_solare_result((), health)

    assert result.status is SolareDetectionStatus.INCONCLUSIVE
    assert expected_message in (result.message or "")
    assert "Retry after reducing capture load" in (result.message or "")


@pytest.mark.parametrize(
    ("health_change", "expected_message"),
    (
        ({"tcp_gap_resets": 2}, "TCP reassembly reset 2 times"),
        ({"pcap_dropped": 3}, "capture backend reported 3 dropped packets"),
        (
            {"pcap_interface_dropped": 4},
            "capture interface reported 4 dropped packets",
        ),
    ),
)
def test_preconfirmation_capture_loss_is_named(
    health_change: dict[str, int],
    expected_message: str,
) -> None:
    health = SolareCaptureHealth(payload_segments=1, **health_change)

    result = build_solare_result((), health)

    assert result.status is SolareDetectionStatus.INCONCLUSIVE
    assert expected_message in (result.message or "")
    assert "Retry with a fresh capture" in (result.message or "")


def test_candidate_rollover_is_explained_only_without_stronger_loss() -> None:
    rolled_over = build_solare_result(
        (),
        SolareCaptureHealth(
            payload_segments=1,
            candidate_history_rolled_over=True,
        ),
    )
    overflowed = build_solare_result(
        (),
        SolareCaptureHealth(
            payload_segments=1,
            candidate_history_rolled_over=True,
            packet_queue_overflows=1,
        ),
    )
    capture_gap = build_solare_result(
        (),
        SolareCaptureHealth(
            payload_segments=1,
            candidate_history_rolled_over=True,
            tcp_gap_resets=1,
        ),
    )

    assert "bounded candidate history rolled over" in (
        rolled_over.message or ""
    )
    assert "packet queue overflow" in (overflowed.message or "")
    assert "candidate history" not in (overflowed.message or "")
    assert "candidate history" not in (capture_gap.message or "")


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


@pytest.mark.parametrize(
    ("health_change", "expected_message"),
    (
        ({"packet_queue_overflows": 1}, "packet queue overflow"),
        ({"flow_state_evictions": 1}, "forced flow-state eviction"),
    ),
)
def test_detected_incomplete_result_names_bounded_pipeline_loss(
    health_change: dict[str, int],
    expected_message: str,
) -> None:
    frames = _complete_frames()
    health = replace(_health(frames), **health_change)

    result = build_solare_result(frames, health)

    assert result.status is SolareDetectionStatus.DETECTED_INCOMPLETE
    assert result.snapshot is None
    assert expected_message in (result.message or "")
    assert "snapshot publication was withheld" in (result.message or "")


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


def test_solare_collector_tolerates_large_lossless_npcap_reorder_burst() -> None:
    observed: list[BDOFrame] = []
    collector = SolareFrameCollector((8889,), observed.append)
    message = bytearray(8_192)
    message[0:2] = len(message).to_bytes(2, "little")
    message[2] = 0
    message[3:5] = (0x4567).to_bytes(2, "little")
    stream = bytes(message) * 2
    pieces = tuple(
        stream[offset : offset + 23]
        for offset in range(0, len(stream), 23)
    )

    # Anchor with the SYN, then emulate a Windows/Npcap callback batch whose
    # first 23 bytes arrive after more than 700 later segments. This exceeds
    # both the generic item-route count policy and the 665-segment peak from
    # the July 30 regression capture, but remains under Solare's explicit
    # count/byte limits and under the ordinary gap deadline.
    collector.process_tcp_segment(
        source_ip=FLOW.source_ip,
        source_port=FLOW.source_port,
        destination_ip=FLOW.destination_ip,
        destination_port=FLOW.destination_port,
        sequence=999,
        payload=b"",
        timestamp=1.0,
        syn=True,
    )
    for index, piece in enumerate(pieces[1:], start=1):
        collector.process_tcp_segment(
            source_ip=FLOW.source_ip,
            source_port=FLOW.source_port,
            destination_ip=FLOW.destination_ip,
            destination_port=FLOW.destination_port,
            sequence=1_000 + index * 23,
            payload=piece,
            timestamp=1.0 + index / 1_000,
        )
    collector.process_tcp_segment(
        source_ip=FLOW.source_ip,
        source_port=FLOW.source_port,
        destination_ip=FLOW.destination_ip,
        destination_port=FLOW.destination_port,
        sequence=1_000,
        payload=pieces[0],
        timestamp=1.3,
    )
    collector.finish()

    assert [frame.opcode for frame in observed] == [0x4567, 0x4567]
    assert collector.health().synchronized_messages == 2
    assert collector.health().tcp_gap_resets == 0
    assert collector.health().capture_is_clean


@pytest.mark.parametrize("close_flag", ("fin", "rst"))
def test_reused_tcp_four_tuple_keeps_connection_snapshots_separate(
    close_flag: str,
) -> None:
    """A closed four-tuple reused at a lower sequence starts a new stream."""

    collector = SolareFrameCollector((8889,))
    snapshots = (
        (_complete_frames(name_prefix="First"), 50_000_000, 0.0),
        (_complete_frames(name_prefix="Second"), 100_000, 10_000.0),
    )

    for frames, initial_sequence, timestamp_delta in snapshots:
        sequence = initial_sequence
        for index, frame in enumerate(frames):
            collector.process_tcp_segment(
                source_ip=FLOW.source_ip,
                source_port=FLOW.source_port,
                destination_ip=FLOW.destination_ip,
                destination_port=FLOW.destination_port,
                sequence=sequence,
                payload=frame.message,
                timestamp=frame.context.timestamp + timestamp_delta,
                fin=index == len(frames) - 1 and close_flag == "fin",
                rst=index == len(frames) - 1 and close_flag == "rst",
            )
            sequence += frame.length
    collector.finish()

    generations = tuple(
        dict.fromkeys(frame.context.flow_generation for frame in collector.frames)
    )
    assert generations == (1, 2)
    assert tuple(
        sum(frame.context.flow_generation == generation for frame in collector.frames)
        for generation in generations
    ) == (360, 360)

    result = build_solare_result(tuple(collector.frames), collector.health())
    _assert_selected_snapshot(
        result,
        name_prefix="First",
        observed_at=2_049.0,
    )


def test_solare_flow_cap_ignores_unknown_controls_and_evicts_lru(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bdo_toolkit.solare._replay_capture as replay_capture_module

    monkeypatch.setattr(replay_capture_module, "SOLARE_MAX_ACTIVE_FLOWS", 2)
    collector = SolareFrameCollector((8889,))
    flow_a = FlowKey("198.51.100.1", 8889, "192.0.2.20", 51001)
    flow_b = FlowKey("198.51.100.2", 8889, "192.0.2.20", 51002)
    flow_c = FlowKey("198.51.100.3", 8889, "192.0.2.20", 51003)
    message = b"\x05\x00\x00\x01\x00"

    def send(
        flow: FlowKey,
        *,
        sequence: int = 100,
        payload: bytes = message,
        fin: bool = False,
        rst: bool = False,
    ) -> None:
        collector.process_tcp_segment(
            source_ip=flow.source_ip,
            source_port=flow.source_port,
            destination_ip=flow.destination_ip,
            destination_port=flow.destination_port,
            sequence=sequence,
            payload=payload,
            timestamp=float(sequence),
            fin=fin,
            rst=rst,
        )

    send(flow_a)
    send(flow_b)
    # Activity, not original insertion order, makes A the most-recent flow.
    send(flow_a, sequence=105)

    unknown = FlowKey("198.51.100.99", 8889, "192.0.2.20", 51999)
    send(unknown, payload=b"")
    send(unknown, payload=b"", fin=True)
    send(unknown, payload=b"", rst=True)
    assert collector.flow_state_evictions == 0
    assert tuple(collector._manager._flows) == (flow_b, flow_a)

    send(flow_c)

    health = collector.health()
    assert tuple(collector._manager._flows) == (flow_a, flow_c)
    assert health.flow_state_evictions == 1
    assert not health.capture_is_clean


def test_collector_retention_is_bounded_after_snapshot_latch() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)
    collector = SolareFrameCollector((8889,), tracker.observe)
    complete = _complete_frames()
    for frame in complete:
        collector._accept_frame(frame)
    tracker.refresh()
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


def test_live_tracker_preconfirmation_retention_has_explicit_budgets() -> None:
    updates: list[SolareUpdate] = []
    tracker = LiveSolareDiscoveryTracker(updates.append)
    noise = _non_solare_frames(DISCOVERY_RETENTION_MAX_FRAMES * 3)

    for frame in noise:
        tracker.observe(frame)

    assert not tracker.complete
    assert tracker.retained_frame_count <= DISCOVERY_RETENTION_MAX_FRAMES
    assert tracker.retained_bytes <= DISCOVERY_RETENTION_MAX_BYTES
    assert len(tracker.retained_frames) == tracker.retained_frame_count
    assert sum(frame.length for frame in tracker.retained_frames) == (
        tracker.retained_bytes
    )
    assert tracker.peak_retained_frame_count <= DISCOVERY_RETENTION_MAX_FRAMES
    assert tracker.peak_retained_bytes <= DISCOVERY_RETENTION_MAX_BYTES
    assert tracker.evicted_frame_count == len(noise) - tracker.retained_frame_count
    assert tracker.evicted_bytes == (
        sum(frame.length for frame in noise) - tracker.retained_bytes
    )
    assert sum(
        update.kind is SolareUpdateKind.WARNING for update in updates
    ) == 1


def test_tracker_auxiliary_indexes_do_not_own_evicted_frames() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)
    one_round = _non_solare_frames(64, distinct_flows=True)

    for round_index in range(12):
        shifted = _shift_frames(
            one_round,
            sequence_delta=round_index * 100_000,
            timestamp_delta=round_index * 100.0,
            index_delta=round_index * 1_000,
        )
        for frame in shifted:
            tracker.observe(frame)

    retained_ids = {id(frame) for frame in tracker.retained_frames}
    indexed_frames = tuple(
        frame
        for recent in tracker._family_recent.values()
        for frame in recent
    )

    assert tracker.evicted_frame_count > 0
    assert {id(frame) for frame in indexed_frames} <= retained_ids
    assert len(retained_ids | {id(frame) for frame in indexed_frames}) == (
        tracker.retained_frame_count
    )


def test_tracker_rollover_preserves_a_compact_best_partial_result() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)
    partial = _complete_frames(include_overall=False)[:200]

    for frame in partial:
        tracker.observe(frame)
    tracker.refresh(end_of_burst=False)
    assert tracker.result.ranked_candidate is not None
    assert tracker.result.ranked_candidate.record_count == 400

    # Unique flows avoid artificial family milestones while enough qualifying
    # traffic arrives to evict every raw frame from the useful partial table.
    noise = _non_solare_frames(
        DISCOVERY_RETENTION_MAX_FRAMES * 2,
        distinct_flows=True,
    )
    for frame in noise:
        tracker.observe(frame)
    tracker.refresh()

    ranked = tracker.result.ranked_candidate
    assert ranked is not None
    assert ranked.record_count == 400
    assert ranked.names[:2] == ("Player0001", "Player0002")
    assert ranked.frames == ()
    assert all(frame.opcode == 0x7A7A for frame in tracker.retained_frames)
    assert tracker.retained_frame_count <= DISCOVERY_RETENTION_MAX_FRAMES
    assert tracker.retained_bytes <= DISCOVERY_RETENTION_MAX_BYTES


def test_collector_can_delegate_frame_storage_to_live_tracker() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)
    collector = SolareFrameCollector(
        (8889,),
        tracker.observe,
        retain_frames=False,
    )
    complete = _complete_frames()

    for frame in complete:
        collector._accept_frame(frame)
    tracker.refresh()

    assert tracker.complete
    assert tracker.confirmed_frames == complete
    assert collector.frames == []
    assert collector.health().synchronized_messages == len(complete)
    assert collector.health().retained_large_messages == 0


def test_completed_tracker_retains_only_the_exact_confirmation_window() -> None:
    updates: list[SolareUpdate] = []
    tracker = LiveSolareDiscoveryTracker(updates.append)
    noise = _non_solare_frames(DISCOVERY_RETENTION_MAX_FRAMES * 2)
    complete = _complete_frames(name_prefix="Confirmed")

    for frame in noise + complete:
        tracker.observe(frame)
    tracker.refresh()

    assert tracker.complete
    assert tracker.confirmed_frames == complete
    assert tracker.retained_frames == complete
    assert tracker.retained_frame_count == len(complete) == 360
    assert tracker.retained_bytes == sum(frame.length for frame in complete)
    assert tracker.peak_retained_frame_count <= DISCOVERY_RETENTION_MAX_FRAMES
    assert tracker.peak_retained_bytes <= DISCOVERY_RETENTION_MAX_BYTES
    assert tracker.evicted_frame_count >= len(noise)
    assert tracker._family_counts == Counter()
    assert tracker._retained_family_counts == Counter()
    assert tracker._family_recent == {}
    assert tracker._family_targets == {}
    assert sum(
        update.kind is SolareUpdateKind.WARNING for update in updates
    ) == 1


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

    def fake_build(
        frames: object,
        health: SolareCaptureHealth,
        **kwargs: object,
    ):
        observed["frames"] = frames
        observed["health"] = health
        observed["build_kwargs"] = kwargs
        return expected

    monkeypatch.setattr(replay_module, "iter_pcap_file", fake_iter)
    monkeypatch.setattr(replay_module, "build_solare_result", fake_build)

    assert replay_module.replay_solare("ignored.pcapng") is expected
    assert observed["frames"] == ()
    health = observed["health"]
    assert isinstance(health, SolareCaptureHealth)
    assert health.saved_packets == 3
    build_kwargs = observed["build_kwargs"]
    assert isinstance(build_kwargs, dict)
    assert build_kwargs["retain_raw_extensions"] is False
    assert build_kwargs["_discovery"] is not None


def test_replay_forwards_raw_retention_to_result_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bdo_toolkit.solare.replay as replay_module

    expected = SolareCaptureResult(
        status=SolareDetectionStatus.NO_TRAFFIC,
        evidence=SolareEvidence(),
    )
    observed: dict[str, object] = {}

    def fake_iter(_path: Path, _collector: object):
        return iter(())

    def fake_build(
        _frames: object,
        _health: SolareCaptureHealth,
        **kwargs: object,
    ) -> SolareCaptureResult:
        observed.update(kwargs)
        return expected

    monkeypatch.setattr(replay_module, "iter_pcap_file", fake_iter)
    monkeypatch.setattr(replay_module, "build_solare_result", fake_build)

    assert replay_module.replay_solare(
        "ignored.pcapng",
        retain_raw_extensions=True,
    ) is expected
    assert observed["retain_raw_extensions"] is True


def test_replay_rejects_non_boolean_raw_retention_before_opening_capture() -> None:
    with pytest.raises(
        TypeError,
        match="retain_raw_extensions must be a boolean",
    ):
        replay_solare(
            "must-not-be-opened.pcapng",
            retain_raw_extensions=1,  # type: ignore[arg-type]
        )


def test_live_tracker_emits_ranked_cross_check_and_confirmation_progress() -> None:
    updates: list[SolareUpdate] = []
    tracker = LiveSolareDiscoveryTracker(updates.append)

    for frame in _complete_frames():
        tracker.observe(frame)

    tracker.refresh()
    assert tracker.complete
    ranked_updates = [
        update.ranked_players
        for update in updates
        if update.kind is SolareUpdateKind.RANKED_PROGRESS
    ]
    assert ranked_updates == [400, 500, 600]
    assert any(update.kind is SolareUpdateKind.RICH_CANDIDATE for update in updates)
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


def test_live_tracker_confirms_divergent_overall_with_actual_overlap_count() -> None:
    updates: list[SolareUpdate] = []
    tracker = LiveSolareDiscoveryTracker(updates.append)
    rich_ranks = (*range(1, 21), *range(22, 622))

    for frame in _complete_frames(rich_ranks=rich_ranks):
        tracker.observe(frame)

    tracker.refresh()
    assert tracker.complete
    assert tracker.result.exact_cross_check == 99
    cross_checks = [
        update.exact_cross_check
        for update in updates
        if update.kind is SolareUpdateKind.CROSS_CHECK
    ]
    assert cross_checks == [20]
    assert updates[-1].kind is SolareUpdateKind.SNAPSHOT_CONFIRMED
    assert updates[-1].exact_cross_check == 99


def test_live_tracker_analyzes_each_exact_structural_window_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bdo_toolkit.solare._discovery as discovery_module

    calls: Counter[tuple[int, ...]] = Counter()
    original = discovery_module._candidate_name_pairs

    def counted_candidate_name_pairs(frames: Sequence[BDOFrame]):
        calls[tuple(id(frame) for frame in frames)] += 1
        return original(frames)

    monkeypatch.setattr(
        discovery_module,
        "_candidate_name_pairs",
        counted_candidate_name_pairs,
    )
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in _complete_frames():
        tracker.observe(frame)
    tracker.refresh()

    assert tracker.complete
    # Before the per-tracker cache, this stream performed twelve analyses:
    # the unchanged 310-frame rich window five times and overall-50 twice.
    assert sorted((len(window), count) for window, count in calls.items()) == [
        (10, 1),
        (24, 1),
        (50, 1),
        (200, 1),
        (250, 1),
        (300, 1),
        (310, 1),
    ]
    assert tracker._analysis_cache.entry_count == 0


def test_live_tracker_clears_analysis_cache_on_retention_eviction() -> None:
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)

    for frame in _complete_frames(include_overall=False)[:200]:
        tracker.observe(frame)
    assert tracker._analysis_cache.entry_count > 0

    for frame in _non_solare_frames(DISCOVERY_RETENTION_MAX_FRAMES):
        tracker.observe(frame)
        if tracker.history_rolled_over:
            break

    assert tracker.history_rolled_over
    assert tracker._analysis_cache.entry_count == 0
