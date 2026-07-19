from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.solare._constants import CLASS_NAMES
from bdo_toolkit.solare._details import decode_solare_details
from bdo_toolkit.solare._discovery import DiscoveredSolareFamily


_GEAR_SIZE = 0x7D1
_ADDON_SIZE = 0x1F5
_HISTORY_SIZE = 0x65
_FLOW = FlowKey("198.51.100.10", 8889, "192.0.2.25", 50000)


@dataclass(frozen=True)
class _Layout:
    layout_id: str
    frame_length: int
    stride: int
    name: int
    rank: int
    player_class: int
    uid: int
    matches: int
    elo: int
    specialization: int
    history: int
    gear: int
    draws: int
    addons: int
    wins: int
    losses: int
    overall_length: int
    overall_stride: int
    overall_name: int
    overall_rank: int
    overall_uid: int
    overall_uid_shift: int = 0


# Kept independent from _details.py so these fixtures verify the promoted
# offsets rather than merely reflecting the implementation's own registry.
_LAYOUTS = (
    _Layout(
        "solare-rich-2026-06-24-v1",
        15900,
        0x1F08,
        0x14,
        0x52,
        0x58,
        0x0A,
        0x5B,
        0x67,
        0x6B,
        0x6E,
        0x019D,
        0x1910,
        0x191C,
        0x1EFB,
        0x1F07,
        16148,
        0x1F80,
        0x17,
        0xCA,
        0x55,
        16,
    ),
    _Layout(
        "solare-rich-2026-07-14-v1",
        15930,
        0x1F15,
        0x19,
        0x10,
        0x62,
        0x5A,
        0x68,
        0x74,
        0x1926,
        0x17EB,
        0x0078,
        0x1F19,
        0x1929,
        0x191A,
        0x1F0D,
        16145,
        0x1F80,
        0x98,
        0x81,
        0x14,
    ),
    _Layout(
        "solare-rich-2026-07-17-v1",
        15914,
        0x1F0F,
        0x1F,
        0x0C,
        0x5D,
        0x10,
        0x1F0F,
        0x1EFC,
        0x077A,
        0x064B,
        0x077D,
        0x063F,
        0x0060,
        0x1F03,
        0x1EF0,
        16143,
        0x1F7F,
        0x8A,
        0x7E,
        0x82,
    ),
)


@dataclass(frozen=True)
class _SyntheticSnapshot:
    rich_frames: tuple[BDOFrame, ...]
    rich: DiscoveredSolareFamily
    overall_frames: tuple[BDOFrame, ...]
    overall: DiscoveredSolareFamily


def _put_u32(message: bytearray, offset: int, value: int) -> None:
    message[offset : offset + 4] = value.to_bytes(4, "little")


def _put_header(message: bytearray, opcode: int) -> None:
    message[0:2] = len(message).to_bytes(2, "little")
    message[2] = 0
    message[3:5] = opcode.to_bytes(2, "little")


def _frame(index: int, message: bytearray, stream_sequence: int) -> BDOFrame:
    return BDOFrame(
        index=index,
        message=bytes(message),
        context=PacketContext(
            timestamp=float(index),
            flow=_FLOW,
            stream_start=stream_sequence,
        ),
        stream_sequence=stream_sequence,
    )


def _write_history(message: bytearray, offset: int, raw: str) -> None:
    encoded = raw.encode("ascii")
    assert len(encoded) < _HISTORY_SIZE
    message[offset : offset + len(encoded)] = encoded
    message[offset + len(encoded)] = 0


def _synthetic_snapshot(
    layout: _Layout,
    *,
    rich_ranks: tuple[int, ...] | None = None,
) -> _SyntheticSnapshot:
    class_codes = tuple(sorted(CLASS_NAMES))
    assert len(class_codes) == 31
    if rich_ranks is None:
        rich_ranks = tuple(range(1, 621))
    assert len(rich_ranks) == 620
    ranks = rich_ranks
    names = tuple(f"TestPlayer{rank:04d}" for rank in ranks)
    primary_codes = tuple(code for code in class_codes for _ in range(20))
    rich_opcode = 0x7070  # Deliberately unrelated to every observed opcode.

    rich_frames: list[BDOFrame] = []
    for frame_index in range(310):
        message = bytearray(layout.frame_length)
        for in_frame_index, base in enumerate((0, layout.stride)):
            ordinal = frame_index * 2 + in_frame_index
            rank = ranks[ordinal]
            name = names[ordinal]
            primary = primary_codes[ordinal]
            classes = [primary, 101, 101]
            specs = [1, 3, 3]
            matches = [100 + rank, 0, 0]
            draws = [rank % 2, 0, 0]
            wins = [50 + rank // 3, 0, 0]
            losses = [matches[0] - draws[0] - wins[0], 0, 0]
            histories = ["1,0,1", "", ""]

            # Exercise all three occupied slots and their independent raw
            # boundaries on the first record only.
            if ordinal == 0:
                classes = [primary, class_codes[1], class_codes[2]]
                specs = [1, 2, 1]
                matches = [101, 20, 10]
                draws = [1, 0, 1]
                wins = [50, 11, 4]
                losses = [50, 9, 5]
                histories = ["1,0,1", "0,1", "1"]

            uid = ((10_000 + rank) << 16).to_bytes(8, "little")
            message[base + layout.uid : base + layout.uid + 8] = uid
            encoded_name = name.encode("utf-16le") + b"\x00\x00"
            message[
                base + layout.name : base + layout.name + len(encoded_name)
            ] = encoded_name
            _put_u32(message, base + layout.rank, rank)
            message[
                base + layout.player_class : base + layout.player_class + 3
            ] = bytes(classes)
            message[
                base + layout.specialization : base + layout.specialization + 3
            ] = bytes(specs)
            for slot in range(3):
                _put_u32(message, base + layout.matches + slot * 4, matches[slot])
                _put_u32(message, base + layout.draws + slot * 4, draws[slot])
                _put_u32(message, base + layout.wins + slot * 4, wins[slot])
                _put_u32(message, base + layout.losses + slot * 4, losses[slot])
                _write_history(
                    message,
                    base + layout.history + slot * _HISTORY_SIZE,
                    histories[slot],
                )
                if ordinal == 0:
                    gear_byte = 0xA1 + slot
                    addon_byte = 0xB1 + slot
                    gear_start = base + layout.gear + slot * _GEAR_SIZE
                    addon_start = base + layout.addons + slot * _ADDON_SIZE
                    message[gear_start : gear_start + _GEAR_SIZE] = bytes(
                        [gear_byte]
                    ) * _GEAR_SIZE
                    message[addon_start : addon_start + _ADDON_SIZE] = bytes(
                        [addon_byte]
                    ) * _ADDON_SIZE
            _put_u32(message, base + layout.elo, 10_000 - rank)

        # The first record's tail can intentionally extend into the otherwise
        # unused prefix of record two, so write the wire header last.
        _put_header(message, rich_opcode)
        rich_frames.append(
            _frame(frame_index, message, frame_index * layout.frame_length)
        )

    rich = DiscoveredSolareFamily(
        role="rich",
        flow=_FLOW,
        opcode=0x1234,  # Decoder selection must not consult this value.
        frame_length=layout.frame_length,
        frame_count=310,
        record_stride=layout.stride,
        name_offset=layout.name,
        rank_offset=layout.rank,
        names=names,
        ranks=ranks,
        first_stream_offset=0,
        last_stream_end=310 * layout.frame_length,
        class_offset=layout.player_class,
        class_codes=primary_codes,
        class_counts=tuple((code, 20) for code in class_codes),
    )

    overall_frames: list[BDOFrame] = []
    overall_opcode = 0x7171
    for frame_index in range(50):
        message = bytearray(layout.overall_length)
        for in_frame_index, base in enumerate((0, layout.overall_stride)):
            ordinal = frame_index * 2 + in_frame_index
            overall_rank = ordinal + 1
            uid_value = (10_000 + overall_rank) << 16
            uid_value >>= layout.overall_uid_shift
            start = base + layout.overall_uid
            message[start : start + 8] = uid_value.to_bytes(8, "little")
        _put_header(message, overall_opcode)
        overall_frames.append(
            _frame(
                310 + frame_index,
                message,
                (310 + frame_index) * layout.overall_length,
            )
        )

    overall = DiscoveredSolareFamily(
        role="overall",
        flow=_FLOW,
        opcode=0x5678,
        frame_length=layout.overall_length,
        frame_count=50,
        record_stride=layout.overall_stride,
        name_offset=layout.overall_name,
        rank_offset=layout.overall_rank,
        names=tuple(f"TestPlayer{rank:04d}" for rank in range(1, 101)),
        ranks=tuple(range(1, 101)),
        first_stream_offset=rich.last_stream_end,
        last_stream_end=rich.last_stream_end + 50 * layout.overall_length,
    )
    return _SyntheticSnapshot(
        tuple(rich_frames), rich, tuple(overall_frames), overall
    )


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detailed_layout_extracts_exact_raw_slot_boundaries(layout: _Layout) -> None:
    synthetic = _synthetic_snapshot(layout)

    result = decode_solare_details(
        synthetic.rich_frames,
        synthetic.rich,
        overall_frames=synthetic.overall_frames,
        overall=synthetic.overall,
        retain_raw_extensions=True,
    )

    assert result is not None
    assert result.layout_id == layout.layout_id
    assert len(result.players) == 620
    first = result.players[0]
    assert first.name == "TestPlayer0001"
    assert first.global_rank == 1
    assert first.elo == 9999
    assert len(first.classes_played) == 3
    for slot, performance in enumerate(first.classes_played):
        assert performance.slot == slot
        assert performance.primary is (slot == 0)
        assert performance.record_is_balanced
        assert performance.gear_loadout_raw is not None
        assert performance.gear_loadout_raw.offset == layout.gear + slot * _GEAR_SIZE
        assert performance.gear_loadout_raw.data == bytes([0xA1 + slot]) * _GEAR_SIZE
        assert performance.skill_addons_raw is not None
        assert (
            performance.skill_addons_raw.offset
            == layout.addons + slot * _ADDON_SIZE
        )
        assert performance.skill_addons_raw.data == bytes(
            [0xB1 + slot]
        ) * _ADDON_SIZE

    encoded = first.classes_played[2].to_dict(include_raw=True)
    assert encoded["gear_loadout_raw"] == {
        "offset": layout.gear + 2 * _GEAR_SIZE,
        "length": _GEAR_SIZE,
        "encoding": "hex",
        "data": (bytes([0xA3]) * _GEAR_SIZE).hex(),
    }
    assert encoded["skill_addons_raw"] == {
        "offset": layout.addons + 2 * _ADDON_SIZE,
        "length": _ADDON_SIZE,
        "encoding": "hex",
        "data": (bytes([0xB3]) * _ADDON_SIZE).hex(),
    }


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detailed_layout_keeps_performance_without_raw_extensions(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)

    result = decode_solare_details(
        synthetic.rich_frames,
        synthetic.rich,
        overall_frames=synthetic.overall_frames,
        overall=synthetic.overall,
    )

    assert result is not None
    first = result.players[0]
    assert first.elo == 9999
    assert len(first.classes_played) == 3
    for performance in first.classes_played:
        assert performance.record_is_balanced
        assert performance.recent_results_raw
        assert performance.gear_loadout_raw is None
        assert performance.skill_addons_raw is None


@pytest.mark.parametrize("value", [None, 0, 1, "yes"])
def test_detail_decoder_rejects_non_boolean_raw_retention(value: object) -> None:
    synthetic = _synthetic_snapshot(_LAYOUTS[0])

    with pytest.raises(
        TypeError,
        match="retain_raw_extensions must be a boolean",
    ):
        decode_solare_details(
            synthetic.rich_frames,
            synthetic.rich,
            retain_raw_extensions=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detail_uid_cross_check_supports_overall_only_player(layout: _Layout) -> None:
    rich_ranks = (*range(1, 21), *range(22, 622))
    synthetic = _synthetic_snapshot(layout, rich_ranks=rich_ranks)

    result = decode_solare_details(
        synthetic.rich_frames,
        synthetic.rich,
        overall_frames=synthetic.overall_frames,
        overall=synthetic.overall,
    )

    assert result is not None
    assert len(result.players) == 620
    assert len(result.overall_uids) == 100
    expected_uid = ((10_000 + 21) << 16) >> layout.overall_uid_shift
    assert result.overall_uids[20] == expected_uid.to_bytes(8, "little")


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detail_uid_cross_check_accepts_minimum_twenty_overlaps(
    layout: _Layout,
) -> None:
    rich_ranks = (*range(1, 21), *range(101, 701))
    synthetic = _synthetic_snapshot(layout, rich_ranks=rich_ranks)

    result = decode_solare_details(
        synthetic.rich_frames,
        synthetic.rich,
        overall_frames=synthetic.overall_frames,
        overall=synthetic.overall,
    )

    assert result is not None
    assert len(result.overall_uids) == 100


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detail_uid_cross_check_rejects_one_shared_uid_mismatch(
    layout: _Layout,
) -> None:
    rich_ranks = (*range(1, 21), *range(22, 622))
    synthetic = _synthetic_snapshot(layout, rich_ranks=rich_ranks)
    ordinal = 21  # Overall rank 22 is shared with the rich table.
    frame_index = ordinal // 2
    base = layout.overall_stride if ordinal % 2 else 0
    message = bytearray(synthetic.overall_frames[frame_index].message)
    start = base + layout.overall_uid
    message[start : start + 8] = (9_999_999).to_bytes(8, "little")
    damaged_frames = (
        *synthetic.overall_frames[:frame_index],
        replace(synthetic.overall_frames[frame_index], message=bytes(message)),
        *synthetic.overall_frames[frame_index + 1 :],
    )

    assert (
        decode_solare_details(
            synthetic.rich_frames,
            synthetic.rich,
            overall_frames=damaged_frames,
            overall=synthetic.overall,
        )
        is None
    )


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detail_uid_cross_check_retains_unmatched_overall_uid(layout: _Layout) -> None:
    rich_ranks = (*range(1, 21), *range(22, 622))
    synthetic = _synthetic_snapshot(layout, rich_ranks=rich_ranks)
    ordinal = 20  # Overall rank 21 is intentionally absent from rich.
    frame_index = ordinal // 2
    message = bytearray(synthetic.overall_frames[frame_index].message)
    replacement_uid = (9_888_777).to_bytes(8, "little")
    start = layout.overall_uid
    message[start : start + 8] = replacement_uid
    changed_frames = (
        *synthetic.overall_frames[:frame_index],
        replace(synthetic.overall_frames[frame_index], message=bytes(message)),
        *synthetic.overall_frames[frame_index + 1 :],
    )

    result = decode_solare_details(
        synthetic.rich_frames,
        synthetic.rich,
        overall_frames=changed_frames,
        overall=synthetic.overall,
    )

    assert result is not None
    assert result.overall_uids[ordinal] == replacement_uid


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detailed_layout_fails_closed_on_one_unbalanced_slot(layout: _Layout) -> None:
    synthetic = _synthetic_snapshot(layout)
    message = bytearray(synthetic.rich_frames[0].message)
    _put_u32(message, layout.wins, 51)
    damaged_frames = (
        replace(synthetic.rich_frames[0], message=bytes(message)),
        *synthetic.rich_frames[1:],
    )

    assert (
        decode_solare_details(
            damaged_frames,
            synthetic.rich,
            overall_frames=synthetic.overall_frames,
            overall=synthetic.overall,
        )
        is None
    )


def test_detailed_layout_fails_closed_for_unknown_geometry() -> None:
    synthetic = _synthetic_snapshot(_LAYOUTS[-1])
    unknown = replace(synthetic.rich, name_offset=synthetic.rich.name_offset + 1)

    assert decode_solare_details(synthetic.rich_frames, unknown) is None
