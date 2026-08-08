from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.solare._constants import CLASS_NAMES
from bdo_toolkit.solare._details import (
    decode_solare_details,
    decode_solare_overall_details,
)
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
    overall_elo: int
    overall_total_wins: int
    overall_total_draws: int
    overall_total_losses: int
    overall_class: int
    overall_specialization: int
    overall_matches: int
    overall_wins: int
    overall_draws: int
    overall_losses: int
    overall_history: int
    overall_gear: int
    overall_addons: int


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
        0xD0,
        0xD4,
        0x61,
        0x5D,
        0xD8,
        0x1F82,
        0x1F85,
        0xDB,
        0x7F7,
        0x803,
        0xE7,
        0x80F,
        0x218,
    ),
    _Layout(
        "solare-rich-2026-07-14-v1",
        15930,
        0x1F15,
        0x19,
        0x10,
        0x62,
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
        0x8D,
        0x89,
        0x85,
        0x91,
        0xD6,
        0x6C4,
        0x1F79,
        0x1F85,
        0xD9,
        0x6C9,
        0x1E4A,
        0x6D5,
        0xE5,
    ),
    _Layout(
        "solare-rich-2026-07-17-v1",
        15914,
        0x1F0F,
        0x1F,
        0x0C,
        0x5D,
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
        0x11,
        0xCC,
        0x15,
        0xC8,
        0xD0,
        0x1861,
        0x19A5,
        0x1855,
        0x186A,
        0x1849,
        0x1876,
        0xD3,
        0x19B1,
    ),
)

# These formerly exposed identity-like bytes are retained only as negative
# regression coordinates: changing them must not affect any public ranking,
# Elo, performance, or aggregate detail.
_FORMER_IDENTITY_OFFSETS = {
    "solare-rich-2026-06-24-v1": (0x0A, 0x55),
    "solare-rich-2026-07-14-v1": (0x5A, 0x14),
    "solare-rich-2026-07-17-v1": (0x10, 0x82),
}


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

            encoded_name = name.encode("utf-16le") + b"\x00\x00"
            message[base + layout.name : base + layout.name + len(encoded_name)] = (
                encoded_name
            )
            _put_u32(message, base + layout.rank, rank)
            message[base + layout.player_class : base + layout.player_class + 3] = (
                bytes(classes)
            )
            message[base + layout.specialization : base + layout.specialization + 3] = (
                bytes(specs)
            )
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
                    message[gear_start : gear_start + _GEAR_SIZE] = (
                        bytes([gear_byte]) * _GEAR_SIZE
                    )
                    message[addon_start : addon_start + _ADDON_SIZE] = (
                        bytes([addon_byte]) * _ADDON_SIZE
                    )
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
            name = f"TestPlayer{overall_rank:04d}"
            encoded_name = name.encode("utf-16le") + b"\x00\x00"
            message[
                base
                + layout.overall_name : base
                + layout.overall_name
                + len(encoded_name)
            ] = encoded_name
            _put_u32(message, base + layout.overall_rank, overall_rank)
            _put_u32(message, base + layout.overall_elo, 20_000 - overall_rank)

            primary = class_codes[(ordinal + 7) % len(class_codes)]
            classes = [primary, 101, 101]
            specs = [2, 3, 3]
            matches = [1_000 + overall_rank, 0, 0]
            draws = [overall_rank % 3, 0, 0]
            wins = [600 + overall_rank // 4, 0, 0]
            losses = [matches[0] - draws[0] - wins[0], 0, 0]
            histories = ["0,1,0,1", "", ""]
            if ordinal == 0:
                classes = [class_codes[-1], class_codes[-2], class_codes[-3]]
                specs = [2, 1, 2]
                matches = [200, 80, 30]
                draws = [2, 1, 0]
                wins = [120, 40, 11]
                losses = [78, 39, 19]
                histories = ["0,1,0", "1,1", "0"]

            # The aggregate tuple is an independent overall-record source.
            # For ordinary one-slot rows its components deliberately differ
            # from the slot counters while preserving the same total.  The
            # three-slot row additionally carries 50 matches beyond the
            # exposed slots, and its aggregate loss count is deliberately
            # lower than the exposed loss sum: neither componentwise equality
            # nor dominance is a valid protocol invariant.
            aggregate_wins = sum(wins) + 2
            aggregate_draws = sum(draws) + 1
            aggregate_losses = sum(losses) - 3
            if ordinal == 0:
                aggregate_wins = 230
                aggregate_draws = 4
                aggregate_losses = 126

            message[base + layout.overall_class : base + layout.overall_class + 3] = (
                bytes(classes)
            )
            message[
                base
                + layout.overall_specialization : base
                + layout.overall_specialization
                + 3
            ] = bytes(specs)
            for slot in range(3):
                _put_u32(
                    message,
                    base + layout.overall_matches + slot * 4,
                    matches[slot],
                )
                _put_u32(
                    message,
                    base + layout.overall_wins + slot * 4,
                    wins[slot],
                )
                _put_u32(
                    message,
                    base + layout.overall_draws + slot * 4,
                    draws[slot],
                )
                _put_u32(
                    message,
                    base + layout.overall_losses + slot * 4,
                    losses[slot],
                )
                _write_history(
                    message,
                    base + layout.overall_history + slot * _HISTORY_SIZE,
                    histories[slot],
                )
                if classes[slot] != 101:
                    gear_start = base + layout.overall_gear + slot * _GEAR_SIZE
                    addon_start = base + layout.overall_addons + slot * _ADDON_SIZE
                    gear_byte = 0xC1 + slot if ordinal == 0 else 0x40 + ordinal % 0x40
                    addon_byte = 0xD1 + slot if ordinal == 0 else 0x80 + ordinal % 0x40
                    message[gear_start : gear_start + _GEAR_SIZE] = (
                        bytes([gear_byte]) * _GEAR_SIZE
                    )
                    message[addon_start : addon_start + _ADDON_SIZE] = (
                        bytes([addon_byte]) * _ADDON_SIZE
                    )
            _put_u32(
                message,
                base + layout.overall_total_wins,
                aggregate_wins,
            )
            _put_u32(
                message,
                base + layout.overall_total_draws,
                aggregate_draws,
            )
            _put_u32(
                message,
                base + layout.overall_total_losses,
                aggregate_losses,
            )
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
    return _SyntheticSnapshot(tuple(rich_frames), rich, tuple(overall_frames), overall)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_detailed_layout_extracts_exact_raw_slot_boundaries(layout: _Layout) -> None:
    synthetic = _synthetic_snapshot(layout)

    result = decode_solare_details(
        synthetic.rich_frames,
        synthetic.rich,
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
        assert performance.skill_addons_raw.offset == layout.addons + slot * _ADDON_SIZE
        assert performance.skill_addons_raw.data == bytes([0xB1 + slot]) * _ADDON_SIZE

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


def _replace_overall_bytes(
    synthetic: _SyntheticSnapshot,
    layout: _Layout,
    *,
    ordinal: int,
    offset: int,
    value: bytes,
) -> tuple[BDOFrame, ...]:
    frame_index = ordinal // 2
    base = layout.overall_stride if ordinal % 2 else 0
    message = bytearray(synthetic.overall_frames[frame_index].message)
    start = base + offset
    message[start : start + len(value)] = value
    return (
        *synthetic.overall_frames[:frame_index],
        replace(synthetic.overall_frames[frame_index], message=bytes(message)),
        *synthetic.overall_frames[frame_index + 1 :],
    )


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_layout_decodes_its_own_details_and_raw(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)

    result = decode_solare_overall_details(
        synthetic.overall_frames,
        synthetic.overall,
        retain_raw_extensions=True,
    )

    assert result is not None
    assert result.layout_id == layout.layout_id.replace("rich", "overall")
    assert result.capabilities == frozenset(
        {
            "rankings",
            "elo",
            "aggregate_performance",
            "performance",
            "raw_extensions",
        }
    )
    assert len(result.entries) == 100
    first = result.entries[0]
    assert first.name == "TestPlayer0001"
    assert first.global_rank == 1
    assert first.elo == 19_999
    assert first.total_wins == 230
    assert first.total_draws == 4
    assert first.total_losses == 126
    assert first.total_matches == 360
    assert not hasattr(layout, "overall_total_matches")
    assert first.total_matches == (
        first.total_wins + first.total_draws + first.total_losses
    )
    assert [item.player_class.code for item in first.classes_played] == [
        34,
        33,
        32,
    ]
    assert [item.matches for item in first.classes_played] == [200, 80, 30]
    assert [item.wins for item in first.classes_played] == [120, 40, 11]
    assert [item.draws for item in first.classes_played] == [2, 1, 0]
    assert [item.losses for item in first.classes_played] == [78, 39, 19]
    assert first.total_wins != sum(
        item.wins or 0 for item in first.classes_played
    )
    assert first.total_draws != sum(
        item.draws or 0 for item in first.classes_played
    )
    assert first.total_losses < sum(
        item.losses or 0 for item in first.classes_played
    )
    assert first.total_matches > sum(
        item.matches or 0 for item in first.classes_played
    )
    for slot, performance in enumerate(first.classes_played):
        assert performance.primary is (slot == 0)
        assert performance.record_is_balanced
        assert performance.gear_loadout_raw is not None
        assert (
            performance.gear_loadout_raw.offset
            == layout.overall_gear + slot * _GEAR_SIZE
        )
        assert performance.gear_loadout_raw.data == bytes([0xC1 + slot]) * _GEAR_SIZE
        assert performance.skill_addons_raw is not None
        assert (
            performance.skill_addons_raw.offset
            == layout.overall_addons + slot * _ADDON_SIZE
        )
        assert performance.skill_addons_raw.data == bytes([0xD1 + slot]) * _ADDON_SIZE


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_only_player_retains_direct_performance_and_raw(
    layout: _Layout,
) -> None:
    rich_ranks = (*range(1, 21), *range(22, 622))
    synthetic = _synthetic_snapshot(layout, rich_ranks=rich_ranks)

    rich = decode_solare_details(synthetic.rich_frames, synthetic.rich)
    overall = decode_solare_overall_details(
        synthetic.overall_frames,
        synthetic.overall,
        retain_raw_extensions=True,
    )

    assert rich is not None
    assert all(player.global_rank != 21 for player in rich.players)
    assert overall is not None
    player = overall.entries[20]
    assert (player.global_rank, player.name, player.elo) == (
        21,
        "TestPlayer0021",
        19_979,
    )
    assert len(player.classes_played) == 1
    performance = player.classes_played[0]
    assert performance.matches == 1_021
    assert performance.record_is_balanced
    assert player.total_matches == 1_021
    assert player.total_wins == (performance.wins or 0) + 2
    assert player.total_draws == (performance.draws or 0) + 1
    assert player.total_losses == (performance.losses or 0) - 3
    assert performance.gear_loadout_raw is not None
    assert performance.gear_loadout_raw.data == bytes([0x54]) * _GEAR_SIZE
    assert performance.skill_addons_raw is not None
    assert performance.skill_addons_raw.data == bytes([0x94]) * _ADDON_SIZE


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_and_rich_retain_differing_valid_wire_values(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)

    rich = decode_solare_details(synthetic.rich_frames, synthetic.rich)
    overall = decode_solare_overall_details(
        synthetic.overall_frames,
        synthetic.overall,
    )

    assert rich is not None and overall is not None
    assert rich.players[0].elo == 9_999
    assert overall.entries[0].elo == 19_999
    assert rich.players[0].primary_class.code == 0
    assert overall.entries[0].primary_class is not None
    assert overall.entries[0].primary_class.code == 34


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_former_identity_bytes_do_not_gate_supported_details(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)
    rich_offset, overall_offset = _FORMER_IDENTITY_OFFSETS[layout.layout_id]

    rich_message = bytearray(synthetic.rich_frames[0].message)
    rich_message[rich_offset : rich_offset + 8] = b"\xa5" * 8
    damaged_rich_frames = (
        replace(synthetic.rich_frames[0], message=bytes(rich_message)),
        *synthetic.rich_frames[1:],
    )
    damaged_overall_frames = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=overall_offset,
        value=b"\x5a" * 8,
    )

    original_rich = decode_solare_details(
        synthetic.rich_frames,
        synthetic.rich,
    )
    damaged_rich = decode_solare_details(
        damaged_rich_frames,
        synthetic.rich,
    )
    original_overall = decode_solare_overall_details(
        synthetic.overall_frames,
        synthetic.overall,
    )
    damaged_overall = decode_solare_overall_details(
        damaged_overall_frames,
        synthetic.overall,
    )

    assert original_rich is not None and damaged_rich is not None
    assert original_overall is not None and damaged_overall is not None
    assert damaged_rich.capabilities == original_rich.capabilities
    assert damaged_overall.capabilities == original_overall.capabilities
    assert tuple(item.to_dict() for item in damaged_rich.players) == tuple(
        item.to_dict() for item in original_rich.players
    )
    assert tuple(item.to_dict() for item in damaged_overall.entries) == tuple(
        item.to_dict() for item in original_overall.entries
    )


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_raw_retention_is_opt_in(layout: _Layout) -> None:
    synthetic = _synthetic_snapshot(layout)

    result = decode_solare_overall_details(
        synthetic.overall_frames,
        synthetic.overall,
    )

    assert result is not None
    assert result.capabilities == frozenset(
        {
            "rankings",
            "elo",
            "aggregate_performance",
            "performance",
        }
    )
    assert all(
        performance.gear_loadout_raw is None and performance.skill_addons_raw is None
        for entry in result.entries
        for performance in entry.classes_played
    )


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
@pytest.mark.parametrize(
    "offset_name",
    (
        "overall_total_wins",
        "overall_total_draws",
        "overall_total_losses",
    ),
)
def test_overall_aggregate_field_corruption_withholds_only_aggregate_group(
    layout: _Layout,
    offset_name: str,
) -> None:
    synthetic = _synthetic_snapshot(layout)
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=getattr(layout, offset_name),
        value=(1_000_001).to_bytes(4, "little"),
    )

    result = decode_solare_overall_details(
        damaged,
        synthetic.overall,
        retain_raw_extensions=True,
    )

    assert result is not None
    assert "aggregate_performance" not in result.capabilities
    assert {
        "rankings",
        "elo",
        "performance",
        "raw_extensions",
    } <= result.capabilities
    assert all(entry.total_wins is None for entry in result.entries)
    assert all(entry.total_draws is None for entry in result.entries)
    assert all(entry.total_losses is None for entry in result.entries)
    assert all(entry.total_matches is None for entry in result.entries)
    assert all(entry.classes_played for entry in result.entries)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_aggregate_rejects_plausible_components_with_oversized_total(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=layout.overall_total_wins,
        value=(999_999).to_bytes(4, "little"),
    )

    result = decode_solare_overall_details(damaged, synthetic.overall)

    assert result is not None
    assert "aggregate_performance" not in result.capabilities
    assert "performance" in result.capabilities
    assert all(entry.total_matches is None for entry in result.entries)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_aggregate_rejects_zero_total(layout: _Layout) -> None:
    synthetic = _synthetic_snapshot(layout)
    message = bytearray(synthetic.overall_frames[0].message)
    for offset in (
        layout.overall_total_wins,
        layout.overall_total_draws,
        layout.overall_total_losses,
    ):
        _put_u32(message, offset, 0)
    damaged = (
        replace(synthetic.overall_frames[0], message=bytes(message)),
        *synthetic.overall_frames[1:],
    )

    result = decode_solare_overall_details(damaged, synthetic.overall)

    assert result is not None
    assert "aggregate_performance" not in result.capabilities
    assert "performance" in result.capabilities
    assert all(entry.total_matches is None for entry in result.entries)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_aggregate_requires_exact_total_below_three_occupied_slots(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)
    # Rank two exposes one slot totaling 1002 matches. Its valid synthetic
    # aggregate tuple is 602/3/397; adding one win must invalidate the entire
    # aggregate group even though every component remains independently sane.
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=1,
        offset=layout.overall_total_wins,
        value=(603).to_bytes(4, "little"),
    )

    result = decode_solare_overall_details(damaged, synthetic.overall)

    assert result is not None
    assert "aggregate_performance" not in result.capabilities
    assert "performance" in result.capabilities
    assert all(entry.total_matches is None for entry in result.entries)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_aggregate_requires_total_to_cover_exposed_three_slot_matches(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)
    # The first row exposes 310 matches. Lowering its aggregate win count from
    # 230 to 100 produces a still-bounded tuple totaling only 230.
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=layout.overall_total_wins,
        value=(100).to_bytes(4, "little"),
    )

    result = decode_solare_overall_details(damaged, synthetic.overall)

    assert result is not None
    assert "aggregate_performance" not in result.capabilities
    assert "performance" in result.capabilities
    assert all(entry.total_matches is None for entry in result.entries)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_aggregate_requires_its_lightweight_slot_match_summary(
    layout: _Layout,
) -> None:
    synthetic = _synthetic_snapshot(layout)
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=layout.overall_matches,
        value=(0).to_bytes(4, "little"),
    )

    result = decode_solare_overall_details(damaged, synthetic.overall)

    assert result is not None
    assert "aggregate_performance" not in result.capabilities
    assert "performance" not in result.capabilities
    assert "elo" in result.capabilities
    assert all(entry.total_matches is None for entry in result.entries)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
@pytest.mark.parametrize(
    ("offset_name", "value", "performance_survives"),
    (
        ("overall_specialization", b"\xff", False),
        ("overall_history", b"!", False),
        ("overall_gear", b"\xff", True),
        ("overall_addons", b"\xff", True),
    ),
)
def test_overall_aggregate_is_independent_of_deeper_and_opaque_fields(
    layout: _Layout,
    offset_name: str,
    value: bytes,
    performance_survives: bool,
) -> None:
    synthetic = _synthetic_snapshot(layout)
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=getattr(layout, offset_name),
        value=value,
    )

    result = decode_solare_overall_details(
        damaged,
        synthetic.overall,
        retain_raw_extensions=True,
    )

    assert result is not None
    assert "aggregate_performance" in result.capabilities
    assert all(entry.total_matches is not None for entry in result.entries)
    assert ("performance" in result.capabilities) is performance_survives
    if performance_survives:
        assert "raw_extensions" in result.capabilities
    else:
        assert "raw_extensions" not in result.capabilities


@pytest.mark.parametrize(
    ("field", "offset", "value", "missing", "preserved"),
    (
        (
            "elo",
            "overall_elo",
            (0).to_bytes(4, "little"),
            "elo",
            {"aggregate_performance", "performance"},
        ),
        (
            "performance",
            "overall_wins",
            (121).to_bytes(4, "little"),
            "performance",
            {"elo", "aggregate_performance"},
        ),
    ),
)
@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_corruption_withholds_only_its_all_table_group(
    layout: _Layout,
    field: str,
    offset: str,
    value: bytes,
    missing: str,
    preserved: set[str],
) -> None:
    synthetic = _synthetic_snapshot(layout)
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=getattr(layout, offset),
        value=value,
    )

    result = decode_solare_overall_details(
        damaged,
        synthetic.overall,
        retain_raw_extensions=True,
    )

    assert result is not None
    assert missing not in result.capabilities
    assert preserved <= result.capabilities
    assert all(entry.total_matches is not None for entry in result.entries)
    if field == "elo":
        assert all(entry.elo is None for entry in result.entries)
        assert all(entry.classes_played for entry in result.entries)
    else:
        assert "raw_extensions" not in result.capabilities
        assert all(not entry.classes_played for entry in result.entries)
        assert all(entry.elo is not None for entry in result.entries)


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_identity_corruption_fails_closed(layout: _Layout) -> None:
    synthetic = _synthetic_snapshot(layout)
    damaged = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=layout.overall_name,
        value=b"!\x00",
    )

    assert decode_solare_overall_details(damaged, synthetic.overall) is None


@pytest.mark.parametrize("layout", _LAYOUTS, ids=lambda item: item.layout_id)
def test_overall_tail_bounds_are_mandatory(layout: _Layout) -> None:
    synthetic = _synthetic_snapshot(layout)
    last = synthetic.overall_frames[-1]
    truncated = replace(last, message=last.message[:-1])

    assert (
        decode_solare_overall_details(
            (*synthetic.overall_frames[:-1], truncated),
            synthetic.overall,
        )
        is None
    )


def test_rich_and_overall_detail_failures_are_independent() -> None:
    layout = _LAYOUTS[-1]
    synthetic = _synthetic_snapshot(layout)
    rich_message = bytearray(synthetic.rich_frames[0].message)
    _put_u32(rich_message, layout.wins, 51)
    damaged_rich = (
        replace(synthetic.rich_frames[0], message=bytes(rich_message)),
        *synthetic.rich_frames[1:],
    )
    damaged_overall = _replace_overall_bytes(
        synthetic,
        layout,
        ordinal=0,
        offset=layout.overall_wins,
        value=(121).to_bytes(4, "little"),
    )

    assert decode_solare_details(damaged_rich, synthetic.rich) is None
    valid_overall = decode_solare_overall_details(
        synthetic.overall_frames,
        synthetic.overall,
    )
    assert valid_overall is not None
    assert "performance" in valid_overall.capabilities

    valid_rich = decode_solare_details(synthetic.rich_frames, synthetic.rich)
    assert valid_rich is not None
    invalid_overall = decode_solare_overall_details(
        damaged_overall,
        synthetic.overall,
    )
    assert invalid_overall is not None
    assert "performance" not in invalid_overall.capabilities


@pytest.mark.parametrize("value", [None, 0, 1, "yes"])
def test_overall_decoder_rejects_non_boolean_raw_retention(value: object) -> None:
    synthetic = _synthetic_snapshot(_LAYOUTS[0])

    with pytest.raises(
        TypeError,
        match="retain_raw_extensions must be a boolean",
    ):
        decode_solare_overall_details(
            synthetic.overall_frames,
            synthetic.overall,
            retain_raw_extensions=value,  # type: ignore[arg-type]
        )


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
        )
        is None
    )


def test_detailed_layout_fails_closed_for_unknown_geometry() -> None:
    synthetic = _synthetic_snapshot(_LAYOUTS[-1])
    unknown = replace(synthetic.rich, name_offset=synthetic.rich.name_offset + 1)

    assert decode_solare_details(synthetic.rich_frames, unknown) is None


def test_overall_detail_layout_fails_closed_for_unknown_geometry() -> None:
    synthetic = _synthetic_snapshot(_LAYOUTS[-1])
    unknown = replace(
        synthetic.overall,
        record_stride=synthetic.overall.record_stride + 1,
    )

    assert decode_solare_overall_details(synthetic.overall_frames, unknown) is None
