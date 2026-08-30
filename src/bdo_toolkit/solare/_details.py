"""Fail-closed decoding for validated Arena of Solare detail layouts.

Leaderboard discovery establishes semantic identity without trusting an
opcode.  This module is deliberately a second, stricter layer: it decodes
optional Elo, performance, and raw-extension fields only when the
discovered message geometry matches a layout validated against a complete
capture and the corresponding record-level invariants still hold.

The rich class tables and independent overall table are decoded from their own
wire records.  Neither decoder uses the other table as a data source.  When
explicitly requested, raw gear and skill-addon sections are retained
byte-for-byte; their internal semantics remain intentionally opaque.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Optional, Sequence

from bdo_toolkit._protocol import BDOFrame

from ._constants import (
    ADVANCED_SPEC_BY_CLASS,
    EMPTY_CLASS_CODE,
    EMPTY_SPEC_CODE,
    class_name,
)
from ._discovery import DiscoveredSolareFamily
from ._validation import validate_retain_raw_extensions
from .models import (
    SolareClass,
    SolareClassPerformance,
    SolareOverallEntry,
    SolarePlayer,
    SolareRawSection,
    SolareSpecialization,
)

_EXPECTED_RICH_RECORDS = 620
_EXPECTED_RICH_FRAMES = _EXPECTED_RICH_RECORDS // 2
_EXPECTED_OVERALL_RECORDS = 100
_EXPECTED_OVERALL_FRAMES = _EXPECTED_OVERALL_RECORDS // 2
_CLASS_SLOT_COUNT = 3

_HISTORY_SLOT_SIZE = 0x65
_GEAR_SLOT_SIZE = 0x7D1
_ADDON_SLOT_SIZE = 0x1F5
_MAX_PLAUSIBLE_MATCHES = 1_000_000
_MAX_PLAUSIBLE_ELO = 1_000_000
_HISTORY_PATTERN = re.compile(r"[01](?:,[01]){0,9}")


@dataclass(frozen=True)
class _RichDetailLayout:
    layout_id: str
    frame_length: int
    record_stride: int
    name_offset: int
    rank_offset: int
    class_offset: int
    matches_offset: int
    elo_offset: int
    spec_offset: int
    history_offset: int
    gear_offset: int
    draws_offset: int
    addons_offset: int
    wins_offset: int
    losses_offset: int

    @property
    def geometry(self) -> tuple[int, int, int, int, int]:
        return (
            self.frame_length,
            self.record_stride,
            self.name_offset,
            self.rank_offset,
            self.class_offset,
        )

    @property
    def required_record_end(self) -> int:
        return max(
            self.matches_offset + 12,
            self.elo_offset + 4,
            self.spec_offset + _CLASS_SLOT_COUNT,
            self.history_offset + _CLASS_SLOT_COUNT * _HISTORY_SLOT_SIZE,
            self.gear_offset + _CLASS_SLOT_COUNT * _GEAR_SLOT_SIZE,
            self.draws_offset + 12,
            self.addons_offset + _CLASS_SLOT_COUNT * _ADDON_SLOT_SIZE,
            self.wins_offset + 12,
            self.losses_offset + 12,
        )


@dataclass(frozen=True)
class _OverallDetailLayout:
    layout_id: str
    frame_length: int
    record_stride: int
    name_offset: int
    rank_offset: int
    elo_offset: int
    aggregate_wins_offset: int
    aggregate_draws_offset: int
    aggregate_losses_offset: int
    class_offset: int
    spec_offset: int
    matches_offset: int
    wins_offset: int
    draws_offset: int
    losses_offset: int
    history_offset: int
    gear_offset: int
    addons_offset: int

    @property
    def geometry(self) -> tuple[int, int, int, int]:
        return (
            self.frame_length,
            self.record_stride,
            self.name_offset,
            self.rank_offset,
        )

    @property
    def required_record_end(self) -> int:
        return max(
            self.elo_offset + 4,
            self.aggregate_wins_offset + 4,
            self.aggregate_draws_offset + 4,
            self.aggregate_losses_offset + 4,
            self.class_offset + _CLASS_SLOT_COUNT,
            self.spec_offset + _CLASS_SLOT_COUNT,
            self.matches_offset + 12,
            self.wins_offset + 12,
            self.draws_offset + 12,
            self.losses_offset + 12,
            self.history_offset + _CLASS_SLOT_COUNT * _HISTORY_SLOT_SIZE,
            self.gear_offset + _CLASS_SLOT_COUNT * _GEAR_SLOT_SIZE,
            self.addons_offset + _CLASS_SLOT_COUNT * _ADDON_SLOT_SIZE,
        )


# These fingerprints contain no opcode.  An opcode-only patch therefore keeps
# decoding, while any unvalidated geometry change disables optional detail
# capabilities and leaves structural rankings available.
_RICH_DETAIL_LAYOUTS = (
    _RichDetailLayout(
        layout_id="solare-rich-2026-06-24-v1",
        frame_length=15900,
        record_stride=0x1F08,
        name_offset=0x14,
        rank_offset=0x52,
        class_offset=0x58,
        matches_offset=0x5B,
        elo_offset=0x67,
        spec_offset=0x6B,
        history_offset=0x6E,
        gear_offset=0x019D,
        draws_offset=0x1910,
        addons_offset=0x191C,
        wins_offset=0x1EFB,
        losses_offset=0x1F07,
    ),
    _RichDetailLayout(
        layout_id="solare-rich-2026-07-14-v1",
        frame_length=15930,
        record_stride=0x1F15,
        name_offset=0x19,
        rank_offset=0x10,
        class_offset=0x62,
        matches_offset=0x68,
        elo_offset=0x74,
        spec_offset=0x1926,
        history_offset=0x17EB,
        gear_offset=0x0078,
        draws_offset=0x1F19,
        addons_offset=0x1929,
        wins_offset=0x191A,
        losses_offset=0x1F0D,
    ),
    _RichDetailLayout(
        layout_id="solare-rich-2026-07-17-v1",
        frame_length=15914,
        record_stride=0x1F0F,
        name_offset=0x1F,
        rank_offset=0x0C,
        class_offset=0x5D,
        matches_offset=0x1F0F,
        elo_offset=0x1EFC,
        spec_offset=0x077A,
        history_offset=0x064B,
        gear_offset=0x077D,
        draws_offset=0x063F,
        addons_offset=0x0060,
        wins_offset=0x1F03,
        losses_offset=0x1EF0,
    ),
)


_OVERALL_DETAIL_LAYOUTS = (
    _OverallDetailLayout(
        layout_id="solare-overall-2026-06-24-v1",
        frame_length=16148,
        record_stride=0x1F80,
        name_offset=0x17,
        rank_offset=0xCA,
        elo_offset=0xD0,
        aggregate_wins_offset=0xD4,
        aggregate_draws_offset=0x61,
        aggregate_losses_offset=0x5D,
        class_offset=0xD8,
        spec_offset=0x1F82,
        matches_offset=0x1F85,
        wins_offset=0xDB,
        draws_offset=0x7F7,
        losses_offset=0x803,
        history_offset=0xE7,
        gear_offset=0x80F,
        addons_offset=0x218,
    ),
    _OverallDetailLayout(
        layout_id="solare-overall-2026-07-14-v1",
        frame_length=16145,
        record_stride=0x1F80,
        name_offset=0x98,
        rank_offset=0x81,
        elo_offset=0x8D,
        aggregate_wins_offset=0x89,
        aggregate_draws_offset=0x85,
        aggregate_losses_offset=0x91,
        class_offset=0xD6,
        spec_offset=0x6C4,
        matches_offset=0x1F79,
        wins_offset=0x1F85,
        draws_offset=0xD9,
        losses_offset=0x6C9,
        history_offset=0x1E4A,
        gear_offset=0x6D5,
        addons_offset=0xE5,
    ),
    _OverallDetailLayout(
        layout_id="solare-overall-2026-07-17-v1",
        frame_length=16143,
        record_stride=0x1F7F,
        name_offset=0x8A,
        rank_offset=0x7E,
        elo_offset=0x11,
        aggregate_wins_offset=0xCC,
        aggregate_draws_offset=0x15,
        aggregate_losses_offset=0xC8,
        class_offset=0xD0,
        spec_offset=0x1861,
        matches_offset=0x19A5,
        wins_offset=0x1855,
        draws_offset=0x186A,
        losses_offset=0x1849,
        history_offset=0x1876,
        gear_offset=0xD3,
        addons_offset=0x19B1,
    ),
)


@dataclass(frozen=True)
class SolareDetailDecode:
    """A completely validated rich-table decode."""

    layout_id: str
    players: tuple[SolarePlayer, ...]
    capabilities: frozenset[str]


@dataclass(frozen=True)
class SolareOverallDetailDecode:
    """Independently decoded overall-table detail groups."""

    layout_id: str
    entries: tuple[SolareOverallEntry, ...]
    capabilities: frozenset[str]


def _u32le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _read_name(data: bytes, offset: int, max_chars: int = 32) -> str:
    raw = bytearray()
    for index in range(max_chars):
        position = offset + index * 2
        if position + 1 >= len(data):
            return ""
        low = data[position]
        high = data[position + 1]
        if low == 0 and high == 0:
            return raw.decode("ascii") if raw else ""
        if high != 0 or not (
            48 <= low <= 57 or 65 <= low <= 90 or 97 <= low <= 122 or low in (45, 95)
        ):
            return ""
        raw.append(low)
    return ""


def _read_u32_slots(data: bytes, base: int, offset: int) -> tuple[int, int, int]:
    return tuple(
        _u32le(data, base + offset + index * 4) for index in range(_CLASS_SLOT_COUNT)
    )  # type: ignore[return-value]


def _decode_history_region(region: bytes) -> Optional[tuple[str, tuple[int, ...]]]:
    nul = region.find(b"\x00")
    if nul < 0:
        return None
    encoded = region[:nul]
    try:
        raw = encoded.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not raw:
        return "", ()
    if _HISTORY_PATTERN.fullmatch(raw) is None:
        return None
    return raw, tuple(int(value) for value in raw.split(","))


def _specialization(class_code: int, code: int) -> SolareSpecialization:
    if code == 1:
        return SolareSpecialization(
            code=code,
            branch="advanced",
            name=ADVANCED_SPEC_BY_CLASS.get(class_code, "Awakening"),
        )
    return SolareSpecialization(code=code, branch="succession", name="Succession")


def _rich_layout_for(
    family: DiscoveredSolareFamily,
) -> Optional[_RichDetailLayout]:
    if family.class_offset is None:
        return None
    geometry = (
        family.frame_length,
        family.record_stride,
        family.name_offset,
        family.rank_offset,
        family.class_offset,
    )
    matches = [layout for layout in _RICH_DETAIL_LAYOUTS if layout.geometry == geometry]
    return matches[0] if len(matches) == 1 else None


def _overall_layout_for(
    family: DiscoveredSolareFamily,
) -> Optional[_OverallDetailLayout]:
    geometry = (
        family.frame_length,
        family.record_stride,
        family.name_offset,
        family.rank_offset,
    )
    matches = [
        layout for layout in _OVERALL_DETAIL_LAYOUTS if layout.geometry == geometry
    ]
    return matches[0] if len(matches) == 1 else None


def _record_locations(
    frames: Sequence[BDOFrame],
    *,
    expected_frames: int,
    frame_length: int,
    record_stride: int,
    required_record_end: int,
) -> Optional[tuple[tuple[bytes, int], ...]]:
    if len(frames) != expected_frames:
        return None
    locations: list[tuple[bytes, int]] = []
    for frame in frames:
        if frame.length != frame_length or len(frame.message) != frame_length:
            return None
        for base in (0, record_stride):
            if base + required_record_end > len(frame.message):
                return None
            locations.append((frame.message, base))
    return tuple(locations)


def _occupied_slot_match_summary(
    data: bytes,
    base: int,
    layout: _OverallDetailLayout,
) -> Optional[tuple[int, int]]:
    """Validate only occupied class slots and their match counters.

    Aggregate W/D/L is an independent overall-record group.  Its validation
    needs to know how many class slots are exposed and how many matches those
    slots account for, but it must not inherit the deeper performance group's
    specialization, history, per-outcome, or opaque-section requirements.
    """

    class_codes = tuple(
        data[base + layout.class_offset + index]
        for index in range(_CLASS_SLOT_COUNT)
    )
    matches = _read_u32_slots(data, base, layout.matches_offset)

    occupied = 0
    exposed_matches = 0
    seen_empty = False
    occupied_codes: set[int] = set()
    for class_code, slot_matches in zip(class_codes, matches):
        if class_code == EMPTY_CLASS_CODE:
            seen_empty = True
            if slot_matches != 0:
                return None
            continue

        if (
            seen_empty
            or class_name(class_code) is None
            or class_code in occupied_codes
            or not 0 < slot_matches <= _MAX_PLAUSIBLE_MATCHES
        ):
            return None
        occupied_codes.add(class_code)
        occupied += 1
        exposed_matches += slot_matches

    if (
        occupied == 0
        or exposed_matches <= 0
        or exposed_matches > _MAX_PLAUSIBLE_MATCHES
    ):
        return None
    return occupied, exposed_matches


def _decode_overall_aggregate_performance(
    data: bytes,
    base: int,
    layout: _OverallDetailLayout,
) -> Optional[tuple[int, int, int]]:
    """Decode one independently validated overall aggregate W/D/L tuple."""

    summary = _occupied_slot_match_summary(data, base, layout)
    if summary is None:
        return None
    occupied_slots, exposed_matches = summary

    wins = _u32le(data, base + layout.aggregate_wins_offset)
    draws = _u32le(data, base + layout.aggregate_draws_offset)
    losses = _u32le(data, base + layout.aggregate_losses_offset)
    components = (wins, draws, losses)
    if any(value > _MAX_PLAUSIBLE_MATCHES for value in components):
        return None

    total_matches = wins + draws + losses
    if not 0 < total_matches <= _MAX_PLAUSIBLE_MATCHES:
        return None
    if total_matches < exposed_matches:
        return None
    if occupied_slots < _CLASS_SLOT_COUNT and total_matches != exposed_matches:
        return None
    return components


def _decode_performance_slots(
    data: bytes,
    base: int,
    layout: _RichDetailLayout | _OverallDetailLayout,
    *,
    retain_raw_extensions: bool,
) -> Optional[tuple[SolareClassPerformance, ...]]:
    class_codes = tuple(
        data[base + layout.class_offset + index] for index in range(_CLASS_SLOT_COUNT)
    )
    spec_codes = tuple(
        data[base + layout.spec_offset + index] for index in range(_CLASS_SLOT_COUNT)
    )
    matches = _read_u32_slots(data, base, layout.matches_offset)
    wins = _read_u32_slots(data, base, layout.wins_offset)
    draws = _read_u32_slots(data, base, layout.draws_offset)
    losses = _read_u32_slots(data, base, layout.losses_offset)

    performances: list[SolareClassPerformance] = []
    seen_empty = False
    occupied_codes: set[int] = set()
    for slot in range(_CLASS_SLOT_COUNT):
        class_code = class_codes[slot]
        spec_code = spec_codes[slot]
        slot_matches = matches[slot]
        slot_wins = wins[slot]
        slot_draws = draws[slot]
        slot_losses = losses[slot]

        history_start = base + layout.history_offset + slot * _HISTORY_SLOT_SIZE
        history_region = bytes(data[history_start : history_start + _HISTORY_SLOT_SIZE])
        history = _decode_history_region(history_region)
        if history is None:
            return None
        history_raw, history_codes = history

        is_empty = class_code == EMPTY_CLASS_CODE
        if is_empty:
            seen_empty = True
            if (
                spec_code != EMPTY_SPEC_CODE
                or any((slot_matches, slot_wins, slot_draws, slot_losses))
                or history_raw
            ):
                return None
            continue

        display_name = class_name(class_code)
        if (
            seen_empty
            or display_name is None
            or class_code in occupied_codes
            or spec_code not in (1, 2)
            or not 0 < slot_matches <= _MAX_PLAUSIBLE_MATCHES
            or any(
                value > slot_matches for value in (slot_wins, slot_draws, slot_losses)
            )
            or slot_wins + slot_draws + slot_losses != slot_matches
            or not history_raw
        ):
            return None
        occupied_codes.add(class_code)

        gear_loadout_raw: Optional[SolareRawSection] = None
        skill_addons_raw: Optional[SolareRawSection] = None
        if retain_raw_extensions:
            gear_offset = layout.gear_offset + slot * _GEAR_SLOT_SIZE
            addon_offset = layout.addons_offset + slot * _ADDON_SLOT_SIZE
            gear = bytes(
                data[base + gear_offset : base + gear_offset + _GEAR_SLOT_SIZE]
            )
            addons = bytes(
                data[base + addon_offset : base + addon_offset + _ADDON_SLOT_SIZE]
            )
            if len(gear) != _GEAR_SLOT_SIZE or len(addons) != _ADDON_SLOT_SIZE:
                return None
            gear_loadout_raw = SolareRawSection(offset=gear_offset, data=gear)
            skill_addons_raw = SolareRawSection(
                offset=addon_offset,
                data=addons,
            )

        player_class = SolareClass(class_code, display_name)
        performances.append(
            SolareClassPerformance(
                slot=slot,
                primary=slot == 0,
                player_class=player_class,
                specialization=_specialization(class_code, spec_code),
                matches=slot_matches,
                wins=slot_wins,
                draws=slot_draws,
                losses=slot_losses,
                recent_results_raw=history_codes,
                recent_results_wire_text=history_raw,
                gear_loadout_raw=gear_loadout_raw,
                skill_addons_raw=skill_addons_raw,
            )
        )

    if not performances or not performances[0].primary:
        return None
    return tuple(performances)


def decode_solare_details(
    rich_frames: Sequence[BDOFrame],
    rich: DiscoveredSolareFamily,
    *,
    retain_raw_extensions: bool = False,
) -> Optional[SolareDetailDecode]:
    """Decode a complete rich table or return ``None`` on any contradiction.

    ``rich_frames`` must already belong to the discovered rich family and be
    in wire order.  The overall table is deliberately not an input.
    """

    retain_raw_extensions = validate_retain_raw_extensions(retain_raw_extensions)
    layout = _rich_layout_for(rich)
    if layout is None:
        return None
    locations = _record_locations(
        rich_frames,
        expected_frames=_EXPECTED_RICH_FRAMES,
        frame_length=layout.frame_length,
        record_stride=layout.record_stride,
        required_record_end=layout.required_record_end,
    )
    if locations is None or len(locations) != _EXPECTED_RICH_RECORDS:
        return None
    if not (
        len(rich.names)
        == len(rich.ranks)
        == len(rich.class_codes)
        == _EXPECTED_RICH_RECORDS
    ):
        return None

    players: list[SolarePlayer] = []
    primary_codes: list[int] = []
    previous_elo: Optional[int] = None

    for ordinal, (data, base) in enumerate(locations):
        name = _read_name(data, base + layout.name_offset)
        rank = _u32le(data, base + layout.rank_offset)
        class_code = data[base + layout.class_offset]
        elo = _u32le(data, base + layout.elo_offset)

        if (
            name != rich.names[ordinal]
            or rank != rich.ranks[ordinal]
            or class_code != rich.class_codes[ordinal]
            or not 0 < elo <= _MAX_PLAUSIBLE_ELO
            or (previous_elo is not None and previous_elo < elo)
        ):
            return None
        previous_elo = elo

        performances = _decode_performance_slots(
            data,
            base,
            layout,
            retain_raw_extensions=retain_raw_extensions,
        )
        if performances is None:
            return None
        primary = performances[0].player_class
        players.append(
            SolarePlayer(
                name=name,
                global_rank=rank,
                primary_class=primary,
                elo=elo,
                classes_played=performances,
            )
        )
        primary_codes.append(primary.code)

    if (
        len({player.name for player in players}) != _EXPECTED_RICH_RECORDS
        or len({player.global_rank for player in players}) != _EXPECTED_RICH_RECORDS
        or tuple(player.global_rank for player in players[:20]) != tuple(range(1, 21))
        or any(
            left.global_rank >= right.global_rank
            for left, right in zip(players, players[1:])
        )
    ):
        return None

    class_counts = tuple(sorted(Counter(primary_codes).items()))
    if class_counts != rich.class_counts or any(
        count != 20 for _, count in class_counts
    ):
        return None

    capabilities = {"rankings", "elo", "performance"}
    if retain_raw_extensions:
        capabilities.add("raw_extensions")
    return SolareDetailDecode(
        layout.layout_id,
        tuple(players),
        frozenset(capabilities),
    )


def decode_solare_overall_details(
    overall_frames: Sequence[BDOFrame],
    overall: DiscoveredSolareFamily,
    *,
    retain_raw_extensions: bool = False,
) -> Optional[SolareOverallDetailDecode]:
    """Decode independently validated detail groups from the overall table.

    Rank/name identity and record geometry are mandatory. Elo, aggregate W/D/L,
    and class performance are each all-table groups: one contradiction withholds
    that field family from every entry without contaminating independently valid
    groups.
    """

    retain_raw_extensions = validate_retain_raw_extensions(retain_raw_extensions)
    layout = _overall_layout_for(overall)
    if layout is None:
        return None
    locations = _record_locations(
        overall_frames,
        expected_frames=_EXPECTED_OVERALL_FRAMES,
        frame_length=layout.frame_length,
        record_stride=layout.record_stride,
        required_record_end=layout.required_record_end,
    )
    if locations is None or len(locations) != _EXPECTED_OVERALL_RECORDS:
        return None
    if not (
        len(overall.names) == len(overall.ranks) == _EXPECTED_OVERALL_RECORDS
        and overall.ranks == tuple(range(1, _EXPECTED_OVERALL_RECORDS + 1))
        and len(set(overall.names)) == _EXPECTED_OVERALL_RECORDS
    ):
        return None

    elos: list[int] = []
    aggregates: list[Optional[tuple[int, int, int]]] = []
    performances: list[Optional[tuple[SolareClassPerformance, ...]]] = []
    for ordinal, (data, base) in enumerate(locations):
        name = _read_name(data, base + layout.name_offset)
        rank = _u32le(data, base + layout.rank_offset)
        if name != overall.names[ordinal] or rank != overall.ranks[ordinal]:
            return None
        elos.append(_u32le(data, base + layout.elo_offset))
        aggregates.append(
            _decode_overall_aggregate_performance(data, base, layout)
        )
        performances.append(
            _decode_performance_slots(
                data,
                base,
                layout,
                retain_raw_extensions=False,
            )
        )

    elo_valid = all(0 < elo <= _MAX_PLAUSIBLE_ELO for elo in elos) and all(
        left >= right for left, right in zip(elos, elos[1:])
    )
    aggregate_valid = all(item is not None for item in aggregates)
    performance_valid = all(item is not None for item in performances)

    selected_performances = performances
    raw_valid = False
    if performance_valid and retain_raw_extensions:
        with_raw = [
            _decode_performance_slots(
                data,
                base,
                layout,
                retain_raw_extensions=True,
            )
            for data, base in locations
        ]
        if all(item is not None for item in with_raw):
            selected_performances = with_raw
            raw_valid = True

    capabilities = {"rankings"}
    if elo_valid:
        capabilities.add("elo")
    if aggregate_valid:
        capabilities.add("aggregate_performance")
    if performance_valid:
        capabilities.add("performance")
    if raw_valid:
        capabilities.add("raw_extensions")

    def entry_performances(
        ordinal: int,
    ) -> tuple[SolareClassPerformance, ...]:
        item = selected_performances[ordinal]
        return item if performance_valid and item is not None else ()

    def entry_aggregate(
        ordinal: int,
    ) -> tuple[Optional[int], Optional[int], Optional[int]]:
        item = aggregates[ordinal]
        if aggregate_valid and item is not None:
            return item
        return None, None, None

    entries: list[SolareOverallEntry] = []
    for ordinal, (name, rank) in enumerate(zip(overall.names, overall.ranks)):
        total_wins, total_draws, total_losses = entry_aggregate(ordinal)
        entries.append(
            SolareOverallEntry(
                name=name,
                global_rank=rank,
                elo=elos[ordinal] if elo_valid else None,
                total_wins=total_wins,
                total_draws=total_draws,
                total_losses=total_losses,
                classes_played=entry_performances(ordinal),
            )
        )
    return SolareOverallDetailDecode(
        layout.layout_id,
        tuple(entries),
        frozenset(capabilities),
    )
