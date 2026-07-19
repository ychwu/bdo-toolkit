"""Fail-closed decoding for validated Arena of Solare rich-record layouts.

Leaderboard discovery establishes semantic identity without trusting an
opcode.  This module is deliberately a second, stricter layer: it decodes
performance fields only when the discovered message geometry matches a layout
that has been validated against a complete capture and every record-level
invariant still holds.

When explicitly requested, raw gear and skill-addon sections are retained
byte-for-byte. Their fixed boundaries are stable across the three observed
layouts, but their internal semantics remain intentionally opaque.
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
class _DetailLayout:
    layout_id: str
    frame_length: int
    record_stride: int
    name_offset: int
    rank_offset: int
    class_offset: int
    uid_offset: int
    matches_offset: int
    elo_offset: int
    spec_offset: int
    history_offset: int
    gear_offset: int
    draws_offset: int
    addons_offset: int
    wins_offset: int
    losses_offset: int
    overall_frame_length: int
    overall_record_stride: int
    overall_name_offset: int
    overall_rank_offset: int
    overall_uid_offset: int
    overall_uid_shift: int = 0

    @property
    def rich_geometry(self) -> tuple[int, int, int, int, int]:
        return (
            self.frame_length,
            self.record_stride,
            self.name_offset,
            self.rank_offset,
            self.class_offset,
        )

    @property
    def overall_geometry(self) -> tuple[int, int, int, int]:
        return (
            self.overall_frame_length,
            self.overall_record_stride,
            self.overall_name_offset,
            self.overall_rank_offset,
        )

    @property
    def required_record_end(self) -> int:
        return max(
            self.uid_offset + 8,
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


# These fingerprints contain no opcode.  An opcode-only patch therefore keeps
# decoding, while any unvalidated geometry change disables only the optional
# performance capability and leaves structural rankings available.
_DETAIL_LAYOUTS = (
    _DetailLayout(
        layout_id="solare-rich-2026-06-24-v1",
        frame_length=15900,
        record_stride=0x1F08,
        name_offset=0x14,
        rank_offset=0x52,
        class_offset=0x58,
        uid_offset=0x0A,
        matches_offset=0x5B,
        elo_offset=0x67,
        spec_offset=0x6B,
        history_offset=0x6E,
        gear_offset=0x019D,
        draws_offset=0x1910,
        addons_offset=0x191C,
        wins_offset=0x1EFB,
        losses_offset=0x1F07,
        overall_frame_length=16148,
        overall_record_stride=0x1F80,
        overall_name_offset=0x17,
        overall_rank_offset=0xCA,
        overall_uid_offset=0x55,
        overall_uid_shift=16,
    ),
    _DetailLayout(
        layout_id="solare-rich-2026-07-14-v1",
        frame_length=15930,
        record_stride=0x1F15,
        name_offset=0x19,
        rank_offset=0x10,
        class_offset=0x62,
        uid_offset=0x5A,
        matches_offset=0x68,
        elo_offset=0x74,
        spec_offset=0x1926,
        history_offset=0x17EB,
        gear_offset=0x0078,
        draws_offset=0x1F19,
        addons_offset=0x1929,
        wins_offset=0x191A,
        losses_offset=0x1F0D,
        overall_frame_length=16145,
        overall_record_stride=0x1F80,
        overall_name_offset=0x98,
        overall_rank_offset=0x81,
        overall_uid_offset=0x14,
    ),
    _DetailLayout(
        layout_id="solare-rich-2026-07-17-v1",
        frame_length=15914,
        record_stride=0x1F0F,
        name_offset=0x1F,
        rank_offset=0x0C,
        class_offset=0x5D,
        uid_offset=0x10,
        matches_offset=0x1F0F,
        elo_offset=0x1EFC,
        spec_offset=0x077A,
        history_offset=0x064B,
        gear_offset=0x077D,
        draws_offset=0x063F,
        addons_offset=0x0060,
        wins_offset=0x1F03,
        losses_offset=0x1EF0,
        overall_frame_length=16143,
        overall_record_stride=0x1F7F,
        overall_name_offset=0x8A,
        overall_rank_offset=0x7E,
        overall_uid_offset=0x82,
    ),
)


@dataclass(frozen=True)
class SolareDetailDecode:
    """A completely validated rich-table decode."""

    layout_id: str
    players: tuple[SolarePlayer, ...]
    overall_uids: tuple[bytes, ...] = ()


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
            48 <= low <= 57
            or 65 <= low <= 90
            or 97 <= low <= 122
            or low in (45, 95)
        ):
            return ""
        raw.append(low)
    return ""


def _read_u32_slots(data: bytes, base: int, offset: int) -> tuple[int, int, int]:
    return tuple(
        _u32le(data, base + offset + index * 4)
        for index in range(_CLASS_SLOT_COUNT)
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


def _layout_for(family: DiscoveredSolareFamily) -> Optional[_DetailLayout]:
    if family.class_offset is None:
        return None
    geometry = (
        family.frame_length,
        family.record_stride,
        family.name_offset,
        family.rank_offset,
        family.class_offset,
    )
    matches = [layout for layout in _DETAIL_LAYOUTS if layout.rich_geometry == geometry]
    return matches[0] if len(matches) == 1 else None


def _record_locations(
    frames: Sequence[BDOFrame], layout: _DetailLayout
) -> Optional[tuple[tuple[bytes, int], ...]]:
    if len(frames) != _EXPECTED_RICH_FRAMES:
        return None
    locations: list[tuple[bytes, int]] = []
    for frame in frames:
        if frame.length != layout.frame_length or len(frame.message) != layout.frame_length:
            return None
        for base in (0, layout.record_stride):
            if base + layout.required_record_end > len(frame.message):
                return None
            locations.append((frame.message, base))
    return tuple(locations)


def _validate_overall_uids(
    players: Sequence[SolarePlayer],
    frames: Sequence[BDOFrame],
    family: DiscoveredSolareFamily,
    layout: _DetailLayout,
) -> Optional[tuple[bytes, ...]]:
    if (
        family.frame_length,
        family.record_stride,
        family.name_offset,
        family.rank_offset,
    ) != layout.overall_geometry:
        return None
    if len(frames) != _EXPECTED_OVERALL_FRAMES:
        return None
    if not (
        len(family.names)
        == len(family.ranks)
        == _EXPECTED_OVERALL_RECORDS
    ):
        return None

    overall_uids: list[bytes] = []
    for frame in frames:
        if frame.length != layout.overall_frame_length:
            return None
        for base in (0, layout.overall_record_stride):
            start = base + layout.overall_uid_offset
            end = start + 8
            if end > len(frame.message):
                return None
            overall_uids.append(bytes(frame.message[start:end]))

    if (
        len(overall_uids) != _EXPECTED_OVERALL_RECORDS
        or len(set(overall_uids)) != _EXPECTED_OVERALL_RECORDS
        or any(uid == b"\x00" * 8 for uid in overall_uids)
    ):
        return None

    rich_by_rank = {player.global_rank: player for player in players}
    rich_by_name = {player.name: player for player in players}
    overlap = 0
    for rank, name, overall_uid in zip(
        family.ranks,
        family.names,
        overall_uids,
    ):
        ranked_player = rich_by_rank.get(rank)
        if ranked_player is not None:
            if ranked_player.name != name or ranked_player.player_uid_raw is None:
                return None
            rich_uid = (
                int.from_bytes(ranked_player.player_uid_raw, "little")
                >> layout.overall_uid_shift
            )
            if rich_uid != int.from_bytes(overall_uid, "little"):
                return None
            overlap += 1
        named_player = rich_by_name.get(name)
        if named_player is not None and named_player.global_rank != rank:
            return None

    return tuple(overall_uids) if overlap >= 20 else None


def decode_solare_details(
    rich_frames: Sequence[BDOFrame],
    rich: DiscoveredSolareFamily,
    *,
    overall_frames: Sequence[BDOFrame] = (),
    overall: Optional[DiscoveredSolareFamily] = None,
    retain_raw_extensions: bool = False,
) -> Optional[SolareDetailDecode]:
    """Decode a complete rich table or return ``None`` on any contradiction.

    ``rich_frames`` must already belong to the discovered rich family and be
    in wire order.  Passing the confirmed overall family enables an additional
    independent UID cross-check; callers must pass both overall arguments or
    neither.
    """

    retain_raw_extensions = validate_retain_raw_extensions(
        retain_raw_extensions
    )
    if bool(overall_frames) != (overall is not None):
        return None
    layout = _layout_for(rich)
    if layout is None:
        return None
    locations = _record_locations(rich_frames, layout)
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
    player_uids: list[bytes] = []
    primary_codes: list[int] = []
    previous_elo: Optional[int] = None

    for ordinal, (data, base) in enumerate(locations):
        name = _read_name(data, base + layout.name_offset)
        rank = _u32le(data, base + layout.rank_offset)
        class_codes = tuple(
            data[base + layout.class_offset + index]
            for index in range(_CLASS_SLOT_COUNT)
        )
        spec_codes = tuple(
            data[base + layout.spec_offset + index]
            for index in range(_CLASS_SLOT_COUNT)
        )
        matches = _read_u32_slots(data, base, layout.matches_offset)
        wins = _read_u32_slots(data, base, layout.wins_offset)
        draws = _read_u32_slots(data, base, layout.draws_offset)
        losses = _read_u32_slots(data, base, layout.losses_offset)
        elo = _u32le(data, base + layout.elo_offset)
        uid = bytes(data[base + layout.uid_offset : base + layout.uid_offset + 8])

        if (
            name != rich.names[ordinal]
            or rank != rich.ranks[ordinal]
            or class_codes[0] != rich.class_codes[ordinal]
            or not uid
            or uid == b"\x00" * 8
            or not 0 < elo <= _MAX_PLAUSIBLE_ELO
            or (previous_elo is not None and previous_elo < elo)
        ):
            return None
        previous_elo = elo

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

            if (
                seen_empty
                or class_code in occupied_codes
                or spec_code not in (1, 2)
                or not 0 < slot_matches <= _MAX_PLAUSIBLE_MATCHES
                or any(
                    value < 0 or value > slot_matches
                    for value in (slot_wins, slot_draws, slot_losses)
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
                    data[
                        base + gear_offset : base + gear_offset + _GEAR_SLOT_SIZE
                    ]
                )
                addons = bytes(
                    data[
                        base + addon_offset : base + addon_offset + _ADDON_SLOT_SIZE
                    ]
                )
                if len(gear) != _GEAR_SLOT_SIZE or len(addons) != _ADDON_SLOT_SIZE:
                    return None
                gear_loadout_raw = SolareRawSection(
                    offset=gear_offset,
                    data=gear,
                )
                skill_addons_raw = SolareRawSection(
                    offset=addon_offset,
                    data=addons,
                )

            player_class = SolareClass(class_code, class_name(class_code))
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
        primary = performances[0].player_class
        players.append(
            SolarePlayer(
                name=name,
                global_rank=rank,
                primary_class=primary,
                player_uid_raw=uid,
                elo=elo,
                classes_played=tuple(performances),
            )
        )
        player_uids.append(uid)
        primary_codes.append(primary.code)

    if (
        len(set(player_uids)) != _EXPECTED_RICH_RECORDS
        or len({player.name for player in players}) != _EXPECTED_RICH_RECORDS
        or len({player.global_rank for player in players}) != _EXPECTED_RICH_RECORDS
        or tuple(player.global_rank for player in players[:20])
        != tuple(range(1, 21))
        or any(
            left.global_rank >= right.global_rank
            for left, right in zip(players, players[1:])
        )
    ):
        return None

    class_counts = tuple(sorted(Counter(primary_codes).items()))
    if class_counts != rich.class_counts or any(count != 20 for _, count in class_counts):
        return None

    overall_uids: tuple[bytes, ...] = ()
    if overall is not None:
        validated_uids = _validate_overall_uids(
            players,
            overall_frames,
            overall,
            layout,
        )
        if validated_uids is None:
            return None
        overall_uids = validated_uids

    return SolareDetailDecode(layout.layout_id, tuple(players), overall_uids)
