"""Bounded, fail-closed learning for unregistered Solare detail layouts.

Structural discovery has already proved the two leaderboard responses before
this module is called.  The learner works only from those complete response
records and never trusts an opcode. It does not persist layouts.

The class-table and overall-table records remain independent data sources.
Comparisons between them may disambiguate a candidate, but decoded values are
always read from the response that owns the public row.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from collections import Counter
from dataclasses import dataclass, replace
from typing import Callable, Mapping, Optional, Sequence

from bdo_toolkit._protocol import BDOFrame

from ._constants import (
    EMPTY_CLASS_CODE,
    EMPTY_SPEC_CODE,
    SOLARE_RICH_RECORD_COUNTS,
    class_name,
)
from ._details import (
    _ADDON_SLOT_SIZE,
    _CLASS_SLOT_COUNT,
    _GEAR_SLOT_SIZE,
    _HISTORY_SLOT_SIZE,
    _MAX_PLAUSIBLE_MATCHES,
    _OverallDetailLayout,
    _RichDetailLayout,
    _decode_history_region,
    _history_outcome_counts,
    _history_matches_outcomes,
    _decode_overall_aggregate_performance,
    _decode_performance_slots,
    _read_name,
    _record_locations,
    _u32le,
    SolareDetailDecode,
    SolareOverallDetailDecode,
)
from ._discovery import DiscoveredSolareFamily
from .models import (
    SolareClass,
    SolareClassPerformance,
    SolareEquipment,
    SolareOverallEntry,
    SolarePlayer,
)


_EXPECTED_OVERALL_RECORDS = 100
_EXPECTED_OVERALL_FRAMES = _EXPECTED_OVERALL_RECORDS // 2
_MIN_ELO_DISTINCT = 20
_MAX_LEARNED_ELO = 0xFFFF
_MAX_LEARNED_COUNTER = 0xFFFF
# Experienced-player boards can make all outcome arrays positive, including
# nearby byte-shift aliases. Let balanced-counter validation resolve them.
_MAX_MATCH_CANDIDATES = 8
_MAX_COUNTER_CANDIDATES = 64
_MAX_PREFILTER_CANDIDATES = 128
_MAX_ACTIVE_OUTCOME_PREFILTER_CANDIDATES = 4096
_MAX_AGGREGATE_VECTORS = 256
_MAX_LEARNED_RECORD_END = 32 * 1024
_MIN_HISTORY_DISCRIMINATORS = 5
_PREFILTER_ROWS = 32
_MAX_WHOLE_ZERO_REGION = 15
_MAX_ZERO_PLACEMENT_REGION = 16


@dataclass(frozen=True)
class _RecordTable:
    family: DiscoveredSolareFamily
    rows: tuple[bytes, ...]
    names: tuple[str, ...]
    ranks: tuple[int, ...]

    @property
    def record_end(self) -> int:
        return self.family.frame_length - self.family.record_stride


@dataclass(frozen=True)
class _PerformanceOffsets:
    class_offset: int
    spec_offset: int
    matches_offset: int
    wins_offset: int
    draws_offset: int
    losses_offset: int
    history_offset: int
    occupancies: tuple[int, ...]
    # Alternative positions in one bounded zero region. The representative
    # offset is only a reader position; it does not establish an exact address.
    zero_outcome_candidates: tuple[int, ...] = ()


@dataclass(frozen=True)
class _RawOffsets:
    gear_offset: int
    addons_offset: int


@dataclass(frozen=True)
class _AggregateOffsets:
    wins_offset: int
    draws_offset: int
    losses_offset: int


@dataclass(frozen=True)
class _LearnedTable:
    records: _RecordTable
    elo_offset: Optional[int]
    performance: Optional[_PerformanceOffsets]
    raw: Optional[_RawOffsets] = None
    aggregate: Optional[_AggregateOffsets] = None


def _extract_records(
    frames: Sequence[BDOFrame],
    family: DiscoveredSolareFamily,
    *,
    expected_frames: int,
    expected_records: int,
) -> Optional[_RecordTable]:
    record_end = family.frame_length - family.record_stride
    if not 0 < record_end <= _MAX_LEARNED_RECORD_END:
        return None
    locations: Optional[tuple[tuple[bytes, int], ...]]
    if family.short_record_locations:
        locations = tuple((frame.message, base) for frame, base in family.short_record_locations)
        if any(base + record_end > len(data) for data, base in locations):
            return None
    else:
        locations = _record_locations(
            frames,
            expected_frames=expected_frames,
            frame_length=family.frame_length,
            record_stride=family.record_stride,
            required_record_end=record_end,
        )
    if locations is None or len(locations) != expected_records:
        return None
    rows = tuple(bytes(data[base : base + record_end]) for data, base in locations)
    if len(family.names) != expected_records or len(family.ranks) != expected_records:
        return None
    for ordinal, row in enumerate(rows):
        if (
            _read_name(row, family.name_offset) != family.names[ordinal]
            or _u32le(row, family.rank_offset) != family.ranks[ordinal]
        ):
            return None
    return _RecordTable(family, rows, family.names, family.ranks)


def _class_occupancies(
    rows: Sequence[bytes],
    offset: int,
) -> Optional[tuple[int, ...]]:
    if not rows or offset < 0 or offset + _CLASS_SLOT_COUNT > len(rows[0]):
        return None
    occupancies: list[int] = []
    observed_codes: set[int] = set()
    for row in rows:
        codes = tuple(row[offset + slot] for slot in range(_CLASS_SLOT_COUNT))
        occupied = 0
        seen_empty = False
        row_codes: set[int] = set()
        for code in codes:
            if code == EMPTY_CLASS_CODE:
                seen_empty = True
                continue
            if (
                seen_empty
                or class_name(code) is None
                or code in row_codes
            ):
                return None
            row_codes.add(code)
            observed_codes.add(code)
            occupied += 1
        if occupied == 0:
            return None
        occupancies.append(occupied)
    if len(observed_codes) < 5:
        return None
    return tuple(occupancies)


def _learn_overall_class_offset(
    records: _RecordTable,
) -> Optional[tuple[int, tuple[int, ...]]]:
    candidates: list[tuple[int, tuple[int, ...]]] = []
    for offset in range(records.record_end - _CLASS_SLOT_COUNT + 1):
        occupancies = _class_occupancies(records.rows, offset)
        if occupancies is not None:
            candidates.append((offset, occupancies))
            if len(candidates) > 1:
                return None
    return candidates[0] if len(candidates) == 1 else None


def _learn_spec_offset(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
) -> Optional[int]:
    candidates: list[int] = []
    record_end = len(rows[0])
    for offset in range(record_end - _CLASS_SLOT_COUNT + 1):
        valid = True
        observed_occupied: set[int] = set()
        for row, occupied in zip(rows, occupancies):
            for slot in range(_CLASS_SLOT_COUNT):
                code = row[offset + slot]
                if slot < occupied:
                    if code not in (1, 2):
                        valid = False
                        break
                    observed_occupied.add(code)
                elif code != EMPTY_SPEC_CODE:
                    valid = False
                    break
            if not valid:
                break
        if valid and observed_occupied:
            candidates.append(offset)
            if len(candidates) > 1:
                return None
    return candidates[0] if len(candidates) == 1 else None


def _elo_candidates(records: _RecordTable) -> tuple[int, ...]:
    sample = _sample_ordinals(len(records.rows))
    prefiltered: list[int] = []
    for offset in range(records.record_end - 3):
        sample_values = tuple(
            _u32le(records.rows[ordinal], offset) for ordinal in sample
        )
        if (
            not all(0 < value <= _MAX_LEARNED_ELO for value in sample_values)
            or not all(
                left >= right
                for left, right in zip(sample_values, sample_values[1:])
            )
        ):
            continue
        prefiltered.append(offset)
        if len(prefiltered) > _MAX_PREFILTER_CANDIDATES:
            return ()

    candidates: list[int] = []
    for offset in prefiltered:
        values = tuple(_u32le(row, offset) for row in records.rows)
        if (
            all(0 < value <= _MAX_LEARNED_ELO for value in values)
            and all(left >= right for left, right in zip(values, values[1:]))
            and len(set(values)) >= _MIN_ELO_DISTINCT
        ):
            candidates.append(offset)
    return tuple(candidates)


def _choose_elo_offsets(
    rich: _RecordTable,
    overall: _RecordTable,
) -> tuple[Optional[int], Optional[int]]:
    rich_candidates = _elo_candidates(rich)
    overall_candidates = _elo_candidates(overall)

    rich_ordinals = {name: ordinal for ordinal, name in enumerate(rich.names)}
    shared = tuple(name for name in overall.names if name in rich_ordinals)
    if len(shared) < 20:
        return None, None
    overall_ordinals = {name: ordinal for ordinal, name in enumerate(overall.names)}
    pairs: list[tuple[int, int]] = []
    for rich_offset in rich_candidates:
        for overall_offset in overall_candidates:
            if all(
                _u32le(rich.rows[rich_ordinals[name]], rich_offset)
                == _u32le(overall.rows[overall_ordinals[name]], overall_offset)
                for name in shared
            ):
                pairs.append((rich_offset, overall_offset))
    if len(pairs) == 1:
        return pairs[0]
    return None, None


def _choose_anchored_elo_offset(
    records: _RecordTable,
    authoritative_by_name: Optional[Mapping[str, int]],
) -> Optional[int]:
    if authoritative_by_name is None:
        return None
    ordinals = {name: ordinal for ordinal, name in enumerate(records.names)}
    shared = tuple(
        name for name in authoritative_by_name if name in ordinals
    )
    if len(shared) < 20:
        return None
    candidates = tuple(
        offset
        for offset in _elo_candidates(records)
        if all(
            _u32le(records.rows[ordinals[name]], offset)
            == authoritative_by_name[name]
            for name in shared
        )
    )
    return candidates[0] if len(candidates) == 1 else None


def _counter_vector(rows: Sequence[bytes], offset: int) -> tuple[int, ...]:
    return tuple(
        _u32le(row, offset + slot * 4)
        for row in rows
        for slot in range(_CLASS_SLOT_COUNT)
    )


def _sample_ordinals(
    count: int,
    occupancies: Optional[Sequence[int]] = None,
) -> tuple[int, ...]:
    if count <= _PREFILTER_ROWS:
        return tuple(range(count))
    selected = {
        round(index * (count - 1) / (_PREFILTER_ROWS - 1))
        for index in range(_PREFILTER_ROWS)
    }
    if occupancies is not None:
        for occupied in range(1, _CLASS_SLOT_COUNT + 1):
            matching = (
                ordinal
                for ordinal, value in enumerate(occupancies)
                if value == occupied
            )
            selected.update(itertools.islice(matching, 4))
    return tuple(sorted(selected))


def _matches_offset_valid(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    offset: int,
    ordinals: Sequence[int],
) -> bool:
    for ordinal in ordinals:
        row = rows[ordinal]
        occupied = occupancies[ordinal]
        for slot in range(_CLASS_SLOT_COUNT):
            value = _u32le(row, offset + slot * 4)
            if slot < occupied:
                if not 0 < value <= _MAX_LEARNED_COUNTER:
                    return False
            elif value != 0:
                return False
    return True


def _matches_candidates(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
) -> tuple[tuple[int, tuple[int, ...]], ...]:
    sample = _sample_ordinals(len(rows), occupancies)
    prefiltered: list[int] = []
    for offset in range(len(rows[0]) - 11):
        if _matches_offset_valid(rows, occupancies, offset, sample):
            prefiltered.append(offset)
            if len(prefiltered) > _MAX_PREFILTER_CANDIDATES:
                return ()

    candidates: list[tuple[int, tuple[int, ...]]] = []
    all_ordinals = tuple(range(len(rows)))
    for offset in prefiltered:
        if not _matches_offset_valid(
            rows,
            occupancies,
            offset,
            all_ordinals,
        ):
            continue
        vector = _counter_vector(rows, offset)
        candidates.append((offset, vector))
        # Every match candidate requires a separate bounded scan for its
        # component columns.  More than this small set is ambiguous evidence
        # as well as disproportionate work, so fail closed before expanding
        # the search.
        if len(candidates) > _MAX_MATCH_CANDIDATES:
            return ()
    return tuple(candidates)


def _outcome_offset_valid(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    matches: Sequence[int],
    offset: int,
    ordinals: Sequence[int],
    *,
    require_positive: bool,
) -> bool:
    observed_positive = False
    for ordinal in ordinals:
        row = rows[ordinal]
        occupied = occupancies[ordinal]
        base = ordinal * _CLASS_SLOT_COUNT
        for slot in range(_CLASS_SLOT_COUNT):
            value = _u32le(row, offset + slot * 4)
            match_value = matches[base + slot]
            if slot < occupied:
                if value > match_value:
                    return False
                observed_positive = observed_positive or value > 0
            elif value != 0:
                return False
    return observed_positive or not require_positive


def _outcome_candidates(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    matches: Sequence[int],
    activity_masks: Sequence[bytes],
) -> tuple[tuple[int, tuple[int, ...]], ...]:
    sample = _sample_ordinals(len(rows), occupancies)
    prefiltered: list[int] = []
    for offset in range(len(rows[0]) - 11):
        if _outcome_offset_valid(
            rows,
            occupancies,
            matches,
            offset,
            sample,
            require_positive=False,
        ):
            if not any(
                any(
                    activity_masks[slot][
                        offset + slot * 4 : offset + slot * 4 + 4
                    ]
                )
                for slot in range(_CLASS_SLOT_COUNT)
            ):
                continue
            prefiltered.append(offset)
            if (
                len(prefiltered)
                > _MAX_ACTIVE_OUTCOME_PREFILTER_CANDIDATES
            ):
                return ()

    candidates: list[tuple[int, tuple[int, ...]]] = []
    all_ordinals = tuple(range(len(rows)))
    for offset in prefiltered:
        if not _outcome_offset_valid(
            rows,
            occupancies,
            matches,
            offset,
            all_ordinals,
            require_positive=True,
        ):
            continue
        vector = _counter_vector(rows, offset)
        candidates.append((offset, vector))
        if len(candidates) > _MAX_COUNTER_CANDIDATES:
            return ()
    return tuple(candidates)


def _anchored_zero_outcome_offsets(
    records: _RecordTable,
    occupancies: Sequence[int],
    matches_offset: int,
    matches: tuple[int, ...],
    outcomes: tuple[tuple[int, tuple[int, ...]], ...],
) -> tuple[int, ...]:
    """Locate zero counters by bounded field geometry, never by zero scans.

    Require two complementary active outcomes and independently validated
    text-array boundaries. Across the tail from class codes to record end,
    one bounded 12..15-byte zero region may remain. Shorter unassigned gaps
    cannot contain a complete three-counter array. Every complete placement
    in a fully zero region decodes the same vector. Otherwise require a unique
    bounded region of at most 16 bytes and exactly one all-zero array placement.
    No arbitrary zero region is promoted.
    Distinct container proofs and conflicting counter solutions still reject.
    """
    complementary = tuple(
        (first_offset, second_offset)
        for index, (first_offset, first) in enumerate(outcomes)
        for second_offset, second in outcomes[index + 1:]
        if all(a + b == total for a, b, total in zip(first, second, matches))
    )
    if not complementary:
        return ()
    rows = records.rows
    class_field = records.family.class_offset
    if class_field is None:
        learned_class = _learn_overall_class_offset(records)
        if learned_class is None:
            return ()
        class_field = learned_class[0]
    spec = _learn_spec_offset(rows, occupancies)
    history = _history_candidates(rows, occupancies, matches_offset)
    elos = _elo_candidates(records)
    if spec is None or len(history) != 1 or len(elos) != 1:
        return ()
    gear = _raw_base_candidates(
        rows, occupancies, value_count=126, slot_size=_GEAR_SLOT_SIZE,
        minimum_text_length=300, maximum_text_length=500,
    )
    addons = _raw_base_candidates(
        rows, occupancies, value_count=12, slot_size=_ADDON_SLOT_SIZE,
        minimum_text_length=20, maximum_text_length=100,
        allow_empty_slots=True,
    )
    if len(gear) != 1 or len(addons) != 1:
        return ()
    fixed = [
        (class_field, 3), (spec, 3), (matches_offset, 12),
        (history[0], 3 * _HISTORY_SLOT_SIZE),
        (gear[0], 3 * _GEAR_SLOT_SIZE),
        (addons[0], 3 * _ADDON_SLOT_SIZE),
    ]
    if elos[0] >= class_field:
        fixed.append((elos[0], 4))
    proofs: set[tuple[int, ...]] = set()
    placement_containers: set[tuple[int, int]] = set()
    for first_offset, second_offset in complementary:
        intervals = sorted(fixed + [(first_offset, 12), (second_offset, 12)])
        cursor = class_field
        gaps: list[tuple[int, int]] = []
        valid = True
        for start, size in intervals:
            if start < cursor or start + size > records.record_end:
                valid = False
                break
            if start > cursor:
                gaps.append((cursor, start - cursor))
            cursor = start + size
        if not valid:
            continue
        if cursor < records.record_end:
            gaps.append((cursor, records.record_end - cursor))
        wide = [(start, size) for start, size in gaps if size >= 12]
        # Unknown bytes smaller than a full array cannot compete with its
        # container. Larger gaps still require the unique bounded proof below.
        if len(wide) != 1 or wide[0][1] > _MAX_ZERO_PLACEMENT_REGION:
            continue
        start, size = wide[0]
        if size <= _MAX_WHOLE_ZERO_REGION and all(
            row[start:start + size] == bytes(size) for row in rows
        ):
            proofs.add(tuple(range(start, start + size - 12 + 1)))
            if len(proofs) > 1:
                return ()
        else:
            placement_containers.add((start, size))
    if proofs:
        return next(iter(proofs))
    # Only after ordinary whole-container proof fails: the complementary
    # counters require zero in every slot. Adjacent bytes have no meaning.
    if len(placement_containers) != 1:
        return ()
    start, size = placement_containers.pop()
    placements = tuple(
        offset for offset in range(start, start + size - 12 + 1)
        if all(row[offset:offset + 12] == bytes(12) for row in rows)
    )
    return placements if len(placements) == 1 else ()


def _balanced_counter_solution(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    *,
    records: Optional[_RecordTable] = None,
    validate: Optional[Callable[[int, tuple[int, int, int]], bool]] = None,
) -> Optional[tuple[int, tuple[int, int, int]]]:
    record_size = len(rows[0])
    occupied_activity = [0] * _CLASS_SLOT_COUNT
    for row, occupied in zip(rows, occupancies):
        row_bits = int.from_bytes(row, "little")
        for slot in range(occupied):
            occupied_activity[slot] |= row_bits
    activity_masks = tuple(
        value.to_bytes(record_size, "little")
        for value in occupied_activity
    )

    solutions: set[tuple[int, tuple[int, int, int]]] = set()
    for matches_offset, matches in _matches_candidates(rows, occupancies):
        outcomes = _outcome_candidates(
            rows,
            occupancies,
            matches,
            activity_masks,
        )
        if not outcomes:
            continue
        if records is not None:
            zero_offsets = _anchored_zero_outcome_offsets(
                records, occupancies, matches_offset, matches, outcomes,
            )
            outcomes += tuple(
                # All placements in the proved container have identical values.
                # Keep one reader position, preserving alternatives below.
                (offset, (0,) * len(matches)) for offset in zero_offsets[:1]
            )
        by_vector: dict[tuple[int, ...], list[int]] = {}
        for offset, vector in outcomes:
            by_vector.setdefault(vector, []).append(offset)
        unique = tuple(by_vector)
        if len(unique) > _MAX_COUNTER_CANDIDATES:
            continue
        for left_index, left in enumerate(unique):
            for right in unique[left_index:]:
                remainder = tuple(
                    match - first - second
                    for match, first, second in zip(matches, left, right)
                )
                if any(value < 0 for value in remainder):
                    continue
                third_offsets = by_vector.get(remainder)
                if third_offsets is None:
                    continue
                for left_offset in by_vector[left]:
                    for right_offset in by_vector[right]:
                        for third_offset in third_offsets:
                            bases = (
                                matches_offset,
                                left_offset,
                                right_offset,
                                third_offset,
                            )
                            if any(
                                abs(left_base - right_base) < 12
                                for index, left_base in enumerate(bases)
                                for right_base in bases[index + 1 :]
                            ):
                                continue
                            ordered = sorted(
                                (left_offset, right_offset, third_offset)
                            )
                            solutions.add((matches_offset, (ordered[0], ordered[1], ordered[2])))
                            # Never truncate a search and claim uniqueness.
                            if len(solutions) > 64:
                                return None
    supported = [candidate for candidate in sorted(solutions)
                 if validate is None or validate(*candidate)]
    return supported[0] if len(supported) == 1 else None


def _history_candidates(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    matches_offset: int,
    *, independent_counters: bool = False,
) -> tuple[int, ...]:
    required = _CLASS_SLOT_COUNT * _HISTORY_SLOT_SIZE
    sample = _sample_ordinals(len(rows), occupancies)

    def valid_for(offset: int, ordinals: Sequence[int]) -> bool:
        for ordinal in ordinals:
            row = rows[ordinal]
            occupied = occupancies[ordinal]
            for slot in range(_CLASS_SLOT_COUNT):
                start = offset + slot * _HISTORY_SLOT_SIZE
                decoded = _decode_history_region(
                    row[start : start + _HISTORY_SLOT_SIZE]
                )
                if decoded is None:
                    return False
                raw, codes = decoded
                matches = _u32le(row, matches_offset + slot * 4)
                if slot < occupied:
                    if (
                        not raw
                        or (not independent_counters and len(codes) != 2 * min(matches, 5))
                        or (independent_counters and (len(codes) not in (2, 4, 6, 8, 10)
                                                     or _history_outcome_counts(codes) is None))
                    ):
                        return False
                elif raw or codes:
                    return False
        return True

    prefiltered: list[int] = []
    for offset in range(len(rows[0]) - required + 1):
        if valid_for(offset, sample):
            prefiltered.append(offset)
            if len(prefiltered) > _MAX_PREFILTER_CANDIDATES:
                return ()

    all_ordinals = tuple(range(len(rows)))
    candidates: list[int] = []
    for offset in prefiltered:
        if valid_for(offset, all_ordinals):
            candidates.append(offset)
            if len(candidates) > 1:
                return ()
    return tuple(candidates)


def _history_outcome_candidates(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    matches_offset: int,
    outcome_offsets: Sequence[int],
    history_offset: int,
    *,
    minimum_discriminators: int = _MIN_HISTORY_DISCRIMINATORS,
) -> tuple[tuple[int, int, int], ...]:
    """Constrain lifetime outcomes with complete or bounded recent histories.

    Binary equal/unequal pairs give wins/losses; the observed (-1, 0) pair
    gives draws. Complete short histories must match every lifetime component;
    longer records must contain each recent count. Ambiguous mappings stay unavailable.
    """
    candidates: list[tuple[int, int, int]] = []
    for wins_offset, draws_offset, losses_offset in itertools.permutations(outcome_offsets):
        discriminators = 0
        valid = True
        for row, occupied in zip(rows, occupancies):
            for slot in range(occupied):
                matches = _u32le(row, matches_offset + slot * 4)
                decoded = _decode_history_region(row[
                    history_offset + slot * _HISTORY_SLOT_SIZE:
                    history_offset + (slot + 1) * _HISTORY_SLOT_SIZE
                ])
                if decoded is None or len(decoded[1]) != 2 * min(matches, 5):
                    valid = False
                    break
                recent = _history_outcome_counts(decoded[1])
                wins = _u32le(row, wins_offset + slot * 4)
                draws = _u32le(row, draws_offset + slot * 4)
                losses = _u32le(row, losses_offset + slot * 4)
                if recent is None or not _history_matches_outcomes(
                    recent, matches, wins, draws, losses,
                ):
                    valid = False
                    break
                if matches > 5 and draws and not recent[1]:
                    # An older lifetime draw absent from this window constrains
                    # candidates but does not positively identify the draw column.
                    # Preserve the existing witness requirement for binary history.
                    continue
                if recent[0] != recent[2] or recent[1]:
                    discriminators += 1
            if not valid:
                break
        if valid and discriminators >= minimum_discriminators:
            candidates.append((wins_offset, draws_offset, losses_offset))
    return tuple(candidates)


def _orient_outcomes(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    matches_offset: int,
    outcome_offsets: Sequence[int],
    history_offset: int,
) -> Optional[tuple[int, int, int]]:
    candidates = _history_outcome_candidates(
        rows, occupancies, matches_offset, outcome_offsets, history_offset,
    )
    return candidates[0] if len(candidates) == 1 else None


def _companion_outcomes_agree(
    records: _RecordTable,
    class_offset: int,
    occupancies: Sequence[int],
    matches_offset: int,
    outcomes: tuple[int, int, int],
    companion: _RecordTable,
    known: _PerformanceOffsets,
) -> bool:
    by_name = {name: i for i, name in enumerate(companion.names)}
    shared = 0
    discriminating_names = 0
    for row, name, rank, occupied in zip(
        records.rows, records.names, records.ranks, occupancies,
    ):
        ordinal = by_name.get(name)
        if ordinal is None:
            continue
        other = companion.rows[ordinal]
        if rank != companion.ranks[ordinal] or occupied != known.occupancies[ordinal]:
            return False
        discriminating = False
        for slot in range(occupied):
            if row[class_offset + slot] != other[known.class_offset + slot]:
                return False
            values = tuple(_u32le(row, offset + slot * 4)
                           for offset in (matches_offset, *outcomes))
            expected = tuple(_u32le(other, offset + slot * 4) for offset in (
                known.matches_offset, known.wins_offset,
                known.draws_offset, known.losses_offset,
            ))
            if values != expected:
                return False
            discriminating |= len(set(values[1:])) == 3
        shared += 1
        discriminating_names += discriminating
    return shared >= 20 and discriminating_names >= _MIN_HISTORY_DISCRIMINATORS


def _counter_geometry_check(
    records: _RecordTable, class_offset: int, occupancies: tuple[int, ...],
    source: _RecordTable, source_class: int, source_occupancies: tuple[int, ...],
) -> Optional[Callable[[int, tuple[int, int, int]], bool]]:
    # Establish numerical geometry without assigning any W/D/L labels.
    # An ambiguous source cannot corroborate another ambiguous response.
    counters = _balanced_counter_solution(
        source.rows, source_occupancies, records=source,
    )
    if counters is None:
        return None
    source_matches, source_outcomes = counters
    if len(_history_candidates(source.rows, source_occupancies, source_matches)) != 1:
        return None
    by_name = {name: i for i, name in enumerate(source.names)}

    def agrees(matches: int, outcomes: tuple[int, int, int]) -> bool:
        shared = 0
        for row, name, rank, occupied in zip(
            records.rows, records.names, records.ranks, occupancies,
        ):
            ordinal = by_name.get(name)
            if ordinal is None:
                continue
            other = source.rows[ordinal]
            if rank != source.ranks[ordinal] or occupied != source_occupancies[ordinal]:
                return False
            for slot in range(occupied):
                if row[class_offset + slot] != other[source_class + slot]:
                    return False
                if _u32le(row, matches + slot * 4) != _u32le(other, source_matches + slot * 4):
                    return False
                if sorted(_u32le(row, off + slot * 4) for off in outcomes) != sorted(
                    _u32le(other, off + slot * 4) for off in source_outcomes
                ):
                    return False
            shared += 1
        return shared >= 20
    return agrees


def _learn_performance_offsets(
    records: _RecordTable,
    class_offset: int,
    occupancies: tuple[int, ...],
    *,
    companion: Optional[tuple[_RecordTable, _PerformanceOffsets]] = None,
    counter_check: Optional[Callable[[int, tuple[int, int, int]], bool]] = None,
) -> Optional[_PerformanceOffsets]:
    spec_offset = _learn_spec_offset(records.rows, occupancies)
    if spec_offset is None:
        return None

    def validate(matches: int, outcomes: tuple[int, int, int]) -> bool:
        if counter_check is not None and not counter_check(matches, outcomes):
            return False
        return _validate_performance_candidate(
            records, class_offset, occupancies, spec_offset, matches, outcomes,
            companion=companion,
        ) is not None
    counters = _balanced_counter_solution(
        records.rows, occupancies, records=records, validate=validate,
    )
    if counters is None:
        return None
    return _validate_performance_candidate(
        records, class_offset, occupancies, spec_offset, *counters,
        companion=companion,
    )


def _validate_performance_candidate(
    records: _RecordTable,
    class_offset: int,
    occupancies: tuple[int, ...],
    spec_offset: int,
    matches_offset: int,
    outcome_offsets: tuple[int, int, int],
    *,
    companion: Optional[tuple[_RecordTable, _PerformanceOffsets]] = None,
) -> Optional[_PerformanceOffsets]:
    independent = bool(getattr(records.family, "short_record_locations", ())) and companion is not None
    histories = _history_candidates(
        records.rows,
        occupancies,
        matches_offset,
        independent_counters=independent,
    )
    if len(histories) != 1:
        return None
    history_offset = histories[0]
    oriented = _orient_outcomes(
        records.rows,
        occupancies,
        matches_offset,
        outcome_offsets,
        history_offset,
    )
    if oriented is None and companion is not None:
        # Short-board fallback: a separately oriented companion establishes
        # labels. Recent UI history may cover a different set of matches;
        # preserve valid raw windows without treating them as counter totals.
        # Ordinary full-board inference retains its original history checks.
        supported = tuple(
            proposed for proposed in (
                tuple((a, b, c) for a, b, c in itertools.permutations(outcome_offsets)) if independent else
                _history_outcome_candidates(
                    records.rows, occupancies, matches_offset, outcome_offsets,
                    history_offset, minimum_discriminators=0,
                )
            )
            if _companion_outcomes_agree(
                records, class_offset, occupancies, matches_offset, proposed,
                companion[0], companion[1],
            )
        )
        if len(supported) == 1:
            oriented = supported[0]
    if oriented is None:
        return None
    if companion is not None and not _companion_outcomes_agree(
        records, class_offset, occupancies, matches_offset, oriented,
        companion[0], companion[1],
    ):
        return None
    wins_offset, draws_offset, losses_offset = oriented
    active = tuple(
        (offset, vector) for offset in outcome_offsets
        if any(vector := _counter_vector(records.rows, offset))
    )
    zero_candidates = (
        _anchored_zero_outcome_offsets(
            records, occupancies, matches_offset,
            _counter_vector(records.rows, matches_offset), active,
        ) if len(active) == 2 else ()
    )
    return _PerformanceOffsets(
        class_offset=class_offset,
        spec_offset=spec_offset,
        matches_offset=matches_offset,
        wins_offset=wins_offset,
        draws_offset=draws_offset,
        losses_offset=losses_offset,
        history_offset=history_offset,
        occupancies=occupancies,
        zero_outcome_candidates=zero_candidates if len(zero_candidates) > 1 else (),
    )


def _csv_integer_count(
    row: bytes,
    offset: int,
    *,
    maximum_length: int = 512,
) -> Optional[tuple[int, int]]:
    if offset < 0 or offset >= len(row):
        return None
    if not 48 <= row[offset] <= 57:
        return None
    if offset > 0 and (48 <= row[offset - 1] <= 57 or row[offset - 1] == 44):
        return None
    end_limit = min(len(row), offset + maximum_length + 1)
    nul = row.find(b"\x00", offset, end_limit)
    if nul < 0:
        return None
    encoded = row[offset:nul]
    try:
        text = encoded.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = text.split(",")
    if not parts or any(not part.isdigit() for part in parts):
        return None
    return len(parts), len(encoded)


def _raw_base_candidates(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    *,
    value_count: int,
    slot_size: int,
    minimum_text_length: int,
    maximum_text_length: int,
    allow_empty_slots: bool = False,
) -> tuple[int, ...]:
    first = rows[0]
    candidates: list[int] = []
    required_end = _CLASS_SLOT_COUNT * slot_size
    offsets: Sequence[int] = range(len(first) - required_end + 1)
    use_text_witnesses = allow_empty_slots or value_count == 126
    if use_text_witnesses:
        # Blank addons or a CSV-like preceding binary byte can hide one witness.
        # Gather witnesses across records and slots, then validate each boundary.
        pattern = rb"(?<![0-9,])[0-9]+(?:,[0-9]+){" + str(value_count - 1).encode() + rb"}\x00"
        witnessed = {
            match.start() - slot * slot_size
            for row in rows
            for match in re.finditer(pattern, row)
            for slot in range(_CLASS_SLOT_COUNT)
            if 0 <= match.start() - slot * slot_size <= len(first) - required_end
        }
        offsets = sorted(witnessed)
    for offset in offsets:
        if allow_empty_slots or value_count == 126:
            # Gear must satisfy its typed slot grammar; addons permit zero to
            # six complete pairs. Validate every occupied block and its padding;
            # a population percentage must not decide whether partial lists fit.
            valid_blocks = True
            for row, occupied in zip(rows, occupancies):
                for slot in range(occupied):
                    start = offset + slot * slot_size
                    block = row[start:start + slot_size]
                    if len(block) != slot_size:
                        valid_blocks = False
                        break
                    if not any(block) and allow_empty_slots:
                        continue
                    if value_count == 126:
                        if _parse_equipment(block) is None:
                            valid_blocks = False
                            break
                        continue
                    # The candidate fixes this block's boundary. A byte in the
                    # preceding binary field must not extend its CSV text.
                    shape = _csv_integer_count(block, 0)
                    if (shape is None or not 2 <= shape[0] <= value_count
                            or shape[0] % 2 or shape[1] > maximum_text_length
                            or any(block[shape[1]:])):
                        valid_blocks = False
                        break
                if not valid_blocks:
                    break
            if valid_blocks and all(any(n > slot for n in occupancies)
                                    for slot in range(_CLASS_SLOT_COUNT)):
                candidates.append(offset)
                if len(candidates) > 1:
                    return ()
            continue
        first_shape = (
            _csv_integer_count(first[offset:offset + slot_size], 0)
            if use_text_witnesses else _csv_integer_count(first, offset)
        )
        if not allow_empty_slots and (
            first_shape is None
            or first_shape[0] != value_count
            or not minimum_text_length <= first_shape[1] <= maximum_text_length
        ):
            continue
        valid = True
        for row in rows:
            shape = _csv_integer_count(row[offset:offset + slot_size], 0)
            if allow_empty_slots and not any(row[offset : offset + slot_size]):
                continue
            if (
                shape is None
                or shape[0] != value_count
                or not minimum_text_length
                <= shape[1]
                <= maximum_text_length
            ):
                valid = False
                break
        if not valid:
            continue
        # Secondary/tertiary sections provide periodicity evidence.  A tiny
        # minority of observed occupied addon slots carry a shorter legitimate
        # form, so require overwhelming support instead of fabricating an
        # all-record grammar that the wire does not have.
        for slot in range(1, _CLASS_SLOT_COUNT):
            eligible = tuple(
                row
                for row, occupied in zip(rows, occupancies)
                if occupied > slot
            )
            if not eligible:
                valid = False
                break
            matching = 0
            for row in eligible:
                start = offset + slot * slot_size
                if allow_empty_slots and not any(row[start:start + slot_size]):
                    matching += 1
                    continue
                shape = _csv_integer_count(row[start:start + slot_size], 0)
                if (
                    shape is not None
                    and shape[0] == value_count
                    and minimum_text_length
                    <= shape[1]
                    <= maximum_text_length
                ):
                    matching += 1
            if matching * 100 < len(eligible) * 95:
                valid = False
                break
        if valid:
            candidates.append(offset)
            if len(candidates) > 1:
                return ()
    return tuple(candidates)


def _learn_raw_offsets(
    records: _RecordTable,
    performance: _PerformanceOffsets,
) -> Optional[_RawOffsets]:
    gear = _raw_base_candidates(
        records.rows,
        performance.occupancies,
        value_count=126,
        slot_size=_GEAR_SLOT_SIZE,
        minimum_text_length=300,
        maximum_text_length=500,
    )
    addons = _raw_base_candidates(
        records.rows,
        performance.occupancies,
        value_count=12,
        slot_size=_ADDON_SLOT_SIZE,
        minimum_text_length=20,
        maximum_text_length=100,
    )
    if len(gear) != 1 or len(addons) != 1:
        return None
    return _RawOffsets(gear[0], addons[0])


def _ranges_overlap(left: int, right: int, size: int = 4) -> bool:
    return left < right + size and right < left + size


def _aggregate_zero_offsets(
    records: _RecordTable,
    performance: _PerformanceOffsets,
    companion: Optional[_RecordTable],
) -> tuple[int, ...]:
    """Prove zero counters in four-byte gaps between independent header fields.

    Historical headers carry a 62-byte name, a 101-byte recent-history block,
    and an eight-byte identity shared with the class response. Identity matches
    must be unique across both headers, not guessed from a small numeric value.
    No absolute era-specific offsets or arbitrary runs of zeroes are used.
    """
    if companion is None or companion.family.class_offset is None:
        return ()
    elos = _elo_candidates(records)
    rich_elos = _elo_candidates(companion)
    if len(elos) != 1 or len(rich_elos) != 1:
        return ()
    boundary = performance.class_offset
    rich_boundary = companion.family.class_offset
    if max(boundary, rich_boundary) > 512:
        return ()
    fields = [(records.family.name_offset, 62),
              (records.family.rank_offset, 4), (elos[0], 4)]
    rich_fields = [(companion.family.name_offset, 62),
                   (companion.family.rank_offset, 4), (rich_elos[0], 4)]

    def free(start: int, size: int, blocks: Sequence[tuple[int, int]]) -> bool:
        return all(start + size <= base or base + width <= start
                   for base, width in blocks)

    # Header history is distinct from the three per-class history blocks.
    histories = []
    for offset in range(5, boundary - _HISTORY_SLOT_SIZE + 1):
        if not free(offset, _HISTORY_SLOT_SIZE, fields):
            continue
        valid = True
        for row, occupied in zip(records.rows, performance.occupancies):
            decoded = _decode_history_region(row[offset:offset + _HISTORY_SLOT_SIZE])
            matches = sum(_u32le(row, performance.matches_offset + slot * 4)
                          for slot in range(occupied))
            if decoded is None or not decoded[0] or len(decoded[1]) != 2 * min(matches, 5):
                valid = False
                break
        if valid:
            histories.append(offset)
    if len(histories) != 1:
        return ()
    fields.append((histories[0], _HISTORY_SLOT_SIZE))
    lookup = dict(zip(companion.names, companion.rows))
    pairs = [(row, lookup[name]) for name, row in zip(records.names, records.rows)
             if name in lookup]
    if len(pairs) < 20:
        return ()
    identities = []
    for offset in range(5, boundary - 7):
        if not free(offset, 8, fields):
            continue
        values = tuple(row[offset:offset + 8] for row, _ in pairs)
        all_values = tuple(row[offset:offset + 8] for row in records.rows)
        if len(set(all_values)) != len(all_values) or any(not any(v) for v in all_values):
            continue
        for other in range(5, rich_boundary - 7):
            if free(other, 8, rich_fields) and all(
                value == row[other:other + 8] for value, (_, row) in zip(values, pairs)
            ):
                identities.append((offset, other))
    proofs = set()
    for identity, other in identities:
        ordered = sorted(fields + [(identity, 8)])
        for (start, size), (end, _) in zip(ordered, ordered[1:]):
            if (end - start - size == 4
                    and all(not any(row[start + size:end]) for row in records.rows)):
                proofs.add((identity, other, start + size))
    # Shifted identity aliases are possible when high bytes are zero. Only a
    # unique identity/boundary proof can authorize the zero counter.
    return (next(iter(proofs))[2],) if len(proofs) == 1 else ()


def _aggregate_candidates(
    records: _RecordTable,
    performance: _PerformanceOffsets,
    *,
    companion: Optional[_RecordTable] = None,
) -> Optional[tuple[int, int, int]]:
    protected = (
        performance.matches_offset,
        performance.wins_offset,
        performance.draws_offset,
        performance.losses_offset,
    )
    exposed = tuple(
        sum(
            _u32le(row, performance.matches_offset + slot * 4)
            for slot in range(occupied)
        )
        for row, occupied in zip(records.rows, performance.occupancies)
    )
    exact_ordinals = tuple(
        ordinal
        for ordinal, occupied in enumerate(performance.occupancies)
        if occupied < _CLASS_SLOT_COUNT
    )
    if not exact_ordinals or not any(
        occupied == _CLASS_SLOT_COUNT
        for occupied in performance.occupancies
    ):
        return None

    zero_offsets = _aggregate_zero_offsets(records, performance, companion)
    # A proven header counter limits the search before applying fan-out bounds.
    # Name/rank bytes are independently owned fields, including name padding;
    # numeric-looking UTF-16 bytes cannot be competing lifetime counters.
    scan_end = performance.class_offset if zero_offsets else records.record_end
    forbidden = ((records.family.name_offset, 62), (records.family.rank_offset, 4))
    by_vector: dict[tuple[int, ...], list[int]] = {}
    for offset in range(scan_end - 3):
        if any(offset < start + size and start < offset + 4
               for start, size in forbidden):
            continue
        if any(
            _ranges_overlap(offset, base + slot * 4)
            for base in protected
            for slot in range(_CLASS_SLOT_COUNT)
        ):
            continue
        values = tuple(_u32le(row, offset) for row in records.rows)
        if (
            not any(values)
            or any(value > _MAX_LEARNED_COUNTER for value in values)
            or any(values[index] > exposed[index] for index in exact_ordinals)
        ):
            continue
        by_vector.setdefault(values, []).append(offset)
        if len(by_vector) > _MAX_AGGREGATE_VECTORS:
            return None

    if zero_offsets:
        by_vector[(0,) * len(records.rows)] = list(zero_offsets)
    vectors = tuple(by_vector)
    subset_lookup: dict[tuple[int, ...], list[tuple[int, ...]]] = {}
    for vector in vectors:
        key = tuple(vector[index] for index in exact_ordinals)
        subset_lookup.setdefault(key, []).append(vector)

    target = tuple(exposed[index] for index in exact_ordinals)
    solutions: set[tuple[int, int, int]] = set()
    for left_index, left in enumerate(vectors):
        for right in vectors[left_index:]:
            remainder = tuple(
                target_value - left[index] - right[index]
                for index, target_value in zip(exact_ordinals, target)
            )
            if any(value < 0 for value in remainder):
                continue
            for third in subset_lookup.get(remainder, ()):
                totals = tuple(
                    first + second + last
                    for first, second, last in zip(left, right, third)
                )
                if any(
                    total < minimum
                    or total <= 0
                    or total > _MAX_PLAUSIBLE_MATCHES
                    or (
                        performance.occupancies[ordinal] < _CLASS_SLOT_COUNT
                        and total != minimum
                    )
                    for ordinal, (total, minimum) in enumerate(
                        zip(totals, exposed)
                    )
                ):
                    continue
                if not any(
                    performance.occupancies[ordinal] == _CLASS_SLOT_COUNT
                    and total > exposed[ordinal]
                    for ordinal, total in enumerate(totals)
                ):
                    continue
                for left_offset in by_vector[left]:
                    for right_offset in by_vector[right]:
                        for third_offset in by_vector[third]:
                            offsets = (
                                left_offset,
                                right_offset,
                                third_offset,
                            )
                            if len(set(offsets)) != 3:
                                continue
                            ordered = sorted(offsets)
                            solutions.add(
                                (ordered[0], ordered[1], ordered[2])
                            )
                            if len(solutions) > 8:
                                return None
    return next(iter(solutions)) if len(solutions) == 1 else None


def _orient_aggregate(
    records: _RecordTable,
    performance: _PerformanceOffsets,
    candidates: Sequence[int],
) -> Optional[_AggregateOffsets]:
    one_slot = tuple(
        ordinal
        for ordinal, occupied in enumerate(performance.occupancies)
        if occupied == 1
    )
    if len(one_slot) < 5:
        return None
    scored: list[tuple[int, int, tuple[int, int, int]]] = []
    for wins_offset, draws_offset, losses_offset in itertools.permutations(
        candidates
    ):
        exact = 0
        distance = 0
        for ordinal, row in enumerate(records.rows):
            exposed_wins = sum(
                _u32le(row, performance.wins_offset + slot * 4)
                for slot in range(performance.occupancies[ordinal])
            )
            exposed_draws = sum(
                _u32le(row, performance.draws_offset + slot * 4)
                for slot in range(performance.occupancies[ordinal])
            )
            exposed_losses = sum(
                _u32le(row, performance.losses_offset + slot * 4)
                for slot in range(performance.occupancies[ordinal])
            )
            aggregate = (
                _u32le(row, wins_offset),
                _u32le(row, draws_offset),
                _u32le(row, losses_offset),
            )
            exposed_values = (exposed_wins, exposed_draws, exposed_losses)
            distance += sum(
                abs(value - expected)
                for value, expected in zip(aggregate, exposed_values)
            )
            if ordinal in one_slot and aggregate == exposed_values:
                exact += 1
        scored.append(
            (distance, -exact, (wins_offset, draws_offset, losses_offset))
        )
    scored.sort()
    if len(scored) < 2:
        return None
    best_distance, best_negative_exact, best = scored[0]
    second_distance = scored[1][0]
    minimum_exact = max(5, (len(one_slot) * 3) // 4)
    if (
        -best_negative_exact < minimum_exact
        or second_distance <= best_distance * 4
    ):
        return None
    return _AggregateOffsets(*best)


def _learn_aggregate(
    records: _RecordTable,
    performance: _PerformanceOffsets,
    *,
    companion: Optional[_RecordTable] = None,
) -> Optional[_AggregateOffsets]:
    candidates = _aggregate_candidates(records, performance)
    if candidates is None and companion is not None:
        candidates = _aggregate_candidates(records, performance, companion=companion)
    if candidates is None:
        return None
    return _orient_aggregate(records, performance, candidates)


def _raw_sections_agree(
    rich: _LearnedTable,
    overall: _LearnedTable,
) -> bool:
    if (
        rich.raw is None
        or overall.raw is None
        or rich.performance is None
        or overall.performance is None
    ):
        return False
    rich_ordinals = {
        name: ordinal for ordinal, name in enumerate(rich.records.names)
    }
    compared = 0
    for overall_ordinal, name in enumerate(overall.records.names):
        rich_ordinal = rich_ordinals.get(name)
        if rich_ordinal is None:
            continue
        rich_row = rich.records.rows[rich_ordinal]
        overall_row = overall.records.rows[overall_ordinal]
        rich_occupied = rich.performance.occupancies[rich_ordinal]
        overall_occupied = overall.performance.occupancies[overall_ordinal]
        for slot in range(min(rich_occupied, overall_occupied)):
            rich_class = rich_row[rich.performance.class_offset + slot]
            overall_class = overall_row[overall.performance.class_offset + slot]
            if rich_class != overall_class:
                continue
            rich_gear = rich_row[
                rich.raw.gear_offset
                + slot * _GEAR_SLOT_SIZE : rich.raw.gear_offset
                + (slot + 1) * _GEAR_SLOT_SIZE
            ]
            overall_gear = overall_row[
                overall.raw.gear_offset
                + slot * _GEAR_SLOT_SIZE : overall.raw.gear_offset
                + (slot + 1) * _GEAR_SLOT_SIZE
            ]
            rich_addons = rich_row[
                rich.raw.addons_offset
                + slot * _ADDON_SLOT_SIZE : rich.raw.addons_offset
                + (slot + 1) * _ADDON_SLOT_SIZE
            ]
            overall_addons = overall_row[
                overall.raw.addons_offset
                + slot * _ADDON_SLOT_SIZE : overall.raw.addons_offset
                + (slot + 1) * _ADDON_SLOT_SIZE
            ]
            if rich_gear != overall_gear or rich_addons != overall_addons:
                return False
            compared += 1
    return compared >= 20


def _layout_id(
    role: str,
    records: _RecordTable,
    elo_offset: Optional[int],
    performance: Optional[_PerformanceOffsets],
    raw: Optional[_RawOffsets] = None,
    aggregate: Optional[_AggregateOffsets] = None,
) -> str:
    fields: tuple[object, ...] = (
        "solare-ephemeral-detail-v1",
        role,
        records.family.frame_length,
        records.family.record_stride,
        records.family.name_offset,
        records.family.rank_offset,
        elo_offset,
        (
            None
            if performance is None
            else (
                performance.class_offset,
                performance.spec_offset,
                performance.matches_offset,
                performance.wins_offset,
                performance.draws_offset,
                performance.losses_offset,
                performance.history_offset,
            )
        ),
        (
            None
            if aggregate is None
            else (
                aggregate.wins_offset,
                aggregate.draws_offset,
                aggregate.losses_offset,
            )
        ),
        (
            None
            if raw is None
            else (
                raw.gear_offset,
                raw.addons_offset,
            )
        ),
    )
    if performance is not None and performance.zero_outcome_candidates:
        fields += (("equivalent-zero-outcome-offsets", performance.zero_outcome_candidates),)
    digest = hashlib.sha256(repr(fields).encode("ascii")).hexdigest()[:16]
    return f"solare-{role}-ephemeral-v1-{digest}"


def _performance_layout(
    learned: _LearnedTable,
    layout_id: str,
) -> Optional[_RichDetailLayout | _OverallDetailLayout]:
    performance = learned.performance
    if performance is None:
        return None
    raw = learned.raw
    frame_length = learned.records.family.frame_length
    record_stride = learned.records.family.record_stride
    name_offset = learned.records.family.name_offset
    rank_offset = learned.records.family.rank_offset
    elo_offset = learned.elo_offset or 0
    gear_offset = raw.gear_offset if raw is not None else 0
    addons_offset = raw.addons_offset if raw is not None else 0
    if learned.records.family.role == "rich":
        return _RichDetailLayout(
            layout_id=layout_id,
            frame_length=frame_length,
            record_stride=record_stride,
            name_offset=name_offset,
            rank_offset=rank_offset,
            class_offset=performance.class_offset,
            matches_offset=performance.matches_offset,
            elo_offset=elo_offset,
            spec_offset=performance.spec_offset,
            history_offset=performance.history_offset,
            gear_offset=gear_offset,
            draws_offset=performance.draws_offset,
            addons_offset=addons_offset,
            wins_offset=performance.wins_offset,
            losses_offset=performance.losses_offset,
        )
    aggregate = learned.aggregate
    return _OverallDetailLayout(
        layout_id=layout_id,
        frame_length=frame_length,
        record_stride=record_stride,
        name_offset=name_offset,
        rank_offset=rank_offset,
        elo_offset=elo_offset,
        aggregate_wins_offset=(
            aggregate.wins_offset if aggregate is not None else 0
        ),
        aggregate_draws_offset=(
            aggregate.draws_offset if aggregate is not None else 0
        ),
        aggregate_losses_offset=(
            aggregate.losses_offset if aggregate is not None else 0
        ),
        class_offset=performance.class_offset,
        spec_offset=performance.spec_offset,
        matches_offset=performance.matches_offset,
        wins_offset=performance.wins_offset,
        draws_offset=performance.draws_offset,
        losses_offset=performance.losses_offset,
        history_offset=performance.history_offset,
        gear_offset=gear_offset,
        addons_offset=addons_offset,
    )


def _decode_learned_rich(learned: _LearnedTable) -> Optional[SolareDetailDecode]:
    if learned.elo_offset is None and learned.performance is None:
        return None
    layout_id = _layout_id(
        "rich",
        learned.records,
        learned.elo_offset,
        learned.performance,
        learned.raw,
    )
    layout = _performance_layout(learned, layout_id)
    players: list[SolarePlayer] = []
    primary_codes: list[int] = []
    previous_elo: Optional[int] = None
    raw_enabled = learned.raw is not None
    for ordinal, row in enumerate(learned.records.rows):
        class_code = (
            row[learned.performance.class_offset]
            if learned.performance is not None
            else learned.records.family.class_codes[ordinal]
        )
        display_name = class_name(class_code)
        if display_name is None:
            return None
        elo = (
            _u32le(row, learned.elo_offset)
            if learned.elo_offset is not None
            else None
        )
        if elo is not None:
            if (
                not 0 < elo <= _MAX_LEARNED_ELO
                or (previous_elo is not None and previous_elo < elo)
            ):
                return None
            previous_elo = elo
        performances: tuple[SolareClassPerformance, ...] = ()
        if layout is not None:
            decoded = _decode_performance_slots(
                row,
                0,
                layout,
                retain_raw_extensions=raw_enabled,
            )
            if decoded is None:
                return None
            performances = decoded
            class_code = performances[0].player_class.code
            display_name = performances[0].player_class.name
        primary = SolareClass(class_code, display_name)
        players.append(
            SolarePlayer(
                name=learned.records.names[ordinal],
                global_rank=learned.records.ranks[ordinal],
                primary_class=primary,
                elo=elo,
                classes_played=performances,
            )
        )
        primary_codes.append(class_code)
    if (
        tuple(primary_codes) != learned.records.family.class_codes
        or tuple(sorted(Counter(primary_codes).items()))
        != learned.records.family.class_counts
    ):
        return None
    capabilities = {"rankings"}
    if learned.elo_offset is not None:
        capabilities.add("elo")
    if learned.performance is not None:
        capabilities.add("performance")
    if learned.raw is not None:
        capabilities.add("raw_extensions")
    return SolareDetailDecode(layout_id, tuple(players), frozenset(capabilities))


def _decode_learned_overall(
    learned: _LearnedTable,
) -> Optional[SolareOverallDetailDecode]:
    if (
        learned.elo_offset is None
        and learned.performance is None
        and learned.aggregate is None
    ):
        return None
    layout_id = _layout_id(
        "overall",
        learned.records,
        learned.elo_offset,
        learned.performance,
        learned.raw,
        learned.aggregate,
    )
    layout = _performance_layout(learned, layout_id)
    raw_enabled = learned.raw is not None
    entries: list[SolareOverallEntry] = []
    previous_elo: Optional[int] = None
    for ordinal, row in enumerate(learned.records.rows):
        elo = (
            _u32le(row, learned.elo_offset)
            if learned.elo_offset is not None
            else None
        )
        if elo is not None:
            if (
                not 0 < elo <= _MAX_LEARNED_ELO
                or (previous_elo is not None and previous_elo < elo)
            ):
                return None
            previous_elo = elo
        performances: tuple[SolareClassPerformance, ...] = ()
        aggregate: Optional[tuple[int, int, int]] = None
        if layout is not None:
            if not isinstance(layout, _OverallDetailLayout):
                return None
            decoded = _decode_performance_slots(
                row,
                0,
                layout,
                retain_raw_extensions=raw_enabled,
            )
            if decoded is None:
                return None
            performances = decoded
            if learned.aggregate is not None:
                aggregate = _decode_overall_aggregate_performance(row, 0, layout)
                if aggregate is None:
                    return None
        total_wins, total_draws, total_losses = (
            aggregate if aggregate is not None else (None, None, None)
        )
        entries.append(
            SolareOverallEntry(
                name=learned.records.names[ordinal],
                global_rank=learned.records.ranks[ordinal],
                elo=elo,
                classes_played=performances,
                total_wins=total_wins,
                total_draws=total_draws,
                total_losses=total_losses,
            )
        )
    capabilities = {"rankings"}
    if learned.elo_offset is not None:
        capabilities.add("elo")
    if learned.performance is not None:
        capabilities.add("performance")
    if learned.aggregate is not None:
        capabilities.add("aggregate_performance")
    if learned.raw is not None:
        capabilities.add("raw_extensions")
    return SolareOverallDetailDecode(
        layout_id,
        tuple(entries),
        frozenset(capabilities),
    )


def learn_unknown_solare_details(
    rich_frames: Sequence[BDOFrame],
    rich: DiscoveredSolareFamily,
    overall_frames: Sequence[BDOFrame],
    overall: DiscoveredSolareFamily,
    *,
    learn_rich: bool,
    learn_overall: bool,
    retain_raw_extensions: bool,
    known_rich_elos: Optional[Mapping[str, int]] = None,
    known_overall_elos: Optional[Mapping[str, int]] = None,
) -> tuple[Optional[SolareDetailDecode], Optional[SolareOverallDetailDecode]]:
    """Learn and decode unregistered detail layouts for one complete snapshot.

    The caller decides which table geometries are unregistered. A returned
    decode is ephemeral and applies only to this snapshot; no offsets are
    cached or written to disk.
    """

    if rich.record_count not in SOLARE_RICH_RECORD_COUNTS and not rich.short_record_locations:
        return None, None
    rich_records = _extract_records(
        rich_frames,
        rich,
        expected_frames=rich.record_count // 2,
        expected_records=rich.record_count,
    )
    overall_records = _extract_records(
        overall_frames,
        overall,
        expected_frames=_EXPECTED_OVERALL_FRAMES,
        expected_records=_EXPECTED_OVERALL_RECORDS,
    )
    if rich_records is None or overall_records is None:
        return None, None

    rich_occupancies: Optional[tuple[int, ...]] = None
    if rich.class_offset is not None:
        rich_occupancies = _class_occupancies(
            rich_records.rows,
            rich.class_offset,
        )
        if (
            rich_occupancies is not None
            and tuple(
                row[rich.class_offset] for row in rich_records.rows
            )
            != rich.class_codes
        ):
            rich_occupancies = None
    overall_class = _learn_overall_class_offset(overall_records)

    if learn_rich and learn_overall:
        rich_elo, overall_elo = _choose_elo_offsets(
            rich_records,
            overall_records,
        )
    elif learn_rich:
        rich_elo = _choose_anchored_elo_offset(
            rich_records,
            known_overall_elos,
        )
        overall_elo = None
    elif learn_overall:
        rich_elo = None
        overall_elo = _choose_anchored_elo_offset(
            overall_records,
            known_rich_elos,
        )
    else:
        rich_elo = None
        overall_elo = None
    # Learn the companion table's slot geometry as shadow evidence even when
    # that geometry has a registered decoder.  Public rows still come only
    # from their owning decoder; this shadow result is used solely to prove
    # opted-in raw-section boundaries across the two independent responses.
    rich_performance = (
        _learn_performance_offsets(
            rich_records,
            rich.class_offset,
            rich_occupancies,
        )
        if (learn_rich or retain_raw_extensions)
        and rich.class_offset is not None
        and rich_occupancies is not None
        else None
    )
    overall_performance = (
        _learn_performance_offsets(
            overall_records,
            overall_class[0],
            overall_class[1],
        )
        if (learn_overall or retain_raw_extensions)
        and overall_class is not None
        else None
    )
    if (learn_overall and overall_performance is None and rich_performance is None
            and overall_class is not None and rich.class_offset is not None
            and rich_occupancies is not None):
        check = _counter_geometry_check(
            overall_records, overall_class[0], overall_class[1],
            rich_records, rich.class_offset, rich_occupancies,
        )
        if check is not None:
            overall_performance = _learn_performance_offsets(
                overall_records, overall_class[0], overall_class[1], counter_check=check,
            )
    if learn_overall and overall_performance is None and rich_performance is not None and overall_class is not None:
        overall_performance = _learn_performance_offsets(
            overall_records, overall_class[0], overall_class[1],
            companion=(rich_records, rich_performance),
        )
    elif learn_rich and rich_performance is None and overall_performance is not None and rich.class_offset is not None and rich_occupancies is not None:
        rich_performance = _learn_performance_offsets(
            rich_records, rich.class_offset, rich_occupancies,
            companion=(overall_records, overall_performance),
        )
    rich_learned = _LearnedTable(
        rich_records,
        rich_elo if learn_rich else None,
        rich_performance,
    )
    overall_learned = _LearnedTable(
        overall_records,
        overall_elo if learn_overall else None,
        overall_performance,
        aggregate=(
            _learn_aggregate(overall_records, overall_performance, companion=rich_records)
            if learn_overall and overall_performance is not None
            else None
        ),
    )

    if retain_raw_extensions:
        rich_raw = (
            _learn_raw_offsets(rich_records, rich_performance)
            if rich_performance is not None
            else None
        )
        overall_raw = (
            _learn_raw_offsets(overall_records, overall_performance)
            if overall_performance is not None
            else None
        )
        proposed_rich = _LearnedTable(
            rich_learned.records,
            rich_learned.elo_offset,
            rich_learned.performance,
            raw=rich_raw,
            aggregate=rich_learned.aggregate,
        )
        proposed_overall = _LearnedTable(
            overall_learned.records,
            overall_learned.elo_offset,
            overall_learned.performance,
            raw=overall_raw,
            aggregate=overall_learned.aggregate,
        )
        if _raw_sections_agree(proposed_rich, proposed_overall):
            rich_learned = proposed_rich
            overall_learned = proposed_overall

    return (
        _decode_learned_rich(rich_learned) if learn_rich else None,
        _decode_learned_overall(overall_learned) if learn_overall else None,
    )


_EQUIPMENT_SLOT_CODES = (0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 27, 29)


def _parse_equipment(data: bytes) -> Optional[tuple[SolareEquipment, ...]]:
    """Validate the observed 14 x 9 CSV grammar without collapsing duplicates."""
    if len(data) != _GEAR_SLOT_SIZE or b"\0" not in data:
        return None
    text = data.split(b"\0", 1)[0]
    tokens = text.split(b",")
    if len(tokens) != 126 or any(not t.isdigit() or len(t) > 10 for t in tokens):
        return None
    values = [int(token) for token in tokens]
    if any(value > 0xFFFFFFFF for value in values):
        return None
    groups = [values[i:i + 9] for i in range(0, 126, 9)]
    if tuple(g[0] for g in groups) != _EQUIPMENT_SLOT_CODES:
        return None
    if any(g[1] == 0 for g in groups):
        return None
    return tuple(
        SolareEquipment(
            slot_code=g[0],
            item_id=g[1],
            crystal_ids=(g[3], g[4]),
            unknown_fields=(g[2], g[5], g[6], g[7], g[8]),
        )
        for g in groups
    )


def decode_equipment_table(
    frames: Sequence[BDOFrame],
    family: DiscoveredSolareFamily,
    entries: Sequence[SolarePlayer] | Sequence[SolareOverallEntry],
    *,
    gear_offset: Optional[int] = None,
) -> Optional[dict[str, tuple[SolareClassPerformance, ...]]]:
    """Validate equipment independently of addons, for every occupied class slot.

    Registered geometries supply their pinned boundary; only unknown geometries
    use the bounded CSV boundary finder. Existing class ownership is required.
    A failed slot withholds equipment for this table, preserving other details.
    """
    by_name = {entry.name: entry for entry in entries}
    if len(by_name) != family.record_count or any(not e.classes_played for e in entries):
        return None
    records = _extract_records(
        frames, family,
        expected_frames=family.frame_count,
        expected_records=family.record_count,
    )
    if records is None:
        return None
    occupancies = tuple(len(by_name[name].classes_played) for name in records.names)
    if gear_offset is None:
        candidates = _raw_base_candidates(
            records.rows, occupancies,
            value_count=126,
            slot_size=_GEAR_SLOT_SIZE,
            minimum_text_length=300,
            maximum_text_length=500,
        )
        if len(candidates) != 1:
            return None
        gear_offset = candidates[0]
    output: dict[str, tuple[SolareClassPerformance, ...]] = {}
    for name, row in zip(records.names, records.rows):
        slots = []
        for performance in by_name[name].classes_played:
            start = gear_offset + performance.slot * _GEAR_SLOT_SIZE
            equipment = _parse_equipment(row[start:start + _GEAR_SLOT_SIZE])
            if equipment is None:
                return None
            slots.append(replace(performance, equipment=equipment))
        output[name] = tuple(slots)
    return output
