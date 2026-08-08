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
from collections import Counter
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from bdo_toolkit._protocol import BDOFrame

from ._constants import EMPTY_CLASS_CODE, EMPTY_SPEC_CODE, class_name
from ._details import (
    _ADDON_SLOT_SIZE,
    _CLASS_SLOT_COUNT,
    _GEAR_SLOT_SIZE,
    _HISTORY_SLOT_SIZE,
    _MAX_PLAUSIBLE_MATCHES,
    _OverallDetailLayout,
    _RichDetailLayout,
    _decode_history_region,
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
    SolareOverallEntry,
    SolarePlayer,
)


_EXPECTED_RICH_RECORDS = 620
_EXPECTED_RICH_FRAMES = _EXPECTED_RICH_RECORDS // 2
_EXPECTED_OVERALL_RECORDS = 100
_EXPECTED_OVERALL_FRAMES = _EXPECTED_OVERALL_RECORDS // 2
_MIN_ELO_DISTINCT = 20
_MAX_LEARNED_ELO = 0xFFFF
_MAX_LEARNED_COUNTER = 0xFFFF
_MAX_MATCH_CANDIDATES = 2
_MAX_COUNTER_CANDIDATES = 64
_MAX_PREFILTER_CANDIDATES = 128
_MAX_ACTIVE_OUTCOME_PREFILTER_CANDIDATES = 4096
_MAX_AGGREGATE_VECTORS = 256
_MAX_LEARNED_RECORD_END = 32 * 1024
_MIN_HISTORY_DISCRIMINATORS = 5
_PREFILTER_ROWS = 32


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


def _balanced_counter_solution(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
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
                            solutions.add(
                                (
                                    matches_offset,
                                    (ordered[0], ordered[1], ordered[2]),
                                )
                            )
                            if len(solutions) > 1:
                                return None
    return next(iter(solutions)) if len(solutions) == 1 else None


def _history_candidates(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    matches_offset: int,
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
                        or len(codes) != 2 * min(matches, 5)
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


def _orient_outcomes(
    rows: Sequence[bytes],
    occupancies: Sequence[int],
    matches_offset: int,
    outcome_offsets: Sequence[int],
    history_offset: int,
) -> Optional[tuple[int, int, int]]:
    valid_permutations: list[tuple[int, int, int]] = []
    for wins_offset, draws_offset, losses_offset in itertools.permutations(
        outcome_offsets
    ):
        discriminators = 0
        valid = True
        for row, occupied in zip(rows, occupancies):
            for slot in range(occupied):
                matches = _u32le(row, matches_offset + slot * 4)
                if matches > 5:
                    continue
                decoded = _decode_history_region(
                    row[
                        history_offset
                        + slot * _HISTORY_SLOT_SIZE : history_offset
                        + (slot + 1) * _HISTORY_SLOT_SIZE
                    ]
                )
                if decoded is None:
                    valid = False
                    break
                _raw, codes = decoded
                equal = sum(
                    codes[index] == codes[index + 1]
                    for index in range(0, len(codes), 2)
                )
                unequal = matches - equal
                wins = _u32le(row, wins_offset + slot * 4)
                draws = _u32le(row, draws_offset + slot * 4)
                losses = _u32le(row, losses_offset + slot * 4)
                if draws != 0 or wins != equal or losses != unequal:
                    valid = False
                    break
                if wins != losses:
                    discriminators += 1
            if not valid:
                break
        if valid and discriminators >= _MIN_HISTORY_DISCRIMINATORS:
            valid_permutations.append(
                (wins_offset, draws_offset, losses_offset)
            )
    return valid_permutations[0] if len(valid_permutations) == 1 else None


def _learn_performance_offsets(
    records: _RecordTable,
    class_offset: int,
    occupancies: tuple[int, ...],
) -> Optional[_PerformanceOffsets]:
    spec_offset = _learn_spec_offset(records.rows, occupancies)
    counters = _balanced_counter_solution(records.rows, occupancies)
    if spec_offset is None or counters is None:
        return None
    matches_offset, outcome_offsets = counters
    histories = _history_candidates(
        records.rows,
        occupancies,
        matches_offset,
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
    if oriented is None:
        return None
    wins_offset, draws_offset, losses_offset = oriented
    return _PerformanceOffsets(
        class_offset=class_offset,
        spec_offset=spec_offset,
        matches_offset=matches_offset,
        wins_offset=wins_offset,
        draws_offset=draws_offset,
        losses_offset=losses_offset,
        history_offset=history_offset,
        occupancies=occupancies,
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
) -> tuple[int, ...]:
    first = rows[0]
    candidates: list[int] = []
    required_end = _CLASS_SLOT_COUNT * slot_size
    for offset in range(len(first) - required_end + 1):
        first_shape = _csv_integer_count(first, offset)
        if (
            first_shape is None
            or first_shape[0] != value_count
            or not minimum_text_length <= first_shape[1] <= maximum_text_length
        ):
            continue
        valid = True
        for row in rows:
            shape = _csv_integer_count(row, offset)
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
                shape = _csv_integer_count(row, offset + slot * slot_size)
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


def _aggregate_candidates(
    records: _RecordTable,
    performance: _PerformanceOffsets,
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

    by_vector: dict[tuple[int, ...], list[int]] = {}
    for offset in range(records.record_end - 3):
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
) -> Optional[_AggregateOffsets]:
    candidates = _aggregate_candidates(records, performance)
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

    rich_records = _extract_records(
        rich_frames,
        rich,
        expected_frames=_EXPECTED_RICH_FRAMES,
        expected_records=_EXPECTED_RICH_RECORDS,
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
            _learn_aggregate(overall_records, overall_performance)
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
