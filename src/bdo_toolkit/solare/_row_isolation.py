"""Recover a single local field defect only after re-proving both record layouts."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import Optional, TypeVar, cast

from ._details import (
    _OverallDetailLayout,
    _decode_overall_aggregate_performance,
    _decode_performance_slots,
    _GEAR_SLOT_SIZE,
    _u32le,
)
from ._detail_learning import (
    _balanced_counter_solution,
    _class_occupancies,
    _learn_overall_class_offset,
    _RecordTable,
    _LearnedTable,
    _MAX_LEARNED_ELO,
    _extract_records,
    _learn_record_layouts,
    _parse_equipment,
    _performance_layout,
    _raw_base_candidates,
)
from ._discovery import DiscoveredSolareFamily
from .models import SolarePlayer, SolareOverallEntry

_Entry = TypeVar("_Entry", SolarePlayer, SolareOverallEntry)
_REQUIRED = {"elo", "performance", "equipment"}


def _subset(table: _RecordTable, keep: Callable[[str, int], bool]) -> _RecordTable:
    indices = [
        i
        for i, (name, rank) in enumerate(zip(table.names, table.ranks))
        if keep(name, rank)
    ]
    family = table.family
    if family.class_codes:
        family = replace(
            family, class_codes=tuple(family.class_codes[i] for i in indices)
        )
    return _RecordTable(
        family,
        tuple(table.rows[i] for i in indices),
        tuple(table.names[i] for i in indices),
        tuple(table.ranks[i] for i in indices),
    )


def _invalid_ratings(ratings: Sequence[int]) -> Optional[set[int]]:
    invalid = {i for i, value in enumerate(ratings) if value > _MAX_LEARNED_ELO}
    ordered = [i for i in range(len(ratings)) if i not in invalid]
    inversions = [
        (i, j) for i, j in zip(ordered, ordered[1:]) if ratings[i] < ratings[j]
    ]
    if inversions:
        choices = []
        for i in inversions[0]:
            rest = [ratings[j] for j in ordered if j != i]
            if all(a >= b for a, b in zip(rest, rest[1:])):
                choices.append(i)
        if len(choices) != 1:
            return None
        invalid.add(choices[0])
    return invalid


def _read_table(
    table: _RecordTable,
    learned: _LearnedTable,
    entries: Sequence[_Entry],
    issues: dict[str, list[str]],
    retain_raw: bool,
) -> Optional[tuple[tuple[_Entry, ...], set[str]]]:
    perf = learned.performance
    layout = _performance_layout(learned, "isolated")
    if layout is None or perf is None or learned.elo_offset is None:
        return None
    offsets = _raw_base_candidates(
        learned.records.rows,
        perf.occupancies,
        value_count=126,
        slot_size=_GEAR_SLOT_SIZE,
        minimum_text_length=300,
        maximum_text_length=500,
    )
    if len(offsets) != 1:
        return None
    ratings = [_u32le(row, learned.elo_offset) for row in table.rows]
    invalid = _invalid_ratings(ratings)
    if invalid is None:
        return None
    available = _REQUIRED.copy()
    output = []
    for i, (entry, row) in enumerate(zip(entries, table.rows, strict=True)):
        if entry.name != table.names[i] or entry.global_rank != table.ranks[i]:
            return None

        def warn(field: str, slot: Optional[int] = None) -> None:
            available.discard(field)
            suffix = "" if slot is None else f" slot {slot}"
            issues.setdefault(entry.name, []).append(
                f"{table.family.role} rank {entry.global_rank} {entry.name}{suffix}: {field} unavailable"
            )

        elo = None if i in invalid else ratings[i]
        if entry.elo is not None and entry.elo != elo:
            return None
        if elo is None:
            warn("elo")
        slots = _decode_performance_slots(
            row,
            0,
            layout,
            retain_raw_extensions=retain_raw and learned.raw is not None,
            isolate_fields=True,
        )
        if not slots or (
            isinstance(entry, SolarePlayer)
            and slots[0].player_class != entry.primary_class
        ):
            return None
        result_slots = []
        for slot in slots:
            start = offsets[0] + slot.slot * _GEAR_SLOT_SIZE
            gear = _parse_equipment(row[start : start + _GEAR_SLOT_SIZE])
            if gear is None:
                warn("equipment", slot.slot)
            if slot.matches is None:
                warn("performance", slot.slot)
            if slot.specialization is None:
                warn("specialization", slot.slot)
                available.discard("performance")
            checked = replace(slot, equipment=gear)
            if entry.classes_played:
                if len(entry.classes_played) != len(slots):
                    return None
                previous = entry.classes_played[slot.slot]
                if previous.equipment is not None and previous.equipment != gear:
                    return None
                if previous.gear_loadout_raw is not None:
                    checked = replace(
                        checked,
                        gear_loadout_raw=previous.gear_loadout_raw,
                        skill_addons_raw=previous.skill_addons_raw,
                    )
                if (
                    replace(
                        checked,
                        gear_loadout_raw=previous.gear_loadout_raw,
                        skill_addons_raw=previous.skill_addons_raw,
                        equipment=previous.equipment,
                    )
                    != previous
                ):
                    return None
            result_slots.append(checked)
        if len(issues) > 1:
            return None
        updated = replace(entry, elo=elo, classes_played=tuple(result_slots))
        if isinstance(updated, SolareOverallEntry) and isinstance(
            layout, _OverallDetailLayout
        ):
            if learned.aggregate is not None and updated.total_matches is None:
                aggregate = _decode_overall_aggregate_performance(row, 0, layout)
                if aggregate is not None:
                    updated = cast(
                        _Entry,
                        replace(
                            cast(SolareOverallEntry, updated),
                            total_wins=aggregate[0],
                            total_draws=aggregate[1],
                            total_losses=aggregate[2],
                        ),
                    )
                else:
                    warn("aggregate_performance")
        output.append(updated)
    if learned.raw is not None and retain_raw:
        available.add("raw_extensions")
    if output and all(
        isinstance(p, SolareOverallEntry) and p.total_matches is not None
        for p in output
    ):
        available.add("aggregate_performance")
    return tuple(output), available


def _nominate(table: _RecordTable, candidate: _LearnedTable) -> set[str]:
    """Find outliers without using a sampled layout to authorize any result."""
    sample = candidate.records
    class_offset = table.family.class_offset
    if class_offset is None:
        placement = _learn_overall_class_offset(table)
        if placement is None:
            return set()
        class_offset = placement[0]
        sample = replace(
            sample, family=replace(sample.family, class_offset=class_offset)
        )
    occupied = _class_occupancies(table.rows, class_offset)
    sample_occupied = _class_occupancies(sample.rows, class_offset)
    if occupied is None or sample_occupied is None:
        return set()
    gear = _raw_base_candidates(
        sample.rows,
        sample_occupied,
        value_count=126,
        slot_size=_GEAR_SLOT_SIZE,
        minimum_text_length=300,
        maximum_text_length=500,
    )
    layout = _performance_layout(candidate, "sample")
    counters = (
        None
        if layout
        else _balanced_counter_solution(sample.rows, sample_occupied, records=sample)
    )
    suspects: set[str] = set()
    if candidate.elo_offset is not None:
        invalid = _invalid_ratings(
            [_u32le(row, candidate.elo_offset) for row in table.rows]
        )
        if invalid is not None:
            suspects.update(table.names[i] for i in invalid)
    for name, row, count in zip(table.names, table.rows, occupied):
        if (
            layout
            and _decode_performance_slots(row, 0, layout, retain_raw_extensions=False)
            is None
        ):
            suspects.add(name)
        for slot in range(count):
            if len(gear) == 1:
                start = gear[0] + slot * _GEAR_SLOT_SIZE
                if _parse_equipment(row[start : start + _GEAR_SLOT_SIZE]) is None:
                    suspects.add(name)
            if counters:
                matches, outcomes = counters
                if _u32le(row, matches + 4 * slot) != sum(
                    _u32le(row, offset + 4 * slot) for offset in outcomes
                ):
                    suspects.add(name)
    return suspects if len(suspects) == 1 else set()


def _counter_outliers(table: _RecordTable, companion: Sequence[_Entry]) -> set[str]:
    """Use shared primary counters only to nominate an identity for full revalidation."""
    lookup = {p.name: p for p in companion if p.classes_played}
    shared = [
        (name, row, lookup[name].classes_played[0])
        for name, row in zip(table.names, table.rows)
        if name in lookup
    ]
    if len(shared) < 20:
        return set()
    suspects: set[str] = set()
    for field in ("matches", "wins", "draws", "losses"):
        values = [getattr(slot, field) for _, _, slot in shared]
        if None in values or len(set(values)) < 5:
            continue
        # One of two distinct players must supply the uncorrupted placement.
        offsets = set()
        for (_, row, _), value in zip(shared[:2], values):
            needle = value.to_bytes(4, "little")
            offset = row.find(needle)
            while offset >= 0:
                offsets.add(offset)
                offset = row.find(needle, offset + 1)
        for offset in offsets:
            mismatches = []
            for (name, row, _), value in zip(shared, values):
                if _u32le(row, offset) != value:
                    mismatches.append(name)
                    if len(mismatches) > 1:
                        break
            if len(mismatches) == 1:
                suspects.add(mismatches[0])
    return suspects


def recover_one_player(
    rich: DiscoveredSolareFamily,
    overall: DiscoveredSolareFamily,
    players: Sequence[SolarePlayer],
    leaders: Sequence[SolareOverallEntry],
    retain_raw: bool = False,
) -> Optional[
    tuple[
        tuple[SolarePlayer, ...],
        tuple[SolareOverallEntry, ...],
        set[str],
        set[str],
        tuple[str, ...],
    ]
]:
    rich_rows = _extract_records(
        rich.frames,
        rich,
        expected_frames=rich.frame_count,
        expected_records=rich.record_count,
    )
    overall_rows = _extract_records(
        overall.frames, overall, expected_frames=50, expected_records=100
    )
    if rich_rows is None or overall_rows is None:
        return None

    def learn(keep: Callable[[str, int], bool]) -> tuple[_LearnedTable, _LearnedTable]:
        assert rich_rows is not None and overall_rows is not None
        return _learn_record_layouts(
            _subset(rich_rows, keep),
            _subset(overall_rows, keep),
            learn_rich=True,
            learn_overall=True,
            retain_raw_extensions=retain_raw,
        )

    suspects: set[str] = set()
    # Cohorts can suggest an identity. Only the all-other-players proof below
    # can authorize returning fields.
    for parity in (0, 1):
        if sum(rank % 2 == parity for rank in rich_rows.ranks) < 20:
            continue
        pair = learn(lambda name, rank: rank % 2 == parity)
        for table, candidate in zip((rich_rows, overall_rows), pair):
            suspects.update(_nominate(table, candidate))
    if not suspects:
        suspects.update(_counter_outliers(rich_rows, leaders))
        suspects.update(_counter_outliers(overall_rows, players))
    if len(suspects) != 1:
        return None
    name = suspects.pop()
    left, right = learn(lambda other, rank: other != name)
    issues: dict[str, list[str]] = {}
    class_result = _read_table(rich_rows, left, players, issues, retain_raw)
    if class_result is None:
        return None
    overall_result = _read_table(overall_rows, right, leaders, issues, retain_raw)
    if overall_result is None or set(issues) != {name}:
        return None
    by_name = {p.name: p for p in class_result[0]}
    for entry in overall_result[0]:
        other = by_name.get(entry.name)
        if (
            other
            and entry.elo is not None
            and other.elo is not None
            and entry.elo != other.elo
        ):
            return None
    return (
        class_result[0],
        overall_result[0],
        class_result[1],
        overall_result[1],
        tuple(issues[name]),
    )
