"""Adversarial fail-closed tests for ephemeral Solare detail learning.

These tests deliberately construct wire-like record tables with either two
equally valid interpretations or one corrupted invariant.  Optional detail
groups must be withheld in both cases while unrelated, independently valid
groups remain publishable.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typing import cast

import bdo_toolkit.solare._detail_learning as learning
from bdo_toolkit.solare._discovery import DiscoveredSolareFamily


_CLASS_OFFSET = 0
_SPEC_OFFSET = 4
_MATCHES_OFFSET = 16
_WINS_OFFSET = 32
_DRAWS_OFFSET = 48
_LOSSES_OFFSET = 64
_AGGREGATE_WINS_OFFSET = 100
_AGGREGATE_DRAWS_OFFSET = 104
_AGGREGATE_LOSSES_OFFSET = 108
_ELO_OFFSET = 150
_HISTORY_OFFSET = 180
_DUPLICATE_HISTORY_OFFSET = 500
_ROW_SIZE = 900


def _family(
    *,
    role: str,
    row_size: int,
    names: tuple[str, ...],
    ranks: tuple[int, ...],
    class_codes: tuple[int, ...] = (),
    class_counts: tuple[tuple[int, int], ...] = (),
) -> DiscoveredSolareFamily:
    """Return the narrow family surface used by the private learner helpers."""

    return cast(
        DiscoveredSolareFamily,
        SimpleNamespace(
            role=role,
            frame_length=row_size + 4,
            record_stride=4,
            name_offset=120,
            rank_offset=124,
            class_offset=(
                _CLASS_OFFSET if role == "rich" else None
            ),
            names=names,
            ranks=ranks,
            class_codes=class_codes,
            class_counts=class_counts,
        ),
    )


def _table(
    rows: tuple[bytes, ...],
    *,
    role: str = "overall",
    class_codes: tuple[int, ...] = (),
) -> learning._RecordTable:
    names = tuple(f"Player{ordinal:03d}" for ordinal in range(len(rows)))
    ranks = tuple(range(1, len(rows) + 1))
    counts = tuple(
        sorted(
            (code, class_codes.count(code))
            for code in set(class_codes)
        )
    )
    return learning._RecordTable(
        family=_family(
            role=role,
            row_size=len(rows[0]),
            names=names,
            ranks=ranks,
            class_codes=class_codes,
            class_counts=counts,
        ),
        rows=rows,
        names=names,
        ranks=ranks,
    )


def _write_u32_slots(
    row: bytearray,
    offset: int,
    values: tuple[int, int, int],
) -> None:
    for slot, value in enumerate(values):
        start = offset + slot * 4
        row[start : start + 4] = value.to_bytes(4, "little")


def _history_text(matches: int, wins: int) -> bytes:
    pairs = ((1, 1),) * wins + ((1, 0),) * (matches - wins)
    values = tuple(value for pair in pairs[:5] for value in pair)
    return ",".join(str(value) for value in values).encode("ascii")


def _performance_rows(
    *,
    duplicate_counters: bool = False,
    duplicate_history: bool = False,
    corrupt_counter: bool = False,
    corrupt_history: bool = False,
    include_aggregate: bool = False,
    duplicate_aggregate: bool = False,
    corrupt_aggregate: bool = False,
) -> tuple[learning._RecordTable, learning._PerformanceOffsets]:
    rows: list[bytes] = []
    occupancies = (1,) * 6 + (2,) * 6 + (3,) * 6
    duplicate_counter_offsets = (76, 88, 116, 128)
    # A genuine competing field, outside the independently known name block.
    duplicate_aggregate_offsets = (810, 814, 818)

    for ordinal, occupied in enumerate(occupancies):
        row = bytearray(b"\xFE" * _ROW_SIZE)
        classes = tuple(
            (10 + slot) if slot < occupied else 101
            for slot in range(3)
        )
        specs = tuple(
            (1 + slot % 2) if slot < occupied else 3
            for slot in range(3)
        )
        row[_CLASS_OFFSET : _CLASS_OFFSET + 3] = bytes(classes)
        row[_SPEC_OFFSET : _SPEC_OFFSET + 3] = bytes(specs)

        match_values: list[int] = []
        win_values: list[int] = []
        draw_values: list[int] = []
        loss_values: list[int] = []
        for slot in range(3):
            if slot >= occupied:
                match_values.append(0)
                win_values.append(0)
                draw_values.append(0)
                loss_values.append(0)
                continue
            if ordinal < 6:
                matches = ordinal % 5 + 1
                wins = matches if ordinal % 2 == 0 else 0
                draws = 0
            else:
                matches = 12 + ordinal + slot
                draws = 1
                wins = matches // 2
            losses = matches - wins - draws
            match_values.append(matches)
            win_values.append(wins)
            draw_values.append(draws)
            loss_values.append(losses)

            for history_base in (
                (_HISTORY_OFFSET, _DUPLICATE_HISTORY_OFFSET)
                if duplicate_history
                else (_HISTORY_OFFSET,)
            ):
                start = history_base + slot * learning._HISTORY_SLOT_SIZE
                row[start : start + learning._HISTORY_SLOT_SIZE] = (
                    b"\x00" * learning._HISTORY_SLOT_SIZE
                )
                text = _history_text(matches, wins)
                row[start : start + len(text)] = text

        # Empty histories must be represented by a leading NUL.
        for slot in range(occupied, 3):
            for history_base in (
                (_HISTORY_OFFSET, _DUPLICATE_HISTORY_OFFSET)
                if duplicate_history
                else (_HISTORY_OFFSET,)
            ):
                start = history_base + slot * learning._HISTORY_SLOT_SIZE
                row[start : start + learning._HISTORY_SLOT_SIZE] = (
                    b"\x00" * learning._HISTORY_SLOT_SIZE
                )

        matches_tuple = cast(tuple[int, int, int], tuple(match_values))
        wins_tuple = cast(tuple[int, int, int], tuple(win_values))
        draws_tuple = cast(tuple[int, int, int], tuple(draw_values))
        losses_tuple = cast(tuple[int, int, int], tuple(loss_values))
        _write_u32_slots(row, _MATCHES_OFFSET, matches_tuple)
        _write_u32_slots(row, _WINS_OFFSET, wins_tuple)
        _write_u32_slots(row, _DRAWS_OFFSET, draws_tuple)
        _write_u32_slots(row, _LOSSES_OFFSET, losses_tuple)

        if duplicate_counters:
            for offset, values in zip(
                duplicate_counter_offsets,
                (matches_tuple, wins_tuple, draws_tuple, losses_tuple),
            ):
                _write_u32_slots(row, offset, values)

        row[_ELO_OFFSET : _ELO_OFFSET + 4] = (
            3_000 - ordinal
        ).to_bytes(4, "little")

        if include_aggregate:
            aggregate_wins = sum(wins_tuple[:occupied])
            aggregate_draws = sum(draws_tuple[:occupied])
            aggregate_losses = sum(losses_tuple[:occupied])
            if occupied == 3:
                # Supply the nontrivial aggregate excess required by the
                # learner while keeping the correct W/D/L orientation much
                # closer than any permutation.
                aggregate_wins += 1
            aggregates = (
                aggregate_wins,
                aggregate_draws,
                aggregate_losses,
            )
            for offset, value in zip(
                (
                    _AGGREGATE_WINS_OFFSET,
                    _AGGREGATE_DRAWS_OFFSET,
                    _AGGREGATE_LOSSES_OFFSET,
                ),
                aggregates,
            ):
                row[offset : offset + 4] = value.to_bytes(4, "little")
            if duplicate_aggregate:
                for offset, value in zip(
                    duplicate_aggregate_offsets,
                    aggregates,
                ):
                    row[offset : offset + 4] = value.to_bytes(4, "little")

        rows.append(bytes(row))

    if corrupt_counter:
        row = bytearray(rows[0])
        current = int.from_bytes(
            row[_MATCHES_OFFSET : _MATCHES_OFFSET + 4],
            "little",
        )
        row[_MATCHES_OFFSET : _MATCHES_OFFSET + 4] = (
            current + 1
        ).to_bytes(4, "little")
        rows[0] = bytes(row)

    if corrupt_history:
        row = bytearray(rows[0])
        start = _HISTORY_OFFSET
        row[start : start + learning._HISTORY_SLOT_SIZE] = (
            b"\xFF" * learning._HISTORY_SLOT_SIZE
        )
        rows[0] = bytes(row)

    if corrupt_aggregate:
        row = bytearray(rows[0])
        current = int.from_bytes(
            row[
                _AGGREGATE_WINS_OFFSET : _AGGREGATE_WINS_OFFSET + 4
            ],
            "little",
        )
        row[
            _AGGREGATE_WINS_OFFSET : _AGGREGATE_WINS_OFFSET + 4
        ] = (current + 1).to_bytes(4, "little")
        rows[0] = bytes(row)

    records = _table(tuple(rows))
    performance = learning._PerformanceOffsets(
        class_offset=_CLASS_OFFSET,
        spec_offset=_SPEC_OFFSET,
        matches_offset=_MATCHES_OFFSET,
        wins_offset=_WINS_OFFSET,
        draws_offset=_DRAWS_OFFSET,
        losses_offset=_LOSSES_OFFSET,
        history_offset=_HISTORY_OFFSET,
        occupancies=occupancies,
    )
    return records, performance


def _elo_table(
    values: tuple[int, ...],
    *,
    offsets: tuple[int, ...],
    role: str,
) -> learning._RecordTable:
    rows: list[bytes] = []
    for value in values:
        row = bytearray(b"\xFF" * 24)
        for offset in offsets:
            row[offset : offset + 4] = value.to_bytes(4, "little")
        rows.append(bytes(row))
    return _table(tuple(rows), role=role)


def _csv(values: tuple[int, ...]) -> bytes:
    return ",".join(str(value) for value in values).encode("ascii")


def _gear_text() -> bytes:
    return _csv(tuple(
        value for slot in (0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 27, 29)
        for value in (slot, 740603, 0, 15252, 15252, 0, 0, 0, 0)
    ))


def _raw_rows(
    *,
    duplicate: bool = False,
    corrupt: bool = False,
) -> tuple[learning._RecordTable, learning._PerformanceOffsets]:
    gear_base = 100
    addons_base = 6_500
    duplicate_gear_base = 8_100
    duplicate_addons_base = 14_300
    row_size = 16_000
    occupancies = (1,) * 20 + (2,) * 2 + (3,) * 2
    gear_text = _gear_text()
    addon_text = _csv(tuple(10 + index for index in range(12)))
    rows: list[bytes] = []

    for occupied in occupancies:
        row = bytearray(b"\xFF" * row_size)
        for slot in range(occupied):
            for base, stride, text in (
                (gear_base, learning._GEAR_SLOT_SIZE, gear_text),
                (addons_base, learning._ADDON_SLOT_SIZE, addon_text),
            ):
                start = base + slot * stride
                row[start : start + len(text)] = text
                row[start + len(text)] = 0
            if duplicate:
                for base, stride, text in (
                    (
                        duplicate_gear_base,
                        learning._GEAR_SLOT_SIZE,
                        gear_text,
                    ),
                    (
                        duplicate_addons_base,
                        learning._ADDON_SLOT_SIZE,
                        addon_text,
                    ),
                ):
                    start = base + slot * stride
                    row[start : start + len(text)] = text
                    row[start + len(text)] = 0
        rows.append(bytes(row))

    if corrupt:
        row = bytearray(rows[-1])
        row[gear_base] = ord("x")
        rows[-1] = bytes(row)

    records = _table(tuple(rows))
    performance = learning._PerformanceOffsets(
        class_offset=0,
        spec_offset=0,
        matches_offset=0,
        wins_offset=0,
        draws_offset=0,
        losses_offset=0,
        history_offset=0,
        occupancies=occupancies,
    )
    return records, performance


def test_duplicate_or_corrupted_elo_columns_withhold_elo() -> None:
    values = tuple(range(50_000, 49_900, -1))
    ambiguous_rich = _elo_table(values, offsets=(0, 8), role="rich")
    ambiguous_overall = _elo_table(values, offsets=(0, 8), role="overall")

    assert learning._choose_elo_offsets(
        ambiguous_rich,
        ambiguous_overall,
    ) == (None, None)

    rich = _elo_table(values, offsets=(0,), role="rich")
    corrupt_values = list(values)
    corrupt_values[50] -= 1
    corrupt_overall = _elo_table(
        tuple(corrupt_values),
        offsets=(8,),
        role="overall",
    )
    assert learning._choose_elo_offsets(
        rich,
        corrupt_overall,
    ) == (None, None)


def test_anchored_elo_requires_one_exact_authoritative_match() -> None:
    values = tuple(range(50_000, 49_900, -1))
    authoritative = {
        f"Player{ordinal:03d}": value
        for ordinal, value in enumerate(values)
    }
    matching = _elo_table(values, offsets=(8,), role="overall")
    assert (
        learning._choose_anchored_elo_offset(matching, authoritative)
        == 8
    )

    # A plausible and uniquely descending column is not enough when the known
    # table supplies authoritative name/Elo anchors that disagree with it.
    shifted = tuple(value - 1 for value in values)
    disagreeing = _elo_table(shifted, offsets=(8,), role="overall")
    assert (
        learning._choose_anchored_elo_offset(disagreeing, authoritative)
        is None
    )

    # Two byte columns agreeing with every anchor are equally plausible and
    # must therefore be treated as ambiguity, not arbitrarily selected.
    duplicate = _elo_table(values, offsets=(0, 8), role="overall")
    assert (
        learning._choose_anchored_elo_offset(duplicate, authoritative)
        is None
    )


def test_ambiguous_or_unbalanced_counters_withhold_performance() -> None:
    ambiguous, occupancies = _performance_rows(duplicate_counters=True)
    assert (
        learning._learn_performance_offsets(
            ambiguous,
            _CLASS_OFFSET,
            occupancies.occupancies,
        )
        is None
    )

    corrupted, occupancies = _performance_rows(corrupt_counter=True)
    assert (
        learning._learn_performance_offsets(
            corrupted,
            _CLASS_OFFSET,
            occupancies.occupancies,
        )
        is None
    )


def test_ambiguous_or_corrupted_history_withholds_performance() -> None:
    ambiguous, performance = _performance_rows(duplicate_history=True)
    assert (
        learning._learn_performance_offsets(
            ambiguous,
            _CLASS_OFFSET,
            performance.occupancies,
        )
        is None
    )

    corrupted, performance = _performance_rows(corrupt_history=True)
    assert (
        learning._learn_performance_offsets(
            corrupted,
            _CLASS_OFFSET,
            performance.occupancies,
        )
        is None
    )


def test_bad_aggregate_is_withheld_without_losing_per_class_details() -> None:
    valid, performance = _performance_rows(include_aggregate=True)
    aggregate = learning._learn_aggregate(valid, performance)
    assert aggregate == learning._AggregateOffsets(
        _AGGREGATE_WINS_OFFSET,
        _AGGREGATE_DRAWS_OFFSET,
        _AGGREGATE_LOSSES_OFFSET,
    )

    for records in (
        _performance_rows(
            include_aggregate=True,
            duplicate_aggregate=True,
        )[0],
        _performance_rows(
            include_aggregate=True,
            corrupt_aggregate=True,
        )[0],
    ):
        assert learning._learn_aggregate(records, performance) is None
        decoded = learning._decode_learned_overall(
            learning._LearnedTable(
                records=records,
                elo_offset=_ELO_OFFSET,
                performance=performance,
                aggregate=None,
            )
        )
        assert decoded is not None
        assert decoded.capabilities == frozenset(
            {"rankings", "elo", "performance"}
        )
        assert all(entry.classes_played for entry in decoded.entries)
        assert all(entry.total_matches is None for entry in decoded.entries)


def test_bad_raw_candidates_are_withheld_and_cross_table_must_agree() -> None:
    valid, performance = _raw_rows()
    raw = learning._learn_raw_offsets(valid, performance)
    assert raw == learning._RawOffsets(100, 6_500)

    ambiguous, ambiguous_performance = _raw_rows(duplicate=True)
    assert (
        learning._learn_raw_offsets(ambiguous, ambiguous_performance)
        is None
    )
    corrupted, corrupted_performance = _raw_rows(corrupt=True)
    assert (
        learning._learn_raw_offsets(corrupted, corrupted_performance)
        is None
    )

    rich = learning._LearnedTable(
        valid,
        elo_offset=None,
        performance=performance,
        raw=raw,
    )
    overall_rows = list(valid.rows)
    mismatched = bytearray(overall_rows[-1])
    mismatched[raw.gear_offset] ^= 1
    overall_rows[-1] = bytes(mismatched)
    overall_records = learning._RecordTable(
        family=_family(
            role="overall",
            row_size=len(overall_rows[0]),
            names=valid.names,
            ranks=valid.ranks,
        ),
        rows=tuple(overall_rows),
        names=valid.names,
        ranks=valid.ranks,
    )
    overall = learning._LearnedTable(
        overall_records,
        elo_offset=None,
        performance=performance,
        raw=raw,
    )
    assert not learning._raw_sections_agree(rich, overall)


def test_elo_survives_when_performance_is_withheld() -> None:
    rows: list[bytes] = []
    class_codes = (10,) * 20
    for ordinal in range(20):
        row = bytearray(b"\xFF" * 32)
        row[8:12] = (3_000 - ordinal).to_bytes(4, "little")
        rows.append(bytes(row))
    records = _table(
        tuple(rows),
        role="rich",
        class_codes=class_codes,
    )

    decoded = learning._decode_learned_rich(
        learning._LearnedTable(
            records=records,
            elo_offset=8,
            performance=None,
        )
    )
    assert decoded is not None
    assert decoded.capabilities == frozenset({"rankings", "elo"})
    assert all(player.elo is not None for player in decoded.players)
    assert all(not player.classes_played for player in decoded.players)


def test_all_zero_draws_do_not_establish_a_unique_outcome_layout() -> None:
    records, performance = _performance_rows()
    rows = []
    for source in records.rows:
        row = bytearray(source)
        for slot in range(3):
            draws = learning._u32le(row, _DRAWS_OFFSET + slot * 4)
            losses = learning._u32le(row, _LOSSES_OFFSET + slot * 4)
            start = _LOSSES_OFFSET + slot * 4
            row[start:start + 4] = (losses + draws).to_bytes(4, "little")
        row[_DRAWS_OFFSET:_DRAWS_OFFSET + 12] = bytes(12)
        rows.append(bytes(row))
    assert learning._balanced_counter_solution(rows, performance.occupancies) is None


def _zero_draw_tail() -> tuple[learning._RecordTable, tuple[int, ...]]:
    # Independent synthetic geometry, not copied from a captured layout.
    rows = []
    occupancies = (1,) * 8 + (2,) * 8 + (3,) * 8
    primary = (0, 1, 2, 4, 5, 6)
    for ordinal, occupied in enumerate(occupancies):
        row = bytearray(7879)
        row[12:15] = bytes((primary[ordinal % 6], 7 if occupied > 1 else 101,
                            8 if occupied > 2 else 101))
        row[358:361] = bytes((1, 2 if occupied > 1 else 3,
                              1 if occupied > 2 else 3))
        row[51:55] = (2000 - ordinal).to_bytes(4, "little")
        for slot in range(occupied):
            matches = (ordinal % 5 + 1) if ordinal < 8 else 12 + ordinal + slot
            wins = matches if ordinal % 4 == 1 else max(matches - 1, 0)
            for offset, value in ((15, matches), (27, wins), (39, matches - wins)):
                start = offset + slot * 4
                row[start:start + 4] = value.to_bytes(4, "little")
            history = _history_text(matches, wins)
            start = 55 + slot * 101
            row[start:start + len(history)] = history
            addons = b",".join([b"1"] * 12)
            start = 361 + slot * 501
            row[start:start + len(addons)] = addons
            gear = _gear_text()
            start = 1864 + slot * 2001
            row[start:start + len(gear)] = gear
        rows.append(bytes(row))
    codes = tuple(row[12] for row in rows)
    table = _table(tuple(rows), role="rich", class_codes=codes)
    table.family.class_offset = 12  # type: ignore[misc]
    return table, occupancies


def test_zero_draws_require_unique_surrounding_field_boundaries() -> None:
    records, occupancies = _zero_draw_tail()
    performance = learning._learn_performance_offsets(records, 12, occupancies)
    assert performance is not None
    assert (performance.matches_offset, performance.wins_offset,
            performance.draws_offset, performance.losses_offset) == (15, 27, 7867, 39)


@pytest.mark.parametrize("padding", (1, 2, 3))
def test_zero_outcomes_retain_every_equivalent_position(padding):
    records, occupancies = _zero_draw_tail()
    records.family.frame_length += padding
    records = replace(records, rows=tuple(row + bytes(padding) for row in records.rows))
    performance = learning._learn_performance_offsets(records, 12, occupancies)
    assert performance is not None
    assert performance.draws_offset == 7867  # Representative reader position.
    assert performance.zero_outcome_candidates == tuple(range(7867, 7868 + padding))
    assert all(row[offset:offset + 12] == bytes(12)
               for row in records.rows for offset in performance.zero_outcome_candidates)
    # The ephemeral ID records the alternative proof, not an exact address claim.
    assert learning._layout_id("rich", records, 51, performance) != learning._layout_id(
        "rich", records, 51, replace(performance, zero_outcome_candidates=()))


def test_zero_outcomes_allow_one_separate_unassigned_word_and_binary_gear_prefix():
    records, occupancies = _zero_draw_tail()
    records.family.frame_length += 6
    rows = tuple(row[:1864] + b"\0\0\0\x33" + row[1864:] + bytes(2)
                 for row in records.rows)
    performance = learning._learn_performance_offsets(replace(records, rows=rows), 12, occupancies)
    assert performance is not None
    assert performance.zero_outcome_candidates == (7871, 7872, 7873)


@pytest.mark.parametrize("gap_size", range(1, 12))
@pytest.mark.parametrize("zero_filled", (False, True))
def test_zero_outcomes_ignore_gaps_too_short_for_another_counter_array(gap_size, zero_filled):
    records, occupancies = _zero_draw_tail()
    # Place unknown bytes before gear, shifting both gear and the draw container.
    # Exercise zeros too: a short zero run is not a competing three-counter array.
    gap = bytes(gap_size) if zero_filled else bytes(range(17, 17 + gap_size))
    records.family.frame_length += gap_size + 2
    rows = tuple(row[:1864] + gap + row[1864:] + bytes(2) for row in records.rows)
    performance = learning._learn_performance_offsets(replace(records, rows=rows), 12, occupancies)
    assert performance is not None
    assert (performance.matches_offset, performance.wins_offset,
            performance.losses_offset) == (15, 27, 39)
    assert performance.zero_outcome_candidates == tuple(range(7867 + gap_size, 7870 + gap_size))


@pytest.mark.parametrize("gap_size", (12, 13, 15, 16, 24))
@pytest.mark.parametrize("zero_filled", (False, True))
def test_zero_outcomes_reject_another_gap_large_enough_for_a_counter_array(gap_size, zero_filled):
    records, occupancies = _zero_draw_tail()
    gap = bytes(gap_size) if zero_filled else bytes(range(17, 17 + gap_size))
    records.family.frame_length += gap_size
    rows = tuple(row[:1864] + gap + row[1864:] for row in records.rows)
    assert learning._learn_performance_offsets(replace(records, rows=rows), 12, occupancies) is None


@pytest.mark.parametrize("leading,trailing", (
    (b"", b"\x12\x34"), (b"\x56", b"\x78"), (b"\x34\x12", b""),
    (b"", b"\x01\x02\x03\x04"), (b"\x01\x02", b"\x03\x04"), (b"\x01\x02\x03\x04", b""),
))
def test_zero_outcomes_require_unique_placement_inside_nonzero_container(leading, trailing):
    records, occupancies = _zero_draw_tail()
    rows = tuple(row[:7867] + (leading if i == 1 else bytes(len(leading))) +
                 row[7867:] + (trailing if i == 1 else bytes(len(trailing)))
                 for i, row in enumerate(records.rows))
    records.family.frame_length += len(leading) + len(trailing)
    performance = learning._learn_performance_offsets(replace(records, rows=rows), 12, occupancies)
    assert performance is not None
    assert performance.draws_offset == 7867 + len(leading)
    assert not performance.zero_outcome_candidates


@pytest.mark.parametrize("trailing", (
    b"\x00\x01\x02\x03",  # Two valid starts in a 16-byte region.
    b"\x01\x02\x03\x04\x05",  # Unique placement, but beyond the fallback's bound.
))
def test_zero_outcomes_reject_ambiguous_or_oversized_placement_region(trailing):
    records, occupancies = _zero_draw_tail()
    rows = tuple(row + trailing for row in records.rows)
    records.family.frame_length += len(trailing)
    assert learning._learn_performance_offsets(replace(records, rows=rows), 12, occupancies) is None


@pytest.mark.parametrize("damage", ("large_tail", "nonzero_before", "nonzero_after", "other_wide_gap"))
def test_zero_outcome_equivalence_rejects_unproved_containers(damage):
    records, occupancies = _zero_draw_tail()
    rows = [row + bytes(2) for row in records.rows]
    extra = 2
    if damage == "large_tail":
        rows = [row + bytes(2) for row in rows]
        extra += 2
    elif damage in ("nonzero_before", "nonzero_after"):
        row = bytearray(rows[0])
        row[7867 if damage == "nonzero_before" else -1] = 1
        rows[0] = bytes(row)
    else:
        size = 12
        rows = [row[:1864] + bytes(size) + row[1864:] for row in rows]
        extra += size
    records.family.frame_length += extra
    assert learning._learn_performance_offsets(replace(records, rows=tuple(rows)), 12, occupancies) is None


@pytest.mark.parametrize("damage", ("extra_gap", "nonzero_draw", "broken_gear", "broken_addons", "broken_history", "unbalanced"))
def test_zero_draw_boundary_proof_rejects_missing_evidence(damage: str) -> None:
    records, occupancies = _zero_draw_tail()
    rows = list(records.rows)
    if damage == "extra_gap":
        rows = [row + bytes(12) for row in rows]
        records.family.frame_length += 12  # type: ignore[misc]
    else:
        row = bytearray(rows[0])
        offset = {"nonzero_draw": 7867, "broken_gear": 1864, "broken_addons": 361, "broken_history": 55, "unbalanced": 27}[damage]
        row[offset] = 255
        rows[0] = bytes(row)
    changed = replace(records, rows=tuple(rows))
    assert learning._learn_performance_offsets(changed, 12, occupancies) is None


@pytest.mark.parametrize("empty_rows, supported", ((1, True), (2, True)))
def test_zero_draw_anchor_accepts_blank_addons_without_authorizing_raw(
    empty_rows: int, supported: bool,
) -> None:
    records, occupancies = _zero_draw_tail()
    rows = list(records.rows)
    for ordinal in range(1, empty_rows + 1):
        row = bytearray(rows[ordinal])
        row[361:862] = bytes(501)
        rows[ordinal] = bytes(row)
    changed = replace(records, rows=tuple(rows))
    performance = learning._learn_performance_offsets(changed, 12, occupancies)
    assert (performance is not None) is supported
    if performance is not None:
        assert learning._learn_raw_offsets(changed, performance) is None


@pytest.mark.parametrize("empty_slots", ((0,), (1,), (2,), (0, 1, 2)))
def test_empty_addons_in_any_player_class_slot(empty_slots):
    records, occupancies = _zero_draw_tail()
    rows = []
    for ordinal, source in enumerate(records.rows):
        row = bytearray(source)
        # Include a fully blank first player, and more than five percent of
        # tertiary loadouts; retain text witnesses in other records.
        if ordinal % 2 == 0:
            for slot in empty_slots:
                row[361 + slot * 501:361 + (slot + 1) * 501] = bytes(501)
        rows.append(bytes(row))
    changed = replace(records, rows=tuple(rows))
    performance = learning._learn_performance_offsets(changed, 12, occupancies)
    assert performance is not None
    assert performance.draws_offset == 7867


def test_entire_table_without_addon_text_cannot_establish_a_boundary():
    records, occupancies = _zero_draw_tail()
    rows = tuple(row[:361] + bytes(1503) + row[1864:] for row in records.rows)
    assert learning._learn_performance_offsets(replace(records, rows=rows), 12, occupancies) is None


@pytest.mark.parametrize("slot", (0, 1, 2))
@pytest.mark.parametrize("count", (2, 4, 6, 8, 10))
def test_partial_addon_pairs_anchor_without_population_threshold(slot, count):
    records, occupancies = _zero_draw_tail()
    rows = list(records.rows)
    for ordinal in range(16, 24):
        row = bytearray(rows[ordinal])
        start = 361 + slot * 501
        text = b",".join([b"1572"] * count)
        row[start:start + 501] = text + bytes(501 - len(text))
        rows[ordinal] = bytes(row)
    performance = learning._learn_performance_offsets(
        replace(records, rows=tuple(rows)), 12, occupancies)
    assert performance is not None
    assert performance.draws_offset == 7867


@pytest.mark.parametrize("text", (b"1,2,3", b",".join([b"1"] * 14),
                                 b"1,x", b"1,2\x00junk", b"1,2,"))
def test_malformed_partial_addon_rejected_even_in_one_tertiary_slot(text):
    records, occupancies = _zero_draw_tail()
    row = bytearray(records.rows[-1])
    start = 361 + 2 * 501
    row[start:start + 501] = text + bytes(501 - len(text))
    changed = replace(records, rows=records.rows[:-1] + (bytes(row),))
    assert learning._learn_performance_offsets(changed, 12, occupancies) is None


@pytest.mark.parametrize("preceding", (ord("0"), ord("5"), ord("9"), ord(",")))
@pytest.mark.parametrize("count", (0, 2, 4, 6, 8, 10, 12))
def test_addon_boundary_validation_ignores_preceding_binary_byte(preceding, count):
    records, occupancies = _zero_draw_tail()
    row = bytearray(records.rows[0])
    row[360] = preceding
    text = b",".join([b"1572"] * count)
    row[361:862] = text + bytes(501 - len(text))
    rows = (bytes(row),) + records.rows[1:]
    assert learning._raw_base_candidates(
        rows, occupancies, value_count=12, slot_size=501,
        minimum_text_length=20, maximum_text_length=100,
        allow_empty_slots=True,
    ) == (361,)


@pytest.mark.parametrize("preceding", (ord("0"), ord("3"), ord("9"), ord(",")))
def test_equipment_boundary_uses_typed_blocks_when_every_primary_has_binary_prefix(preceding):
    records, performance = _raw_rows()
    rows = []
    for original in records.rows:
        row = bytearray(original)
        row[99] = preceding
        rows.append(bytes(row))
    assert learning._raw_base_candidates(
        rows, performance.occupancies, value_count=126, slot_size=2001,
        minimum_text_length=300, maximum_text_length=500,
    ) == (100,)


def test_aggregate_candidates_exclude_the_independent_name_field():
    records, performance = _performance_rows(include_aggregate=True)
    rows = []
    for original in records.rows:
        row = bytearray(original)
        for source, alias in zip((100, 104, 108), (136, 140, 144)):
            row[alias:alias + 4] = row[source:source + 4]
        rows.append(bytes(row))
    assert learning._learn_aggregate(replace(records, rows=tuple(rows)), performance) == (
        learning._AggregateOffsets(100, 104, 108))


def test_blank_addon_requires_entire_slot_to_be_zero():
    records, occupancies = _zero_draw_tail()
    row = bytearray(records.rows[0])
    row[361:862] = bytes(501)
    row[861] = 255
    changed = replace(records, rows=(bytes(row),) + records.rows[1:])
    assert learning._learn_performance_offsets(changed, 12, occupancies) is None


@pytest.mark.parametrize("damage", (None, "stats", "rank", "class", "few_shared", "no_local_history"))
def test_small_local_history_requires_independent_companion_agreement(damage):
    records, occupied = _zero_draw_tail()
    extra = []
    for i, original in enumerate(records.rows[-8:]):
        row = bytearray(original)
        row[51:55] = (1976 - i).to_bytes(4, "little")
        extra.append(bytes(row))
    rows = records.rows + tuple(extra)
    source = _table(rows, role="rich", class_codes=tuple(row[12] for row in rows))
    source.family.class_offset = 12
    source_occupied = occupied + occupied[-8:]
    known = learning._learn_performance_offsets(source, 12, source_occupied)
    assert known is not None
    target = replace(source, rows=source.rows[5:], names=source.names[5:], ranks=source.ranks[5:])
    target_occupied = source_occupied[5:]
    # Isolate orientation policy: counter geometry has separate adversarial
    # coverage and remains a prerequisite in production.
    def infer(**kwargs):
        with patch.object(learning, "_balanced_counter_solution", return_value=(15, (27, 39, 7867))), patch.object(learning, "_orient_outcomes", return_value=None):
            return learning._learn_performance_offsets(target, 12, target_occupied, **kwargs)
    assert infer() is None
    if damage == "stats":
        row = bytearray(target.rows[-1])
        row[27:31], row[39:43] = row[39:43], row[27:31]
        target = replace(target, rows=target.rows[:-1] + (bytes(row),))
    elif damage == "rank":
        target = replace(target, ranks=target.ranks[:-1] + (999,))
    elif damage == "class":
        row = bytearray(target.rows[-1]); row[12] = 30
        target = replace(target, rows=target.rows[:-1] + (bytes(row),))
    elif damage == "few_shared":
        target = replace(target, names=tuple("Other" + n if i > 10 else n for i, n in enumerate(target.names)))
    elif damage == "no_local_history":
        target = replace(target, rows=target.rows[3:], names=target.names[3:], ranks=target.ranks[3:])
        target_occupied = target_occupied[3:]
    inferred = infer(companion=(source, known))
    assert (inferred is not None) is (damage in (None, "no_local_history"))


@pytest.mark.parametrize("case", ("verified", "ambiguous", "contradictory", "insufficient"))
def test_outcome_orientation_without_any_low_match_players(case):
    fixed = []
    for i in range(4 if case == "insufficient" else 12):
        row = bytearray(200)
        matches = 100 + i
        wins = 60 if case == "ambiguous" else matches - 1
        for offset, value in ((0, matches), (12, wins), (24, 0), (36, matches - wins)):
            row[offset:offset + 4] = value.to_bytes(4, "little")
        text = b"1,0,1,0,1,0,1,0,1,0" if case == "contradictory" and i == 0 else b"1,1,1,1,1,1,1,1,1,1"
        row[50:50 + len(text)] = text
        fixed.append(bytes(row))
    actual = learning._orient_outcomes(fixed, (1,) * len(fixed), 0, (12, 24, 36), 50)
    assert actual == ((12, 24, 36) if case == "verified" else None)


def test_full_performance_discovery_when_every_player_is_experienced():
    records, occupancies = _zero_draw_tail()
    rows = []
    for ordinal, (source, occupied) in enumerate(zip(records.rows, occupancies)):
        row = bytearray(source)
        for slot in range(occupied):
            matches = 30 + ordinal + slot
            wins = matches - 1
            for offset, value in ((15, matches), (27, wins), (39, 1)):
                start = offset + slot * 4
                row[start:start + 4] = value.to_bytes(4, "little")
            start = 55 + slot * 101
            row[start:start + 101] = bytes(101)
            history = _history_text(matches, wins)
            row[start:start + len(history)] = history
        rows.append(bytes(row))
    changed = replace(records, rows=tuple(rows))
    candidates = learning._matches_candidates(changed.rows, occupancies)
    assert 2 < len(candidates) <= learning._MAX_MATCH_CANDIDATES
    performance = learning._learn_performance_offsets(changed, 12, occupancies)
    assert performance is not None
    assert (performance.matches_offset, performance.wins_offset, performance.draws_offset, performance.losses_offset) == (15, 27, 7867, 39)


def test_match_search_still_rejects_candidate_overflow():
    row = b"".join(value.to_bytes(4, "little") + bytes(8) for value in range(1, 20))
    assert learning._matches_candidates((row,), (1,)) == ()


def _zero_aggregate_tables(shift=0):
    rows, rich_rows = [], []
    occupied = (1,) * 29 + (3,)
    for i, n in enumerate(occupied):
        row, rich = bytearray(1000 + shift), bytearray(300 + shift)
        name = f"Player{i:03d}".encode("utf-16-le")
        row[40 + shift:40 + shift + len(name)] = name
        rich[60 + shift:60 + shift + len(name)] = name
        identity = (900000 + i * 71).to_bytes(8, "little")
        row[28 + shift:36 + shift] = identity
        rich[40 + shift:48 + shift] = identity
        rich[39 + shift] = 255
        wins, losses = 0, 0
        for slot in range(n):
            w, loss = (60 + i, 40) if slot == 0 else (3, 2)
            wins += w
            losses += loss
            for off, val in ((300, w + loss), (312, w), (336, loss)):
                start = off + shift + slot * 4
                row[start:start + 4] = val.to_bytes(4, "little")
        for off, val in ((20, 3000 - i), (36, losses + (3 if n == 3 else 0)),
                         (205, wins + (1 if n == 3 else 0)), (209, i + 1)):
            row[off + shift:off + shift + 4] = val.to_bytes(4, "little")
        for off, val in ((130, i + 1), (150, 3000 - i)):
            rich[off + shift:off + shift + 4] = val.to_bytes(4, "little")
        history = b"0,0,1,1,0,1,1,0,0,0"
        row[102 + shift:102 + shift + len(history)] = history
        rows.append(bytes(row))
        rich_rows.append(bytes(rich))
    table, companion = _table(tuple(rows)), _table(tuple(rich_rows), role="rich")
    table.family.name_offset, table.family.rank_offset = 40 + shift, 209 + shift
    companion.family.name_offset, companion.family.rank_offset = 60 + shift, 130 + shift
    companion.family.class_offset = 170 + shift
    perf = learning._PerformanceOffsets(213 + shift, 216 + shift, 300 + shift,
        312 + shift, 324 + shift, 336 + shift, 360 + shift, occupied)
    return table, companion, perf


@pytest.mark.parametrize("shift", (0, 17, 49))
def test_zero_aggregate_discovery_follows_shifted_header_fields(shift):
    table, companion, perf = _zero_aggregate_tables(shift)
    assert learning._learn_aggregate(table, perf, companion=companion) == (
        learning._AggregateOffsets(205 + shift, 24 + shift, 36 + shift))


@pytest.mark.parametrize("damage", ("identity", "history", "zero", "total", "no_excess", "few_shared", "ambiguous_identity"))
def test_zero_aggregate_requires_independent_header_and_counter_proof(damage):
    table, companion, perf = _zero_aggregate_tables()
    rows = list(table.rows)
    row = bytearray(rows[-1])
    if damage == "few_shared":
        companion = replace(companion, names=companion.names[:19], rows=companion.rows[:19])
    elif damage == "ambiguous_identity":
        copies = []
        for source in companion.rows:
            changed = bytearray(source)
            changed[20:28] = changed[40:48]
            copies.append(bytes(changed))
        companion = replace(companion, rows=tuple(copies))
    elif damage == "no_excess":
        row[205:209] = (95).to_bytes(4, "little")
        row[36:40] = (44).to_bytes(4, "little")
    elif damage == "total":
        row[205:209] = bytes(4)
    else:
        row[{"identity": 28, "history": 102, "zero": 24, "total": 205}[damage]] ^= 255
    rows[-1] = bytes(row)
    assert learning._learn_aggregate(replace(table, rows=tuple(rows)), perf,
                                     companion=companion) is None

@pytest.mark.parametrize("damage", (None, "counter", "rank", "class", "few_shared", "ambiguous_source"))
def test_unoriented_counter_geometry_requires_independent_exact_joins(damage):
    source, performance = _performance_rows(duplicate_counters=damage == "ambiguous_source")
    source = _table(source.rows * 2)
    occupied = performance.occupancies * 2
    target = _table(source.rows)
    if damage == "counter":
        row = bytearray(target.rows[0])
        row[performance.matches_offset] ^= 1
        target = replace(target, rows=(bytes(row),) + target.rows[1:])
    elif damage == "rank":
        target = replace(target, ranks=(999,) + target.ranks[1:])
    elif damage == "class":
        row = bytearray(target.rows[0]); row[_CLASS_OFFSET] = 30
        target = replace(target, rows=(bytes(row),) + target.rows[1:])
    elif damage == "few_shared":
        target = replace(target, names=tuple(n if i < 19 else "Other" + n for i, n in enumerate(target.names)))
    check = learning._counter_geometry_check(
        target, _CLASS_OFFSET, occupied, source, _CLASS_OFFSET, occupied,
    )
    if damage == "ambiguous_source":
        assert check is None
    else:
        assert check is not None
        outcomes = (performance.losses_offset, performance.draws_offset, performance.wins_offset)
        assert check(performance.matches_offset, outcomes) is (damage is None)


def test_counter_solver_applies_evidence_before_rejecting_multiple_alignments():
    records, performance = _performance_rows(duplicate_counters=True)
    calls = []
    def validate(matches, outcomes):
        calls.append((matches, outcomes))
        return matches == performance.matches_offset and set(outcomes) == {
            performance.wins_offset, performance.draws_offset, performance.losses_offset,
        }
    result = learning._balanced_counter_solution(
        records.rows, performance.occupancies, validate=validate,
    )
    assert result is not None and result[0] == performance.matches_offset
    assert len(calls) > 1
    assert learning._balanced_counter_solution(
        records.rows, performance.occupancies, validate=lambda *args: True,
    ) is None

@pytest.mark.parametrize("history", (b"1,0,1,1", b"1,1,1,1,1,1,1,1,1,1"))
def test_short_fallback_preserves_unrelated_recent_history_with_independent_counters(history):
    source, perf = _performance_rows()
    source = _table(source.rows * 2)
    occupied = perf.occupancies * 2
    companion = replace(source, rows=source.rows[:-1], names=source.names[:-1], ranks=source.ranks[:-1])
    known = replace(perf, occupancies=occupied[:-1])
    row = bytearray(source.rows[-1])
    for offset, value in ((_MATCHES_OFFSET, 2), (_WINS_OFFSET, 0), (_DRAWS_OFFSET, 0), (_LOSSES_OFFSET, 2)):
        row[offset:offset+4] = value.to_bytes(4, "little")
    row[_HISTORY_OFFSET:_HISTORY_OFFSET+101] = history + bytes(101-len(history))
    target = replace(source, rows=source.rows[:-1] + (bytes(row),))
    def infer(other):
        return learning._validate_performance_candidate(
            target, _CLASS_OFFSET, occupied, _SPEC_OFFSET, _MATCHES_OFFSET,
            (_WINS_OFFSET, _DRAWS_OFFSET, _LOSSES_OFFSET), companion=other,
        )
    # The full-board route keeps the old strict rule.
    assert infer((companion, known)) is None
    target.family.short_record_locations = ((None, 0),)
    assert infer(None) is None
    assert infer((companion, known)) is not None
    damaged = replace(companion, ranks=(999,) + companion.ranks[1:])
    assert infer((damaged, known)) is None
    malformed = bytearray(target.rows[-1])
    malformed[_HISTORY_OFFSET:_HISTORY_OFFSET+101] = b"2,2" + bytes(98)
    target = replace(target, rows=target.rows[:-1] + (bytes(malformed),))
    assert infer((companion, known)) is None
