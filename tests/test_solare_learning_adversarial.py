"""Adversarial fail-closed tests for ephemeral Solare detail learning.

These tests deliberately construct wire-like record tables with either two
equally valid interpretations or one corrupted invariant.  Optional detail
groups must be withheld in both cases while unrelated, independently valid
groups remain publishable.
"""

from __future__ import annotations

from types import SimpleNamespace
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
    duplicate_aggregate_offsets = (136, 140, 144)

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
    gear_text = _csv(tuple(10 + index % 90 for index in range(126)))
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
