"""Real-capture regressions for ephemeral Solare detail-layout learning."""

from __future__ import annotations

import re
from contextlib import ExitStack
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

from fixture_paths import optional_fixture_path

import bdo_toolkit.solare._details as details_module
import bdo_toolkit.solare._detail_learning as learning_module
import bdo_toolkit.solare._result as result_module
from bdo_toolkit.solare import (
    SolareCaptureResult,
    SolareDetectionStatus,
    replay_solare,
)
from bdo_toolkit.solare._discovery import DiscoveredSolareFamily


# These are the complete real captures installed in the repository/workspace.
# All real captures are private and optional; synthetic coverage still runs
# when the catalog is absent from a public checkout.
_COMPLETE_CAPTURE_PATHS = (
    optional_fixture_path('solare--leaderboard-complete--1065cbd89c'),
    optional_fixture_path('solare--leaderboard-complete-retry--8bfa6979ab'),
    optional_fixture_path('solare--leaderboard-complete-live--2c033e6b01'),
    optional_fixture_path('solare--leaderboard-complete-post-patch--92d835cbe9'),
    optional_fixture_path('solare--leaderboard-complete-refresh--4a3672bd74'),
)

_SAME_GEOMETRY_CAPTURE_PAIRS = (
    (
        optional_fixture_path('solare--leaderboard-complete-retry--8bfa6979ab'),
        optional_fixture_path('solare--leaderboard-complete-live--2c033e6b01'),
    ),
    (
        optional_fixture_path('solare--leaderboard-complete-post-patch--92d835cbe9'),
        optional_fixture_path('solare--leaderboard-complete-refresh--4a3672bd74'),
    ),
)

_JULY_30_UNKNOWN_LAYOUT_CAPTURE = (
    optional_fixture_path('solare--leaderboard-complete-unregistered--dfeb623bda')
)

_KR_OCTOBER_21_CAPTURE = optional_fixture_path(
    'solare--leaderboard-complete-kr-post-patch--9731c37014')

_EU_RECENT_DRAW_CAPTURE = optional_fixture_path(
    'solare--leaderboard-eu-recent-draw--030a695def')

_LEARNED_CAPABILITIES = frozenset(
    {"rankings", "elo", "performance", "raw_extensions", "equipment"}
)
_LEARNED_OVERALL_CAPABILITIES = (
    _LEARNED_CAPABILITIES | {"aggregate_performance"}
)


@dataclass(frozen=True)
class _ReplayPair:
    registered: SolareCaptureResult
    learned: SolareCaptureResult


@pytest.mark.parametrize("capture_id,occupied_counts,first_outcomes", (
    ("solare--leaderboard-kr-eight-byte-gap--b7a6dab339", (798, 112), (179, 110, 0, 69)),
    ("solare--leaderboard-kr-eight-byte-gap--b0438d4f48", (805, 116), (190, 117, 0, 73)),
    ("solare--leaderboard-sea-eight-byte-gap--09e5978bd4", (895, 126), (102, 66, 0, 36)),
))
def test_short_unknown_fields_preserve_complete_real_capture_details(
    capture_id, occupied_counts, first_outcomes,
):
    path = optional_fixture_path(capture_id)
    if not path.is_file():
        pytest.skip("private short-gap Solare capture is not installed")
    result = replay_solare(path)
    assert result.complete and result.evidence.health.capture_is_clean
    assert result.evidence.exact_cross_check == 100
    snapshot = result.snapshot
    assert snapshot is not None
    assert len(snapshot.players) == 640 and len(snapshot.overall_top_100) == 100
    required = {"rankings", "elo", "performance", "equipment"}
    assert required <= snapshot.class_table_capabilities
    assert required <= snapshot.overall_capabilities
    assert tuple(sum(len(p.classes_played) for p in rows) for rows in (
        snapshot.players, snapshot.overall_top_100,
    )) == occupied_counts
    by_rank = {player.global_rank: player for player in snapshot.players}
    primary = by_rank[1].classes_played[0]
    assert (primary.matches, primary.wins, primary.draws, primary.losses) == first_outcomes
    for player in (*snapshot.players, *snapshot.overall_top_100):
        for slot in player.classes_played:
            assert slot.record_is_balanced and slot.draws == 0
            assert slot.equipment is not None and len(slot.equipment) == 14
    for overall in snapshot.overall_top_100:
        rich = by_rank[overall.global_rank]
        assert (overall.name, overall.elo) == (rich.name, rich.elo)
        assert overall.classes_played == rich.classes_played
    # Unknown groups remain optional; recovery never synthesizes aggregates.
    assert "aggregate_performance" not in snapshot.overall_capabilities


def test_eu_recent_draw_capture_recovers_all_details():
    if not _EU_RECENT_DRAW_CAPTURE.is_file():
        pytest.skip('private EU recent-draw capture is not installed')
    result = replay_solare(_EU_RECENT_DRAW_CAPTURE,retain_raw_extensions=True)
    assert result.complete and result.evidence.health.capture_is_clean
    assert result.evidence.exact_cross_check == 100
    snapshot = result.snapshot
    assert snapshot is not None and len(snapshot.players) == 640
    assert len(snapshot.overall_top_100) == 100
    assert _LEARNED_CAPABILITIES - {'raw_extensions'} <= snapshot.class_table_capabilities
    assert _LEARNED_OVERALL_CAPABILITIES - {'raw_extensions'} <= snapshot.overall_capabilities
    by_rank = {p.global_rank:p for p in snapshot.players}
    recent = by_rank[513].classes_played[0]
    assert by_rank[513].elo == 1424 and recent.player_class.code == 34
    assert (recent.matches,recent.wins,recent.draws,recent.losses) == (81,43,1,37)
    assert recent.recent_results_wire_text == '0,1,1,0,1,1,1,1,-1,0'
    assert recent.recent_results_raw[-2:] == (-1,0)
    older = by_rank[1034].classes_played[0]
    assert (older.matches,older.wins,older.draws,older.losses) == (241,108,1,132)
    assert -1 not in older.recent_results_raw
    for player in (*snapshot.players,*snapshot.overall_top_100):
        for slot in player.classes_played:
            assert slot.record_is_balanced and slot.equipment is not None
            assert len(slot.equipment) == 14
    for overall in snapshot.overall_top_100:
        rich = by_rank[overall.global_rank]
        for left,right in zip(overall.classes_played,rich.classes_played):
            assert (left.matches,left.wins,left.draws,left.losses,left.equipment) == (
                right.matches,right.wins,right.draws,right.losses,right.equipment)


def test_kr_capture_recovers_equivalent_zero_outcomes_and_direct_aggregates() -> None:
    if not _KR_OCTOBER_21_CAPTURE.is_file():
        pytest.skip("private October 21 KR capture is not installed")
    original = learning_module._learn_performance_offsets
    alternatives = []

    def observe(*args, **kwargs):
        learned = original(*args, **kwargs)
        if learned is not None and len(args[0].rows) == 100:
            alternatives.append(learned.zero_outcome_candidates)
        return learned

    with patch.object(learning_module, '_learn_performance_offsets', observe):
        result = replay_solare(_KR_OCTOBER_21_CAPTURE, retain_raw_extensions=True)
    assert result.complete and result.snapshot is not None
    assert result.evidence.health.capture_is_clean
    assert result.evidence.exact_cross_check == 100
    snapshot = result.snapshot
    assert len(snapshot.players) == 640 and len(snapshot.overall_top_100) == 100
    assert snapshot.class_table_capabilities == _LEARNED_CAPABILITIES
    assert snapshot.overall_capabilities == _LEARNED_OVERALL_CAPABILITIES
    assert (8068, 8069, 8070) in alternatives
    by_name = {p.name: p for p in snapshot.players}
    for overall in snapshot.overall_top_100:
        rich = by_name[overall.name]
        assert overall.global_rank == rich.global_rank and overall.elo == rich.elo
        assert len(overall.classes_played) == len(rich.classes_played)
        for a, b in zip(overall.classes_played, rich.classes_played):
            assert (a.player_class, a.matches, a.wins, a.draws, a.losses, a.equipment) == (
                b.player_class, b.matches, b.wins, b.draws, b.losses, b.equipment)
            assert a.record_is_balanced and a.draws == 0
            assert a.equipment is not None and len(a.equipment) == 14
    # The direct overall totals include activity beyond the three exposed slots.
    capped = snapshot.overall_top_100[47]
    assert capped.global_rank == 48 and len(capped.classes_played) == 3
    assert (capped.total_wins, capped.total_draws, capped.total_losses, capped.total_matches) == (26, 0, 4, 30)
    assert sum(p.matches for p in capped.classes_played) == 28


def test_july_30_unknown_layout_learns_complete_snapshot() -> None:
    """An installed unseen-geometry capture learns every supported detail."""

    path = _JULY_30_UNKNOWN_LAYOUT_CAPTURE
    if not path.is_file():
        pytest.skip("private July 30 Solare capture is not installed")

    result = replay_solare(path, retain_raw_extensions=True)

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    snapshot = result.snapshot
    assert len(snapshot.players) == 620
    assert len(snapshot.overall_top_100) == 100
    assert result.evidence.exact_cross_check == 100
    assert result.evidence.candidate_families == (
        (0x0D54, 15_904, 310),
        (0x11CF, 16_127, 50),
    )
    assert result.evidence.health.tcp_gap_resets == 0
    assert result.evidence.health.capture_is_clean
    assert snapshot.class_table_capabilities == _LEARNED_CAPABILITIES
    assert snapshot.overall_capabilities == _LEARNED_OVERALL_CAPABILITIES

    first = snapshot.overall_top_100[0]
    assert first.global_rank == 1
    assert first.name
    assert first.elo is not None and first.elo > 0
    assert first.total_wins is not None
    assert first.total_draws is not None
    assert first.total_losses is not None
    assert first.total_matches == (
        first.total_wins + first.total_draws + first.total_losses
    )
    assert first.total_matches > 0
    assert first.classes_played
    assert all(
        performance.record_is_balanced
        for performance in first.classes_played
    )
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.detail_layout_id is not None
    assert result.evidence.rich_layout.detail_layout_id.startswith(
        "solare-rich-ephemeral-v1-"
    )
    assert result.evidence.overall_layout is not None
    assert result.evidence.overall_layout.detail_layout_id is not None
    assert result.evidence.overall_layout.detail_layout_id.startswith(
        "solare-overall-ephemeral-v1-"
    )


def _unexpected_learner_call(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("the detail learner must not run on this replay")


def _elo_record_table(
    values: tuple[int, ...],
) -> learning_module._RecordTable:
    family = cast(
        DiscoveredSolareFamily,
        SimpleNamespace(frame_length=8, record_stride=4),
    )
    names = tuple(f"Player{ordinal}" for ordinal in range(len(values)))
    return learning_module._RecordTable(
        family=family,
        rows=tuple(value.to_bytes(4, "little") for value in values),
        names=names,
        ranks=tuple(range(1, len(values) + 1)),
    )


def test_elo_learning_requires_cross_table_value_agreement() -> None:
    rich = _elo_record_table(tuple(range(50_000, 49_900, -1)))
    overall = _elo_record_table(tuple(range(40_000, 39_900, -1)))

    assert learning_module._choose_elo_offsets(rich, overall) == (None, None)

    matching = _elo_record_table(tuple(range(50_000, 49_900, -1)))
    assert learning_module._choose_elo_offsets(rich, matching) == (0, 0)


@pytest.fixture(scope="module")
def profile_hidden_replays() -> dict[Path, _ReplayPair]:
    """Replay installed complete captures with and without registered layouts."""

    installed = tuple(path for path in _COMPLETE_CAPTURE_PATHS if path.is_file())
    if not installed:
        pytest.skip("no complete Solare captures are installed")

    # All listed geometries have registered profiles. Prove the ordinary fast
    # path does not pay for, or accidentally depend upon, the learner.
    registered: dict[Path, SolareCaptureResult] = {}
    with patch.object(
        result_module,
        "learn_unknown_solare_details",
        side_effect=_unexpected_learner_call,
    ) as learner:
        for path in installed:
            registered[path] = replay_solare(
                path,
                retain_raw_extensions=True,
            )
        assert learner.call_count == 0

    # Hide both lookups used by result construction and by the registered
    # decoders. This preserves structural discovery while forcing the exact
    # real packets through the unknown-geometry learner.
    learned: dict[Path, SolareCaptureResult] = {}
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(result_module, "_rich_layout_for", return_value=None)
        )
        stack.enter_context(
            patch.object(result_module, "_overall_layout_for", return_value=None)
        )
        stack.enter_context(
            patch.object(details_module, "_rich_layout_for", return_value=None)
        )
        stack.enter_context(
            patch.object(details_module, "_overall_layout_for", return_value=None)
        )
        for path in installed:
            learned[path] = replay_solare(
                path,
                retain_raw_extensions=True,
            )

    return {
        path: _ReplayPair(registered[path], learned[path])
        for path in installed
    }


@pytest.mark.parametrize(
    "path",
    (_COMPLETE_CAPTURE_PATHS[-1],),
    ids=lambda path: path.stem,
)
def test_profile_hidden_replay_matches_public_fields_and_raw_bytes(
    path: Path,
    profile_hidden_replays: dict[Path, _ReplayPair],
) -> None:
    if path not in profile_hidden_replays:
        pytest.skip("private Solare capture is not installed")

    registered_result = profile_hidden_replays[path].registered
    learned_result = profile_hidden_replays[path].learned
    assert registered_result.status is SolareDetectionStatus.COMPLETE
    assert learned_result.status is SolareDetectionStatus.COMPLETE
    assert registered_result.snapshot is not None
    assert learned_result.snapshot is not None
    registered = registered_result.snapshot
    learned = learned_result.snapshot

    assert registered.observed_at == learned.observed_at
    assert len(registered.players) == len(learned.players) == 620
    assert len(registered.overall_top_100) == len(learned.overall_top_100) == 100

    # Registered fast-path and unknown-layout learning are public-data
    # equivalent, including every opted-in opaque byte.
    assert tuple(
        item.to_dict(include_raw=True) for item in learned.players
    ) == tuple(
        item.to_dict(include_raw=True) for item in registered.players
    )
    assert tuple(
        item.to_dict(include_raw=True) for item in learned.overall_top_100
    ) == tuple(
        item.to_dict(include_raw=True) for item in registered.overall_top_100
    )
    assert learned.snapshot_id == registered.snapshot_id
    assert learned.class_table_capabilities == (
        registered.class_table_capabilities
    )
    assert learned.overall_capabilities == registered.overall_capabilities
    assert learned.class_table_capabilities == _LEARNED_CAPABILITIES
    assert learned.overall_capabilities == _LEARNED_OVERALL_CAPABILITIES
    assert learned.capabilities == _LEARNED_CAPABILITIES


def test_learned_layout_ids_are_geometry_stable_and_content_independent(
    profile_hidden_replays: dict[Path, _ReplayPair],
) -> None:
    compared = 0
    pattern_by_role = {
        "rich": re.compile(r"solare-rich-ephemeral-v1-[0-9a-f]{16}"),
        "overall": re.compile(r"solare-overall-ephemeral-v1-[0-9a-f]{16}"),
    }

    for first_path, second_path in _SAME_GEOMETRY_CAPTURE_PAIRS:
        if (
            first_path not in profile_hidden_replays
            or second_path not in profile_hidden_replays
        ):
            continue
        first = profile_hidden_replays[first_path]
        second = profile_hidden_replays[second_path]
        assert first.learned.snapshot is not None
        assert second.learned.snapshot is not None
        assert first.registered.snapshot is not None
        assert second.registered.snapshot is not None

        # These are independent leaderboard deliveries with differing content.
        assert (
            first.registered.snapshot.snapshot_id
            != second.registered.snapshot.snapshot_id
        )

        for role in ("rich", "overall"):
            first_layout = getattr(first.learned.evidence, f"{role}_layout")
            second_layout = getattr(second.learned.evidence, f"{role}_layout")
            first_registered_layout = getattr(
                first.registered.evidence,
                f"{role}_layout",
            )
            assert first_layout is not None
            assert second_layout is not None
            assert first_registered_layout is not None
            first_id = first_layout.detail_layout_id
            second_id = second_layout.detail_layout_id
            assert first_id is not None
            assert second_id is not None
            assert pattern_by_role[role].fullmatch(first_id)
            assert first_id == second_id
            assert first_id != first_registered_layout.detail_layout_id
        compared += 1

    if compared == 0:
        pytest.skip("no independent same-geometry capture pair is installed")


@pytest.mark.parametrize("unknown_role", ("rich", "overall"))
def test_mixed_registered_and_unknown_tables_keep_independent_details(
    unknown_role: str,
    profile_hidden_replays: dict[Path, _ReplayPair],
) -> None:
    path = optional_fixture_path('solare--leaderboard-complete-refresh--4a3672bd74')
    if path not in profile_hidden_replays:
        pytest.skip("the tracked complete Solare capture is not installed")
    registered_result = profile_hidden_replays[path].registered
    assert registered_result.snapshot is not None
    registered = registered_result.snapshot

    lookup_name = (
        "_rich_layout_for" if unknown_role == "rich" else "_overall_layout_for"
    )
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(result_module, lookup_name, return_value=None)
        )
        stack.enter_context(
            patch.object(details_module, lookup_name, return_value=None)
        )
        mixed_result = replay_solare(path, retain_raw_extensions=True)

    assert mixed_result.status is SolareDetectionStatus.COMPLETE
    assert mixed_result.snapshot is not None
    mixed = mixed_result.snapshot
    assert len(mixed.players) == 620
    assert len(mixed.overall_top_100) == 100

    if unknown_role == "rich":
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.players
        ) == tuple(
            item.to_dict(include_raw=True) for item in registered.players
        )
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.overall_top_100
        ) == tuple(
            item.to_dict(include_raw=True)
            for item in registered.overall_top_100
        )
        assert (
            mixed.class_table_capabilities
            == registered.class_table_capabilities
        )
        assert mixed.overall_capabilities == registered.overall_capabilities
    else:
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.players
        ) == tuple(
            item.to_dict(include_raw=True) for item in registered.players
        )
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.overall_top_100
        ) == tuple(
            item.to_dict(include_raw=True)
            for item in registered.overall_top_100
        )
        assert mixed.class_table_capabilities == (
            registered.class_table_capabilities
        )
        assert mixed.overall_capabilities == registered.overall_capabilities

    assert mixed.snapshot_id == registered.snapshot_id

    rich_by_name = {item.name: item for item in mixed.players}
    shared = tuple(
        item
        for item in mixed.overall_top_100
        if item.name in rich_by_name
    )
    assert len(shared) == 100
    assert all(
        item.elo == rich_by_name[item.name].elo
        for item in shared
    )


@pytest.mark.parametrize(
    "capture_id, recoverable",
    (
        ("solare--leaderboard-complete--1065cbd89c", {"rich", "overall"}),
        # Its separate five-byte gap cannot compete with the 12-byte draw
        # container. Removing draws must still recover the original layout.
        ("solare--leaderboard-complete-retry--8bfa6979ab", {"rich", "overall"}),
        ("solare--leaderboard-complete-post-patch--92d835cbe9", {"rich"}),
        ("solare--leaderboard-complete-unregistered--dfeb623bda", {"rich", "overall"}),
        ("solare--leaderboard-complete-live-clock-regression--45c54a0567", {"rich"}),
        ("solare--leaderboard-complete-post-patch-live-timeout-regression--341a4f1b87", set()),
    ),
)
def test_historical_zero_draw_counterfactual_recovers_only_proven_boundaries(
    capture_id: str, recoverable: set[str],
) -> None:
    path = optional_fixture_path(capture_id)
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")
    original = learning_module._learn_performance_offsets
    visited: set[str] = set()

    def inspect(records, class_offset, occupancies):
        proven = original(records, class_offset, occupancies)
        assert proven is not None
        rows = []
        for source in records.rows:
            row = bytearray(source)
            for slot in range(3):
                total = (
                    learning_module._u32le(row, proven.wins_offset + slot * 4)
                    + learning_module._u32le(row, proven.losses_offset + slot * 4)
                )
                start = proven.matches_offset + slot * 4
                row[start:start + 4] = total.to_bytes(4, "little")
            row[proven.draws_offset:proven.draws_offset + 12] = bytes(12)
            rows.append(bytes(row))
        changed = replace(records, rows=tuple(rows))
        learned = original(changed, class_offset, occupancies)
        role = records.family.role
        visited.add(role)
        assert learned == (proven if role in recoverable else None)
        return proven

    with (
        patch.object(details_module, "_RICH_DETAIL_LAYOUTS", ()),
        patch.object(details_module, "_OVERALL_DETAIL_LAYOUTS", ()),
        patch.object(learning_module, "_learn_performance_offsets", inspect),
    ):
        assert replay_solare(path).complete
    assert visited == {"rich", "overall"}


_NO_LOW_MATCH_CAPTURES = _COMPLETE_CAPTURE_PATHS + (
    _JULY_30_UNKNOWN_LAYOUT_CAPTURE,
    optional_fixture_path("solare--leaderboard-complete-live-clock-regression--45c54a0567"),
    optional_fixture_path("solare--leaderboard-complete-post-patch-live-timeout-regression--341a4f1b87"),
    optional_fixture_path("solare--leaderboard-agent--a0658f34ed"),
)


@pytest.mark.parametrize("path", _NO_LOW_MATCH_CAPTURES, ids=lambda path: path.stem)
def test_historical_rediscovery_without_low_match_history(path):
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")
    baseline = replay_solare(path)
    original = learning_module._history_outcome_candidates
    excluded = 0
    def experienced_only(rows, occupancies, matches_offset, *args, **kwargs):
        nonlocal excluded
        kept = [(row, n) for row, n in zip(rows, occupancies)
                if all(learning_module._u32le(row, matches_offset + slot * 4) > 5 for slot in range(n))]
        excluded += len(rows) - len(kept)
        return original(tuple(row for row, n in kept), tuple(n for row, n in kept), matches_offset, *args, **kwargs)
    with patch.object(details_module, "_RICH_DETAIL_LAYOUTS", ()), \
         patch.object(details_module, "_OVERALL_DETAIL_LAYOUTS", ()), \
         patch.object(learning_module, "_history_outcome_candidates", experienced_only):
        result = replay_solare(path)
    assert result.complete and result.evidence.health.capture_is_clean
    assert excluded > 0
    if ("aggregate_performance" in baseline.snapshot.overall_capabilities
            and not path.name.startswith("leaderboard-agent--")):
        assert "aggregate_performance" in result.snapshot.overall_capabilities
        assert any(p.total_draws for p in baseline.snapshot.overall_top_100)
        assert [(p.name, p.total_wins, p.total_draws, p.total_losses)
                for p in result.snapshot.overall_top_100] == [
                    (p.name, p.total_wins, p.total_draws, p.total_losses)
                    for p in baseline.snapshot.overall_top_100]
    for before, after, caps in (
        (baseline.snapshot.players, result.snapshot.players, result.snapshot.class_table_capabilities),
        (baseline.snapshot.overall_top_100, result.snapshot.overall_top_100, result.snapshot.overall_capabilities),
    ):
        # With observed draw-pair semantics, the season-start alternative that
        # treated recent losses as lifetime draws is now contradicted too.
        assert "performance" in caps
        reference = {p.name: p for p in before}
        for player in after:
            expected = reference[player.name]
            assert player.global_rank == expected.global_rank
            assert len(player.classes_played) == len(expected.classes_played)
            for a, b in zip(player.classes_played, expected.classes_played):
                assert (a.slot, a.player_class.code, a.matches, a.wins, a.draws, a.losses) == (b.slot, b.player_class.code, b.matches, b.wins, b.draws, b.losses)


def test_historical_aggregate_draw_field_rediscovered_when_zeroed():
    path = optional_fixture_path("solare--leaderboard-complete-post-patch--92d835cbe9")
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")
    captured = []
    extract = learning_module._extract_records
    def collect(*args, **kwargs):
        table = extract(*args, **kwargs)
        if table is not None:
            captured.append(table)
        return table
    with patch.object(details_module, "_RICH_DETAIL_LAYOUTS", ()), \
         patch.object(details_module, "_OVERALL_DETAIL_LAYOUTS", ()), \
         patch.object(learning_module, "_extract_records", collect):
        baseline = replay_solare(path)
    overall = next(t for t in captured if len(t.rows) == 100)
    rich = next(t for t in captured if len(t.rows) > 100)
    class_offset, occupied = learning_module._learn_overall_class_offset(overall)
    perf = learning_module._learn_performance_offsets(overall, class_offset, occupied)
    known = learning_module._learn_aggregate(overall, perf)
    assert known is not None
    assert any(p.total_draws for p in baseline.snapshot.overall_top_100)
    rows = []
    for source in overall.rows:
        row = bytearray(source)
        # Counterfactual only: turn draws into losses, preserving match totals.
        for draw, loss in [(known.draws_offset, known.losses_offset)] + [
            (perf.draws_offset + slot * 4, perf.losses_offset + slot * 4)
            for slot in range(3)
        ]:
            total = learning_module._u32le(row, draw) + learning_module._u32le(row, loss)
            row[loss:loss + 4] = total.to_bytes(4, "little")
            row[draw:draw + 4] = bytes(4)
        rows.append(bytes(row))
    changed = replace(overall, rows=tuple(rows))
    assert learning_module._learn_aggregate(changed, perf, companion=rich) == known
