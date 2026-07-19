"""Optional private-capture regressions for observed Solare generations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

from bdo_toolkit.solare import (
    SolareDetectionStatus,
    SolareFamilyLayout,
    replay_solare,
)


ROOT = Path(__file__).resolve().parents[1]
_GEAR_SIZE = 0x7D1
_ADDON_SIZE = 0x1F5
_CLASS_CODES = (
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    15,
    16,
    17,
    19,
    20,
    21,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
)


@dataclass(frozen=True)
class _CompleteCapture:
    relative_path: str
    scanned_messages: int
    candidate_families: tuple[tuple[int, int, int], ...]
    rich_layout: SolareFamilyLayout
    overall_layout: SolareFamilyLayout
    gear_offset: int
    addon_offset: int
    max_rank: int
    class_slot_counts: tuple[tuple[int, int], ...]


_COMPLETE_CAPTURES = (
    _CompleteCapture(
        relative_path=(
            "docs/captures/fixtures/solare/"
            "leaderboard_full_stream_2026-06-24.pcapng"
        ),
        scanned_messages=361,
        candidate_families=(
            (0x0BE2, 15900, 310),
            (0x1C69, 16148, 50),
        ),
        rich_layout=SolareFamilyLayout(
            role="rich",
            opcode=0x0BE2,
            message_length=15900,
            message_count=310,
            record_stride=0x1F08,
            name_offset=0x14,
            rank_offset=0x52,
            class_offset=0x58,
            detail_layout_id="solare-rich-2026-06-24-v1",
        ),
        overall_layout=SolareFamilyLayout(
            role="overall",
            opcode=0x1C69,
            message_length=16148,
            message_count=50,
            record_stride=0x1F80,
            name_offset=0x17,
            rank_offset=0xCA,
        ),
        gear_offset=0x019D,
        addon_offset=0x191C,
        max_rank=5494,
        class_slot_counts=((1, 391), (2, 123), (3, 106)),
    ),
    _CompleteCapture(
        relative_path=(
            "tools/solare/captures/"
            "solare_discovery_retry_20260714_3.pcapng"
        ),
        scanned_messages=385,
        candidate_families=(
            (0x0CAA, 15930, 310),
            (0x1A30, 16145, 50),
            (0x19CB, 13921, 24),
        ),
        rich_layout=SolareFamilyLayout(
            role="rich",
            opcode=0x0CAA,
            message_length=15930,
            message_count=310,
            record_stride=0x1F15,
            name_offset=0x19,
            rank_offset=0x10,
            class_offset=0x62,
            detail_layout_id="solare-rich-2026-07-14-v1",
        ),
        overall_layout=SolareFamilyLayout(
            role="overall",
            opcode=0x1A30,
            message_length=16145,
            message_count=50,
            record_stride=0x1F80,
            name_offset=0x98,
            rank_offset=0x81,
        ),
        gear_offset=0x0078,
        addon_offset=0x1929,
        max_rank=5548,
        class_slot_counts=((1, 348), (2, 141), (3, 131)),
    ),
    _CompleteCapture(
        relative_path=(
            "tools/solare/captures/solare_live_20260714_145323.pcapng"
        ),
        scanned_messages=384,
        candidate_families=(
            (0x0CAA, 15930, 310),
            (0x1A30, 16145, 50),
            (0x19CB, 13921, 24),
        ),
        rich_layout=SolareFamilyLayout(
            role="rich",
            opcode=0x0CAA,
            message_length=15930,
            message_count=310,
            record_stride=0x1F15,
            name_offset=0x19,
            rank_offset=0x10,
            class_offset=0x62,
            detail_layout_id="solare-rich-2026-07-14-v1",
        ),
        overall_layout=SolareFamilyLayout(
            role="overall",
            opcode=0x1A30,
            message_length=16145,
            message_count=50,
            record_stride=0x1F80,
            name_offset=0x98,
            rank_offset=0x81,
        ),
        gear_offset=0x0078,
        addon_offset=0x1929,
        max_rank=4973,
        class_slot_counts=((1, 348), (2, 140), (3, 132)),
    ),
    _CompleteCapture(
        relative_path=(
            "tools/solare/captures/solare_post_patch_20260717_1.pcapng"
        ),
        scanned_messages=384,
        candidate_families=(
            (0x0CB0, 15914, 310),
            (0x0CBB, 16143, 50),
            (0x19FD, 13916, 24),
        ),
        rich_layout=SolareFamilyLayout(
            role="rich",
            opcode=0x0CB0,
            message_length=15914,
            message_count=310,
            record_stride=0x1F0F,
            name_offset=0x1F,
            rank_offset=0x0C,
            class_offset=0x5D,
            detail_layout_id="solare-rich-2026-07-17-v1",
        ),
        overall_layout=SolareFamilyLayout(
            role="overall",
            opcode=0x0CBB,
            message_length=16143,
            message_count=50,
            record_stride=0x1F7F,
            name_offset=0x8A,
            rank_offset=0x7E,
        ),
        gear_offset=0x077D,
        addon_offset=0x0060,
        max_rank=5558,
        class_slot_counts=((1, 342), (2, 142), (3, 136)),
    ),
)


@pytest.mark.parametrize(
    "case",
    _COMPLETE_CAPTURES,
    ids=lambda case: Path(case.relative_path).stem,
)
def test_complete_private_capture_generation(case: _CompleteCapture) -> None:
    path = ROOT / case.relative_path
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")

    result = replay_solare(path, retain_raw_extensions=True)

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.complete
    assert result.snapshot is not None
    snapshot = result.snapshot

    # These aggregate assertions preserve the historical public contract while
    # keeping player identities and their field values out of test source and
    # failure output.
    assert len(snapshot.players) == 620
    assert len({player.name for player in snapshot.players}) == 620
    assert len({player.global_rank for player in snapshot.players}) == 620
    assert [player.global_rank for player in snapshot.players] == sorted(
        player.global_rank for player in snapshot.players
    )
    assert snapshot.players[0].global_rank == 1
    assert snapshot.players[-1].global_rank == case.max_rank
    assert snapshot.capabilities == frozenset(
        {"rankings", "performance", "raw_extensions"}
    )
    assert snapshot.schema_version == 1

    assert len(snapshot.overall_top_100) == 100
    assert [entry.global_rank for entry in snapshot.overall_top_100] == list(
        range(1, 101)
    )
    assert len(snapshot.top_100) == 100
    assert [player.global_rank for player in snapshot.top_100] == list(
        range(1, 101)
    )
    rich_by_rank = {player.global_rank: player for player in snapshot.players}
    assert sum(
        rich_by_rank.get(entry.global_rank) is not None
        and rich_by_rank[entry.global_rank].name == entry.name
        for entry in snapshot.overall_top_100
    ) == 100

    assert result.evidence.scanned_messages == case.scanned_messages
    assert result.evidence.candidate_families == case.candidate_families
    assert result.evidence.ranked_players == 620
    assert result.evidence.overall_players == 100
    assert result.evidence.exact_cross_check == 100
    assert len(result.evidence.class_group_counts) == 31
    assert tuple(
        code for code, _count in result.evidence.class_group_counts
    ) == _CLASS_CODES
    assert set(dict(result.evidence.class_group_counts).values()) == {20}
    assert result.evidence.rich_layout == case.rich_layout
    assert result.evidence.overall_layout == case.overall_layout
    assert result.evidence.health.capture_is_clean
    assert result.evidence.health.tcp_gap_resets == 0
    assert (
        result.evidence.health.retained_large_messages
        == case.scanned_messages
    )

    assert all(
        player.elo is not None and player.elo > 0
        for player in snapshot.players
    )
    assert all(
        player.player_uid_raw is not None
        and len(player.player_uid_raw) == 8
        for player in snapshot.players
    )
    assert all(
        1 <= len(player.classes_played) <= 3
        for player in snapshot.players
    )
    assert tuple(
        sorted(
            Counter(
                len(player.classes_played) for player in snapshot.players
            ).items()
        )
    ) == case.class_slot_counts
    assert tuple(
        sorted(
            Counter(
                player.primary_class.code for player in snapshot.players
            ).items()
        )
    ) == result.evidence.class_group_counts
    performances = tuple(
        performance
        for player in snapshot.players
        for performance in player.classes_played
    )
    assert {performance.slot for performance in performances} == {0, 1, 2}
    assert all(
        performance.primary is (performance.slot == 0)
        for performance in performances
    )
    assert all(
        performance.record_is_balanced is True
        for performance in performances
    )
    assert len(performances) == sum(
        slots * players for slots, players in case.class_slot_counts
    )
    assert all(
        performance.specialization is not None
        for performance in performances
    )
    assert all(performance.recent_results_raw for performance in performances)
    assert all(
        performance.recent_results_wire_text is not None
        for performance in performances
    )
    assert all(
        performance.gear_loadout_raw is not None
        and performance.gear_loadout_raw.offset
        == case.gear_offset + performance.slot * _GEAR_SIZE
        and performance.gear_loadout_raw.length == _GEAR_SIZE
        for performance in performances
    )
    assert all(
        performance.skill_addons_raw is not None
        and performance.skill_addons_raw.offset
        == case.addon_offset + performance.slot * _ADDON_SIZE
        and performance.skill_addons_raw.length == _ADDON_SIZE
        for performance in performances
    )

    without_raw = result.to_dict()
    snapshot_json = without_raw["snapshot"]  # type: ignore[index]
    assert snapshot_json["record_count"] == 620  # type: ignore[index]
    assert snapshot_json["overall_record_count"] == 100  # type: ignore[index]
    player_json = snapshot_json["players"][0]  # type: ignore[index]
    class_json = player_json["classes_played"][0]  # type: ignore[index]
    assert "gear_loadout_raw" not in class_json
    assert "skill_addons_raw" not in class_json

    with_raw = result.to_dict(include_raw=True)
    raw_player = with_raw["snapshot"]["players"][0]  # type: ignore[index]
    raw_class = raw_player["classes_played"][0]  # type: ignore[index]
    assert raw_class["gear_loadout_raw"]["length"] == _GEAR_SIZE
    assert raw_class["skill_addons_raw"]["length"] == _ADDON_SIZE


@pytest.mark.parametrize(
    "case",
    _COMPLETE_CAPTURES[:2],
    ids=lambda case: f"raw-retention-{Path(case.relative_path).stem}",
)
def test_raw_retention_is_opt_in_without_changing_snapshot_semantics(
    case: _CompleteCapture,
) -> None:
    path = ROOT / case.relative_path
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")

    default_result = replay_solare(path)
    raw_result = replay_solare(path, retain_raw_extensions=True)
    assert default_result.snapshot is not None
    assert raw_result.snapshot is not None
    default = default_result.snapshot
    retained = raw_result.snapshot

    assert default.snapshot_id == retained.snapshot_id
    assert default.overall_top_100 == retained.overall_top_100
    assert default.capabilities == frozenset({"rankings", "performance"})
    assert retained.capabilities == frozenset(
        {"rankings", "performance", "raw_extensions"}
    )

    def semantic_rows(snapshot: object) -> tuple[object, ...]:
        players = snapshot.players  # type: ignore[attr-defined]
        return tuple(
            (
                player.name,
                player.global_rank,
                player.player_uid_raw,
                player.elo,
                tuple(
                    (
                        performance.slot,
                        performance.primary,
                        performance.player_class,
                        performance.specialization,
                        performance.matches,
                        performance.wins,
                        performance.draws,
                        performance.losses,
                        performance.recent_results_raw,
                        performance.recent_results_wire_text,
                    )
                    for performance in player.classes_played
                ),
            )
            for player in players
        )

    assert semantic_rows(default) == semantic_rows(retained)

    default_performances = tuple(
        performance
        for player in default.players
        for performance in player.classes_played
    )
    retained_performances = tuple(
        performance
        for player in retained.players
        for performance in player.classes_played
    )
    assert all(
        performance.gear_loadout_raw is None
        and performance.skill_addons_raw is None
        for performance in default_performances
    )
    assert all(
        performance.gear_loadout_raw is not None
        and performance.gear_loadout_raw.length == _GEAR_SIZE
        and performance.skill_addons_raw is not None
        and performance.skill_addons_raw.length == _ADDON_SIZE
        for performance in retained_performances
    )


@dataclass(frozen=True)
class _NonCompleteCapture:
    relative_path: str
    status: SolareDetectionStatus
    scanned_messages: int
    candidate_families: tuple[tuple[int, int, int], ...]
    ranked_players: int = 0
    overall_players: int = 0
    exact_cross_check: int = 0
    tcp_gap_resets: int = 0
    overall_layout: SolareFamilyLayout | None = None


_NON_COMPLETE_CAPTURES = (
    _NonCompleteCapture(
        relative_path=(
            "docs/captures/fixtures/solare/"
            "leaderboard_truncated_single_packet_2026-06-24.pcapng"
        ),
        status=SolareDetectionStatus.INCONCLUSIVE,
        scanned_messages=0,
        candidate_families=(),
    ),
    _NonCompleteCapture(
        relative_path=(
            "tools/solare/captures/solare_discovery_retry_20260714.pcapng"
        ),
        status=SolareDetectionStatus.DETECTED_INCOMPLETE,
        scanned_messages=300,
        candidate_families=(
            (0x0CAA, 15930, 266),
            (0x19CB, 13921, 24),
            (0x1A30, 16145, 10),
        ),
        ranked_players=532,
        overall_players=20,
        exact_cross_check=20,
        tcp_gap_resets=8,
        overall_layout=SolareFamilyLayout(
            role="overall-partial",
            opcode=0x1A30,
            message_length=16145,
            message_count=10,
            record_stride=0x1F80,
            name_offset=0x98,
            rank_offset=0x81,
        ),
    ),
    _NonCompleteCapture(
        relative_path=(
            "tools/solare/captures/solare_discovery_retry_20260714_2.pcapng"
        ),
        status=SolareDetectionStatus.MENU_CONTEXT,
        scanned_messages=24,
        candidate_families=((0x19CB, 13921, 24),),
    ),
    _NonCompleteCapture(
        relative_path=(
            "tools/solare/captures/solare_discovery_test_menu_only.pcapng"
        ),
        status=SolareDetectionStatus.MENU_CONTEXT,
        scanned_messages=24,
        candidate_families=((0x19CB, 13921, 24),),
    ),
    _NonCompleteCapture(
        relative_path=(
            "tools/solare/captures/solare_live_probe_20260714_121723.pcapng"
        ),
        status=SolareDetectionStatus.INCONCLUSIVE,
        scanned_messages=0,
        candidate_families=(),
    ),
)


@pytest.mark.parametrize(
    "case",
    _NON_COMPLETE_CAPTURES,
    ids=lambda case: Path(case.relative_path).stem,
)
def test_private_non_complete_capture_never_exposes_snapshot(
    case: _NonCompleteCapture,
) -> None:
    path = ROOT / case.relative_path
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")

    result = replay_solare(path)

    assert result.status is case.status
    assert not result.complete
    assert result.snapshot is None
    assert result.evidence.scanned_messages == case.scanned_messages
    assert result.evidence.candidate_families == case.candidate_families
    assert result.evidence.ranked_players == case.ranked_players
    assert result.evidence.overall_players == case.overall_players
    assert result.evidence.exact_cross_check == case.exact_cross_check
    assert result.evidence.class_group_counts == ()
    assert result.evidence.rich_layout is None
    assert result.evidence.overall_layout == case.overall_layout
    assert result.evidence.health.payload_segments > 0
    assert result.evidence.health.payload_bytes > 0
    assert (
        result.evidence.health.retained_large_messages
        == case.scanned_messages
    )
    assert result.evidence.health.tcp_gap_resets == case.tcp_gap_resets
    assert result.evidence.health.capture_is_clean is (
        case.tcp_gap_resets == 0
    )
