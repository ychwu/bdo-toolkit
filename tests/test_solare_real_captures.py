"""Optional private-capture regressions for observed Solare generations."""

from __future__ import annotations

from pathlib import Path

import pytest

from bdo_toolkit.solare import SolareDetectionStatus, replay_solare


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("relative_path", "layout_id"),
    (
        (
            "docs/captures/fixtures/solare/"
            "leaderboard_full_stream_2026-06-24.pcapng",
            "solare-rich-2026-06-24-v1",
        ),
        (
            "tools/solare/captures/solare_discovery_retry_20260714_3.pcapng",
            "solare-rich-2026-07-14-v1",
        ),
        (
            "tools/solare/captures/solare_post_patch_20260717_1.pcapng",
            "solare-rich-2026-07-17-v1",
        ),
    ),
)
def test_complete_private_capture_generation(
    relative_path: str,
    layout_id: str,
) -> None:
    path = ROOT / relative_path
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")

    result = replay_solare(path)

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    snapshot = result.snapshot
    assert len(snapshot.players) == 620
    assert snapshot.capabilities == frozenset(
        {"rankings", "performance", "raw_extensions"}
    )
    assert len(snapshot.top_100) == 100
    assert len(result.evidence.class_group_counts) == 31
    assert set(dict(result.evidence.class_group_counts).values()) == {20}
    assert result.evidence.exact_cross_check == 100
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.detail_layout_id == layout_id

    first = snapshot.players[0]
    assert first.name
    assert isinstance(first.elo, int)
    assert first.elo > 0
    assert first.player_uid_raw is not None
    assert len(first.player_uid_raw) == 8
    assert first.classes_played
    performance = first.classes_played[0]
    assert performance.record_is_balanced
    assert performance.recent_results_raw
    assert performance.gear_loadout_raw is not None
    assert len(performance.gear_loadout_raw.data) == 0x7D1
    assert performance.skill_addons_raw is not None
    assert len(performance.skill_addons_raw.data) == 0x1F5

    without_raw = result.to_dict()
    player_json = without_raw["snapshot"]["players"][0]  # type: ignore[index]
    class_json = player_json["classes_played"][0]  # type: ignore[index]
    assert "gear_loadout_raw" not in class_json
    with_raw = result.to_dict(include_raw=True)
    raw_player = with_raw["snapshot"]["players"][0]  # type: ignore[index]
    raw_class = raw_player["classes_played"][0]  # type: ignore[index]
    assert raw_class["gear_loadout_raw"]["length"] == 0x7D1
    assert raw_class["skill_addons_raw"]["length"] == 0x1F5


@pytest.mark.parametrize(
    ("relative_path", "expected_status"),
    (
        (
            "tools/solare/captures/solare_discovery_retry_20260714.pcapng",
            SolareDetectionStatus.DETECTED_INCOMPLETE,
        ),
        (
            "tools/solare/captures/solare_discovery_test_menu_only.pcapng",
            SolareDetectionStatus.MENU_CONTEXT,
        ),
    ),
)
def test_private_incomplete_capture_never_exposes_snapshot(
    relative_path: str,
    expected_status: SolareDetectionStatus,
) -> None:
    path = ROOT / relative_path
    if not path.is_file():
        pytest.skip("private Solare capture is not installed")

    result = replay_solare(path)

    assert result.status is expected_status
    assert result.snapshot is None
