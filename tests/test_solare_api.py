"""Public model and namespace contract for the Solare domain."""

from __future__ import annotations

import json
from dataclasses import replace

import bdo_toolkit
import pytest
from bdo_toolkit.solare import (
    AsyncLiveSolareSession,
    LiveSolareSession,
    SolareCaptureEndpoint,
    SolareCaptureResult,
    SolareClass,
    SolareClassPerformance,
    SolareDetectionStatus,
    SolareEvidence,
    SolareLeaderboardSnapshot,
    SolareOverallEntry,
    SolarePlayer,
    SolareRawSection,
    capture_solare_snapshot,
    replay_solare,
)
from bdo_toolkit.solare.models import solare_snapshot_id


def test_solare_is_a_curated_package_namespace() -> None:
    assert bdo_toolkit.solare.replay_solare is replay_solare
    assert bdo_toolkit.solare.capture_solare_snapshot is capture_solare_snapshot
    assert bdo_toolkit.solare.LiveSolareSession is LiveSolareSession
    assert bdo_toolkit.solare.AsyncLiveSolareSession is AsyncLiveSolareSession
    assert bdo_toolkit.solare.SolareCaptureEndpoint is SolareCaptureEndpoint
    assert bdo_toolkit.solare.SolareOverallEntry is SolareOverallEntry
    assert not any(name.startswith("_") for name in bdo_toolkit.solare.__all__)


def test_capture_endpoint_is_a_public_serializable_value() -> None:
    endpoint = SolareCaptureEndpoint(
        interface="capture-adapter",
        local_ip="192.0.2.50",
        bpf_filter="tcp",
    )

    assert endpoint.to_dict() == {
        "interface": "capture-adapter",
        "local_ip": "192.0.2.50",
        "bpf_filter": "tcp",
    }


def test_opaque_extensions_are_literal_bytes_and_json_is_opt_in() -> None:
    performance = SolareClassPerformance(
        slot=0,
        primary=True,
        player_class=SolareClass(11, "Lahn"),
        matches=10,
        wins=6,
        draws=1,
        losses=3,
        recent_results_raw=(1, 0, 1),
        recent_results_wire_text="1,0,1",
        gear_loadout_raw=SolareRawSection(offset=0x78, data=b"\x01\x02"),
        skill_addons_raw=SolareRawSection(offset=0x1929, data=b"\xaa\xbb"),
    )
    player = SolarePlayer(
        name="Example",
        global_rank=1,
        primary_class=performance.player_class,
        elo=1234,
        classes_played=(performance,),
    )

    assert performance.record_is_balanced
    assert performance.win_rate == 60.0
    assert performance.gear_loadout_raw is not None
    assert performance.gear_loadout_raw.data == b"\x01\x02"
    assert performance.skill_addons_raw is not None
    assert performance.skill_addons_raw.data == b"\xaa\xbb"

    normal = player.to_dict()
    assert normal["classes_played"][0]["recent_results_raw"] == [1, 0, 1]
    assert "gear_loadout_raw" not in normal["classes_played"][0]

    raw = player.to_dict(include_raw=True)
    gear = raw["classes_played"][0]["gear_loadout_raw"]
    assert gear == {
        "offset": 0x78,
        "length": 2,
        "encoding": "hex",
        "data": "0102",
    }
    json.dumps(raw)


def test_overall_entry_keeps_independent_details_and_raw_extensions() -> None:
    player_class = SolareClass(11, "Lahn")
    performance = SolareClassPerformance(
        slot=0,
        primary=True,
        player_class=player_class,
        matches=10,
        wins=6,
        draws=1,
        losses=3,
        recent_results_raw=(1, 0, 1),
        recent_results_wire_text="1,0,1",
        gear_loadout_raw=SolareRawSection(offset=0x80F, data=b"\x11\x22"),
        skill_addons_raw=SolareRawSection(offset=0x218, data=b"\x33\x44"),
    )
    entry = SolareOverallEntry(
        name="OverallExample",
        global_rank=7,
        elo=2345,
        classes_played=(performance,),
    )

    assert entry.primary_class == player_class
    assert entry.to_dict() == {
        "name": "OverallExample",
        "global_rank": 7,
        "classes_played": [
            {
                "slot": 0,
                "primary": True,
                "class": {"code": 11, "name": "Lahn"},
                "matches": 10,
                "wins": 6,
                "draws": 1,
                "losses": 3,
                "win_rate": 60.0,
                "recent_results_raw": [1, 0, 1],
                "recent_results_wire_text": "1,0,1",
            }
        ],
        "primary_class": {"code": 11, "name": "Lahn"},
        "elo": 2345,
    }
    raw = entry.to_dict(include_raw=True)
    assert raw["classes_played"][0]["gear_loadout_raw"] == {
        "offset": 0x80F,
        "length": 2,
        "encoding": "hex",
        "data": "1122",
    }
    assert raw["classes_played"][0]["skill_addons_raw"] == {
        "offset": 0x218,
        "length": 2,
        "encoding": "hex",
        "data": "3344",
    }
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id="sha256:overall-raw",
        observed_at=1.0,
        players=(),
        evidence=SolareEvidence(),
        overall_top_100=(entry,),
    )
    assert (
        "gear_loadout_raw"
        not in snapshot.to_dict()["overall_top_100"][0]["classes_played"][0]
    )
    assert (
        snapshot.to_dict(include_raw=True)["overall_top_100"][0]["classes_played"][0][
            "gear_loadout_raw"
        ]["data"]
        == "1122"
    )
    assert SolareOverallEntry("NoDetails", 8).to_dict() == {
        "name": "NoDetails",
        "global_rank": 8,
        "classes_played": [],
    }


def test_overall_aggregate_totals_are_derived_and_keyword_only() -> None:
    entry = SolareOverallEntry(
        "AggregateExample",
        9,
        total_wins=7,
        total_draws=1,
        total_losses=2,
    )

    assert entry.total_matches == 10
    assert entry.total_win_rate == 70.0
    assert entry.to_dict() == {
        "name": "AggregateExample",
        "global_rank": 9,
        "classes_played": [],
        "total_matches": 10,
        "total_wins": 7,
        "total_draws": 1,
        "total_losses": 2,
        "total_win_rate": 70.0,
    }

    unavailable = SolareOverallEntry("Unavailable", 10, total_wins=7)
    assert unavailable.total_matches is None
    assert unavailable.total_win_rate is None
    assert not any(key.startswith("total_") for key in unavailable.to_dict())

    with pytest.raises(TypeError):
        SolareOverallEntry("Positional", 11, 7)  # type: ignore[misc]


def test_optional_player_details_are_keyword_only() -> None:
    player_class = SolareClass(11, "Lahn")

    with pytest.raises(TypeError):
        SolarePlayer(  # type: ignore[misc,arg-type]
            "FormerIdentityPosition",
            1,
            player_class,
            b"eightbyt",
        )
    with pytest.raises(TypeError):
        SolareOverallEntry(  # type: ignore[misc,arg-type]
            "FormerIdentityPosition",
            1,
            b"eightbyt",
        )


def test_snapshot_separates_authoritative_overall_rows_from_rich_details() -> None:
    player_class = SolareClass(11, "Lahn")
    rich_players = (
        SolarePlayer("OutsideTop100", 101, player_class),
        SolarePlayer("RichRank4", 4, player_class),
        SolarePlayer("RichRank1", 1, player_class),
        SolarePlayer("RichRank2", 2, player_class),
    )
    evidence = SolareEvidence()

    overall = (
        SolareOverallEntry("RichRank1", 1),
        SolareOverallEntry("RichRank2", 2),
        SolareOverallEntry("OverallOnly", 3, elo=2111),
        SolareOverallEntry("RichRank4", 4),
    )
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id="sha256:example",
        observed_at=1.0,
        players=rich_players,
        evidence=evidence,
        overall_top_100=overall,
        class_table_capabilities=frozenset({"rankings", "elo", "performance"}),
        overall_capabilities=frozenset({"rankings", "elo"}),
    )

    assert [player.global_rank for player in snapshot.top_100] == [1, 2, 4]
    assert snapshot.overall_top_100 == overall
    assert snapshot.get_player("OverallOnly") is None
    overall_only = snapshot.get_overall_entry("OverallOnly")
    assert overall_only == overall[2]
    assert overall_only is not None
    assert overall_only.elo == 2111
    assert snapshot.get_overall_entry("overallonly") is None
    assert snapshot.capabilities == frozenset({"rankings", "elo"})
    assert [player.global_rank for player in snapshot.class_leaderboard(11)] == [
        1,
        2,
        4,
        101,
    ]

    payload = snapshot.to_dict()
    assert snapshot.schema_version == 2
    assert payload["schema_version"] == 2
    assert payload["capabilities"] == ["elo", "rankings"]
    assert payload["class_table_capabilities"] == [
        "elo",
        "performance",
        "rankings",
    ]
    assert payload["overall_capabilities"] == ["elo", "rankings"]
    assert payload["record_count"] == 4
    assert payload["overall_record_count"] == 4
    assert payload["overall_top_100"] == [entry.to_dict() for entry in overall]
    json.dumps(payload)


def test_solare_schema_version_is_library_owned() -> None:
    evidence = SolareEvidence()
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id="sha256:versioned",
        observed_at=1.0,
        players=(),
        evidence=evidence,
    )
    result = SolareCaptureResult(
        status=SolareDetectionStatus.COMPLETE,
        evidence=evidence,
        snapshot=snapshot,
    )

    assert snapshot.schema_version == 2
    assert result.schema_version == 2
    assert snapshot.to_dict()["schema_version"] == 2
    assert result.to_dict()["schema_version"] == 2

    with pytest.raises(TypeError, match="schema_version"):
        SolareLeaderboardSnapshot(
            snapshot_id="sha256:caller-version",
            observed_at=1.0,
            players=(),
            evidence=evidence,
            schema_version=2,
        )
    with pytest.raises(TypeError, match="schema_version"):
        SolareCaptureResult(
            status=SolareDetectionStatus.INCONCLUSIVE,
            evidence=evidence,
            schema_version=2,
        )
    with pytest.raises(TypeError):
        SolareLeaderboardSnapshot(
            "sha256:positional-capabilities",
            1.0,
            (),
            evidence,
            frozenset({"rankings"}),
        )


def test_snapshot_id_preserves_exact_overlap_and_identifies_divergence() -> None:
    player_class = SolareClass(11, "Lahn")
    players = (
        SolarePlayer("RankOne", 1, player_class),
        SolarePlayer("RankTwo", 2, player_class),
    )
    exact = (
        SolareOverallEntry("RankOne", 1),
        SolareOverallEntry("RankTwo", 2),
    )
    divergent = (
        SolareOverallEntry("RankOne", 1),
        SolareOverallEntry("OverallOnly", 2),
    )

    legacy_id = solare_snapshot_id(players)
    assert solare_snapshot_id(players, overall_top_100=exact) == legacy_id

    divergent_id = solare_snapshot_id(
        players,
        overall_top_100=divergent,
    )
    assert divergent_id != legacy_id
    assert divergent_id == solare_snapshot_id(
        players,
        overall_top_100=(
            SolareOverallEntry("RankOne", 1),
            SolareOverallEntry("OverallOnly", 2),
        ),
    )


def test_snapshot_id_preserves_only_semantically_equal_overall_details() -> None:
    player_class = SolareClass(11, "Lahn")
    class_performance = SolareClassPerformance(
        slot=0,
        primary=True,
        player_class=player_class,
        matches=10,
        wins=6,
        draws=1,
        losses=3,
        recent_results_raw=(1, 0, 1),
        recent_results_wire_text="1,0,1",
        gear_loadout_raw=SolareRawSection(offset=0x78, data=b"class raw"),
    )
    player = SolarePlayer(
        "RankOne",
        1,
        player_class,
        elo=2100,
        classes_played=(class_performance,),
    )
    legacy_id = solare_snapshot_id((player,))
    equal_overall = SolareOverallEntry(
        "RankOne",
        1,
        elo=2100,
        classes_played=(
            SolareClassPerformance(
                slot=0,
                primary=True,
                player_class=player_class,
                matches=10,
                wins=6,
                draws=1,
                losses=3,
                recent_results_raw=(1, 0, 1),
                recent_results_wire_text="1,0,1",
                gear_loadout_raw=SolareRawSection(
                    offset=0x80F,
                    data=b"different overall raw",
                ),
            ),
        ),
    )

    assert solare_snapshot_id((player,), overall_top_100=(equal_overall,)) == legacy_id

    equal_aggregate = replace(
        equal_overall,
        total_wins=6,
        total_draws=1,
        total_losses=3,
    )
    assert (
        solare_snapshot_id((player,), overall_top_100=(equal_aggregate,))
        == legacy_id
    )

    different_elo = SolareOverallEntry(
        "RankOne",
        1,
        elo=2099,
        classes_played=equal_overall.classes_played,
    )
    assert solare_snapshot_id((player,), overall_top_100=(different_elo,)) != legacy_id

    different_record = SolareOverallEntry(
        "RankOne",
        1,
        elo=2100,
        classes_played=(
            SolareClassPerformance(
                slot=0,
                primary=True,
                player_class=player_class,
                matches=11,
                wins=7,
                draws=1,
                losses=3,
                recent_results_raw=(1, 0, 1),
                recent_results_wire_text="1,0,1",
            ),
        ),
    )
    assert (
        solare_snapshot_id((player,), overall_top_100=(different_record,)) != legacy_id
    )

    different_aggregate = replace(
        equal_aggregate,
        total_wins=5,
        total_draws=1,
        total_losses=4,
    )
    another_aggregate = replace(
        equal_aggregate,
        total_wins=5,
        total_draws=2,
        total_losses=3,
    )
    different_aggregate_id = solare_snapshot_id(
        (player,),
        overall_top_100=(different_aggregate,),
    )
    another_aggregate_id = solare_snapshot_id(
        (player,),
        overall_top_100=(another_aggregate,),
    )
    assert different_aggregate_id != legacy_id
    assert another_aggregate_id != legacy_id
    assert different_aggregate_id != another_aggregate_id
