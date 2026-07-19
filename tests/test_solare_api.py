"""Public model and namespace contract for the Solare domain."""

from __future__ import annotations

import json

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
        player_uid_raw=bytes.fromhex("0102030405060708"),
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
    assert normal["player_uid_raw"] == "0x0807060504030201"
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


def test_overall_entry_keeps_its_uid_source_explicit() -> None:
    entry = SolareOverallEntry(
        name="OverallExample",
        global_rank=7,
        overall_uid_raw=bytes.fromhex("0102030405060708"),
    )

    assert entry.overall_uid_bytes_le == "0102030405060708"
    assert entry.overall_uid_value == "0x0807060504030201"
    assert entry.to_dict() == {
        "name": "OverallExample",
        "global_rank": 7,
        "overall_uid_raw": "0x0807060504030201",
        "overall_uid_bytes_le": "0102030405060708",
    }
    assert SolareOverallEntry("NoUid", 8).to_dict() == {
        "name": "NoUid",
        "global_rank": 8,
    }


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
        SolareOverallEntry("OverallOnly", 3),
        SolareOverallEntry("RichRank4", 4),
    )
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id="sha256:example",
        observed_at=1.0,
        players=rich_players,
        evidence=evidence,
        overall_top_100=overall,
    )

    assert [player.global_rank for player in snapshot.top_100] == [1, 2, 4]
    assert snapshot.overall_top_100 == overall
    assert snapshot.get_player("OverallOnly") is None
    assert snapshot.get_overall_entry("OverallOnly") == overall[2]
    assert snapshot.get_overall_entry("overallonly") is None
    assert [
        player.global_rank for player in snapshot.class_leaderboard(11)
    ] == [1, 2, 4, 101]

    payload = snapshot.to_dict()
    assert snapshot.schema_version == 1
    assert payload["schema_version"] == 1
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

    assert snapshot.schema_version == 1
    assert result.schema_version == 1
    assert snapshot.to_dict()["schema_version"] == 1
    assert result.to_dict()["schema_version"] == 1

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
            "sha256:positional-overall",
            1.0,
            (),
            evidence,
            frozenset({"rankings"}),
            (),
        )


def test_snapshot_id_preserves_exact_overlap_and_identifies_divergence() -> None:
    player_class = SolareClass(11, "Lahn")
    players = (
        SolarePlayer("RankOne", 1, player_class),
        SolarePlayer("RankTwo", 2, player_class),
    )
    exact = (
        SolareOverallEntry("RankOne", 1, b"\x01" * 8),
        SolareOverallEntry("RankTwo", 2, b"\x02" * 8),
    )
    divergent = (
        SolareOverallEntry("RankOne", 1, b"\x01" * 8),
        SolareOverallEntry("OverallOnly", 2, b"\x03" * 8),
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
            SolareOverallEntry("RankOne", 1, b"\xaa" * 8),
            SolareOverallEntry("OverallOnly", 2, b"\xbb" * 8),
        ),
    )
