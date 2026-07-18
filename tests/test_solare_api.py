"""Public model and namespace contract for the Solare domain."""

from __future__ import annotations

import json

import bdo_toolkit
from bdo_toolkit.solare import (
    AsyncLiveSolareSession,
    LiveSolareSession,
    SolareCaptureEndpoint,
    SolareClass,
    SolareClassPerformance,
    SolarePlayer,
    SolareRawSection,
    capture_solare_snapshot,
    replay_solare,
)


def test_solare_is_a_curated_package_namespace() -> None:
    assert bdo_toolkit.solare.replay_solare is replay_solare
    assert bdo_toolkit.solare.capture_solare_snapshot is capture_solare_snapshot
    assert bdo_toolkit.solare.LiveSolareSession is LiveSolareSession
    assert bdo_toolkit.solare.AsyncLiveSolareSession is AsyncLiveSolareSession
    assert bdo_toolkit.solare.SolareCaptureEndpoint is SolareCaptureEndpoint
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
