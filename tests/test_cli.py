"""Synthetic command-line contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fixture_paths import JULY17_OPCODE_PROFILE
from bdo_toolkit import (
    ProfileFetchResult,
    __version__,
    cli,
    load_opcode_profile,
)
from bdo_toolkit._protocol import FlowKey
from bdo_toolkit.calibration import CalibrationResult, MessageSpec
from bdo_toolkit.origin_learning import CompanionObservation
from bdo_toolkit.solare import (
    SolareCaptureResult,
    SolareClass,
    SolareDetectionStatus,
    SolareEvidence,
    SolareLeaderboardSnapshot,
    SolarePlayer,
    SolareUpdate,
    SolareUpdateKind,
)
from bdo_toolkit.solare.models import solare_snapshot_id


def test_replay_invalid_capture_is_a_clean_cli_error(tmp_path, capsys):
    path = tmp_path / "invalid.pcapng"
    path.write_bytes(b"not a capture")

    exit_code = cli.main(
        [
            "replay",
            str(path),
            "--profile",
            str(JULY17_OPCODE_PROFILE),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "error: Could not read capture" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ["replay", "session.pcapng"],
        ["live", "--capture-seconds", "0"],
    ],
)
def test_item_decode_cli_requires_explicit_profile(argv, capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(argv)

    assert exc_info.value.code == 2
    assert "--profile" in capsys.readouterr().err


def test_profile_fetch_cli_forwards_verification_controls(
    tmp_path,
    monkeypatch,
    capsys,
):
    destination = tmp_path / "opcodes.json"
    profile = load_opcode_profile(JULY17_OPCODE_PROFILE)
    observed = {}

    def fake_fetch(url, output, **kwargs):
        observed.update(url=url, output=output, **kwargs)
        return ProfileFetchResult(
            path=destination,
            profile=profile,
            source_url=url,
            revision="naeu-2026-07-17-r1",
            profile_sha256="a" * 64,
            etag='"profile-r1"',
            backup_path=None,
        )

    monkeypatch.setattr(cli, "fetch_opcode_profile", fake_fetch)

    exit_code = cli.main(
        [
            "profile",
            "fetch",
            "https://profiles.example.test/current.json",
            "--output",
            str(destination),
            "--timeout",
            "2.5",
            "--max-bytes",
            "4096",
            "--no-backup",
        ]
    )

    assert exit_code == 0
    assert observed == {
        "url": "https://profiles.example.test/current.json",
        "output": destination,
        "timeout": 2.5,
        "max_bytes": 4096,
        "backup": False,
    }
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "installed opcode profile revision naeu-2026-07-17-r1" in captured.err
    assert "profile sha256: " + "a" * 64 in captured.err
    assert "source etag" not in captured.err
    assert '"profile-r1"' not in captured.err


@pytest.mark.parametrize(
    ("extra_args", "expected_item_id"),
    [
        ([], 15156),
        (["--calibration-item-id", "7003"], 7003),
    ],
)
def test_reset_profile_cli_metadata_item_default_and_override(
    tmp_path,
    capsys,
    extra_args,
    expected_item_id,
):
    profile = tmp_path / "opcodes.json"

    exit_code = cli.main(["reset-profile", str(profile), *extra_args])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "reset" in captured.err
    data = json.loads(profile.read_text(encoding="utf-8"))
    assert data["calibration_item_id"] == expected_item_id
    assert data["profile_active"] is True
    assert all(not entries for entries in data["specs"].values())


@pytest.mark.parametrize(
    ("write_mode", "expected_replace"),
    [
        ([], True),
        (["--merge"], False),
        (["--replace"], True),
    ],
)
def test_calibrate_cli_writes_mocked_result(
    tmp_path, monkeypatch, capsys, write_mode, expected_replace
):
    result = CalibrationResult(
        specs=(
            MessageSpec(
                "STORAGE_ITEM_DELTA",
                0x9999,
                261,
                item_id_offset=37,
                quantity_added_offset=41,
                destination_instance_offset=72,
                context_offset=8,
                record_count_offset=6,
                repeat_stride=226,
            ),
        ),
        ignored=(),
        frames_scanned=1,
        calibration_item_id=99123,
    )
    monkeypatch.setattr(cli, "calibrate_pcap", lambda *args, **kwargs: result)
    real_update_profile = cli.update_profile
    observed = {}

    def recording_update_profile(*args, **kwargs):
        observed["replace"] = kwargs["replace"]
        return real_update_profile(*args, **kwargs)

    monkeypatch.setattr(cli, "update_profile", recording_update_profile)
    profile = tmp_path / "nested" / "opcodes.json"

    exit_code = cli.main(
        [
            "calibrate",
            "--pcap",
            "unused.pcapng",
            "--item-id",
            "99123",
            "--action",
            "inventory-to-storage",
            "--write",
            str(profile),
            *write_mode,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "wrote" in captured.err
    data = json.loads(profile.read_text(encoding="utf-8"))
    assert data["calibration_item_id"] == 99123
    assert observed["replace"] is expected_replace


@pytest.mark.parametrize(
    "argv",
    [
        ["calibrate", "--item-id", "0"],
        ["calibrate", "--item-id", "1", "--qty", "0"],
        ["calibrate", "--item-id", "1", "--min-confidence", "nan"],
        [
            "live",
            "--profile",
            str(JULY17_OPCODE_PROFILE),
            "--capture-seconds",
            "-1",
        ],
        [
            "live",
            "--profile",
            str(JULY17_OPCODE_PROFILE),
            "--event-queue-size",
            "0",
        ],
        [
            "origin-learn",
            "--profile",
            "opcodes.local",
            "--min-observations",
            "0",
        ],
    ],
)
def test_cli_rejects_invalid_numeric_arguments(argv):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(argv)
    assert exc_info.value.code == 2


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--version"])
    assert exc_info.value.code == 0
    assert f"bdo-toolkit {__version__}" in capsys.readouterr().out


def _complete_solare_result() -> SolareCaptureResult:
    player = SolarePlayer(
        name="ExamplePlayer",
        global_rank=1,
        primary_class=SolareClass(0, "Warrior"),
    )
    evidence = SolareEvidence(
        ranked_players=620,
        overall_players=100,
        exact_cross_check=100,
    )
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id=solare_snapshot_id((player,)),
        observed_at=1234.5,
        players=(player,),
        evidence=evidence,
    )
    return SolareCaptureResult(
        status=SolareDetectionStatus.COMPLETE,
        evidence=evidence,
        snapshot=snapshot,
    )


def test_solare_replay_cli_writes_json_and_uses_domain_exit_status(
    monkeypatch,
    capsys,
):
    observed = {}
    result = SolareCaptureResult(
        status=SolareDetectionStatus.MENU_CONTEXT,
        evidence=SolareEvidence(),
        message="menu only",
    )
    def fake_replay(*args, **kwargs):
        observed.update(kwargs)
        return result

    monkeypatch.setattr(cli, "replay_solare", fake_replay)

    exit_code = cli.main(["solare", "replay", "unused.pcapng"])

    captured = capsys.readouterr()
    assert exit_code == 1
    output = json.loads(captured.out)
    assert output["status"] == "menu-context"
    assert output["complete"] is False
    assert captured.err == ""
    assert observed["retain_raw_extensions"] is False


def test_solare_replay_cli_include_raw_controls_decode_and_output(
    monkeypatch,
    capsys,
):
    observed = {}
    result = _complete_solare_result()

    def fake_replay(*args, **kwargs):
        observed.update(kwargs)
        return result

    monkeypatch.setattr(cli, "replay_solare", fake_replay)

    exit_code = cli.main(
        ["solare", "replay", "unused.pcapng", "--include-raw"]
    )

    assert exit_code == 0
    assert observed["retain_raw_extensions"] is True
    assert json.loads(capsys.readouterr().out)["status"] == "complete"


def test_solare_replay_cli_refuses_to_overwrite_input_capture(
    monkeypatch,
    capsys,
    tmp_path,
):
    capture = tmp_path / "leaderboard.pcapng"
    capture.write_bytes(b"capture")
    monkeypatch.setattr(
        cli,
        "replay_solare",
        lambda *args, **kwargs: pytest.fail("replay must not start"),
    )

    exit_code = cli.main(
        ["solare", "replay", str(capture), "--output", str(capture)]
    )

    assert exit_code == 2
    assert capture.read_bytes() == b"capture"
    assert "must not overwrite" in capsys.readouterr().err


def test_solare_live_cli_reports_progress_and_passes_capture_options(
    monkeypatch,
    capsys,
):
    result = _complete_solare_result()
    observed = {}

    def fake_capture(**kwargs):
        observed.update(kwargs)
        kwargs["on_update"](
            SolareUpdate(
                kind=SolareUpdateKind.RANKED_PROGRESS,
                message="400 ranked players recovered",
                ranked_players=400,
            )
        )
        return result

    monkeypatch.setattr(cli, "capture_solare_snapshot", fake_capture)

    exit_code = cli.main(
        [
            "solare",
            "live",
            "--iface",
            "Npcap adapter",
            "--local-ip",
            "192.0.2.25",
            "--no-bpf",
            "--save-pcap",
            "next-patch.pcapng",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "complete"
    assert "[ranked-progress] 400 ranked players recovered" in captured.err
    options = observed["capture_options"]
    assert options.interface == "Npcap adapter"
    assert options.local_ip == "192.0.2.25"
    assert options.use_bpf is False
    assert observed["save_pcap"] == Path("next-patch.pcapng")
    assert observed["stop_on_complete"] is True
    assert observed["capture_seconds"] == 120.0
    assert observed["retain_raw_extensions"] is False


def test_solare_cli_wait_forever_and_include_raw_control_acquisition(
    monkeypatch,
    capsys,
):
    result = _complete_solare_result()
    observed = {}

    def fake_capture(**kwargs):
        observed.update(kwargs)
        return result

    monkeypatch.setattr(cli, "capture_solare_snapshot", fake_capture)

    exit_code = cli.main(
        ["solare", "live", "--wait-forever", "--include-raw", "--quiet"]
    )

    assert exit_code == 0
    assert observed["capture_seconds"] is None
    assert observed["retain_raw_extensions"] is True
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "complete"


def test_solare_live_cli_refuses_shared_capture_and_json_path(
    monkeypatch,
    capsys,
    tmp_path,
):
    destination = tmp_path / "solare-output.pcapng"
    monkeypatch.setattr(
        cli,
        "capture_solare_snapshot",
        lambda **kwargs: pytest.fail("capture must not start"),
    )

    exit_code = cli.main(
        [
            "solare",
            "live",
            "--save-pcap",
            str(destination),
            "--output",
            str(destination),
        ]
    )

    assert exit_code == 2
    assert not destination.exists()
    assert "different paths" in capsys.readouterr().err


def test_origin_learn_cli_persists_confirmed_unknown_family(
    tmp_path,
    monkeypatch,
    capsys,
):
    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)
    calls = 0

    def fake_replay(path, **kwargs):
        nonlocal calls
        calls += 1
        kwargs["origin_observer"](
            CompanionObservation(
                timestamp=float(calls),
                flow=flow,
                stream_sequence=calls * 1000,
                delta_opcode=0x0D7E,
                delta_length=258,
                companion_opcodes=(0x0F7E, 0x0DE1),
                companion_lengths=(60, 23),
                token_digest=f"{calls:016x}",
                token_offsets=(16, 47, 5),
            )
        )
        return iter(())

    monkeypatch.setattr(cli, "replay_pcap", fake_replay)
    candidates = tmp_path / "origin-candidates.json"

    exit_code = cli.main(
        [
            "origin-learn",
            "--profile",
            "opcodes.local",
            "--candidates",
            str(candidates),
            "--pcap",
            "first.pcapng",
            "--pcap",
            "second.pcapng",
        ]
    )

    assert exit_code == 0
    data = json.loads(candidates.read_text(encoding="utf-8"))
    assert data["candidates"][0]["status"] == "confirmed"
    assert data["candidates"][0]["companion_opcodes"] == ["0x0F7E", "0x0DE1"]
    assert "observations=2" in capsys.readouterr().out
