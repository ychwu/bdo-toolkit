"""Synthetic command-line contract tests."""

from __future__ import annotations

import json

import pytest

from bdo_toolkit import cli
from bdo_toolkit._protocol import FlowKey
from bdo_toolkit.calibration import CalibrationResult, MessageSpec
from bdo_toolkit.origin_learning import CompanionObservation


def test_replay_invalid_capture_is_a_clean_cli_error(tmp_path, capsys):
    path = tmp_path / "invalid.pcapng"
    path.write_bytes(b"not a capture")

    exit_code = cli.main(["replay", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "error: Could not read capture" in captured.err
    assert "Traceback" not in captured.err


def test_calibrate_cli_writes_mocked_result(tmp_path, monkeypatch, capsys):
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
                repeat_stride=226,
            ),
        ),
        ignored=(),
        frames_scanned=1,
        calibration_item_id=99123,
    )
    monkeypatch.setattr(cli, "calibrate_pcap", lambda *args, **kwargs: result)
    profile = tmp_path / "nested" / "opcodes.json"

    exit_code = cli.main(
        [
            "calibrate",
            "--pcap",
            "unused.pcapng",
            "--item-id",
            "99123",
            "--write",
            str(profile),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "wrote" in captured.err
    data = json.loads(profile.read_text(encoding="utf-8"))
    assert data["calibration_item_id"] == 99123


@pytest.mark.parametrize(
    "argv",
    [
        ["calibrate", "--item-id", "0"],
        ["calibrate", "--item-id", "1", "--qty", "0"],
        ["calibrate", "--item-id", "1", "--min-confidence", "nan"],
        ["live", "--capture-seconds", "-1"],
        ["live", "--event-queue-size", "0"],
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
    assert "bdo-toolkit 0.1.0" in capsys.readouterr().out


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
