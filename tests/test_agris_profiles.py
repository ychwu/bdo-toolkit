"""Agris profiles remain optional for items and strict when explicitly selected."""
import asyncio
from dataclasses import replace
import json

import pytest

from bdo_toolkit import load_opcode_profile, ProfileError, cli
from bdo_toolkit.profiles import AgrisProfileLayout
from bdo_toolkit.agris import (
    AgrisCalibrationError, AgrisCalibrationResult, AgrisCaptureHealth, AgrisDiscoveryOptions,
    LiveAgrisSession, AsyncLiveAgrisSession, calibrate_agris_live,
    calibrate_agris_and_update, update_agris_profile, replay_agris,
)
from bdo_toolkit.agris import calibration as calibration_module
from bdo_toolkit.agris._discovery import AgrisTracker
from bdo_toolkit.agris.models import AgrisDetectionError
from bdo_toolkit.calibration import MessageSpec, update_profile
from tests.test_agris_session import fake, wait_stopped
from tests.test_agris_discovery import frame, OTHER_FLOW
from tests.test_agris_replay import write_capture


LAYOUT = AgrisProfileLayout(0x1746, 37, 33, 12, observed_date="2026-09-17")


def profile_file(tmp_path, *, layout=LAYOUT, active=True):
    path = tmp_path / "profile.json"
    data = {"version": 1, "profile_active": active, "specs": {},
            "updated_at": "keep-item-date", "calibration_item_id": 15156,
            "extension": {"preserve": [1, 2]}}
    if layout is not None:
        data["agris"] = layout.to_dict()
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def result():
    return AgrisCalibrationResult(LAYOUT, 100000, 5, AgrisCaptureHealth(packets_processed=5),
                                  "2026-09-17T22:37:00+00:00")


def test_optional_profile_section_and_immutable_round_trip(tmp_path):
    path = profile_file(tmp_path, layout=None)
    assert load_opcode_profile(path).agris is None
    assert "agris" not in load_opcode_profile(path).to_dict()
    path = profile_file(tmp_path)
    profile = load_opcode_profile(path)
    assert profile.agris == LAYOUT
    assert profile.to_dict()["agris"] == LAYOUT.to_dict()
    with pytest.raises(AttributeError):
        profile.agris.opcode = 1


@pytest.mark.parametrize("changes", [
    {"opcode": True}, {"opcode": 65536}, {"message_length": 12}, {"message_length": 65536},
    {"message_length": 36}, {"remaining_offset": 4}, {"remaining_offset": 13},
    {"maximum_offset": True}, {"flag": 1}, {"flag": False}, {"encoding": "uint64_le"},
    {"observed_date": "2026-02-30"}, {"observed_date": 3},
])
def test_malformed_agris_rejected_on_load(tmp_path, changes):
    path = profile_file(tmp_path)
    data = json.loads(path.read_text())
    data["agris"].update(changes)
    path.write_text(json.dumps(data))
    with pytest.raises(ProfileError):
        load_opcode_profile(path)


@pytest.mark.parametrize("value", [[], "opcode", {"opcode": "0x1746"}])
def test_incomplete_section_rejected(tmp_path, value):
    path = profile_file(tmp_path)
    data = json.loads(path.read_text())
    data["agris"] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ProfileError):
        load_opcode_profile(path)


def test_profile_session_emits_first_message_and_never_calibrates(fake, tmp_path):
    profile = load_opcode_profile(profile_file(tmp_path))
    owner = LiveAgrisSession(expected_maximum_points=100000, profile=profile, capture_seconds=0.02)
    owner.start()
    wait_stopped(owner)
    assert owner.detection_mode == "profile"
    assert [x.remaining_points for x in owner.events()] == [99960, 99920, 99880, 99840, 99800, 99760]
    assert owner.calibration_result is None
    owner.stop()


@pytest.mark.parametrize("kwargs", [{"layout": None}, {"active": False}])
def test_invalid_profile_refused_before_acquisition(fake, tmp_path, kwargs):
    profile = load_opcode_profile(profile_file(tmp_path, **kwargs))
    with pytest.raises(ProfileError):
        LiveAgrisSession(expected_maximum_points=100000, profile=profile)
    with pytest.raises(ProfileError):
        AsyncLiveAgrisSession(expected_maximum_points=100000, profile=profile)
    with pytest.raises(ProfileError):
        replay_agris(tmp_path / "absent.pcap", expected_maximum_points=100000, profile=profile)
    assert fake == []


def fixed_frame(value=99960, **kwargs):
    geometry = dict(opcode=LAYOUT.opcode, length=37, remaining_offset=33, maximum_offset=12)
    geometry.update(kwargs)
    return frame(value, **geometry)


@pytest.mark.parametrize("kwargs", [{"length": 40}, {"flag": 1}, {"maximum": 50000},
                                    {"generation": 2}, {"flow": OTHER_FLOW}])
def test_profile_rejection_is_latched_without_fallback(kwargs):
    tracker = AgrisTracker(expected_maximum_points=100000, profile_layout=LAYOUT)
    tracker.observe(fixed_frame())
    with pytest.raises(AgrisDetectionError):
        tracker.observe(fixed_frame(**kwargs))
    assert tracker.snapshot().status == "invalid"
    assert tracker.snapshot().balance is None


def test_profile_does_not_interpret_silence_or_other_opcodes_as_failure():
    tracker = AgrisTracker(expected_maximum_points=100000, profile_layout=LAYOUT)
    for index in range(10):
        tracker.observe(fixed_frame(99000 - index, opcode=0x1337, timestamp=index))
    assert tracker.refresh(9999).status == "searching"
    assert tracker.snapshot().candidates == ()


def test_profile_accepts_zero_equal_and_increasing_values():
    emitted = []
    tracker = AgrisTracker(expected_maximum_points=100000, profile_layout=LAYOUT, on_balance=emitted.append)
    for value in (99960, 99960, 0, 100000):
        tracker.observe(fixed_frame(value))
    assert [x.remaining_points for x in emitted] == [99960, 99960, 0, 100000]


def test_profile_replay_yields_single_first_packet(tmp_path):
    path = tmp_path / "first.pcap"
    write_capture(path, count=1, tail=False)
    profile = load_opcode_profile(profile_file(tmp_path))
    with replay_agris(path, expected_maximum_points=100000, profile=profile) as replay:
        assert [x.remaining_points for x in replay] == [99960]


def test_async_profile_and_final_discovery_result(fake, tmp_path):
    async def run():
        profile = load_opcode_profile(profile_file(tmp_path))
        async with AsyncLiveAgrisSession(expected_maximum_points=100000, profile=profile) as owner:
            assert (await owner.poll(1)).remaining_points == 99960
            assert owner.detection_mode == "profile"
        assert owner.calibration_result is None
        async with AsyncLiveAgrisSession(expected_maximum_points=100000,
                    discovery_options=AgrisDiscoveryOptions(settle_seconds=0)) as discovery:
            assert discovery.calibration_result is None
            assert await discovery.poll(1) is not None
        assert discovery.calibration_result.layout.opcode == 0x1746
    asyncio.run(run())


def test_calibration_helper_waits_for_stop_and_uses_cold_discovery(fake):
    progress = []
    calibrated = calibrate_agris_live(expected_maximum_points=100000,
                    discovery_options=AgrisDiscoveryOptions(settle_seconds=0), on_update=progress.append)
    assert calibrated.layout.opcode == 0x1746
    assert fake[0].stopped
    assert progress[-1].status == "tracking"
    assert calibrated.health.capture_is_clean


def test_calibration_timeout_without_qualification_has_no_result(fake):
    with pytest.raises(AgrisCalibrationError):
        calibrate_agris_live(expected_maximum_points=50000, capture_seconds=0.02)


def test_partial_ui_stop_never_produces_calibration_result(fake):
    owner = LiveAgrisSession(expected_maximum_points=100000,
                            discovery_options=AgrisDiscoveryOptions(minimum_updates=100))
    with owner:
        pass
    assert owner.calibration_result is None


def test_discovery_failure_has_no_calibration_result(fake):
    from bdo_toolkit import LiveCaptureOptions
    owner = LiveAgrisSession(expected_maximum_points=100000,
                            live_options=LiveCaptureOptions(packet_queue_size=1))
    with pytest.raises(Exception):
        owner.start()
    assert owner.calibration_result is None


def test_writer_preserves_every_other_section_and_backups_bytes(tmp_path):
    path = profile_file(tmp_path, layout=None)
    before = path.read_bytes()
    update = update_agris_profile(result(), path)
    assert update.written and update.backup_path.read_bytes() == before
    after = json.loads(path.read_text())
    assert after.pop("agris") == LAYOUT.to_dict()
    assert after == json.loads(before)
    assert load_opcode_profile(path).agris == LAYOUT
    assert not update_agris_profile(result(), path).written
    assert len(list((tmp_path / "opcodes_backups").iterdir())) == 1


def test_writer_refuses_changed_profile_without_backup(tmp_path):
    path = profile_file(tmp_path, layout=None)
    before = path.read_bytes()
    with pytest.raises(ProfileError, match="changed"):
        update_agris_profile(result(), path, expected_profile_sha256="0" * 64)
    assert path.read_bytes() == before
    assert not (tmp_path / "opcodes_backups").exists()


def test_writer_requires_existing_valid_active_profile(tmp_path):
    with pytest.raises(FileNotFoundError):
        update_agris_profile(result(), tmp_path / "missing.json")
    path = profile_file(tmp_path, active=False)
    with pytest.raises(ProfileError):
        update_agris_profile(result(), path)


def test_writer_validates_runtime_items_before_replacing(tmp_path):
    path = profile_file(tmp_path, layout=None)
    data = json.loads(path.read_text())
    data["specs"] = {"INVENTORY_TRANSFER": [{"opcode": "0x1000", "length": 20}]}
    path.write_text(json.dumps(data))
    before = path.read_bytes()
    with pytest.raises(ProfileError):
        update_agris_profile(result(), path)
    assert path.read_bytes() == before


def test_atomic_write_failure_preserves_original(tmp_path, monkeypatch):
    path = profile_file(tmp_path, layout=None)
    before = path.read_bytes()
    def fail(*args):
        raise OSError("write failed")
    monkeypatch.setattr(calibration_module, "atomic_write_text", fail)
    with pytest.raises(OSError):
        update_agris_profile(result(), path)
    assert path.read_bytes() == before


def test_existing_item_calibration_preserves_agris(tmp_path):
    path = profile_file(tmp_path)
    update_profile([MessageSpec("STORAGE_ITEM_DELTA", 0x1000, 40,
                               item_id_offset=10, quantity_added_offset=14)], path, backup=False)
    assert load_opcode_profile(path).agris == LAYOUT


def test_combined_calibration_ignores_old_agris_then_updates(fake, tmp_path):
    path = profile_file(tmp_path, layout=AgrisProfileLayout(0x9999, 40, 9, 13))
    update = calibrate_agris_and_update(path, expected_maximum_points=100000,
                         discovery_options=AgrisDiscoveryOptions(settle_seconds=0))
    assert update.written and load_opcode_profile(path).agris.opcode == 0x1746


def test_combined_calibration_refuses_profile_changed_during_capture(fake, tmp_path):
    path = profile_file(tmp_path, layout=None)
    changed = False
    def callback(status):
        nonlocal changed
        if not changed:
            data = json.loads(path.read_text())
            data["extension"] = "changed elsewhere"
            path.write_text(json.dumps(data))
            changed = True
    with pytest.raises(ProfileError, match="changed"):
        calibrate_agris_and_update(path, expected_maximum_points=100000,
            discovery_options=AgrisDiscoveryOptions(settle_seconds=0), on_update=callback)
    assert json.loads(path.read_text())["extension"] == "changed elsewhere"
    assert load_opcode_profile(path).agris is None


def test_cli_profile_replay_and_calibration_save(fake, tmp_path, capsys):
    path = profile_file(tmp_path)
    pcap = tmp_path / "one.pcap"
    write_capture(pcap, count=1, tail=False)
    assert cli.main(["agris", "replay", str(pcap), "--cap", "100000", "--profile", str(path), "--jsonl"]) == 0
    assert json.loads(capsys.readouterr().out)["remaining_points"] == 99960
    assert cli.main(["agris", "calibrate", "--profile", str(path), "--cap", "100000", "--settle-seconds", "0"]) == 0
    assert json.loads(capsys.readouterr().out)["layout"]["opcode"] == "0x1746"


def test_cli_calibration_requires_destination_before_capture(fake):
    with pytest.raises(SystemExit):
        cli.main(["agris", "calibrate", "--cap", "100000"])
    assert not fake


def test_remote_fetch_preserves_agris_and_rejects_invalid_geometry(tmp_path, monkeypatch):
    from bdo_toolkit import fetch_opcode_profile, RemoteProfileError
    from tests.test_remote_profiles import _serve, _envelope
    source = {"version": 1, "profile_active": True, "specs": {}, "agris": LAYOUT.to_dict()}
    path = tmp_path / "download.json"
    _serve(monkeypatch, _envelope(source))
    fetch_opcode_profile("https://profiles.example.test/v1/current.json", path)
    assert load_opcode_profile(path).agris == LAYOUT
    before = path.read_bytes()
    source["agris"]["remaining_offset"] = 500
    _serve(monkeypatch, _envelope(source))
    with pytest.raises(RemoteProfileError):
        fetch_opcode_profile("https://profiles.example.test/v1/current.json", path)
    assert path.read_bytes() == before


def test_callback_cancellation_never_saves(fake, tmp_path):
    path = profile_file(tmp_path, layout=None)
    before = path.read_bytes()
    def cancel(status):
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        calibrate_agris_and_update(path, expected_maximum_points=100000, on_update=cancel)
    assert path.read_bytes() == before
    assert not (tmp_path / "opcodes_backups").exists()


def test_cli_calibration_interrupt_is_reported(tmp_path, monkeypatch, capsys):
    def cancel(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "calibrate_agris_and_update", cancel)
    assert cli.main(["agris", "calibrate", "--profile", str(tmp_path / "profile.json"),
                     "--cap", "100000"]) == 130
    assert "interrupted" in capsys.readouterr().err


def test_final_capture_loss_blocks_calibration_save(fake, tmp_path, monkeypatch):
    from bdo_toolkit import CaptureIntegrityError
    from tests.test_agris_session import FakeCapture
    original_stop = FakeCapture.stop
    def dirty_stop(self):
        original_stop(self)
        self.stats = replace(self.stats, dropped=1)
        return self.stats
    monkeypatch.setattr(FakeCapture, "stop", dirty_stop)
    path = profile_file(tmp_path, layout=None)
    before = path.read_bytes()
    with pytest.raises(CaptureIntegrityError):
        calibrate_agris_and_update(path, expected_maximum_points=100000,
                                  discovery_options=AgrisDiscoveryOptions(settle_seconds=0))
    assert path.read_bytes() == before
