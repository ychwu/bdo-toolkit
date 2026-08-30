"""Convenience accessors on calibration result types, and the one-call facade.

Everything here is synthetic — no private captures required.
"""

import json

import pytest

from bdo_toolkit import PacketCaptureOptions, calibration
from bdo_toolkit.calibration import (
    CalibrationRetention,
    CalibrationResult,
    DirectionEvidence,
    MessageSpec,
    calibrate_and_update,
    update_profile,
)


def _spec(event: str, opcode: int, **kwargs) -> MessageSpec:
    return MessageSpec(event=event, opcode=opcode, length=226, **kwargs)


def _result(*specs: MessageSpec, **kwargs) -> CalibrationResult:
    frames_scanned = kwargs.get("frames_scanned", 42)
    return CalibrationResult(
        specs=specs,
        ignored=kwargs.get("ignored", ()),
        frames_scanned=frames_scanned,
        evidence=kwargs.get("evidence", ()),
        retention=kwargs.get(
            "retention",
            CalibrationRetention(
                frames_observed=frames_scanned,
                frames_retained=frames_scanned,
                frames_discarded=0,
                bytes_observed=0,
                bytes_retained=0,
                bytes_discarded=0,
            ),
        ),
    )


class TestCalibrationResultAccessors:
    def test_events_found_supports_completeness_checks(self):
        result = _result(
            _spec("STORAGE_ITEM_DELTA", 0x0E6A),
            _spec("SOURCE_STACK_DECREMENT", 0x1A32),
        )

        assert result.events_found == {
            "STORAGE_ITEM_DELTA",
            "SOURCE_STACK_DECREMENT",
        }
        assert {"STORAGE_ITEM_DELTA"} <= result.events_found
        assert not {"INVENTORY_TRANSFER"} <= result.events_found
        assert _result().events_found == frozenset()

    def test_specs_by_event_groups_and_keeps_multiple_candidates(self):
        first = _spec("STORAGE_ITEM_DELTA", 0x0E6A)
        second = _spec("STORAGE_ITEM_DELTA", 0x0E6B)
        other = _spec("SOURCE_ITEM_REFERENCE", 0x13A5)
        result = _result(first, second, other)

        grouped = result.specs_by_event()
        assert grouped["STORAGE_ITEM_DELTA"] == (first, second)
        assert grouped["SOURCE_ITEM_REFERENCE"] == (other,)

    def test_summary_names_events_opcodes_and_diagnostics(self):
        result = _result(
            _spec("STORAGE_ITEM_DELTA", 0x0E6A),
            ignored=("candidate at offset 12 failed quantity check",),
            evidence=(
                DirectionEvidence(
                    action="auto",
                    opcode=0x0E6A,
                    detected_family="into_storage",
                    reference_frame=True,
                    context_label=False,
                    storage_context=True,
                ),
            ),
        )

        text = result.summary()
        assert "scanned 42 frames" in text
        assert "STORAGE_ITEM_DELTA (0x0E6A)" in text
        assert "inventory->storage" in text
        assert "ignored 1 candidate(s)" in text
        assert "no message specs promoted" in _result().summary()

    def test_to_json_dict_is_json_serializable_and_complete(self):
        result = _result(
            _spec("STORAGE_ITEM_DELTA", 0x0E6A),
            ignored=("reason",),
            evidence=(
                DirectionEvidence(
                    action="auto",
                    opcode=0x0E6A,
                    detected_family=None,
                    reference_frame=False,
                    context_label=False,
                ),
            ),
        )

        data = json.loads(json.dumps(result.to_json_dict()))
        assert data["frames_scanned"] == 42
        assert data["specs"][0]["event"] == "STORAGE_ITEM_DELTA"
        assert data["specs"][0]["opcode"] == "0x0E6A"
        assert data["ignored"] == ["reason"]
        assert data["evidence"][0]["opcode"] == "0x0E6A"
        assert data["evidence"][0]["detected_family"] is None


class TestProfileUpdateSummary:
    def test_summary_reports_path_backup_and_added_specs(self, tmp_path):
        profile = tmp_path / "opcodes.json"
        update_profile([_spec("STORAGE_ITEM_DELTA", 0x0E6A)], profile)

        update = update_profile([_spec("INVENTORY_TRANSFER", 0x0F16)], profile)
        text = update.summary()
        assert str(profile) in text
        assert "backup at" in text
        assert "added INVENTORY_TRANSFER opcode=0x0F16" in text

        same = update_profile(
            [_spec("INVENTORY_TRANSFER", 0x0F16)],
            profile,
            replace=False,
        )
        assert "no new specs added" in same.summary()

    def test_default_replaces_stale_specs_in_the_same_event_family(self, tmp_path):
        profile = tmp_path / "opcodes.json"
        update_profile([_spec("STORAGE_ITEM_DELTA", 0x9999)], profile)

        update = update_profile([_spec("STORAGE_ITEM_DELTA", 0x0E6A)], profile)

        assert update.replaced_events == ("STORAGE_ITEM_DELTA",)
        written = json.loads(profile.read_text(encoding="utf-8"))
        opcodes = [
            entry["opcode"]
            for entry in written["specs"]["STORAGE_ITEM_DELTA"]
        ]
        assert opcodes == ["0x0E6A"]

    def test_replace_false_is_the_explicit_merge_mode(self, tmp_path):
        profile = tmp_path / "opcodes.json"
        update_profile([_spec("STORAGE_ITEM_DELTA", 0x9999)], profile)

        update = update_profile(
            [_spec("STORAGE_ITEM_DELTA", 0x0E6A)], profile, replace=False
        )

        assert update.replaced_events == ()
        written = json.loads(profile.read_text(encoding="utf-8"))
        opcodes = [
            entry["opcode"]
            for entry in written["specs"]["STORAGE_ITEM_DELTA"]
        ]
        assert opcodes == ["0x9999", "0x0E6A"]


class TestCalibrateAndUpdate:
    def test_pcap_path_calibrates_and_persists_in_one_call(
        self, tmp_path, monkeypatch
    ):
        canned = _result(_spec("STORAGE_ITEM_DELTA", 0x0E6A))
        monkeypatch.setattr(
            calibration, "calibrate_pcap", lambda *args, **kwargs: canned
        )
        profile = tmp_path / "opcodes.json"
        update_profile([_spec("STORAGE_ITEM_DELTA", 0x9999)], profile)

        result, update = calibrate_and_update(
            profile,
            item_id=7003,
            pcap="capture.pcapng",
            action="inventory-to-storage",
        )

        assert result is canned
        assert update is not None
        assert [s.event for s in update.added] == ["STORAGE_ITEM_DELTA"]
        assert update.replaced_events == ("STORAGE_ITEM_DELTA",)
        written = json.loads(profile.read_text(encoding="utf-8"))
        assert [
            spec["opcode"] for spec in written["specs"]["STORAGE_ITEM_DELTA"]
        ] == ["0x0E6A"]

    def test_empty_result_leaves_profile_untouched(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            calibration, "calibrate_pcap", lambda *args, **kwargs: _result()
        )
        profile = tmp_path / "opcodes.json"

        result, update = calibrate_and_update(
            profile, item_id=7003, pcap="capture.pcapng"
        )

        assert result.specs == ()
        assert update is None
        assert not profile.exists()

    @pytest.mark.parametrize(
        "live_only_kwarg",
        [
            {"capture_seconds": 5.0},
            {
                "capture_options": PacketCaptureOptions(
                    interface="eth0",
                    local_ip="10.0.0.5",
                )
            },
        ],
    )
    def test_live_only_arguments_are_rejected_with_pcap(
        self, tmp_path, live_only_kwarg
    ):
        with pytest.raises(ValueError, match="live calibration only"):
            calibrate_and_update(
                tmp_path / "opcodes.json",
                item_id=7003,
                pcap="capture.pcapng",
                **live_only_kwarg,
            )

    def test_pcap_ports_are_forwarded_only_to_offline_calibration(
        self, tmp_path, monkeypatch
    ):
        seen = {}

        def fake_calibrate_pcap(*args, **kwargs):
            seen.update(kwargs)
            return _result()

        monkeypatch.setattr(calibration, "calibrate_pcap", fake_calibrate_pcap)
        calibrate_and_update(
            tmp_path / "opcodes.json",
            item_id=7003,
            pcap="capture.pcapng",
            pcap_ports=(9000, 9001),
        )

        assert seen["ports"] == (9000, 9001)

    def test_capture_options_are_forwarded_only_to_live_calibration(
        self, tmp_path, monkeypatch
    ):
        seen = {}
        options = PacketCaptureOptions(interface="test-interface", use_bpf=False)

        def fake_calibrate_live(**kwargs):
            seen.update(kwargs)
            return _result()

        monkeypatch.setattr(calibration, "calibrate_live", fake_calibrate_live)
        calibrate_and_update(
            tmp_path / "opcodes.json",
            item_id=7003,
            capture_options=options,
        )

        assert seen["capture_options"] is options

    def test_pcap_ports_are_rejected_for_live_calibration(self, tmp_path):
        with pytest.raises(ValueError, match="offline calibration only"):
            calibrate_and_update(
                tmp_path / "opcodes.json",
                item_id=7003,
                pcap_ports=(9000,),
            )
