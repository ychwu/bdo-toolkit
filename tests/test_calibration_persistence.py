"""Calibration profile updates, merge safety, and backups."""

from __future__ import annotations

import json

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps

from bdo_toolkit import ProfileError, load_opcode_profile
from bdo_toolkit._specs import event_specs_from_profile
from bdo_toolkit.calibration import (
    CalibrationAuthorityError,
    CalibrationResult,
    CalibrationRetention,
    MessageSpec,
    calibrate_pcap,
    reset_profile,
    update_profile,
)


def test_empty_profile_update_is_a_true_noop(tmp_path):
    path = tmp_path / "opcodes.json"
    original = '{"sentinel": true}\n'
    path.write_text(original, encoding="utf-8")

    update = update_profile(
        CalibrationResult(
            (),
            (),
            0,
            retention=CalibrationRetention(0, 0, 0, 0, 0, 0),
        ),
        path,
    )

    assert not update.written
    assert update.backup_path is None
    assert path.read_text(encoding="utf-8") == original


def test_partial_auto_calibration_cannot_preserve_stale_storage_silently(tmp_path):
    path = tmp_path / "opcodes.json"
    original = json.dumps(
        {
            "version": 1,
            "profile_active": True,
            "specs": {
                "STORAGE_ITEM_DELTA": [
                    {
                        "event": "STORAGE_ITEM_DELTA",
                        "opcode": "0x0E6A",
                        "length": 261,
                        "item_id_offset": 37,
                        "quantity_added_offset": 41,
                        "destination_instance_offset": 72,
                        "context_offset": 8,
                        "record_count_offset": 6,
                    }
                ]
            },
        },
        indent=2,
    ) + "\n"
    path.write_text(original, encoding="utf-8")
    partial = CalibrationResult(
        specs=(
            MessageSpec(
                "INVENTORY_TRANSFER",
                0x2222,
                255,
                item_id_offset=34,
                quantity_offset=38,
                item_instance_offset=69,
                context_offset=21,
            ),
        ),
        ignored=(),
        frames_scanned=1,
        retention=CalibrationRetention(1, 1, 0, 0, 0, 0),
    )

    with pytest.raises(CalibrationAuthorityError, match="auto calibration is incomplete"):
        update_profile(partial, path, backup=False)

    assert path.read_text(encoding="utf-8") == original


def test_auto_calibration_missing_decrement_cannot_write_profile(tmp_path):
    path = tmp_path / "opcodes.json"
    original = '{"sentinel": true}\n'
    path.write_text(original, encoding="utf-8")
    incomplete = CalibrationResult(
        specs=(
            MessageSpec(
                "INVENTORY_TRANSFER",
                0x2222,
                255,
                item_id_offset=34,
                quantity_offset=38,
                item_instance_offset=69,
                context_offset=21,
            ),
            MessageSpec(
                "STORAGE_ITEM_DELTA",
                0x3333,
                257,
                item_id_offset=36,
                quantity_added_offset=40,
                destination_instance_offset=71,
                context_offset=27,
                record_count_offset=16,
            ),
        ),
        ignored=(),
        frames_scanned=1,
        retention=CalibrationRetention(1, 1, 0, 0, 0, 0),
    )

    with pytest.raises(
        CalibrationAuthorityError,
        match="SOURCE_STACK_DECREMENT",
    ):
        update_profile(incomplete, path)

    assert path.read_text(encoding="utf-8") == original
    assert tuple(tmp_path.iterdir()) == (path,)


def test_profile_dedupe_includes_context_and_inventory_slot(tmp_path):
    first = MessageSpec(
        "INVENTORY_TRANSFER",
        0x1234,
        50,
        item_id_offset=10,
        quantity_offset=14,
        context_offset=5,
        inventory_slot_offset=9,
    )
    second = MessageSpec(
        "INVENTORY_TRANSFER",
        0x1234,
        50,
        item_id_offset=10,
        quantity_offset=14,
        context_offset=6,
        inventory_slot_offset=8,
    )

    update = update_profile([first, second], tmp_path / "opcodes.json")

    assert len(update.added) == 2


def test_advanced_loot_merge_rejects_ambiguity_before_backup_or_write(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    first = MessageSpec(
        "LOOT_PREVIEW",
        0x1643,
        244,
        item_id_offset=23,
        quantity_offset=27,
        item_instance_offset=58,
    )
    second = MessageSpec(
        "LOOT_PREVIEW",
        0x1643,
        244,
        item_id_offset=23,
        quantity_offset=27,
        item_instance_offset=66,
    )
    update_profile([first], profile_path)
    original = profile_path.read_bytes()

    with pytest.raises(ProfileError, match="replace the LOOT_PREVIEW family"):
        update_profile([second], profile_path, replace=False)

    assert profile_path.read_bytes() == original
    assert not (tmp_path / "opcodes_backups").exists()

    replacement = update_profile([second], profile_path, backup=False)
    loaded = event_specs_from_profile(load_opcode_profile(profile_path))

    assert replacement.written
    assert [spec.item_instance_offset for spec in loaded.specs] == [66]


def test_profile_update_does_not_runtime_validate_incomplete_nonloot_specs(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    incomplete_evidence = MessageSpec(
        "STORAGE_ITEM_DELTA",
        0x126D,
        257,
    )

    update = update_profile([incomplete_evidence], profile_path, backup=False)
    written = json.loads(profile_path.read_text(encoding="utf-8"))

    assert update.written
    assert written["specs"]["STORAGE_ITEM_DELTA"] == [
        incomplete_evidence.to_json_dict()
    ]


def test_profile_records_calibration_item_and_uses_unique_backups(tmp_path):
    path = tmp_path / "opcodes.json"
    path.write_text(
        json.dumps({"version": 1, "profile_active": True, "specs": {}}),
        encoding="utf-8",
    )
    first_result = CalibrationResult(
        (MessageSpec("LOOT_PREVIEW", 1, 50, item_id_offset=5, quantity_offset=9),),
        (),
        1,
        calibration_item_id=99123,
        retention=CalibrationRetention(1, 1, 0, 0, 0, 0),
    )
    first = update_profile(first_result, path)
    second = update_profile(
        [MessageSpec("LOOT_PREVIEW", 2, 50, item_id_offset=5, quantity_offset=9)],
        path,
    )

    assert first.backup_path is not None
    assert second.backup_path is not None
    assert first.backup_path != second.backup_path
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["calibration_item_id"] == 99123
    assert not list(tmp_path.glob(".*.tmp"))


requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(), reason="local pcap fixtures not present (private captures)",
)


@requires_fixtures
def test_update_profile_explicit_merge_deduplicates_and_backs_up(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    profile_path.write_text(
        json.dumps(
            {
                "version": 1,
                "updated_at": "2026-01-01T00:00:00",
                "calibration_item_id": 7003,
                "specs": {"LOOT_PREVIEW": []},
            }
        ),
        encoding="utf-8",
    )

    result = calibrate_pcap(
        fixture_path("loot_window_potato_3_new.pcapng"),
        item_id=7003,
        quantity=3,
        action="loot-preview",
    )
    update = update_profile(
        result, profile_path, action="loot-preview", replace=False
    )

    assert len(update.added) == 1
    assert update.backup_path is not None and update.backup_path.exists()

    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert data["profile_active"] is True
    entry = data["specs"]["LOOT_PREVIEW"][0]
    assert entry["opcode"] == "0x1643"
    assert entry["item_id_offset"] == 23
    assert entry["quantity_offset"] == 27

    # Re-applying the same specs is a no-op thanks to dedupe keys.
    second = update_profile(
        result, profile_path, action="loot-preview", replace=False
    )
    assert second.added == ()
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert len(data["specs"]["LOOT_PREVIEW"]) == 1


@requires_fixtures
def test_update_profile_default_replaces_stale_action_specs(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    profile_path.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "LOOT_PREVIEW": [
                        {
                            "event": "LOOT_PREVIEW",
                            "opcode": "0x1643",
                            "length": 244,
                            "item_id_offset": 23,
                            "quantity_offset": 27,
                        }
                    ],
                    "INVENTORY_TRANSFER": [
                        {
                            "event": "INVENTORY_TRANSFER",
                            "opcode": "0xDEAD",
                            "length": 99,
                            "item_id_offset": 10,
                            "quantity_offset": 14,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    result = calibrate_pcap(
        fixture_path("new_potato.pcapng"),
        item_id=7003,
        quantity=10,
        action="storage-to-inventory",
    )
    update = update_profile(result, profile_path, action="storage-to-inventory")

    # Reporting names only families that actually contained entries. The
    # newly created container-decrement family was not replaced.
    assert update.replaced_events == ("INVENTORY_TRANSFER",)
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert [entry["opcode"] for entry in data["specs"]["INVENTORY_TRANSFER"]] == [
        "0x0F16"
    ]
    assert [
        entry["opcode"] for entry in data["specs"]["SOURCE_CONTAINER_DECREMENT"]
    ] == ["0x13A5"]
    # Untouched action keeps its entries.
    assert [entry["opcode"] for entry in data["specs"]["LOOT_PREVIEW"]] == ["0x1643"]


def _write_inventory_to_storage_profile(path):
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "LOOT_PREVIEW": [
                        {
                            "event": "LOOT_PREVIEW",
                            "opcode": "0x1643",
                            "length": 244,
                            "item_id_offset": 23,
                            "quantity_offset": 27,
                        }
                    ],
                    "SOURCE_STACK_DECREMENT": [
                        {
                            "event": "SOURCE_STACK_DECREMENT",
                            "opcode": "0x11AD",
                            "length": 47,
                            "quantity_removed_offset": 27,
                        }
                    ],
                    "SOURCE_ITEM_REFERENCE": [
                        {
                            "event": "SOURCE_ITEM_REFERENCE",
                            "opcode": "0x0F63",
                            "length": 23,
                            "item_id_offset": 9,
                        }
                    ],
                    "STORAGE_ITEM_DELTA": [
                        {
                            "event": "STORAGE_ITEM_DELTA",
                            "opcode": "0x126D",
                            "length": 257,
                            "item_id_offset": 36,
                            "quantity_added_offset": 40,
                            "destination_instance_offset": 71,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )


def _partial_storage_delta_result():
    return CalibrationResult(
        (
            MessageSpec(
                "STORAGE_ITEM_DELTA",
                0x2222,
                258,
                item_id_offset=37,
                quantity_added_offset=41,
                destination_instance_offset=72,
            ),
        ),
        (),
        1,
        retention=CalibrationRetention(1, 1, 0, 0, 0, 0),
    )


def test_partial_explicit_action_replaces_only_observed_event_family(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    _write_inventory_to_storage_profile(profile_path)

    update = update_profile(
        _partial_storage_delta_result(),
        profile_path,
        action="inventory-to-storage",
        backup=False,
    )

    assert update.replaced_events == ("STORAGE_ITEM_DELTA",)
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert [
        entry["opcode"] for entry in data["specs"]["SOURCE_STACK_DECREMENT"]
    ] == ["0x11AD"]
    assert [
        entry["opcode"] for entry in data["specs"]["SOURCE_ITEM_REFERENCE"]
    ] == ["0x0F63"]
    assert [
        entry["opcode"] for entry in data["specs"]["STORAGE_ITEM_DELTA"]
    ] == ["0x2222"]


def test_explicit_entire_action_replacement_clears_missing_families(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    _write_inventory_to_storage_profile(profile_path)

    update = update_profile(
        _partial_storage_delta_result(),
        profile_path,
        action="inventory-to-storage",
        replace_entire_action=True,
        backup=False,
    )

    assert update.replaced_events == (
        "SOURCE_STACK_DECREMENT",
        "SOURCE_ITEM_REFERENCE",
        "STORAGE_ITEM_DELTA",
    )
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert data["specs"]["SOURCE_STACK_DECREMENT"] == []
    assert data["specs"]["SOURCE_ITEM_REFERENCE"] == []
    assert [
        entry["opcode"] for entry in data["specs"]["STORAGE_ITEM_DELTA"]
    ] == ["0x2222"]
    assert [entry["opcode"] for entry in data["specs"]["LOOT_PREVIEW"]] == [
        "0x1643"
    ]


def test_entire_action_replacement_cannot_be_combined_with_merge(tmp_path):
    with pytest.raises(ValueError, match="replace_entire_action"):
        update_profile(
            _partial_storage_delta_result(),
            tmp_path / "opcodes.json",
            action="inventory-to-storage",
            replace=False,
            replace_entire_action=True,
        )


def test_reset_profile_writes_empty_active_profile(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    profile_path.write_text("{}", encoding="utf-8")

    backup = reset_profile(profile_path)
    assert backup is not None and backup.exists()

    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert data["profile_active"] is True
    assert data["calibration_item_id"] == 15156
    assert all(not entries for entries in data["specs"].values())

    profile = event_specs_from_profile(load_opcode_profile(profile_path))
    assert profile.active
    assert profile.specs == ()


def test_reset_profile_accepts_explicit_metadata_item_override(tmp_path):
    profile_path = tmp_path / "opcodes.json"

    assert reset_profile(profile_path, 7003, backup=False) is None

    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert data["calibration_item_id"] == 7003
