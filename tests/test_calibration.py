"""Calibration tests mirroring the legacy prototype's expected discoveries."""

import json
from pathlib import Path

import pytest

from bdo_toolkit.calibration import (
    calibrate_pcap,
    reset_profile,
    update_profile,
)
from bdo_toolkit._specs import load_spec_profile

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

requires_fixtures = pytest.mark.skipif(
    not FIXTURE_DIR.exists() or not any(FIXTURE_DIR.glob("*.pcapng")),
    reason="local pcap fixtures not present (private captures)",
)


def _specs_by_event(result):
    output = {}
    for spec in result.specs:
        output.setdefault(spec.event, []).append(spec)
    return output


@requires_fixtures
def test_calibration_discovers_current_patch_loot_preview():
    result = calibrate_pcap(
        FIXTURE_DIR / "loot_window_potato_3_new.pcapng",
        item_id=7003,
        quantity=3,
        action="loot-preview",
    )

    specs = _specs_by_event(result)["LOOT_PREVIEW"]
    assert len(specs) == 1
    spec = specs[0]
    assert (spec.opcode, spec.length) == (0x1643, 244)
    assert (spec.item_id_offset, spec.quantity_offset) == (23, 27)
    assert spec.item_instance_offset == 58


@requires_fixtures
def test_calibration_discovers_current_storage_to_inventory():
    result = calibrate_pcap(
        FIXTURE_DIR / "new_potato.pcapng",
        item_id=7003,
        quantity=10,
        action="storage-to-inventory",
    )

    specs = _specs_by_event(result)
    transfer = specs["INVENTORY_TRANSFER"][0]
    assert (transfer.opcode, transfer.length) == (0x0F16, 255)
    assert (transfer.item_id_offset, transfer.quantity_offset) == (33, 37)
    assert transfer.item_instance_offset == 68
    assert transfer.context_offset == 23

    decrement = specs["SOURCE_CONTAINER_DECREMENT"][0]
    assert (decrement.opcode, decrement.length) == (0x13A5, 40)
    assert decrement.context_offset == 7
    assert decrement.source_instance_offset == 23
    assert decrement.quantity_removed_offset == 32


@requires_fixtures
def test_calibration_storage_to_inventory_with_changed_source_instance():
    result = calibrate_pcap(
        FIXTURE_DIR / "potato_qty6.pcapng",
        item_id=7003,
        quantity=6,
        action="storage-to-inventory",
    )

    specs = _specs_by_event(result)
    transfer = specs["INVENTORY_TRANSFER"][0]
    assert (transfer.opcode, transfer.length) == (0x0F16, 255)
    decrement = specs["SOURCE_CONTAINER_DECREMENT"][0]
    assert (decrement.opcode, decrement.length) == (0x13A5, 40)


@requires_fixtures
def test_calibration_accepts_total_quantity_for_unstackable_multi_record_transfer():
    result = calibrate_pcap(
        FIXTURE_DIR / "hit_1_5_unstackable.pcapng",
        item_id=1000306,
        quantity=5,
        action="storage-to-inventory",
    )

    specs = _specs_by_event(result)
    transfer = specs["INVENTORY_TRANSFER"][0]
    # length is normalized to the SINGLE-record frame length (1167 - 4*228):
    # the profile loader treats it as a minimum, so recording the observed
    # multi-record length would block ordinary single transfers.
    assert (transfer.opcode, transfer.length) == (0x0F16, 255)
    assert transfer.repeat_stride == 228
    assert transfer.item_id_offset == 33
    assert transfer.quantity_offset == 37


@requires_fixtures
def test_profile_from_unstackable_calibration_decodes_single_transfers(tmp_path):
    """End-to-end guard for the multi-record length-poisoning bug."""
    from bdo_toolkit import replay_pcap

    result = calibrate_pcap(
        FIXTURE_DIR / "hit_1_5_unstackable.pcapng",
        item_id=1000306,
        quantity=5,
        action="storage-to-inventory",
    )
    profile_path = tmp_path / "opcodes.json"
    update_profile(result, profile_path, action="storage-to-inventory", backup=False)

    multi = list(
        replay_pcap(FIXTURE_DIR / "hit_1_5_unstackable.pcapng", opcode_profile=profile_path)
    )
    single = list(replay_pcap(FIXTURE_DIR / "new_potato.pcapng", opcode_profile=profile_path))
    assert len(multi) == 5
    assert [(e.item_id, e.quantity) for e in single] == [(7003, 10)]


@requires_fixtures
def test_storage_to_inventory_calibration_rejects_storage_delta_family():
    # Declared storage-to-inventory on an inventory-to-storage capture must
    # refuse loudly (symmetric with the inverse case), not return empty.
    from bdo_toolkit.calibration import DirectionMismatchError

    with pytest.raises(DirectionMismatchError, match="inventory-to-storage"):
        calibrate_pcap(
            FIXTURE_DIR / "new_potato_3_tostorage.pcapng",
            item_id=7003,
            quantity=3,
            action="storage-to-inventory",
        )


@requires_fixtures
def test_calibration_discovers_current_inventory_to_storage():
    result = calibrate_pcap(
        FIXTURE_DIR / "new_potato_3_tostorage.pcapng",
        item_id=7003,
        quantity=3,
        action="inventory-to-storage",
    )

    specs = _specs_by_event(result)
    stack = specs["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length) == (0x1A32, 52)
    assert stack.source_instance_offset == 34
    assert stack.quantity_removed_offset == 42

    reference = specs["SOURCE_ITEM_REFERENCE"][0]
    assert (reference.opcode, reference.length) == (0x0C3B, 24)
    assert reference.item_id_offset == 10

    delta = specs["STORAGE_ITEM_DELTA"][0]
    assert (delta.opcode, delta.length) == (0x0E6A, 261)
    assert (delta.item_id_offset, delta.quantity_added_offset) == (37, 41)
    assert delta.destination_instance_offset == 72


@requires_fixtures
def test_calibration_still_discovers_old_inventory_to_storage():
    result = calibrate_pcap(
        FIXTURE_DIR / "potato_leaving_inventory_qty20.pcapng",
        item_id=7003,
        quantity=20,
        action="inventory-to-storage",
    )

    specs = _specs_by_event(result)
    stack = specs["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length) == (0x13ED, 45)
    assert stack.source_instance_offset == 29
    assert stack.quantity_removed_offset == 37

    reference = specs["SOURCE_ITEM_REFERENCE"][0]
    assert (reference.opcode, reference.length) == (0x1358, 28)
    assert reference.item_id_offset == 24

    delta = specs["STORAGE_ITEM_DELTA"][0]
    assert (delta.opcode, delta.length) == (0x1B6A, 264)
    assert (delta.item_id_offset, delta.quantity_added_offset) == (43, 47)
    assert delta.destination_instance_offset == 78


@requires_fixtures
def test_update_profile_merges_and_backs_up(tmp_path):
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
        FIXTURE_DIR / "loot_window_potato_3_new.pcapng",
        item_id=7003,
        quantity=3,
        action="loot-preview",
    )
    update = update_profile(result, profile_path, action="loot-preview")

    assert len(update.added) == 1
    assert update.backup_path is not None and update.backup_path.exists()

    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert data["profile_active"] is True
    entry = data["specs"]["LOOT_PREVIEW"][0]
    assert entry["opcode"] == "0x1643"
    assert entry["item_id_offset"] == 23
    assert entry["quantity_offset"] == 27

    # Re-applying the same specs is a no-op thanks to dedupe keys.
    second = update_profile(result, profile_path, action="loot-preview")
    assert second.added == ()
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert len(data["specs"]["LOOT_PREVIEW"]) == 1


@requires_fixtures
def test_update_profile_replace_clears_stale_action_specs(tmp_path):
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
        FIXTURE_DIR / "new_potato.pcapng",
        item_id=7003,
        quantity=10,
        action="storage-to-inventory",
    )
    update = update_profile(
        result, profile_path, action="storage-to-inventory", replace=True
    )

    assert set(update.replaced_events) == {
        "INVENTORY_TRANSFER",
        "SOURCE_CONTAINER_DECREMENT",
    }
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert [entry["opcode"] for entry in data["specs"]["INVENTORY_TRANSFER"]] == [
        "0x0F16"
    ]
    assert [
        entry["opcode"] for entry in data["specs"]["SOURCE_CONTAINER_DECREMENT"]
    ] == ["0x13A5"]
    # Untouched action keeps its entries.
    assert [entry["opcode"] for entry in data["specs"]["LOOT_PREVIEW"]] == ["0x1643"]


@requires_fixtures
def test_calibrated_profile_round_trips_into_decoder_specs(tmp_path):
    """End-to-end: calibrate -> write profile -> decode with it."""
    from bdo_toolkit import replay_pcap

    profile_path = tmp_path / "opcodes.json"
    result = calibrate_pcap(
        FIXTURE_DIR / "new_potato_3_tostorage.pcapng",
        item_id=7003,
        quantity=3,
        action="inventory-to-storage",
    )
    update_profile(result, profile_path, action="inventory-to-storage")

    events = list(
        replay_pcap(
            FIXTURE_DIR / "new_potato_3_tostorage.pcapng",
            opcode_profile=profile_path,
        )
    )
    assert [(event.event_type, event.item_id, event.quantity) for event in events] == [
        ("storage_delta", 7003, 3)
    ]


def test_reset_profile_writes_empty_active_profile(tmp_path):
    profile_path = tmp_path / "opcodes.json"
    profile_path.write_text("{}", encoding="utf-8")

    backup = reset_profile(profile_path, 7003)
    assert backup is not None and backup.exists()

    data = json.loads(profile_path.read_text(encoding="utf-8"))
    assert data["profile_active"] is True
    assert all(not entries for entries in data["specs"].values())

    profile = load_spec_profile(profile_path)
    assert profile.active
    assert profile.specs == ()


def test_calibration_session_guards_lifecycle():
    from bdo_toolkit.calibration import CalibrationSession

    session = CalibrationSession(item_id=7003)
    assert not session.running
    assert session.frames_collected == 0

    # stop() before start() is a usage error, not a silent empty result
    import pytest

    with pytest.raises(RuntimeError, match="not started"):
        session.stop()
