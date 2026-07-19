"""Calibration tests mirroring the legacy prototype's expected discoveries."""

import json

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit import PacketCaptureOptions
from bdo_toolkit import _capture_backend as capture_backend
from bdo_toolkit.calibration import (
    CalibrationSession,
    calibrate_pcap,
    reset_profile,
    update_profile,
)
from bdo_toolkit._specs import load_spec_profile

requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
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
        fixture_path("loot_window_potato_3_new.pcapng"),
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
        fixture_path("new_potato.pcapng"),
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
        fixture_path("potato_qty6.pcapng"),
        item_id=7003,
        quantity=6,
        action="storage-to-inventory",
    )

    specs = _specs_by_event(result)
    transfer = specs["INVENTORY_TRANSFER"][0]
    assert (transfer.opcode, transfer.length) == (0x0F16, 255)
    decrement = specs["SOURCE_CONTAINER_DECREMENT"][0]
    assert (decrement.opcode, decrement.length) == (0x13A5, 40)
    assert decrement.context_offset == 7
    assert decrement.quantity_removed_offset == 32
    # This capture's source instance differs from the receipt instance. The
    # legacy instance + separator + quantity shape still proves its offset.
    assert decrement.source_instance_offset == 23


@requires_fixtures
def test_calibration_accepts_total_quantity_for_unstackable_multi_record_transfer():
    result = calibrate_pcap(
        fixture_path("hit_1_5_unstackable.pcapng"),
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
        fixture_path("hit_1_5_unstackable.pcapng"),
        item_id=1000306,
        quantity=5,
        action="storage-to-inventory",
    )
    profile_path = tmp_path / "opcodes.json"
    update_profile(result, profile_path, action="storage-to-inventory", backup=False)

    multi = list(
        replay_pcap(fixture_path("hit_1_5_unstackable.pcapng"), opcode_profile=profile_path)
    )
    single = list(replay_pcap(fixture_path("new_potato.pcapng"), opcode_profile=profile_path))
    assert len(multi) == 5
    assert [(e.item_id, e.quantity) for e in single] == [(7003, 10)]


@requires_fixtures
def test_storage_to_inventory_calibration_rejects_storage_delta_family():
    # Declared storage-to-inventory on an inventory-to-storage capture must
    # refuse loudly (symmetric with the inverse case), not return empty.
    from bdo_toolkit.calibration import DirectionMismatchError

    with pytest.raises(DirectionMismatchError, match="inventory-to-storage"):
        calibrate_pcap(
            fixture_path("new_potato_3_tostorage.pcapng"),
            item_id=7003,
            quantity=3,
            action="storage-to-inventory",
        )


@requires_fixtures
def test_calibration_discovers_current_inventory_to_storage():
    result = calibrate_pcap(
        fixture_path("new_potato_3_tostorage.pcapng"),
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
        fixture_path("potato_leaving_inventory_qty20.pcapng"),
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
@pytest.mark.parametrize(
    (
        "fixture_name",
        "item_id",
        "quantity",
        "expected_opcode",
        "expected_length",
        "expected_instance_offset",
        "expected_quantity_offset",
    ),
    [
        ("new_potato_1_1_1.pcapng", 7003, 1, 0x1A32, 52, 34, 42),
        ("potato_leaving_inventory_qty10.pcapng", 7003, 10, 0x13ED, 45, 29, 37),
        ("potato_7_3_to_storage.pcapng", 7003, 7, 0x13ED, 45, 29, 37),
        ("new_item_to_storage_13_42.pcapng", 44195, 42, 0x13ED, 45, 29, 37),
    ],
)
def test_calibration_preserves_legacy_stack_layout_when_instances_differ(
    fixture_name,
    item_id,
    quantity,
    expected_opcode,
    expected_length,
    expected_instance_offset,
    expected_quantity_offset,
):
    result = calibrate_pcap(
        fixture_path(fixture_name),
        item_id=item_id,
        quantity=quantity,
        action="inventory-to-storage",
    )

    stack = _specs_by_event(result)["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length) == (expected_opcode, expected_length)
    assert stack.source_instance_offset == expected_instance_offset
    assert stack.quantity_removed_offset == expected_quantity_offset


@requires_fixtures
@pytest.mark.parametrize(
    "fixture_name",
    [
        "calibration_5_inven_0_storage.pcapng",
        "calibration_to_different_inventory_through_remote.pcapng",
    ],
)
def test_calibration_discovers_all_current_patch_transfer_specs(fixture_name):
    result = calibrate_pcap(
        fixture_path(fixture_name),
        item_id=7003,
        quantity=5,
    )

    specs = _specs_by_event(result)
    assert set(specs) == {
        "INVENTORY_TRANSFER",
        "SOURCE_CONTAINER_DECREMENT",
        "SOURCE_STACK_DECREMENT",
        "SOURCE_ITEM_REFERENCE",
        "STORAGE_ITEM_DELTA",
    }

    transfer = specs["INVENTORY_TRANSFER"][0]
    assert (transfer.opcode, transfer.length) == (0x194A, 254)
    assert (transfer.item_id_offset, transfer.quantity_offset) == (31, 35)
    assert transfer.item_instance_offset == 66
    assert transfer.context_offset == 27

    container = specs["SOURCE_CONTAINER_DECREMENT"][0]
    assert (container.opcode, container.length) == (0x17E8, 42)
    assert container.context_offset == 13
    assert container.source_instance_offset == 5
    assert container.quantity_removed_offset == 17

    stack = specs["SOURCE_STACK_DECREMENT"][0]
    assert (stack.opcode, stack.length) == (0x11AD, 47)
    assert stack.source_instance_offset == 35
    assert stack.quantity_removed_offset == 27

    reference = specs["SOURCE_ITEM_REFERENCE"][0]
    assert (reference.opcode, reference.length) == (0x0F63, 23)
    assert reference.item_id_offset == 9

    delta = specs["STORAGE_ITEM_DELTA"][0]
    assert (delta.opcode, delta.length) == (0x126D, 257)
    assert (delta.item_id_offset, delta.quantity_added_offset) == (36, 40)
    assert delta.destination_instance_offset == 71


def test_stack_companion_fallback_rejects_incidental_pre_quantity_bytes():
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import (
        _CalibratedItemRecord,
        _Options,
        _discover_source_stack_decrement,
    )

    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)

    def frame(index, opcode, message):
        message[0:2] = len(message).to_bytes(2, "little")
        message[3:5] = opcode.to_bytes(2, "little")
        return BDOFrame(
            index=index,
            message=bytes(message),
            context=PacketContext(1000.0 + index, flow),
            stream_sequence=index,
        )

    quantity = 5
    item_id = 7003
    target_instance = bytes.fromhex("1122334455667788")

    decrement_message = bytearray(47)
    decrement_message[19:27] = bytes.fromhex("00000000be5b0500")
    decrement_message[27:31] = quantity.to_bytes(4, "little")
    # A current-layout source instance follows the quantity and zero gap. It
    # differs from the destination instance, while unrelated nonzero bytes at
    # q-8 reproduce the false offset 19 seen in the remote capture.
    decrement_message[35:43] = bytes.fromhex("0102030405060708")
    decrement_message[43:47] = bytes.fromhex("002bff00")
    decrement = frame(0, 0xBEEF, decrement_message)

    reference_message = bytearray(23)
    reference_message[9:13] = item_id.to_bytes(4, "little")
    reference = frame(1, 0xCAFE, reference_message)

    delta_message = bytearray(257)
    delta_message[36:40] = item_id.to_bytes(4, "little")
    delta_message[40:44] = quantity.to_bytes(4, "little")
    delta_message[71:79] = target_instance
    delta = frame(2, 0xFACE, delta_message)
    record = _CalibratedItemRecord(
        frame=delta,
        item_offset=36,
        item_id=item_id,
        quantity=quantity,
        instance_offset=71,
        instance=target_instance,
        confidence=0.95,
        reasons=(),
    )
    options = _Options(item_id, quantity, "auto", 5, 0.80)

    spec = _discover_source_stack_decrement(
        [decrement, reference, delta], record, options
    )

    assert spec is not None
    assert (spec.opcode, spec.length, spec.quantity_removed_offset) == (
        0xBEEF,
        47,
        27,
    )
    assert spec.source_instance_offset == 35


@pytest.mark.parametrize(
    ("layout", "expected_context", "expected_instance", "expected_quantity"),
    [
        ("current", 13, 5, 17),
        ("legacy-different-instance", 7, 23, 32),
    ],
)
def test_container_companion_discovers_both_known_field_orders(
    layout,
    expected_context,
    expected_instance,
    expected_quantity,
):
    from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
    from bdo_toolkit.calibration import (
        _CalibratedItemRecord,
        _Options,
        _discover_source_container_decrement,
    )

    flow = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)

    def frame(index, opcode, message):
        message[0:2] = len(message).to_bytes(2, "little")
        message[3:5] = opcode.to_bytes(2, "little")
        return BDOFrame(
            index=index,
            message=bytes(message),
            context=PacketContext(1000.0 + index, flow),
            stream_sequence=index,
        )

    quantity = 5
    item_id = 7003
    receipt_instance = bytes.fromhex("1122334455667788")
    source_context = bytes.fromhex("d0f205a3")

    if layout == "current":
        companion_message = bytearray(42)
        companion_message[5:13] = receipt_instance
        companion_message[13:17] = source_context
        companion_message[17:21] = quantity.to_bytes(4, "little")
    else:
        companion_message = bytearray(40)
        companion_message[7:11] = source_context
        companion_message[23:31] = bytes.fromhex("0102030405060708")
        companion_message[31] = 0x02
        companion_message[32:36] = quantity.to_bytes(4, "little")
    companion = frame(0, 0xBEEF, companion_message)

    receipt_frame = frame(1, 0xCAFE, bytearray(80))
    receipt = _CalibratedItemRecord(
        frame=receipt_frame,
        item_offset=31,
        item_id=item_id,
        quantity=quantity,
        instance_offset=66,
        instance=receipt_instance,
        confidence=0.95,
        reasons=(),
    )
    options = _Options(item_id, quantity, "auto", 5, 0.80)

    spec = _discover_source_container_decrement(
        [companion, receipt_frame], receipt, options
    )

    assert spec is not None
    assert (spec.opcode, spec.length) == (0xBEEF, len(companion_message))
    assert spec.context_offset == expected_context
    assert spec.source_instance_offset == expected_instance
    assert spec.quantity_removed_offset == expected_quantity


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
        fixture_path("new_potato_3_tostorage.pcapng"),
        item_id=7003,
        quantity=3,
        action="inventory-to-storage",
    )
    update_profile(result, profile_path, action="inventory-to-storage")

    events = list(
        replay_pcap(
            fixture_path("new_potato_3_tostorage.pcapng"),
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
    session = CalibrationSession(item_id=7003)
    assert not session.running
    assert session.frames_collected == 0

    # stop() before start() is a usage error, not a silent empty result
    import pytest

    with pytest.raises(RuntimeError, match="not started"):
        session.stop()


def test_calibration_session_uses_shared_packet_capture_options(monkeypatch):
    class FakeSniffer:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.__class__.instances.append(self)

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

    monkeypatch.setattr(
        capture_backend,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeSniffer)

    session = CalibrationSession(
        item_id=7003,
        capture_options=PacketCaptureOptions(
            interface="test-interface",
            ports=(9000,),
            use_bpf=False,
            auto_local_ip=False,
        ),
    )
    session.start()

    sniffer = FakeSniffer.instances[-1]
    assert sniffer.kwargs["iface"] == "test-interface"
    assert sniffer.kwargs["filter"] is None
    assert callable(sniffer.kwargs["lfilter"])
    session.stop()


def test_calibration_session_rejects_wrong_capture_options_type():
    with pytest.raises(TypeError, match="PacketCaptureOptions"):
        CalibrationSession(item_id=7003, capture_options=object())


def test_calibration_session_can_disable_automatic_local_ip(monkeypatch):
    class FakeSniffer:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.__class__.instances.append(self)

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

    monkeypatch.setattr(
        capture_backend,
        "import_scapy",
        lambda: (object(), object(), None, None, None),
    )
    monkeypatch.setattr(
        capture_backend,
        "detect_default_capture_target",
        lambda: capture_backend.CaptureTarget(
            interface="default-interface",
            local_ip="192.0.2.25",
            gateway="192.0.2.1",
        ),
    )
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeSniffer)

    session = CalibrationSession(
        item_id=7003,
        capture_options=PacketCaptureOptions(auto_local_ip=False),
    )
    session.start()

    sniffer = FakeSniffer.instances[-1]
    assert sniffer.kwargs["iface"] == "default-interface"
    assert "dst host" not in sniffer.kwargs["filter"]
    session.stop()
