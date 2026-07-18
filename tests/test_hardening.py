"""Synthetic regressions for public API and transport hardening."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bdo_toolkit import (
    BDOEvent,
    EventFilter,
    Flow,
    ProfileError,
    load_opcode_profile,
    replay_pcap,
)
from bdo_toolkit import capture as capture_module
from bdo_toolkit._capture_backend import import_scapy
from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._protocol import BDOFrame, EventSpec, FlowKey, PacketContext
from bdo_toolkit._specs import load_spec_profile
from bdo_toolkit.calibration import (
    CalibrationResult,
    DirectionMismatchError,
    MessageSpec,
    calibrate_frames,
    update_profile,
)
from bdo_toolkit import calibration as calibration_module


def _loot_preview_frame(item_id: int = 7003, quantity: int = 3) -> bytes:
    message = bytearray(244)
    message[0:2] = (244).to_bytes(2, "little")
    message[3:5] = (0x1643).to_bytes(2, "little")
    message[23:27] = item_id.to_bytes(4, "little")
    message[27:31] = quantity.to_bytes(4, "little")
    return bytes(message)


SYNTHETIC_EVENT_SPECS = (
    EventSpec(
        label="LOOT_PREVIEW",
        opcode=0x1643,
        item_offset=23,
        quantity_offset=27,
        min_message_length=31,
        default_context="Gathering",
    ),
    EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x0E6A,
        item_offset=37,
        quantity_offset=41,
        min_message_length=80,
        source_context_offset=8,
        storage_instance_offset=72,
        repeat_stride=226,
        single_record_message_length=261,
        default_context="Storage",
    ),
)


def _engine(events: list) -> PacketEngine:
    return PacketEngine(
        server_ports=(8889,),
        event_specs=SYNTHETIC_EVENT_SPECS,
        on_event=lambda event, raw: events.append(event),
    )


def _segment(
    engine: PacketEngine,
    sequence: int,
    payload: bytes,
    *,
    fin: bool = False,
    syn: bool = False,
) -> None:
    engine.process_tcp_segment(
        source_ip="203.0.113.1",
        source_port=8889,
        destination_ip="198.51.100.2",
        destination_port=50000,
        sequence=sequence,
        payload=payload,
        timestamp=1000.0,
        fin=fin,
        syn=syn,
    )


def _storage_frame(
    *,
    opcode: int = 0x9999,
    item_id: int = 99123,
    quantity: int = 3,
    contradictory: bool = False,
) -> BDOFrame:
    length = 261
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    if contradictory:
        message[20:24] = bytes.fromhex("d0f205a3")
    message[37:41] = item_id.to_bytes(4, "little")
    message[41:45] = quantity.to_bytes(4, "little")
    message[72:80] = b"\x22" * 8
    return BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000),
        ),
        stream_sequence=100,
    )


def test_replay_yields_before_processing_the_next_packet(monkeypatch):
    progress: list[str] = []

    def fake_iter(path: Path, engine: PacketEngine):
        _segment(engine, 1000, _loot_preview_frame(7003, 1))
        progress.append("first")
        yield None
        progress.append("second")
        _segment(engine, 2000, _loot_preview_frame(7004, 1))
        yield None
        engine.finish()

    monkeypatch.setattr(capture_module, "iter_pcap_file", fake_iter)
    events = replay_pcap("unused.pcapng")
    assert next(events).item_id == 7003
    assert progress == ["first"]
    events.close()


def test_callback_collector_does_not_retain_delivered_events():
    delivered: list[BDOEvent] = []
    collector = capture_module._EventCollector(
        server_ports=(8889,),
        on_event=delivered.append,
    )
    event = BDOEvent("test", 0.0, Flow("a", 1, "b", 2), 1, 1)

    collector._deliver(event)

    assert delivered == [event]
    assert list(collector.drain_events()) == []


def test_fin_drains_a_complete_segment_pending_after_a_gap():
    events: list = []
    engine = _engine(events)
    _segment(engine, 1000, b"prefix")
    _segment(engine, 2000, _loot_preview_frame(), fin=True)
    engine.finish()

    assert [(event.item_id, event.quantity) for event in events] == [(7003, 3)]


def test_fragmented_frame_reassembles_across_tcp_sequence_wrap():
    events: list = []
    engine = _engine(events)
    message = _loot_preview_frame()
    _segment(engine, 0xFFFFFFF0, message[:16])
    _segment(engine, 0, message[16:])
    engine.finish()

    assert [(event.item_id, event.quantity) for event in events] == [(7003, 3)]


def test_syn_sequence_number_is_consumed_before_payload():
    events: list = []
    engine = _engine(events)
    message = _loot_preview_frame()
    _segment(engine, 1000, message[:10], syn=True)
    _segment(engine, 1011, message[10:])
    engine.finish()

    assert len(events) == 1


def test_storage_batch_above_old_4096_byte_limit_decodes_all_records():
    count = 18
    length = 35 + 226 * count
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x0E6A).to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    for index in range(count):
        offset = 37 + 226 * index
        message[offset : offset + 4] = (7003 + index).to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (1).to_bytes(4, "little")
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")

    events: list = []
    engine = _engine(events)
    _segment(engine, 1, bytes(message))
    engine.finish()

    assert len(events) == count


def test_invalid_capture_is_value_error_and_does_not_remain_locked(tmp_path):
    capture = tmp_path / "invalid.pcapng"
    capture.write_bytes(b"not a capture")

    with pytest.raises(ValueError, match="Could not read capture"):
        list(replay_pcap(capture))

    capture.unlink()
    assert not capture.exists()


def test_import_scapy_does_not_mutate_global_ipv6_setting():
    from scapy.config import conf

    previous = conf.ipv6_enabled
    try:
        conf.ipv6_enabled = True
        import_scapy()
        assert conf.ipv6_enabled is True
    finally:
        conf.ipv6_enabled = previous


def test_explicit_calibration_refuses_contradictory_intrinsics():
    frame = _storage_frame(contradictory=True)

    with pytest.raises(DirectionMismatchError, match="contradictory"):
        calibrate_frames(
            [frame],
            item_id=99123,
            quantity=3,
            action="inventory-to-storage",
        )


def test_post_patch_storage_profile_keeps_context_and_stride(tmp_path):
    frame = _storage_frame(opcode=0x9999)
    result = calibrate_frames(
        [frame],
        item_id=99123,
        quantity=3,
        action="inventory-to-storage",
    )
    delta = next(spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA")

    assert delta.context_offset == 8
    assert delta.repeat_stride == 226

    profile_path = tmp_path / "nested" / "opcodes.json"
    update_profile(result, profile_path, action="inventory-to-storage")
    loaded = load_spec_profile(profile_path)
    decode_spec = next(spec for spec in loaded.specs if spec.opcode == 0x9999)
    assert decode_spec.source_context_offset == 8
    assert decode_spec.repeat_stride == 226

    message = bytearray(487)
    message[0:2] = (487).to_bytes(2, "little")
    message[3:5] = (0x9999).to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    for index, item_id in enumerate((99123, 99124)):
        offset = 37 + 226 * index
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (1).to_bytes(4, "little")
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")
    decoded: list = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=loaded.specs,
        on_event=lambda event, raw: decoded.append(event),
    )
    _segment(engine, 1, bytes(message))
    engine.finish()
    assert [event.item_id for event in decoded] == [99123, 99124]


def test_post_patch_profile_uses_its_own_single_record_lengths(tmp_path):
    """A patch may change wrapper bytes without changing record offsets/stride."""
    profile_path = tmp_path / "opcodes.local"
    update_profile(
        [
            MessageSpec(
                event="INVENTORY_TRANSFER",
                opcode=0x1AAE,
                length=254,
                item_id_offset=33,
                quantity_offset=37,
                item_instance_offset=68,
                context_offset=24,
                repeat_stride=228,
            ),
            MessageSpec(
                event="STORAGE_ITEM_DELTA",
                opcode=0x0D7E,
                length=258,
                item_id_offset=37,
                quantity_added_offset=41,
                destination_instance_offset=72,
                context_offset=8,
            ),
        ],
        profile_path,
        backup=False,
    )
    loaded = load_spec_profile(profile_path, missing_ok=False)
    by_label = {spec.label: spec for spec in loaded.specs}

    assert by_label["INVENTORY_TRANSFER"].single_record_message_length == 254
    assert by_label["INVENTORY_TO_STORAGE"].repeat_stride is None
    assert by_label["INVENTORY_TO_STORAGE"].single_record_message_length == 258

    inventory = bytearray(254)
    inventory[0:2] = (254).to_bytes(2, "little")
    inventory[3:5] = (0x1AAE).to_bytes(2, "little")
    inventory[24:28] = bytes.fromhex("d0f205a3")
    inventory[33:37] = (7003).to_bytes(4, "little")
    inventory[37:41] = (5).to_bytes(4, "little")
    inventory[68:76] = b"\x11" * 8

    storage = bytearray(258)
    storage[0:2] = (258).to_bytes(2, "little")
    storage[3:5] = (0x0D7E).to_bytes(2, "little")
    storage[8:12] = bytes.fromhex("05000000")
    storage[37:41] = (7003).to_bytes(4, "little")
    storage[41:45] = (5).to_bytes(4, "little")
    storage[72:80] = b"\x22" * 8

    decoded: list = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=loaded.specs,
        on_event=lambda event, raw: decoded.append(event),
    )
    _segment(engine, 1, bytes(inventory) + bytes(storage))
    engine.finish()

    assert [(event.label, event.item_id, event.quantity) for event in decoded] == [
        ("INVENTORY_TRANSFER", 7003, 5),
        ("INVENTORY_TO_STORAGE", 7003, 5),
    ]


def _july17_structural_batch() -> bytes:
    message = bytearray(479)
    message[0:2] = (479).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 1
    message[7:15] = b"\x31\x41\x59\x26\x53\x58\x97\x93"
    message[16:18] = (2).to_bytes(2, "little")
    message[27:31] = bytes.fromhex("20000000")
    for offset, item_id, quantity, instance_byte in (
        (36, 4802, 1, b"\x11"),
        (258, 4003, 21, b"\x22"),
    ):
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = quantity.to_bytes(4, "little")
        message[offset + 12 : offset + 20] = b"\xff" * 8
        message[offset + 35 : offset + 43] = instance_byte * 8
    return bytes(message)


@pytest.mark.parametrize("saved_stride", [None, 221])
def test_runtime_derives_changed_batch_stride_from_records(saved_stride):
    """A single-record profile must decode a later batch and stale stride."""
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        storage_instance_offset=71,
        repeat_stride=saved_stride,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, _july17_structural_batch())
    engine.finish()

    assert [
        (event.item_id, event.quantity, event.record_index, event.record_count)
        for event in decoded
    ] == [
        (4802, 1, 1, 2),
        (4003, 21, 2, 2),
    ]
    assert {event.storage_id for event in decoded} == {0x20}
    assert {event.storage_operation for event in decoded} == {"live"}


def test_declared_batch_with_invalid_record_instance_fails_closed():
    message = bytearray(_july17_structural_batch())
    # A valid declaration must not allow a corrupt record to be skipped while
    # the remaining records are emitted as a partial batch.
    message[258 + 35 : 258 + 43] = b"\x00" * 8
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_current_wrapper_cannot_fall_back_after_count_geometry_conflicts():
    message = bytearray(_july17_structural_batch())
    # Both records still have the legacy marker. A contradictory declaration
    # must invalidate this current-wrapper frame instead of bypassing the
    # count check through marker recovery.
    message[16:18] = (3).to_bytes(2, "little")
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_current_wrapper_preserves_unfamiliar_operation_mode_as_unknown():
    message = bytearray(_july17_structural_batch())
    message[6] = 3
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert len(decoded) == 2
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_item_minus_nine_context_alone_does_not_disable_legacy_fallback():
    message = bytearray(261)
    message[0:2] = (261).to_bytes(2, "little")
    message[3:5] = (0x0E6A).to_bytes(2, "little")
    message[28:32] = (0x0020).to_bytes(4, "little")
    message[37:41] = (7003).to_bytes(4, "little")
    message[41:45] = (3).to_bytes(4, "little")
    message[45:57] = b"\x00" * 4 + b"\xff" * 8
    message[72:80] = b"\x22" * 8
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x0E6A,
        item_offset=37,
        quantity_offset=41,
        min_message_length=261,
        source_context_offset=28,
        storage_instance_offset=72,
        single_record_message_length=261,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert [(event.item_id, event.quantity) for event in decoded] == [(7003, 3)]
    assert decoded[0].storage_operation is None


def _july17_arehaza_snapshot() -> bytes:
    count = 25
    stride = 222
    length = 35 + count * stride
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 2
    message[16:18] = count.to_bytes(2, "little")
    message[27:31] = (0x02B5).to_bytes(4, "little")

    item_ids = [11, 13, 14, *range(7003, 7025)]
    non_marker_values = (
        bytes.fromhex("5f70f36400000000"),
        bytes.fromhex("1e9a866500000000"),
        bytes.fromhex("b47f926500000000"),
    )
    for index, item_id in enumerate(item_ids):
        offset = 36 + stride * index
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (1).to_bytes(4, "little")
        message[offset + 12 : offset + 20] = (
            non_marker_values[index] if index < 3 else b"\xff" * 8
        )
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")
    return bytes(message)


def test_declared_count_decodes_arehaza_records_without_marker():
    """The first three real Arehaza item types do not carry the FF marker."""
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, _july17_arehaza_snapshot())
    engine.finish()

    assert len(decoded) == 25
    assert [event.item_id for event in decoded[:4]] == [11, 13, 14, 7003]
    assert decoded[0].record_index == 1
    assert decoded[-1].record_index == decoded[-1].record_count == 25
    assert {event.storage_id for event in decoded} == {0x02B5}
    assert {event.storage_operation for event in decoded} == {"snapshot"}


def test_declared_count_length_mismatch_fails_closed_without_markers():
    message = bytearray(_july17_arehaza_snapshot())
    message[16:18] = (24).to_bytes(2, "little")
    decoded: list = []
    spec = EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    _segment(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_calibration_discovers_changed_context_and_mixed_batch_stride(tmp_path):
    message = bytearray(479)
    message[0:2] = (479).to_bytes(2, "little")
    message[3:5] = (0x0D7E).to_bytes(2, "little")
    message[25:29] = bytes.fromhex("20000000")
    for offset, item_id, quantity, instance_byte in (
        (37, 5004, 6, b"\x11"),
        (258, 4604, 25, b"\x22"),
    ):
        message[offset : offset + 4] = item_id.to_bytes(4, "little")
        message[offset + 4 : offset + 8] = quantity.to_bytes(4, "little")
        message[offset + 12 : offset + 20] = b"\xff" * 8
        message[offset + 35 : offset + 43] = instance_byte * 8
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000),
        ),
        stream_sequence=100,
    )

    result = calibrate_frames(
        [frame],
        item_id=5004,
        quantity=6,
        action="inventory-to-storage",
    )
    delta = next(spec for spec in result.specs if spec.event == "STORAGE_ITEM_DELTA")

    assert delta.length == 258
    assert delta.context_offset == 25
    assert delta.repeat_stride == 221

    # Watching the SECOND item in the same mixed batch must still write a
    # first-record profile rather than pinning offsets to record 2.
    second_result = calibrate_frames(
        [frame],
        item_id=4604,
        quantity=25,
        action="inventory-to-storage",
    )
    second_delta = next(
        spec for spec in second_result.specs if spec.event == "STORAGE_ITEM_DELTA"
    )
    assert (
        second_delta.length,
        second_delta.item_id_offset,
        second_delta.quantity_added_offset,
        second_delta.destination_instance_offset,
        second_delta.repeat_stride,
    ) == (258, 37, 41, 72, 221)

    profile_path = tmp_path / "opcodes.local"
    update_profile(result, profile_path, backup=False)
    loaded = load_spec_profile(profile_path, missing_ok=False)
    decoded: list = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=loaded.specs,
        on_event=lambda event, raw: decoded.append(event),
    )
    _segment(engine, 1, bytes(message))
    engine.finish()

    assert [(event.item_id, event.quantity) for event in decoded] == [
        (5004, 6),
        (4604, 25),
    ]


def test_growing_reference_frame_is_persisted():
    record = _storage_frame()
    reference_message = bytearray(54)
    reference_message[0:2] = (54).to_bytes(2, "little")
    reference_message[3:5] = (0x1234).to_bytes(2, "little")
    reference_message[10:14] = (99123).to_bytes(4, "little")
    reference = BDOFrame(
        index=1,
        message=bytes(reference_message),
        context=PacketContext(999.0, record.context.flow),
        stream_sequence=1,
    )

    result = calibrate_frames(
        [reference, record],
        item_id=99123,
        quantity=3,
        action="inventory-to-storage",
    )

    source_ref = next(
        spec for spec in result.specs if spec.event == "SOURCE_ITEM_REFERENCE"
    )
    assert source_ref.length == 54
    assert source_ref.item_id_offset == 10


def test_missing_explicit_profile_does_not_silently_fall_back(tmp_path):
    events = replay_pcap(
        tmp_path / "capture.pcapng",
        opcode_profile=tmp_path / "typo.json",
    )
    with pytest.raises(FileNotFoundError, match="Opcode profile"):
        next(events)


def test_inactive_explicit_profile_fails_instead_of_mixing_authorities(tmp_path):
    profile_path = tmp_path / "inactive.json"
    profile_path.write_text(
        json.dumps({"profile_active": False, "specs": {}}),
        encoding="utf-8",
    )

    assert load_opcode_profile(profile_path).active is False
    events = replay_pcap("unused.pcapng", opcode_profile=profile_path)
    with pytest.raises(ProfileError, match="inactive"):
        next(events)


def test_event_collector_loads_profile_once(monkeypatch):
    real_load = capture_module.load_opcode_profile
    calls = []

    def counted_load(path):
        calls.append(path)
        return real_load(path)

    monkeypatch.setattr(capture_module, "load_opcode_profile", counted_load)
    capture_module._EventCollector(server_ports=(8889,))

    assert len(calls) == 1


def test_empty_profile_update_is_a_true_noop(tmp_path):
    path = tmp_path / "opcodes.json"
    original = '{"sentinel": true}\n'
    path.write_text(original, encoding="utf-8")

    update = update_profile(CalibrationResult((), (), 0), path)

    assert not update.written
    assert update.backup_path is None
    assert path.read_text(encoding="utf-8") == original


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


def test_profile_records_calibration_item_and_uses_unique_backups(tmp_path):
    path = tmp_path / "opcodes.json"
    path.write_text("{}", encoding="utf-8")
    first_result = CalibrationResult(
        (MessageSpec("LOOT_PREVIEW", 1, 50, item_id_offset=5, quantity_offset=9),),
        (),
        1,
        calibration_item_id=99123,
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


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"profile_active": "false", "specs": {}},
        {"version": "one", "specs": {}},
        {"specs": {"INVENTORY_TRANSFER": {}}},
        {
            "specs": {
                "INVENTORY_TRANSFER": [
                    {"event": "LOOT_PREVIEW", "opcode": "0x1234"}
                ]
            }
        },
        {
            "specs": {},
            "origin_companion_families": [
                {
                    "detection": "opcode-only",
                    "delta_opcode": "0x0D7E",
                    "companion_opcodes": ["0x0F7E", "0x0DE1"],
                    "companion_lengths": [60, 23],
                    "observations": 2,
                }
            ],
        },
    ],
)
def test_malformed_profiles_raise_public_profile_error(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProfileError):
        load_opcode_profile(path)


def test_event_extra_is_deeply_immutable_hashable_and_json_safe():
    original = {"nested": {"values": [1, 2]}}
    event = BDOEvent("test", 0.0, Flow("a", 1, "b", 2), 1, 1, extra=original)
    original["nested"]["values"].append(3)

    with pytest.raises(TypeError):
        event.extra["new"] = True
    with pytest.raises(TypeError):
        event.extra["nested"]["new"] = True
    assert hash(event) == hash(event)
    assert event.to_dict()["extra"] == {"nested": {"values": [1, 2]}}
    assert event.to_dict()["timestamp_iso"] == "1970-01-01T00:00:00.000Z"
    assert "timestamp_text" not in event.to_dict()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"item_id": 0},
        {"item_id": -1},
        {"item_id": 1, "quantity": 0},
        {"item_id": 1, "context_frames": 0},
        {"item_id": 1, "min_confidence": float("nan")},
        {"item_id": 1, "min_confidence": 1.1},
    ],
)
def test_calibration_rejects_invalid_options(kwargs):
    with pytest.raises(ValueError):
        calibrate_frames([], **kwargs)


def test_calibrate_live_cleans_up_when_waiting_raises(monkeypatch):
    state = {"entered": False, "exited": False, "stopped": False}

    class FakeSession:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            state["entered"] = True
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            state["exited"] = True

        def stop(self):
            state["stopped"] = True
            return CalibrationResult((), (), 0)

    def fail_sleep(seconds):
        raise RuntimeError("wait failed")

    monkeypatch.setattr(calibration_module, "CalibrationSession", FakeSession)
    monkeypatch.setattr("time.sleep", fail_sleep)

    with pytest.raises(RuntimeError, match="wait failed"):
        calibration_module.calibrate_live(item_id=1, capture_seconds=1)

    assert state == {"entered": True, "exited": True, "stopped": False}


def test_filter_rejects_accidental_string_iterables():
    with pytest.raises(TypeError, match="not a string"):
        EventFilter.from_values(sources="Mob Drop")


def test_event_filter_constructor_normalizes_and_freezes_inputs():
    sources = {"Mob Drop"}
    event_filter = EventFilter(sources=sources)
    sources.add("Storage")

    assert event_filter.sources == frozenset({"Mob Drop"})
