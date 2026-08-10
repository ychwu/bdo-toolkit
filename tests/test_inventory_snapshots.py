"""Atomic inventory hydration and current storage-wrapper regressions."""

from bdo_toolkit._engine import PacketEngine, toolkit_event_from_record
from bdo_toolkit._protocol import BDOFrame, EventSpec, FlowKey, PacketContext
from bdo_toolkit.calibration import _discover_storage_context_offset


def _segment(engine: PacketEngine, payload: bytes) -> None:
    engine.process_tcp_segment(
        source_ip="10.0.0.1",
        source_port=8889,
        destination_ip="10.0.0.2",
        destination_port=50000,
        sequence=1,
        payload=payload,
        timestamp=1000.0,
    )
    engine.finish()


def _inventory_spec(*, saved_stride: int | None = None) -> EventSpec:
    return EventSpec(
        label="INVENTORY_TRANSFER",
        opcode=0x194A,
        item_offset=31,
        quantity_offset=35,
        min_message_length=254,
        source_context_offset=27,
        item_instance_offset=66,
        repeat_stride=saved_stride,
        single_record_message_length=254,
    )


def _inventory_snapshot(
    *,
    count: int = 3,
    count_fields: tuple[tuple[int, int], ...] | None = None,
) -> bytearray:
    stride = 223
    length = 254 + (count - 1) * stride
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x194A).to_bytes(2, "little")
    for offset, value in count_fields or ((22, count),):
        message[offset : offset + 2] = value.to_bytes(2, "little")
    message[27:31] = b"\x00" * 4
    for index in range(count):
        item_offset = 31 + index * stride
        message[item_offset : item_offset + 4] = (7003 + index).to_bytes(4, "little")
        message[item_offset + 4 : item_offset + 8] = (index + 1).to_bytes(4, "little")
        message[item_offset + 35 : item_offset + 43] = (index + 1).to_bytes(8, "little")
    return message


def _decode(spec: EventSpec, message: bytes):
    decoded = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )
    _segment(engine, message)
    return decoded


def test_zero_context_inventory_batch_discovers_count_and_stride_atomically():
    message = _inventory_snapshot(count_fields=((20, 3), (22, 3)))

    decoded = _decode(_inventory_spec(saved_stride=221), bytes(message))

    assert [(event.item_id, event.quantity) for event in decoded] == [
        (7003, 1),
        (7004, 2),
        (7005, 3),
    ]
    assert [event.record_index for event in decoded] == [1, 2, 3]
    assert {event.record_count for event in decoded} == {3}
    assert {event.source_context_candidate for event in decoded} == {b"\x00" * 4}
    normalized = toolkit_event_from_record(decoded[0])
    assert normalized.event_type == "inventory_snapshot"
    assert normalized.raw_context == "0x00000000"


def test_zero_context_inventory_batch_rejects_every_record_on_one_invalid_instance():
    message = _inventory_snapshot()
    message[31 + 223 + 35 : 31 + 223 + 43] = b"\x00" * 8

    assert _decode(_inventory_spec(), bytes(message)) == []


def _storage_message(*, mode: int = 1, storage_id: int = 0x0020) -> bytes:
    count = 2
    stride = 222
    length = 257 + stride
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = mode
    message[7:15] = b"\x31\x41\x59\x26\x53\x58\x97\x93"
    message[16:18] = count.to_bytes(2, "little")
    message[27:31] = storage_id.to_bytes(4, "little")
    for index, item_id in enumerate((4802, 4003)):
        item_offset = 36 + index * stride
        message[item_offset : item_offset + 4] = item_id.to_bytes(4, "little")
        message[item_offset + 4 : item_offset + 8] = (index + 1).to_bytes(4, "little")
        message[item_offset + 35 : item_offset + 43] = (index + 1).to_bytes(8, "little")
    return bytes(message)


def _storage_spec_without_context() -> EventSpec:
    return EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        record_count_offset=16,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )


def test_contextless_storage_spec_does_not_promote_a_registered_prefix_decoy():
    decoded = _decode(_storage_spec_without_context(), _storage_message())

    assert len(decoded) == 2
    assert {event.source_context_candidate for event in decoded} == {None}
    assert {event.storage_id for event in decoded} == {None}
    assert {event.storage_operation for event in decoded} == {"unknown"}
    normalized = toolkit_event_from_record(decoded[0])
    assert normalized.raw_context is None
    assert normalized.storage_name is None
    assert normalized.source == "Storage"


def test_contextless_storage_records_are_not_filtered_by_registered_town_bytes():
    mapped = _decode(
        _storage_spec_without_context(),
        _storage_message(mode=3, storage_id=0x0020),
    )
    assert {event.storage_operation for event in mapped} == {"unknown"}
    assert {event.storage_id for event in mapped} == {None}
    assert {event.source_context_candidate for event in mapped} == {None}

    unmapped = _decode(
        _storage_spec_without_context(),
        _storage_message(mode=3, storage_id=0xDEADBEEF),
    )
    assert len(mapped) == len(unmapped) == 2
    assert [(event.item_id, event.quantity) for event in mapped] == [
        (event.item_id, event.quantity) for event in unmapped
    ]
    assert {event.storage_operation for event in unmapped} == {"unknown"}
    assert {event.storage_id for event in unmapped} == {None}
    assert {event.source_context_candidate for event in unmapped} == {None}


def test_wrapper_mode_cannot_authenticate_an_unmapped_destination():
    decoded = _decode(
        _storage_spec_without_context(),
        _storage_message(mode=1, storage_id=0xDEADBEEF),
    )

    assert {event.storage_operation for event in decoded} == {"unknown"}
    assert {event.storage_id for event in decoded} == {None}
    assert {event.source_context_candidate for event in decoded} == {None}


def test_calibration_keeps_mapped_current_destination_with_unknown_mode():
    message = _storage_message(mode=3)
    frame = BDOFrame(
        index=0,
        message=message,
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
        ),
        stream_sequence=None,
    )

    assert _discover_storage_context_offset(frame, 36) == 27


def test_calibration_rejects_mapped_integer_without_declared_record_geometry():
    message = bytearray(_storage_message(mode=3))
    # Keep the plausible mapped town and nonzero declared count, but corrupt
    # record two. The destination integer alone must not become an intrinsic
    # storage-direction/context signal.
    message[36 + 222 + 35 : 36 + 222 + 43] = b"\x00" * 8
    frame = BDOFrame(
        index=0,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0,
            flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
        ),
        stream_sequence=None,
    )

    assert _discover_storage_context_offset(frame, 36) is None
