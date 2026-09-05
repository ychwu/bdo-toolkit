"""Record validation, frame boundaries, and decoder acceptance."""

from __future__ import annotations

from dataclasses import replace

import pytest

from _support.framing import (
    feed_collector,
    finish_collector,
    framing_message,
    framing_profile,
)
from _support.packets import feed_engine, make_item_engine

from bdo_toolkit import EventFilter
from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._framing import (
    _declared_inventory_snapshot_record_deltas,
    _declared_storage_record_deltas,
)
from bdo_toolkit._protocol import BDOFrame, EventSpec, FlowKey, LootEvent, PacketContext
from bdo_toolkit.capture import _EventCollector


def test_storage_batch_above_old_4096_byte_limit_decodes_all_records():
    count = 18
    length = 35 + 226 * count
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x0E6A).to_bytes(2, "little")
    message[6:8] = count.to_bytes(2, "little")
    message[8:12] = bytes.fromhex("20000000")
    for index in range(count):
        offset = 37 + 226 * index
        message[offset : offset + 4] = (7003 + index).to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (1).to_bytes(4, "little")
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")

    events: list = []
    engine = make_item_engine(events)
    feed_engine(engine, 1, bytes(message))
    engine.finish()

    assert len(events) == count


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
    spec = replace(_july17_storage_spec(), repeat_stride=saved_stride)
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(engine, 1, _july17_structural_batch())
    engine.finish()

    assert [
        (event.item_id, event.quantity, event.record_index, event.record_count)
        for event in decoded
    ] == [
        (4802, 1, 1, 2),
        (4003, 21, 2, 2),
    ]
    assert {event.storage_id for event in decoded} == {0x20}
    assert {event.storage_operation for event in decoded} == {"unknown"}


@pytest.mark.parametrize(
    ("offset", "invalid_value"),
    [(0, bytes(4)), (4, bytes(8)), (4, (1 << 32).to_bytes(8, "little")), (35, bytes(8))],
    ids=["invalid-item", "zero-quantity", "uint64-only-quantity", "invalid-instance"],
)
def test_declared_storage_batch_with_one_invalid_record_fails_closed(
    offset, invalid_value,
):
    message = bytearray(_july17_structural_batch())
    # A valid declaration must not allow a corrupt record to be skipped while
    # the remaining records are emitted as a partial batch.
    message[258 + offset : 258 + offset + len(invalid_value)] = invalid_value
    decoded: list = []
    spec = _july17_storage_spec()
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_current_wrapper_cannot_fall_back_after_count_geometry_conflicts():
    message = bytearray(_july17_structural_batch())
    # Both records still have the legacy marker. A contradictory declaration
    # must invalidate this current-wrapper frame instead of bypassing the
    # count check through marker recovery.
    message[16:18] = (3).to_bytes(2, "little")
    decoded: list = []
    spec = _july17_storage_spec()
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def test_current_wrapper_preserves_unfamiliar_operation_mode_as_unknown():
    message = bytearray(_july17_structural_batch())
    message[6] = 3
    decoded: list = []
    spec = _july17_storage_spec()
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(engine, 1, bytes(message))
    engine.finish()

    assert len(decoded) == 2
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_storage_profile_without_count_authority_fails_closed():
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

    feed_engine(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


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
    spec = _july17_storage_spec()
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(engine, 1, _july17_arehaza_snapshot())
    engine.finish()

    assert len(decoded) == 25
    assert [event.item_id for event in decoded[:4]] == [11, 13, 14, 7003]
    assert decoded[0].record_index == 1
    assert decoded[-1].record_index == decoded[-1].record_count == 25
    assert {event.storage_id for event in decoded} == {0x02B5}
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_declared_count_length_mismatch_fails_closed_without_markers():
    message = bytearray(_july17_arehaza_snapshot())
    message[16:18] = (24).to_bytes(2, "little")
    decoded: list = []
    spec = _july17_storage_spec()
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


def _august7_storage_wrapper(
    *,
    mode: int,
    token: bytes,
    storage_id: int = 0x0020,
    count: int = 2,
) -> bytes:
    stride = 228
    base_length = 270
    length = base_length + (count - 1) * stride
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = (0x1C51).to_bytes(2, "little")
    message[5:7] = count.to_bytes(2, "little")
    message[8:12] = storage_id.to_bytes(4, "little")
    message[31:39] = token
    message[39] = mode
    for index in range(count):
        offset = 44 + stride * index
        message[offset : offset + 4] = (7003 + index).to_bytes(4, "little")
        message[offset + 4 : offset + 8] = (index + 1).to_bytes(4, "little")
        # Deliberately omit the legacy FF marker: declared count geometry must
        # prove every record without relying on an item-type-specific pattern.
        message[offset + 35 : offset + 43] = (index + 1).to_bytes(8, "little")
    return bytes(message)


@pytest.mark.parametrize(
    ("mode", "token"),
    (
        (2, b"\x00" * 8),
        (1, bytes.fromhex("1122334455667788")),
        (0, b"\x00" * 8),
    ),
)
def test_august_storage_layout_decodes_dynamic_count_and_destination(
    mode,
    token,
):
    decoded: list = []
    spec = _august7_storage_spec()
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(
        engine,
        1,
        _august7_storage_wrapper(mode=mode, token=token),
    )
    engine.finish()

    assert [event.item_id for event in decoded] == [7003, 7004]
    assert [event.record_index for event in decoded] == [1, 2]
    assert {event.record_count for event in decoded} == {2}
    assert {event.storage_id for event in decoded} == {0x0020}
    assert {event.storage_operation for event in decoded} == {"unknown"}


def test_august_snapshot_count_conflict_fails_closed_without_marker_fallback():
    message = bytearray(
        _august7_storage_wrapper(mode=2, token=b"\x00" * 8, count=2)
    )
    message[5:7] = (3).to_bytes(2, "little")
    decoded: list = []
    spec = _august7_storage_spec()
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: decoded.append(event),
    )

    feed_engine(engine, 1, bytes(message))
    engine.finish()

    assert decoded == []


@pytest.mark.parametrize("opcode", [0x1111, 0x2222])
@pytest.mark.parametrize("event_filter", [None, EventFilter.activity(), EventFilter(event_types={"item_received", "loot_preview"})])
@pytest.mark.parametrize("fragmented", [False, True])
def test_nested_activity_is_rejected_and_following_real_frame_survives(
    opcode, event_filter, fragmented,
):
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=framing_profile(), event_filter=event_filter,
    )
    # Establish generic synchronization before fragmenting an unrelated frame.
    prefix = b"\x05\x00\x00\x77\x77"
    feed_collector(collector, prefix)
    collector.engine.service_gaps(1001.0)
    outer = bytearray(180)
    outer[:5] = b"\xb4\x00\x00\x77\x77"
    nested = framing_message(opcode)
    outer[20:20 + len(nested)] = nested
    payload = bytes(outer) + nested
    pieces = (payload[:130], payload[130:]) if fragmented else (payload,)
    sequence = 105
    for index, piece in enumerate(pieces):
        feed_collector(collector, piece, sequence=sequence, timestamp=1001.0 + index / 10)
        sequence += len(piece)
    events = finish_collector(collector)
    assert len(events) == 1
    assert events[0].item_id == 7003
    assert events[0].extra["stream_sequence"] == 285


@pytest.mark.parametrize("opcode", [0x1111, 0x2222, 0x3333])
def test_retransmitted_outer_payload_does_not_create_a_new_frame_boundary(opcode):
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    outer = bytearray(180)
    outer[:5] = b"\xb4\x00\x00\x77\x77"
    nested = framing_message(opcode)
    outer[20:20 + len(nested)] = nested
    feed_collector(collector, bytes(outer))
    # A differently segmented retransmission starts exactly at the nested
    # signature, but these bytes already belonged to the observed outer frame.
    feed_collector(collector, nested, sequence=120, timestamp=1000.1)
    assert finish_collector(collector) == []
    assert collector.decoder_health.storage_messages_observed == 0


def test_earlier_unframed_activity_can_still_be_recovered_standalone():
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    later = framing_message(0x1111)
    earlier = bytearray(later)
    earlier[32:36] = (7004).to_bytes(4, "little")
    feed_collector(collector, later, sequence=180)
    feed_collector(collector, bytes(earlier) + later[:10], sequence=100, timestamp=1000.1)
    assert [event.item_id for event in finish_collector(collector)] == [7003, 7004]


@pytest.mark.parametrize("repeat_stride", [None, 64])
@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("corruption", ["marker", "zero-instance", "ff-instance"])
def test_supported_transfer_validation_never_uses_weaker_fallback(
    repeat_stride, count, corruption,
):
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=framing_profile(repeat_stride=repeat_stride),
    )
    message = bytearray(framing_message(0x2222, count=count))
    if corruption == "marker":
        message[44:52] = b"\x00" * 8
    else:
        message[67:75] = (b"\x00" if corruption == "zero-instance" else b"\xff") * 8
    feed_collector(collector, bytes(message))
    assert finish_collector(collector) == []


@pytest.mark.parametrize("repeat_stride", [None, 64, 63])
@pytest.mark.parametrize("count", [1, 2])
def test_valid_transfer_keeps_structurally_inferred_geometry(repeat_stride, count):
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=framing_profile(repeat_stride=repeat_stride),
    )
    feed_collector(collector, framing_message(0x2222, count=count))
    assert [(event.item_id, event.quantity) for event in finish_collector(collector)] == [
        (7003 + index, index + 1) for index in range(count)
    ]


def test_transfer_without_structural_instance_geometry_keeps_configured_decoder():
    profile = framing_profile()
    specs = profile.to_dict()["specs"]
    del specs["INVENTORY_TRANSFER"][0]["item_instance_offset"]
    profile = replace(profile, specs=specs)
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    message = bytearray(framing_message(0x2222))
    message[44:52] = b"\x00" * 8
    feed_collector(collector, bytes(message))
    assert [(event.item_id, event.quantity) for event in finish_collector(collector)] == [(7003, 1)]


@pytest.mark.parametrize("length", [5, 9, 40, 95])
def test_short_top_level_storage_reports_incompatibility_outside_filter(length):
    diagnostics = []
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=framing_profile(),
        event_filter=EventFilter(storage_ids={5}), on_diagnostic=diagnostics.append,
    )
    message = bytearray(framing_message(0x3333)[:length])
    message[:2] = length.to_bytes(2, "little")
    feed_collector(collector, bytes(message))
    assert finish_collector(collector) == []
    health = collector.decoder_health
    assert health.storage_status == "incompatible"
    assert health.storage_messages_observed == 1
    assert health.storage_geometry_failures == 1
    assert [diagnostic.code for diagnostic in diagnostics] == ["storage_decoder_incompatible"]
    assert diagnostics[0].requested_storage_ids == (5,)


def test_compact_empty_storage_is_not_a_short_record_failure():
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    empty = bytearray(framing_message(0x3333)[:32])
    empty[:2] = (32).to_bytes(2, "little")
    empty[8:10] = b"\x00\x00"
    feed_collector(collector, bytes(empty))
    assert finish_collector(collector) == []
    assert collector.decoder_health.storage_status == "not_observed"


def test_short_nested_storage_does_not_report_a_top_level_failure():
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    short = bytearray(framing_message(0x3333)[:95])
    short[:2] = (95).to_bytes(2, "little")
    outer = bytearray(180)
    outer[:5] = b"\xb4\x00\x00\x77\x77"
    outer[20:115] = short
    feed_collector(collector, bytes(outer))
    assert finish_collector(collector) == []
    assert collector.decoder_health.storage_status == "not_observed"


def test_short_same_opcode_activity_layout_is_not_a_storage_failure():
    profile = framing_profile()
    specs = profile.to_dict()["specs"]
    specs["LOOT_PREVIEW"][0]["opcode"] = 0x3333
    profile = replace(profile, specs=specs)
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    message = bytearray(framing_message(0x1111))
    message[3:5] = (0x3333).to_bytes(2, "little")
    feed_collector(collector, bytes(message))
    assert [event.event_type for event in finish_collector(collector)] == ["loot_preview"]
    assert collector.decoder_health.storage_status == "not_observed"


@pytest.mark.parametrize("sequence", [100, 2**32 - 40, 2**32 + 100])
def test_inventory_pair_recovery_uses_unwrapped_sequence_numbers(sequence):
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    message = bytearray(framing_message(0x2222))
    message[12:16] = b"\x00" * 4
    record = LootEvent(
        label="INVENTORY_TRANSFER", opcode=0x2222, item_id=7003, quantity=1,
        inventory_slot=None, source_context_candidate=b"\x00" * 4,
        item_instance=(1).to_bytes(8, "little"), storage_instance=None,
        message_length=96, default_context=None,
        context=PacketContext(
            timestamp=1000.0, flow=FlowKey("192.0.2.1", 8889, "192.0.2.2", 50000),
            stream_start=sequence, flow_generation=1,
        ),
        stream_sequence=sequence, record_offset=32,
    )
    collector._handle_record(record, bytes(message))
    assert list(collector.drain_events()) == []
    collector._handle_record(replace(record, stream_sequence=sequence + 96), bytes(message))
    assert [event.event_type for event in finish_collector(collector)] == [
        "inventory_snapshot", "inventory_snapshot",
    ]


def _history_candidate(index, label):
    opcode = {
        "LOOT_PREVIEW": 0x1111,
        "INVENTORY_TRANSFER": 0x2222,
        "INVENTORY_TO_STORAGE": 0x3333,
    }[label]
    message = bytearray(framing_message(opcode))
    if label == "INVENTORY_TRANSFER":
        message[12:16] = b"\x00" * 4
    context = PacketContext(
        timestamp=1000.0,
        flow=FlowKey("192.0.2.1", 8889, "192.0.2.2", 50000),
        flow_generation=1,
    )
    # Leave gaps so adjacent-wrapper recovery cannot supply boundary evidence.
    frame = BDOFrame(index, bytes(message), context, index * 1000)
    record = LootEvent(
        label=label, opcode=opcode, item_id=7003, quantity=1,
        inventory_slot=None, source_context_candidate=bytes(message[12:16]),
        item_instance=(1).to_bytes(8, "little"), storage_instance=None,
        message_length=len(message), default_context=None, context=context,
        stream_sequence=frame.stream_sequence, record_offset=32,
    )
    return frame, record


@pytest.mark.parametrize("label", [
    "LOOT_PREVIEW", "INVENTORY_TRANSFER", "INVENTORY_TO_STORAGE",
])
def test_duplicate_boundaries_do_not_extend_record_acceptance(monkeypatch, label):
    monkeypatch.setattr("bdo_toolkit.capture._TARGET_FRAME_HISTORY_LIMIT", 2)
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    accepted = []
    monkeypatch.setattr(
        collector, "_handle_accepted_record",
        lambda record, message: accepted.append(record),
    )
    candidates = [_history_candidate(index, label) for index in range(3)]
    for index in (0, 1, 0, 2):
        frame, _ = candidates[index]
        collector._remember_generic_target_frame(frame)
        if label == "INVENTORY_TO_STORAGE":
            collector._observe_storage_message(
                frame.opcode, frame.length, "decoded", 1,
                frame.context, frame.stream_sequence,
            )

    for frame, record in candidates:
        collector._handle_record(record, frame.message)
    assert accepted == [record for _, record in candidates[1:]]


def test_loot_traffic_does_not_evict_inventory_snapshot_evidence(monkeypatch):
    monkeypatch.setattr("bdo_toolkit.capture._TARGET_FRAME_HISTORY_LIMIT", 2)
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    inventory, record = _history_candidate(0, "INVENTORY_TRANSFER")
    collector._remember_generic_target_frame(inventory)
    for index in (1, 2):
        loot, _ = _history_candidate(index, "LOOT_PREVIEW")
        collector._remember_generic_target_frame(loot)
    collector._handle_record(record, inventory.message)
    assert [event.event_type for event in collector.drain_events()] == [
        "inventory_snapshot",
    ]


def test_storage_acceptance_history_is_independent_of_boundary_history(monkeypatch):
    monkeypatch.setattr("bdo_toolkit.capture._TARGET_FRAME_HISTORY_LIMIT", 2)
    collector = _EventCollector(server_ports=(8889,), opcode_profile=framing_profile())
    accepted = []
    monkeypatch.setattr(
        collector, "_handle_accepted_record",
        lambda record, message: accepted.append(record),
    )
    first, first_record = _history_candidate(0, "INVENTORY_TO_STORAGE")
    collector._remember_generic_target_frame(first)
    collector._observe_storage_message(
        first.opcode, first.length, "decoded", 1,
        first.context, first.stream_sequence,
    )
    for index in (1, 2):
        frame, record = _history_candidate(index, "INVENTORY_TO_STORAGE")
        collector._remember_generic_target_frame(frame)
        collector._handle_record(record, frame.message)
    # A boundary alone cannot authorize a storage record, and observing new
    # boundaries cannot evict an independently validated storage record.
    collector._handle_record(first_record, first.message)
    assert accepted == [first_record]
    # The old boundary has expired even though its validation is still retained.
    collector._observe_storage_message(
        first.opcode, first.length, "decoded", 1,
        first.context, first.stream_sequence,
    )
    assert collector.decoder_health.storage_messages_observed == 1


def _batch(*, quantity=1, quantity_offset=36):
    message = bytearray(160)
    message[:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x2222).to_bytes(2, "little")
    message[8:10] = (2).to_bytes(2, "little")
    for delta in (0, 64):
        message[32 + delta:36 + delta] = (7003).to_bytes(4, "little")
        message[67 + delta:75 + delta] = (delta + 1).to_bytes(8, "little")
        width = min(8, len(message) - quantity_offset - delta)
        message[quantity_offset + delta:quantity_offset + delta + width] = (
            quantity.to_bytes(width, "little")
        )
    inventory = EventSpec(
        "INVENTORY_TRANSFER", 0x2222, 32, quantity_offset, 96,
        item_instance_offset=67, single_record_message_length=96,
    )
    storage = replace(
        inventory, label="INVENTORY_TO_STORAGE", item_instance_offset=None,
        storage_instance_offset=67, record_count_offset=8,
    )
    return message, inventory, storage


def test_field_bounds_use_the_decoders_quantity_width():
    message, inventory, storage = _batch(quantity_offset=92)
    # Four bytes fit at the record's end; eight would cross into its neighbor.
    assert _declared_storage_record_deltas(storage, message) == [0, 64]
    assert _declared_inventory_snapshot_record_deltas(inventory, message) is None


def test_storage_requires_its_calibrated_count_even_when_geometry_matches():
    message, inventory, storage = _batch()
    message[8:10] = b"\x00\x00"
    message[12:14] = (2).to_bytes(2, "little")
    assert _declared_inventory_snapshot_record_deltas(inventory, message) == [0, 64]
    assert _declared_storage_record_deltas(storage, message) == []


def _july17_storage_spec() -> EventSpec:
    return EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x126D,
        item_offset=36,
        quantity_offset=40,
        min_message_length=257,
        source_context_offset=27,
        record_count_offset=16,
        storage_instance_offset=71,
        single_record_message_length=257,
        default_context="Storage",
    )


def _august7_storage_spec() -> EventSpec:
    return EventSpec(
        label="INVENTORY_TO_STORAGE",
        opcode=0x1C51,
        item_offset=44,
        quantity_offset=48,
        min_message_length=270,
        source_context_offset=8,
        record_count_offset=5,
        storage_instance_offset=79,
        single_record_message_length=270,
        default_context="Storage",
    )
