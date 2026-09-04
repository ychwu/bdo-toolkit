"""Synthetic acquisition and framing regressions from the decoder audit."""

from dataclasses import replace
from pathlib import Path
import time

import pytest

from bdo_toolkit import EventFilter, LiveCaptureSession, OpcodeProfile
from bdo_toolkit._protocol import FlowKey, LootEvent, PacketContext
from bdo_toolkit.capture import _EventCollector


def _profile(*, repeat_stride=None):
    transfer = {
        "opcode": 0x2222,
        "length": 96,
        "item_id_offset": 32,
        "quantity_offset": 36,
        "item_instance_offset": 67,
        "context_offset": 12,
    }
    if repeat_stride is not None:
        transfer["repeat_stride"] = repeat_stride
    return OpcodeProfile(
        Path("synthetic-audit-profile"), True, 1, None, None,
        {
            "LOOT_PREVIEW": ({
                "opcode": 0x1111, "length": 80,
                "item_id_offset": 32, "quantity_offset": 36,
            },),
            "INVENTORY_TRANSFER": (transfer,),
            "STORAGE_ITEM_DELTA": ({
                "opcode": 0x3333, "length": 96,
                "item_id_offset": 32, "quantity_added_offset": 36,
                "destination_instance_offset": 67,
                "context_offset": 12, "record_count_offset": 8,
                "repeat_stride": 64,
            },),
        },
    )


def _message(opcode, *, count=1):
    length = 80 if opcode == 0x1111 else 96 + (count - 1) * 64
    message = bytearray(length)
    message[:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    message[8:10] = count.to_bytes(2, "little")
    message[12:16] = (
        (32).to_bytes(4, "little")
        if opcode == 0x3333 else bytes.fromhex("d0f205a3")
    )
    for index in range(count):
        item = 32 + index * 64
        message[item:item + 4] = (7003 + index).to_bytes(4, "little")
        message[item + 4:item + 8] = (index + 1).to_bytes(4, "little")
        message[item + 12:item + 20] = b"\xff" * 8
        message[item + 35:item + 43] = (index + 1).to_bytes(8, "little")
    return bytes(message)


def _segment(collector, payload, *, sequence=100, timestamp=1000.0, syn=False):
    collector.engine.process_tcp_segment(
        source_ip="192.0.2.1", source_port=8889,
        destination_ip="192.0.2.2", destination_port=50000,
        sequence=sequence & 0xFFFFFFFF, payload=payload,
        timestamp=timestamp, syn=syn,
    )


def _finish(collector):
    collector.engine.finish()
    collector.finalize()
    return list(collector.drain_events())


def test_idle_gap_service_preserves_already_queued_missing_bytes():
    profile = _profile()
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    session = LiveCaptureSession(opcode_profile=profile)
    session._collector = collector
    message = _message(0x1111)
    old_timestamp = time.time() - 10
    _segment(collector, b"", sequence=99, timestamp=old_timestamp, syn=True)
    _segment(collector, message[:20], timestamp=old_timestamp)
    _segment(collector, message[60:], sequence=160, timestamp=old_timestamp)
    session._packet_queue.put(message[20:60])

    session._service_engine_clock()
    assert collector.engine.tcp_gap_resets == 0
    _segment(
        collector, session._packet_queue.get_nowait(),
        sequence=120, timestamp=old_timestamp,
    )
    session._service_engine_clock()
    assert collector.engine.tcp_gap_resets == 0
    assert [(event.event_type, event.item_id) for event in _finish(collector)] == [
        ("loot_preview", 7003)
    ]


def test_idle_gap_service_still_expires_a_truly_missing_segment():
    profile = _profile()
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    session = LiveCaptureSession(opcode_profile=profile)
    session._collector = collector
    old_timestamp = time.time() - 10
    _segment(collector, b"", sequence=99, timestamp=old_timestamp, syn=True)
    _segment(collector, _message(0x1111), sequence=120, timestamp=old_timestamp)
    session._service_engine_clock()
    assert collector.engine.tcp_gap_resets == 1
    assert len(_finish(collector)) == 1


@pytest.mark.parametrize("opcode", [0x1111, 0x2222])
@pytest.mark.parametrize("event_filter", [None, EventFilter.activity(), EventFilter(event_types={"item_received", "loot_preview"})])
@pytest.mark.parametrize("fragmented", [False, True])
def test_nested_activity_is_rejected_and_following_real_frame_survives(
    opcode, event_filter, fragmented,
):
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=_profile(), event_filter=event_filter,
    )
    # Establish generic synchronization before fragmenting an unrelated frame.
    prefix = b"\x05\x00\x00\x77\x77"
    _segment(collector, prefix)
    collector.engine.service_gaps(1001.0)
    outer = bytearray(180)
    outer[:5] = b"\xb4\x00\x00\x77\x77"
    nested = _message(opcode)
    outer[20:20 + len(nested)] = nested
    payload = bytes(outer) + nested
    pieces = (payload[:130], payload[130:]) if fragmented else (payload,)
    sequence = 105
    for index, piece in enumerate(pieces):
        _segment(collector, piece, sequence=sequence, timestamp=1001.0 + index / 10)
        sequence += len(piece)
    events = _finish(collector)
    assert len(events) == 1
    assert events[0].item_id == 7003
    assert events[0].extra["stream_sequence"] == 285


@pytest.mark.parametrize("opcode", [0x1111, 0x2222, 0x3333])
def test_retransmitted_outer_payload_does_not_create_a_new_frame_boundary(opcode):
    collector = _EventCollector(server_ports=(8889,), opcode_profile=_profile())
    outer = bytearray(180)
    outer[:5] = b"\xb4\x00\x00\x77\x77"
    nested = _message(opcode)
    outer[20:20 + len(nested)] = nested
    _segment(collector, bytes(outer))
    # A differently segmented retransmission starts exactly at the nested
    # signature, but these bytes already belonged to the observed outer frame.
    _segment(collector, nested, sequence=120, timestamp=1000.1)
    assert _finish(collector) == []
    assert collector.decoder_health.storage_messages_observed == 0


def test_earlier_unframed_activity_can_still_be_recovered_standalone():
    collector = _EventCollector(server_ports=(8889,), opcode_profile=_profile())
    later = _message(0x1111)
    earlier = bytearray(later)
    earlier[32:36] = (7004).to_bytes(4, "little")
    _segment(collector, later, sequence=180)
    _segment(collector, bytes(earlier) + later[:10], sequence=100, timestamp=1000.1)
    assert [event.item_id for event in _finish(collector)] == [7003, 7004]


@pytest.mark.parametrize("repeat_stride", [None, 64])
@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("corruption", ["marker", "zero-instance", "ff-instance"])
def test_supported_transfer_validation_never_uses_weaker_fallback(
    repeat_stride, count, corruption,
):
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=_profile(repeat_stride=repeat_stride),
    )
    message = bytearray(_message(0x2222, count=count))
    if corruption == "marker":
        message[44:52] = b"\x00" * 8
    else:
        message[67:75] = (b"\x00" if corruption == "zero-instance" else b"\xff") * 8
    _segment(collector, bytes(message))
    assert _finish(collector) == []


@pytest.mark.parametrize("repeat_stride", [None, 64, 63])
@pytest.mark.parametrize("count", [1, 2])
def test_valid_transfer_keeps_structurally_inferred_geometry(repeat_stride, count):
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=_profile(repeat_stride=repeat_stride),
    )
    _segment(collector, _message(0x2222, count=count))
    assert [(event.item_id, event.quantity) for event in _finish(collector)] == [
        (7003 + index, index + 1) for index in range(count)
    ]


def test_transfer_without_structural_instance_geometry_keeps_configured_decoder():
    profile = _profile()
    specs = profile.to_dict()["specs"]
    del specs["INVENTORY_TRANSFER"][0]["item_instance_offset"]
    profile = replace(profile, specs=specs)
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    message = bytearray(_message(0x2222))
    message[44:52] = b"\x00" * 8
    _segment(collector, bytes(message))
    assert [(event.item_id, event.quantity) for event in _finish(collector)] == [(7003, 1)]


@pytest.mark.parametrize("length", [5, 9, 40, 95])
def test_short_top_level_storage_reports_incompatibility_outside_filter(length):
    diagnostics = []
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=_profile(),
        event_filter=EventFilter(storage_ids={5}), on_diagnostic=diagnostics.append,
    )
    message = bytearray(_message(0x3333)[:length])
    message[:2] = length.to_bytes(2, "little")
    _segment(collector, bytes(message))
    assert _finish(collector) == []
    health = collector.decoder_health
    assert health.storage_status == "incompatible"
    assert health.storage_messages_observed == 1
    assert health.storage_geometry_failures == 1
    assert [diagnostic.code for diagnostic in diagnostics] == ["storage_decoder_incompatible"]
    assert diagnostics[0].requested_storage_ids == (5,)


def test_compact_empty_storage_is_not_a_short_record_failure():
    collector = _EventCollector(server_ports=(8889,), opcode_profile=_profile())
    empty = bytearray(_message(0x3333)[:32])
    empty[:2] = (32).to_bytes(2, "little")
    empty[8:10] = b"\x00\x00"
    _segment(collector, bytes(empty))
    assert _finish(collector) == []
    assert collector.decoder_health.storage_status == "not_observed"


def test_short_nested_storage_does_not_report_a_top_level_failure():
    collector = _EventCollector(server_ports=(8889,), opcode_profile=_profile())
    short = bytearray(_message(0x3333)[:95])
    short[:2] = (95).to_bytes(2, "little")
    outer = bytearray(180)
    outer[:5] = b"\xb4\x00\x00\x77\x77"
    outer[20:115] = short
    _segment(collector, bytes(outer))
    assert _finish(collector) == []
    assert collector.decoder_health.storage_status == "not_observed"


def test_short_same_opcode_activity_layout_is_not_a_storage_failure():
    profile = _profile()
    specs = profile.to_dict()["specs"]
    specs["LOOT_PREVIEW"][0]["opcode"] = 0x3333
    profile = replace(profile, specs=specs)
    collector = _EventCollector(server_ports=(8889,), opcode_profile=profile)
    message = bytearray(_message(0x1111))
    message[3:5] = (0x3333).to_bytes(2, "little")
    _segment(collector, bytes(message))
    assert [event.event_type for event in _finish(collector)] == ["loot_preview"]
    assert collector.decoder_health.storage_status == "not_observed"


@pytest.mark.parametrize("sequence", [100, 2**32 - 40, 2**32 + 100])
def test_inventory_pair_recovery_uses_unwrapped_sequence_numbers(sequence):
    collector = _EventCollector(server_ports=(8889,), opcode_profile=_profile())
    message = bytearray(_message(0x2222))
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
    assert [event.event_type for event in _finish(collector)] == [
        "inventory_snapshot", "inventory_snapshot",
    ]
