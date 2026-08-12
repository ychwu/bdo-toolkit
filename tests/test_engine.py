"""Unit tests for engine behaviors the pcap fixtures do not exercise."""

import dataclasses
import random

from fixture_paths import JULY17_OPCODE_PROFILE
from bdo_toolkit import EventFilter
from bdo_toolkit._engine import PacketEngine, toolkit_event_from_record
from bdo_toolkit import _engine as engine_module
from bdo_toolkit._framing import FrameCollectorScanner, TargetMessageScanner
from bdo_toolkit._protocol import (
    BDOFrame,
    EventSpec,
    FlowKey,
    LootEvent,
    PacketContext,
    STORAGE_DELTA_CONTEXTS,
    source_label,
)


def test_source_label_known_context_wins_over_default():
    assert source_label(STORAGE_DELTA_CONTEXTS[1], "Storage") == "Heidel"


def test_source_label_default_applies_only_without_candidate():
    assert source_label(None, "Gathering") == "Gathering"
    assert source_label(None, None) is None


def test_source_label_unknown_candidate_stays_visible():
    # A new/unpatched context value must not silently match an existing
    # source filter such as sources={"Storage"}.
    unknown = bytes.fromhex("deadbeef")
    assert source_label(unknown, "Storage") == "UNKNOWN(0xdeadbeef)"
    assert source_label(unknown, None) == "UNKNOWN(0xdeadbeef)"


def test_source_label_promotes_observed_remote_item_contexts():
    assert source_label(bytes.fromhex("60260000")) == "Event Adventures"
    assert source_label(bytes.fromhex("3e010000")) == "Magnus Remote Inventory"


def _loot_preview_frame(item_id: int, quantity: int) -> bytes:
    # LOOT_PREVIEW spec: opcode 0x1643, item @23, quantity @27, min length 31.
    message = bytearray(244)
    message[0:2] = (244).to_bytes(2, "little")
    message[2] = 0
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
)


def _make_engine(events):
    return PacketEngine(
        server_ports=(8889,),
        event_specs=SYNTHETIC_EVENT_SPECS,
        on_event=lambda event, raw: events.append(event),
    )


def _segment(engine, sequence, payload, timestamp=1000.0):
    engine.process_tcp_segment(
        source_ip="10.0.0.1",
        source_port=8889,
        destination_ip="10.0.0.2",
        destination_port=50000,
        sequence=sequence,
        payload=payload,
        timestamp=timestamp,
    )


def _generic_frame(opcode: int, length: int = 13) -> bytes:
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    return bytes(message)


def _frame_context(sequence: int = 100) -> PacketContext:
    return PacketContext(
        timestamp=1000.0,
        flow=FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000),
        stream_start=sequence,
    )


def test_promoted_remote_item_sources_reach_events_and_exact_filters():
    observed = (
        (bytes.fromhex("60260000"), "Event Adventures"),
        (bytes.fromhex("3e010000"), "Magnus Remote Inventory"),
    )

    for raw_context, expected_source in observed:
        event = toolkit_event_from_record(
            LootEvent(
                label="INVENTORY_TRANSFER",
                opcode=0x1234,
                item_id=7003,
                quantity=1,
                inventory_slot=None,
                source_context_candidate=raw_context,
                item_instance=None,
                storage_instance=None,
                message_length=64,
                default_context=None,
                context=_frame_context(),
            )
        )

        assert event.event_type == "item_received"
        assert event.source == expected_source
        assert event.raw_context == f"0x{raw_context.hex()}"
        assert EventFilter(sources={expected_source}).allows(event)
        assert not EventFilter(
            sources={f"UNKNOWN(0x{raw_context.hex()})"}
        ).allows(event)


def _slow_can_anchor_at_start(specs, data: bytes) -> bool:
    """Frozen byte-by-byte reference for the optimized anchor predicate."""
    if len(data) < 5:
        return False
    for offset in range(len(data) - 4):
        message_length = int.from_bytes(data[offset : offset + 2], "little")
        for spec in specs:
            if data[offset + 2 : offset + 5] != spec.signature:
                continue
            if not spec.min_message_length <= message_length <= 0xFFFF:
                continue
            if TargetMessageScanner._message_length_matches_spec(
                spec, message_length
            ):
                return True
    return False


def test_target_anchor_skips_invalid_signature_before_valid_header():
    spec = EventSpec(
        "LOOT_PREVIEW",
        0x1234,
        5,
        9,
        13,
        single_record_message_length=13,
    )
    scanner = TargetMessageScanner(lambda *_: None, (spec,))
    invalid = (12).to_bytes(2, "little") + spec.signature + b"\x00" * 8
    valid = (13).to_bytes(2, "little") + spec.signature + b"\x00" * 8

    assert scanner.can_anchor_at_start(invalid + valid)
    assert not scanner.can_anchor_at_start(spec.signature + b"\x00" * 16)
    assert not scanner.can_anchor_at_start(b"\x00" + spec.signature + b"\x00" * 16)


def test_target_scanner_caches_signatures_for_anchor_and_decode(monkeypatch):
    specs = (
        EventSpec(
            "LOOT_PREVIEW",
            0x1234,
            5,
            9,
            13,
            single_record_message_length=13,
        ),
        EventSpec(
            "LOOT_PREVIEW",
            0x1234,
            5,
            9,
            21,
            single_record_message_length=21,
        ),
        EventSpec(
            "LOOT_PREVIEW",
            0x5678,
            5,
            9,
            13,
            single_record_message_length=13,
        ),
    )
    original_getter = EventSpec.signature.fget
    assert original_getter is not None
    signature_reads = 0

    def counted_signature(spec):
        nonlocal signature_reads
        signature_reads += 1
        return original_getter(spec)

    monkeypatch.setattr(EventSpec, "signature", property(counted_signature))
    events = []
    scanner = TargetMessageScanner(
        lambda event, _raw: events.append(event),
        specs,
    )
    assert signature_reads == len(specs)

    frame = bytearray(13)
    frame[0:2] = len(frame).to_bytes(2, "little")
    frame[2:5] = b"\x00\x34\x12"
    frame[5:9] = (7003).to_bytes(4, "little")
    frame[9:13] = (3).to_bytes(4, "little")
    signature_reads = 0

    assert scanner.can_anchor_at_start(bytes(frame))
    scanner.scan_standalone(bytes(frame), _frame_context())

    assert signature_reads == 0
    assert [(event.item_id, event.quantity) for event in events] == [(7003, 3)]


def test_target_anchor_optimized_search_matches_slow_reference():
    specs = (
        EventSpec(
            "LOOT_PREVIEW",
            0x1234,
            5,
            9,
            13,
            single_record_message_length=13,
        ),
        EventSpec(
            "LOOT_PREVIEW",
            0x1234,
            5,
            9,
            21,
            single_record_message_length=21,
        ),
        EventSpec("INVENTORY_TRANSFER", 0x4321, 5, 9, 13),
    )
    scanner = TargetMessageScanner(lambda *_: None, specs)
    rng = random.Random(0xBD0)

    for _ in range(500):
        data = bytearray(rng.randrange(0, 257))
        for index in range(len(data)):
            data[index] = rng.randrange(256)
        if len(data) >= 5 and rng.randrange(3) == 0:
            spec = rng.choice(specs)
            offset = rng.randrange(len(data) - 4)
            data[offset : offset + 2] = rng.choice(
                (0, 4, 13, 21, 244, 0xFFFF)
            ).to_bytes(2, "little")
            data[offset + 2 : offset + 5] = spec.signature

        frozen = bytes(data)
        assert scanner.can_anchor_at_start(frozen) == _slow_can_anchor_at_start(
            specs, frozen
        )


def test_generic_frame_tap_uses_known_opcode_to_escape_bogus_large_length():
    frames: list[BDOFrame] = []
    scanner = FrameCollectorScanner(frames.append, known_opcodes=(0x1234,))

    scanner.feed(b"\xff\xff" + _generic_frame(0x1234), _frame_context())

    assert [(frame.opcode, frame.stream_sequence) for frame in frames] == [
        (0x1234, 102)
    ]


def test_opcode_free_generic_tap_requires_two_boundaries_after_junk_prefix():
    frames: list[BDOFrame] = []
    scanner = FrameCollectorScanner(frames.append)
    first = _generic_frame(0x1234)
    second = _generic_frame(0x5678)

    scanner.feed(b"\xff\xff" + first, _frame_context())
    assert frames == []

    scanner.feed(second, _frame_context(sequence=102 + len(first)))
    assert [(frame.opcode, frame.stream_sequence) for frame in frames] == [
        (0x1234, 102),
        (0x5678, 102 + len(first)),
    ]


def test_known_generic_tap_recovers_from_every_midframe_attachment_offset():
    partial_source = _generic_frame(0x7777, length=37)
    target = _generic_frame(0x1234, length=19)

    for offset in range(1, len(partial_source)):
        frames: list[BDOFrame] = []
        scanner = FrameCollectorScanner(frames.append, known_opcodes=(0x1234,))
        scanner.feed(
            partial_source[offset:] + target,
            _frame_context(sequence=100 + offset),
        )

        matched = [frame for frame in frames if frame.opcode == 0x1234]
        assert len(matched) == 1, f"failed to recover from byte offset {offset}"
        assert matched[0].stream_sequence == 100 + len(partial_source)


def _same_opcode_layout_frame(*, populate_first: bool, populate_second: bool) -> bytes:
    message = bytearray(40)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x4321).to_bytes(2, "little")
    if populate_first:
        message[12:16] = (7003).to_bytes(4, "little")
        message[16:20] = (2).to_bytes(4, "little")
    if populate_second:
        message[24:28] = (7307).to_bytes(4, "little")
        message[28:32] = (8).to_bytes(4, "little")
    return bytes(message)


def test_same_opcode_layout_selection_is_not_profile_order_dependent():
    first = EventSpec("LOOT_PREVIEW", 0x4321, 12, 16, 20)
    second = EventSpec("LOOT_PREVIEW", 0x4321, 24, 28, 32)

    for ordered_specs in ((first, second), (second, first)):
        events = []
        scanner = TargetMessageScanner(
            lambda event, _raw: events.append(event), ordered_specs
        )
        scanner.scan_standalone(
            _same_opcode_layout_frame(
                populate_first=False,
                populate_second=True,
            ),
            _frame_context(),
        )

        assert [(event.item_id, event.quantity) for event in events] == [(7307, 8)]


def test_same_opcode_layout_ambiguity_fails_closed():
    events = []
    scanner = TargetMessageScanner(
        lambda event, _raw: events.append(event),
        (
            EventSpec("LOOT_PREVIEW", 0x4321, 12, 16, 20),
            EventSpec("LOOT_PREVIEW", 0x4321, 24, 28, 32),
        ),
    )

    scanner.scan_standalone(
        _same_opcode_layout_frame(populate_first=True, populate_second=True),
        _frame_context(),
    )

    assert events == []


def test_finish_drains_pending_segment_after_gap():
    events = []
    engine = _make_engine(events)

    # Establish the flow, then simulate a lost segment: the next payload
    # arrives beyond the expected sequence and sits in pending.
    _segment(engine, 1000, b"\x00" * 8)
    frame = _loot_preview_frame(item_id=7003, quantity=3)
    _segment(engine, 2000, frame)

    assert events == []  # stranded in pending at "end of capture"
    engine.finish()
    assert [(event.item_id, event.quantity) for event in events] == [(7003, 3)]


def test_finish_is_idempotent_and_safe_on_empty_flows():
    events = []
    engine = _make_engine(events)
    engine.finish()

    _segment(engine, 1000, _loot_preview_frame(item_id=5960, quantity=1))
    assert len(events) == 1
    engine.finish()
    engine.finish()
    assert len(events) == 1


def test_identical_reconnect_payload_is_not_deduplicated_across_flow_generations():
    """A reused TCP four-tuple starts a new event identity at each SYN."""
    events = []
    engine = _make_engine(events)
    frame = _loot_preview_frame(item_id=7003, quantity=3)

    for timestamp in (1000.0, 1001.0):
        engine.process_tcp_segment(
            source_ip="10.0.0.1",
            source_port=8889,
            destination_ip="10.0.0.2",
            destination_port=50000,
            sequence=999,
            payload=frame,
            timestamp=timestamp,
            syn=True,
        )

    assert [(event.item_id, event.quantity) for event in events] == [
        (7003, 3),
        (7003, 3),
    ]
    assert [event.stream_sequence for event in events] == [1000, 1000]
    assert [event.context.flow_generation for event in events] == [1, 2]
    normalized = [toolkit_event_from_record(event) for event in events]
    assert [event._flow_generation for event in normalized] == [1, 2]

    first = normalized[0]
    another_generation = dataclasses.replace(first, _flow_generation=2)
    assert first == another_generation
    assert hash(first) == hash(another_generation)
    assert first.to_dict() == another_generation.to_dict()

    event = dataclasses.replace(
        first,
        _flow_generation=9,
        extra={
            **first.extra,
            "_flow_generation": "user-owned",
            "_vendor_extension": "preserved",
        },
    )
    serialized_extra = event.to_dict()["extra"]
    assert serialized_extra == {
        "stream_sequence": 1000,
        "_flow_generation": "user-owned",
        "_vendor_extension": "preserved",
    }
    assert event._flow_generation == 9
    assert "_flow_generation=9" not in repr(event)


def test_item_engine_bounds_active_flows_and_reports_resource_eviction():
    engine = _make_engine([])

    for index in range(65):
        engine.process_tcp_segment(
            source_ip="10.0.0.1",
            source_port=8889,
            destination_ip="10.0.0.2",
            destination_port=40000 + index,
            sequence=1000,
            payload=b"",
            timestamp=float(index),
            syn=True,
        )

    assert engine.flow_state_evictions == 1
    engine.finish()


def test_multi_record_message_is_hashed_once(monkeypatch):
    spec = EventSpec(
        label="LOOT_PREVIEW",
        opcode=0x1234,
        item_offset=5,
        quantity_offset=9,
        min_message_length=13,
        repeat_stride=8,
        single_record_message_length=13,
    )
    message = bytearray(21)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = spec.opcode.to_bytes(2, "little")
    message[5:9] = (7003).to_bytes(4, "little")
    message[9:13] = (3).to_bytes(4, "little")
    message[13:17] = (5960).to_bytes(4, "little")
    message[17:21] = (1).to_bytes(4, "little")
    events = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(spec,),
        on_event=lambda event, raw: events.append(event),
    )
    original_blake2b = engine_module.hashlib.blake2b
    calls = []

    def counted_blake2b(*args, **kwargs):
        calls.append(True)
        return original_blake2b(*args, **kwargs)

    monkeypatch.setattr(engine_module.hashlib, "blake2b", counted_blake2b)
    _segment(engine, 1000, bytes(message))

    assert [(event.item_id, event.quantity) for event in events] == [
        (7003, 3),
        (5960, 1),
    ]
    assert len(calls) == 1


def test_replay_pcap_round_trip_with_synthetic_capture(tmp_path):
    """Cover the pcap-reading path without any private capture files."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    from bdo_toolkit import replay_pcap

    frame = _loot_preview_frame(item_id=7003, quantity=6)
    packet = (
        Ether()
        / IP(src="203.0.113.10", dst="198.51.100.20")
        / TCP(sport=8889, dport=51000, seq=1000, flags="PA")
        / frame
    )
    pcap_path = tmp_path / "synthetic.pcapng"
    wrpcap(str(pcap_path), [packet])

    events = list(
        replay_pcap(pcap_path, opcode_profile=JULY17_OPCODE_PROFILE)
    )
    assert [(event.event_type, event.item_id, event.quantity) for event in events] == [
        ("loot_preview", 7003, 6)
    ]
    assert events[0].source == "Gathering"


def test_yukjo_storage_context_labels_and_stays_storage_mode():
    # 0x8c050000 is the little-endian Yukjo Street destination key. It must
    # never act as a receipt context signature for direction classification.
    yukjo = bytes.fromhex("8c050000")
    assert source_label(yukjo, None) == "Yukjo Street"
    assert yukjo in STORAGE_DELTA_CONTEXTS
