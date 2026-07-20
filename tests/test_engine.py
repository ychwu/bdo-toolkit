"""Unit tests for engine behaviors the pcap fixtures do not exercise."""

from bdo_toolkit._engine import PacketEngine
from bdo_toolkit import _engine as engine_module
from bdo_toolkit._framing import FrameCollectorScanner, TargetMessageScanner
from bdo_toolkit._protocol import (
    BDOFrame,
    EventSpec,
    FlowKey,
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

    events = list(replay_pcap(pcap_path))
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
