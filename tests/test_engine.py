"""Unit tests for engine behaviors the pcap fixtures do not exercise."""

from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._protocol import (
    EventSpec,
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
