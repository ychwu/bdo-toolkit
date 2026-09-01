"""Regression tests for the shared Scapy-to-TCP-segment boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Padding, Raw
from scapy.utils import wrpcap

from fixture_paths import JULY17_OPCODE_PROFILE
from bdo_toolkit._capture_backend import make_packet_handler
from bdo_toolkit._capture_backend import iter_pcap_file
from bdo_toolkit.capture import _EventCollector
from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._protocol import EventSpec


class RecordingConsumer:
    server_ports = frozenset({8889})

    def __init__(self) -> None:
        self.segments: list[dict[str, Any]] = []

    def process_tcp_segment(
        self,
        *,
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        sequence: int,
        payload: bytes,
        timestamp: float,
        syn: bool = False,
        rst: bool = False,
        fin: bool = False,
    ) -> None:
        self.segments.append(
            {
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "sequence": sequence,
                "payload": payload,
                "timestamp": timestamp,
                "syn": syn,
                "rst": rst,
                "fin": fin,
            }
        )

    def finish(self) -> None:
        pass


def _parsed_ether(packet: Ether) -> Ether:
    """Serialize and dissect so header lengths match actual capture packets."""
    parsed = Ether(bytes(packet))
    parsed.time = 1000.25
    return parsed


def _tcp_packet(*, flags: str = "A", sequence: int = 1000) -> Ether:
    return Ether() / IP(src="203.0.113.10", dst="198.51.100.20") / TCP(
        sport=8889,
        dport=51000,
        seq=sequence,
        flags=flags,
    )


def _loot_preview_frame(item_id: int, quantity: int) -> bytes:
    message = bytearray(244)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x1643).to_bytes(2, "little")
    message[23:27] = item_id.to_bytes(4, "little")
    message[27:31] = quantity.to_bytes(4, "little")
    return bytes(message)


def _generic_frame(
    opcode: int,
    length: int,
    *,
    token: bytes | None = None,
) -> bytes:
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    if token is not None:
        message[5:13] = token
    return bytes(message)


def _worker_storage_frame(item_id: int, quantity: int) -> bytes:
    token = bytes.fromhex("3141592653589793")
    message = bytearray(257)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = 1
    message[7:15] = token
    message[16:18] = (1).to_bytes(2, "little")
    message[27:31] = (5).to_bytes(4, "little")
    message[36:40] = item_id.to_bytes(4, "little")
    message[40:44] = quantity.to_bytes(4, "little")
    message[71:79] = bytes.fromhex("1122334455667788")
    return (
        bytes(message)
        + _generic_frame(0x1A59, 64, token=token)
        + _generic_frame(0x155E, 30, token=token)
    )


def test_empty_ack_ignores_ethernet_padding() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)

    packet = _parsed_ether(_tcp_packet() / Padding(load=b"\x00" * 6))
    assert packet[IP].len == 40
    assert bytes(packet[TCP].payload) == b"\x00" * 6
    handler(packet)

    assert len(consumer.segments) == 1
    assert consumer.segments[0]["payload"] == b""


def test_ack_packet_preserves_genuine_application_data() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)

    handler(_parsed_ether(_tcp_packet() / Raw(load=b"application data")))

    assert consumer.segments[0]["payload"] == b"application data"


def test_application_data_excludes_trailing_ethernet_padding() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)

    packet = _tcp_packet() / Raw(load=b"payload") / Padding(load=b"\xaa" * 8)
    handler(_parsed_ether(packet))

    assert consumer.segments[0]["payload"] == b"payload"


def test_ipv4_and_tcp_options_are_included_in_header_lengths() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)
    packet = (
        Ether()
        / IP(
            src="203.0.113.10",
            dst="198.51.100.20",
            options=b"\x01\x01\x01\x01",
        )
        / TCP(
            sport=8889,
            dport=51000,
            seq=1000,
            flags="A",
            options=[("NOP", None)] * 4,
        )
        / Raw(load=b"option-safe")
        / Padding(load=b"\x00" * 6)
    )

    parsed = _parsed_ether(packet)
    assert parsed[IP].ihl == 6
    assert parsed[TCP].dataofs == 6
    handler(parsed)

    assert consumer.segments[0]["payload"] == b"option-safe"


def test_declared_payload_larger_than_captured_payload_fails_closed() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)
    packet = _parsed_ether(_tcp_packet() / Raw(load=b"short"))
    packet[IP].len = int(packet[IP].len) + 4

    with pytest.raises(ValueError, match="truncated"):
        handler(packet)

    assert consumer.segments == []


def test_truncated_tcp_options_fail_closed() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)
    complete = bytes(
        Ether()
        / IP(src="203.0.113.10", dst="198.51.100.20")
        / TCP(
            sport=8889,
            dport=51000,
            seq=1000,
            flags="A",
            options=[("NOP", None)] * 8,
        )
    )
    packet = Ether(complete[:-4])
    packet.time = 1000.25
    assert TCP in packet
    assert len(bytes(packet[IP])) < int(packet[IP].len)

    with pytest.raises(ValueError, match="truncated"):
        handler(packet)

    assert consumer.segments == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("ip_len", None),
        ("ip_ihl", None),
        ("tcp_dataofs", None),
        ("ip_ihl", 4),
        ("tcp_dataofs", 4),
        ("ip_ihl", 16),
        ("tcp_dataofs", 16),
        ("ip_len", 39),
        ("ip_len", 0x10000),
    ),
)
def test_invalid_or_unavailable_header_lengths_fail_visibly(
    field: str,
    value: int | None,
) -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)
    packet = _parsed_ether(_tcp_packet())
    layer_name, attribute = field.split("_", maxsplit=1)
    layer = packet[IP] if layer_name == "ip" else packet[TCP]
    setattr(layer, attribute, value)

    with pytest.raises(ValueError, match="header|length"):
        handler(packet)

    assert consumer.segments == []


def test_first_ipv4_fragment_for_selected_flow_fails_visibly() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)
    packet = (
        Ether()
        / IP(src="203.0.113.10", dst="198.51.100.20", flags="MF")
        / TCP(sport=8889, dport=51000, flags="A")
    )

    with pytest.raises(ValueError, match="fragment"):
        handler(_parsed_ether(packet))

    assert consumer.segments == []


@pytest.mark.parametrize("flags", ("MF", ""))
def test_non_initial_ipv4_fragments_without_tcp_header_are_ignored(
    flags: str,
) -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)
    packet = (
        Ether()
        / IP(
            src="203.0.113.10",
            dst="198.51.100.20",
            proto=6,
            flags=flags,
            frag=1,
        )
        / Raw(load=b"fragment body")
    )

    handler(_parsed_ether(packet))

    assert consumer.segments == []


def test_fragmented_unselected_tcp_flow_is_ignored() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)
    packet = (
        Ether()
        / IP(src="203.0.113.10", dst="198.51.100.20", flags="MF")
        / TCP(sport=80, dport=51000, flags="A")
    )

    handler(_parsed_ether(packet))

    assert consumer.segments == []


@pytest.mark.parametrize(
    ("flags", "expected"),
    (
        ("S", (True, False, False)),
        ("FA", (False, False, True)),
        ("RA", (False, True, False)),
    ),
)
def test_control_flags_survive_padding_removal(
    flags: str,
    expected: tuple[bool, bool, bool],
) -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)

    handler(_parsed_ether(_tcp_packet(flags=flags) / Padding(load=b"\x00" * 6)))

    segment = consumer.segments[0]
    assert segment["payload"] == b""
    assert (segment["syn"], segment["rst"], segment["fin"]) == expected


def test_ipv6_non_tcp_and_non_ip_packets_remain_out_of_scope() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)

    handler(
        _parsed_ether(
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / TCP(sport=8889, dport=51000)
            / Raw(load=b"ipv6")
        )
    )
    handler(
        _parsed_ether(
            Ether()
            / IP(src="203.0.113.10", dst="198.51.100.20", proto=17)
            / Raw(load=b"udp-like")
        )
    )
    handler(_parsed_ether(Ether() / ARP()))

    assert consumer.segments == []


def test_same_sequence_padding_ack_does_not_trim_following_payload() -> None:
    consumer = RecordingConsumer()
    handler = make_packet_handler(consumer)

    handler(_parsed_ether(_tcp_packet(sequence=1000) / Padding(load=b"\x00" * 6)))
    handler(
        _parsed_ether(
            _tcp_packet(flags="PA", sequence=1000) / Raw(load=b"complete payload")
        )
    )

    assert [segment["payload"] for segment in consumer.segments] == [
        b"",
        b"complete payload",
    ]


def test_padding_ack_cannot_poison_full_decoder_at_same_sequence() -> None:
    callbacks = []
    engine = PacketEngine(
        server_ports=(8889,),
        event_specs=(
            EventSpec(
                label="LOOT_PREVIEW",
                opcode=0x1643,
                item_offset=23,
                quantity_offset=27,
                min_message_length=31,
                default_context="Gathering",
            ),
        ),
        on_event=lambda event, raw: callbacks.append((event, raw)),
    )
    handler = make_packet_handler(engine)
    frame = _loot_preview_frame(item_id=7001, quantity=28)

    # Establish a warm flow. SYN consumes sequence 999, so data starts at 1000.
    handler(_parsed_ether(_tcp_packet(flags="S", sequence=999)))
    padded_ack = _parsed_ether(
        _tcp_packet(sequence=1000) / Padding(load=b"\x00" * 6)
    )
    assert padded_ack[IP].len == 40
    assert len(bytes(padded_ack[TCP].payload)) == 6
    handler(padded_ack)
    handler(_parsed_ether(_tcp_packet(flags="PA", sequence=1000) / Raw(load=frame)))
    engine.finish()

    assert len(callbacks) == 1
    event, raw = callbacks[0]
    assert (event.item_id, event.quantity, event.stream_sequence) == (7001, 28, 1000)
    assert raw == frame
    assert engine.events_found == 1
    assert engine.tcp_gap_resets == 0


def test_pcap_replay_padding_cannot_hide_worker_storage_boundary(
    tmp_path: Path,
) -> None:
    worker = _worker_storage_frame(item_id=7001, quantity=28)
    preamble = bytearray(_generic_frame(0x175A, 27))
    preamble[6:8] = (len(preamble) + len(worker) - 6).to_bytes(2, "little")
    stream = bytes(preamble) + worker + _generic_frame(0x9999, 5)
    padding = bytes.fromhex("00008f63ff26")
    packets = (
        _tcp_packet(flags="S", sequence=999),
        _tcp_packet(sequence=1000) / Padding(load=padding),
        _tcp_packet(flags="PA", sequence=1000) / Raw(load=stream),
    )
    capture = tmp_path / "same-sequence-padding.pcap"
    wrpcap(str(capture), packets)
    collector = _EventCollector(
        server_ports=(8889,),
        opcode_profile=JULY17_OPCODE_PROFILE,
    )

    list(iter_pcap_file(capture, collector.engine))
    collector.finalize()

    events = list(collector.drain_events())
    assert [
        (
            event.event_type,
            event.item_id,
            event.quantity,
            event.source,
            event.storage_id,
            event.storage_name,
        )
        for event in events
    ] == [("storage_delta", 7001, 28, "Worker Production", 5, "Velia")]
    health = collector.decoder_health
    assert (
        health.storage_messages_observed,
        health.storage_messages_decoded,
        health.storage_records_decoded,
    ) == (1, 1, 1)
    assert collector.engine.tcp_gap_resets == 0
