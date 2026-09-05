"""Synthetic item packets and passive engine input for regression tests."""

from bdo_toolkit._engine import PacketEngine
from bdo_toolkit._protocol import EventSpec


def loot_preview_frame(item_id: int = 7003, quantity: int = 3) -> bytes:
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
        record_count_offset=6,
        storage_instance_offset=72,
        repeat_stride=226,
        single_record_message_length=261,
        default_context="Storage",
    ),
)


def make_item_engine(events: list) -> PacketEngine:
    return PacketEngine(
        server_ports=(8889,),
        event_specs=SYNTHETIC_EVENT_SPECS,
        on_event=lambda event, raw: events.append(event),
    )


def feed_engine(
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
