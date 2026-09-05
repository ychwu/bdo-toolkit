"""Synthetic layouts shared by frame-boundary and live-clock tests."""

from pathlib import Path

from bdo_toolkit import OpcodeProfile


def framing_profile(*, repeat_stride=None):
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


def framing_message(opcode, *, count=1):
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


def feed_collector(collector, payload, *, sequence=100, timestamp=1000.0, syn=False):
    collector.engine.process_tcp_segment(
        source_ip="192.0.2.1", source_port=8889,
        destination_ip="192.0.2.2", destination_port=50000,
        sequence=sequence & 0xFFFFFFFF, payload=payload,
        timestamp=timestamp, syn=syn,
    )


def finish_collector(collector):
    collector.engine.finish()
    collector.finalize()
    return list(collector.drain_events())
