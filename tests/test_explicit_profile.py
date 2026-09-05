"""Regression coverage for the tracked July 17 opcode profile."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from fixture_paths import JULY17_OPCODE_PROFILE, fixture_path, has_fixture_pcaps

from bdo_toolkit import load_opcode_profile, replay_pcap
from bdo_toolkit.capture import _EventCollector


def _entry_shape(
    entry: Mapping[str, object], *fields: str
) -> tuple[object, ...]:
    return tuple(entry.get(field) for field in fields)


def test_tracked_profile_is_the_reviewed_july17_authority() -> None:
    profile = load_opcode_profile(JULY17_OPCODE_PROFILE)

    assert profile.active is True
    assert set(profile.specs) == {
        "INVENTORY_TRANSFER",
        "LOOT_PREVIEW",
        "SOURCE_CONTAINER_DECREMENT",
        "SOURCE_ITEM_REFERENCE",
        "SOURCE_STACK_DECREMENT",
        "STORAGE_ITEM_DELTA",
    }
    assert all(len(entries) == 1 for entries in profile.specs.values())

    assert _entry_shape(
        profile.specs["INVENTORY_TRANSFER"][0],
        "opcode",
        "length",
        "item_id_offset",
        "quantity_offset",
        "context_offset",
        "item_instance_offset",
        "repeat_stride",
    ) == ("0x194A", 254, 31, 35, 27, 66, None)
    assert _entry_shape(
        profile.specs["STORAGE_ITEM_DELTA"][0],
        "opcode",
        "length",
        "item_id_offset",
        "quantity_added_offset",
        "destination_instance_offset",
        "context_offset",
        "record_count_offset",
        "repeat_stride",
    ) == ("0x126D", 257, 36, 40, 71, 27, 16, None)
    assert _entry_shape(
        profile.specs["SOURCE_CONTAINER_DECREMENT"][0],
        "opcode",
        "length",
        "source_instance_offset",
        "quantity_removed_offset",
        "context_offset",
    ) == ("0x17E8", 42, 5, 17, 13)
    assert _entry_shape(
        profile.specs["SOURCE_ITEM_REFERENCE"][0],
        "opcode",
        "length",
        "item_id_offset",
    ) == ("0x0F63", 23, 9)
    assert _entry_shape(
        profile.specs["SOURCE_STACK_DECREMENT"][0],
        "opcode",
        "length",
        "source_instance_offset",
        "quantity_removed_offset",
    ) == ("0x11AD", 47, 35, 27)

    # Loot was not part of the July 17 transfer calibration. Keep the last
    # reviewed loot entry instead of replacing it with local [] data.
    assert _entry_shape(
        profile.specs["LOOT_PREVIEW"][0],
        "opcode",
        "length",
        "item_id_offset",
        "quantity_offset",
        "item_instance_offset",
    ) == ("0x1643", 244, 23, 27, 58)

    (family,) = profile.origin_companion_families
    assert family.delta_opcode == 0x126D
    assert family.companion_opcodes == (0x1A59, 0x155E)
    assert family.companion_lengths == (64, 30)
    assert family.detection == "shared-token-chain-v1"


def _inventory_snapshot(records: tuple[tuple[int, int], ...]) -> bytes:
    stride = 223
    message = bytearray(254 + (len(records) - 1) * stride)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x194A).to_bytes(2, "little")
    message[22:24] = len(records).to_bytes(2, "little")
    for index, (item_id, quantity) in enumerate(records):
        item_offset = 31 + index * stride
        message[item_offset : item_offset + 4] = item_id.to_bytes(4, "little")
        message[item_offset + 4 : item_offset + 8] = quantity.to_bytes(4, "little")
        message[item_offset + 35 : item_offset + 43] = (index + 1).to_bytes(
            8, "little"
        )
    return bytes(message)


def _storage_delta(
    records: tuple[tuple[int, int], ...],
    *,
    mode: int = 1,
) -> bytes:
    stride = 222
    message = bytearray(257 + (len(records) - 1) * stride)
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = (0x126D).to_bytes(2, "little")
    message[6] = mode
    message[7:15] = bytes.fromhex("3141592653589793")
    message[16:18] = len(records).to_bytes(2, "little")
    message[27:31] = (0x0020).to_bytes(4, "little")
    for index, (item_id, quantity) in enumerate(records):
        item_offset = 36 + index * stride
        message[item_offset : item_offset + 4] = item_id.to_bytes(4, "little")
        message[item_offset + 4 : item_offset + 8] = quantity.to_bytes(4, "little")
        message[item_offset + 35 : item_offset + 43] = (
            0x8877665544332211 + index
        ).to_bytes(
            8, "little"
        )
    return bytes(message)


def _message(opcode: int, length: int, *, token: bytes | None = None) -> bytes:
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    if token is not None:
        message[5:13] = token
    return bytes(message)


def _worker_companions() -> bytes:
    token = bytes.fromhex("3141592653589793")
    return _message(0x1A59, 64, token=token) + _message(0x155E, 30, token=token)


def _manual_decrement(
    quantity: int,
    instance: int = 0x8877665544332211,
) -> bytes:
    message = bytearray(_message(0x11AD, 47))
    message[27:31] = quantity.to_bytes(4, "little")
    message[35:43] = instance.to_bytes(8, "little")
    return bytes(message)


def _collect_with_july17_profile(payload: bytes):
    collector = _EventCollector(
        server_ports=(8889,), opcode_profile=JULY17_OPCODE_PROFILE
    )
    collector.engine.process_tcp_segment(
        source_ip="203.0.113.10",
        source_port=8889,
        destination_ip="198.51.100.20",
        destination_port=51000,
        sequence=1000,
        payload=payload,
        timestamp=1000.0,
    )
    collector.engine.finish()
    collector.finalize()
    return list(collector.drain_events())


def test_july17_profile_decodes_generated_batches() -> None:
    events = _collect_with_july17_profile(
        _inventory_snapshot(((7003, 2), (7004, 3)))
        + _storage_delta(((4802, 1), (4003, 21)))
        + _worker_companions(),
    )
    inventory = [event for event in events if event.event_type == "inventory_snapshot"]
    storage = [event for event in events if event.event_type == "storage_delta"]

    assert [
        (event.item_id, event.quantity, event.record_index, event.record_count)
        for event in inventory
    ] == [(7003, 2, 1, 2), (7004, 3, 2, 2)]
    assert [
        (event.item_id, event.quantity, event.record_index, event.record_count)
        for event in storage
    ] == [(4802, 1, 1, 2), (4003, 21, 2, 2)]
    assert {event.storage_name for event in storage} == {"Heidel"}
    assert {event.source for event in storage} == {"Worker Production"}
    assert all(
        event.extra["deposit_origin_evidence"]["companion_chain"]["known_family"]
        is True
        for event in storage
    )
    assert all(
        event.extra["deposit_origin_evidence"]["companion_chain"]["confirmation"]
        == "profile"
        for event in storage
    )


def test_july17_profile_uses_current_decrement_for_manual_deposit() -> None:
    events = _collect_with_july17_profile(
        _manual_decrement(8) + _storage_delta(((7307, 8),), mode=3),
    )

    assert len(events) == 1
    event = events[0]
    assert (event.event_type, event.item_id, event.quantity) == (
        "storage_delta",
        7307,
        8,
    )
    assert event.source == "Player Inventory"
    assert event.storage_name == "Heidel"
    assert event.extra["storage_operation_evidence"]["signal"] == (
        "matching_decrement"
    )
    assert event.extra["deposit_origin_evidence"]["manual_decrement"] == {
        "opcode": "0x11AD",
        "message_length": 47,
        "quantity_offset": 27,
        "source_instance_offset": 35,
        "match_kind": "instance-and-quantity",
        "confidence": "observed",
        "instance_matches_destination": True,
        "record_index": 1,
    }


def test_july17_profile_does_not_match_the_disproved_offset_19() -> None:
    instance = 0x8877665544332211
    decrement = bytearray(_message(0x11AD, 47))
    decrement[19:27] = instance.to_bytes(8, "little")
    decrement[27:31] = (8).to_bytes(4, "little")
    # The capture-proven source field at offset 35 is deliberately empty.
    events = _collect_with_july17_profile(
        bytes(decrement) + _storage_delta(((7307, 8),), mode=1),
    )

    assert len(events) == 1
    event = events[0]
    assert event.event_type == "storage_record"
    assert event.source is None


@pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)
def test_july17_profile_uses_exact_manual_instance_evidence() -> None:
    events = [
        event
        for event in replay_pcap(
            fixture_path("calibration_5_inven_0_storage.pcapng"),
            opcode_profile=JULY17_OPCODE_PROFILE,
        )
        if event.event_type == "storage_delta"
        and event.item_id == 7003
        and event.quantity == 5
    ]

    assert len(events) == 1
    event = events[0]
    assert event.source == "Player Inventory"
    manual = event.extra["deposit_origin_evidence"]["manual_decrement"]
    assert manual["source_instance_offset"] == 35
    assert manual["match_kind"] == "instance-and-quantity"
    assert manual["confidence"] == "observed"
    assert manual["instance_matches_destination"] is True
