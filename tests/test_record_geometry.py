"""Shared record arithmetic must preserve each decoder's acceptance policy."""

from dataclasses import replace

import pytest

from bdo_toolkit._framing import (
    _declared_inventory_snapshot_record_deltas,
    _declared_storage_record_deltas,
)
from bdo_toolkit._protocol import EventSpec


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


def test_shared_geometry_preserves_distinct_quantity_widths():
    message, inventory, storage = _batch(quantity=1 << 32)
    assert _declared_inventory_snapshot_record_deltas(inventory, message) == [0, 64]
    assert _declared_storage_record_deltas(storage, message) == []


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


@pytest.mark.parametrize("invalid_field", ["item", "quantity", "instance"])
def test_a_corrupt_second_record_rejects_the_entire_batch(invalid_field):
    message, inventory, storage = _batch()
    assert _declared_inventory_snapshot_record_deltas(inventory, message) == [0, 64]
    assert _declared_storage_record_deltas(storage, message) == [0, 64]
    offset, width = {"item": (32, 4), "quantity": (36, 8), "instance": (67, 8)}[
        invalid_field
    ]
    message[64 + offset:64 + offset + width] = bytes(width)
    assert _declared_inventory_snapshot_record_deltas(inventory, message) is None
    assert _declared_storage_record_deltas(storage, message) == []
