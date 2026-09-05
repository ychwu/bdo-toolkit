"""Private calibration constants implementation."""

from __future__ import annotations

from .._protocol import (
    CHARACTER_LOAD_CONTEXT,
    SOURCE_CONTEXT_LABELS,
    STORAGE_DELTA_CONTEXTS,
)


CALIBRATION_ACTIONS = (
    "loot-preview",
    "storage-to-inventory",
    "inventory-to-storage",
)
DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES = 50_000
DEFAULT_CALIBRATION_MAX_RETAINED_BYTES = 64 * 1024 * 1024
_CALIBRATION_MAX_ACTIVE_FLOWS = 64
OPCODE_PROFILE_EVENTS = (
    "LOOT_PREVIEW",
    "INVENTORY_TRANSFER",
    "SOURCE_CONTAINER_DECREMENT",
    "SOURCE_STACK_DECREMENT",
    "SOURCE_ITEM_REFERENCE",
    "STORAGE_ITEM_DELTA",
)
_FAMILY_LABELS = {
    "into_inventory": "storage->inventory",
    "into_storage": "inventory->storage",
}
REFERENCE_FRAME_MAX_LENGTH = 128
SOURCE_DECREMENT_FRAME_MAX_LENGTH = 512
_HIGH_ENTROPY_CONTEXTS = tuple(
    value
    for value in SOURCE_CONTEXT_LABELS
    if value != CHARACTER_LOAD_CONTEXT and value not in STORAGE_DELTA_CONTEXTS
)
_EXPECTED_FAMILY = {
    "storage-to-inventory": "into_inventory",
    "inventory-to-storage": "into_storage",
}
