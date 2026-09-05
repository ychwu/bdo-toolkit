"""Item-state inference thresholds and provisional display labels."""

from __future__ import annotations


_INVENTORY_GENERATION_GAP_SECONDS = 1.0
_INVENTORY_TRAILING_DISCOVERY_BYTES = 12
_STORAGE_DESTINATION_CHUNK_GAP_SECONDS = 1.0
_STORAGE_EMPTY_WINDOW_MARGIN_SECONDS = 1.0
_STORAGE_HYDRATION_BURST_GAP_SECONDS = 0.5
_STORAGE_HYDRATION_MAX_BURST_SECONDS = 1.0
_STORAGE_HYDRATION_EPOCH_SECONDS = 30.0
_STORAGE_HYDRATION_MIN_DESTINATIONS = 8
_ITEM_STATE_SCHEMA_VERSION = 5
# Provisional interpretations from the July 17 load/switch captures.
# Raw container codes remain authoritative.
_INVENTORY_CONTAINER_LABELS: dict[int, tuple[str, str]] = {
    0x00: ("Main Inventory", "provisional"),
    0x10: ("Pearl Inventory", "provisional"),
    0x18: ("Global Currencies", "provisional"),
    0x0B: ("Enhancement Inventory", "provisional"),
}
_CURRENCY_NAMES: dict[tuple[int, int], str] = {
    (0x18, 1): "Silver",
    (0x10, 6): "Pearl",
    (0x10, 7): "Loyalties",
    (0x18, 10): "Crow Coin",
}
