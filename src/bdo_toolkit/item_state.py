"""Canonical experimental facade for aggregate inventory and storage state.

The implementation remains in :mod:`bdo_toolkit.character_state` so existing
imports continue to work.  These aliases provide item-domain naming without a
wholesale move or package-root stability promise.
"""

from __future__ import annotations

from .character_state import (
    CharacterLoadSession,
    CharacterStateSnapshot as ItemStateSnapshot,
    InventoryContainerSummary,
    InventorySnapshotSummary,
    ItemStateCaptureLimitError,
    ItemStateCaptureLimits,
    ItemStateCoverage,
    ItemStateProvenance,
    SnapshotItem,
    StorageContents,
    StorageSnapshotSummary,
    analyze_character_load_pcap as analyze_item_state_pcap,
    format_character_state as format_item_state,
)

__all__ = [
    "CharacterLoadSession",
    "InventoryContainerSummary",
    "InventorySnapshotSummary",
    "ItemStateCaptureLimitError",
    "ItemStateCaptureLimits",
    "ItemStateCoverage",
    "ItemStateProvenance",
    "ItemStateSnapshot",
    "SnapshotItem",
    "StorageContents",
    "StorageSnapshotSummary",
    "analyze_item_state_pcap",
    "format_item_state",
]
