"""Canonical experimental facade for aggregate inventory and storage state.

Implementation lives in the private ``_item_state`` package. This facade and
:mod:`bdo_toolkit.character_state` expose the same objects under their existing
names, without a package-root stability promise.
"""

from __future__ import annotations

from ._item_state.character_models import (
    CharacterItem, CharacterLoadout, CharacterRoster, CharacterSection,
)
from ._item_state.character_profile import CharacterLayoutProfile
from .character_state import (
    CharacterLoadSession,
    CharacterStateSnapshot as ItemStateSnapshot,
    InventoryContainerSummary,
    InventoryHydrationDiagnostics,
    InventorySnapshotSummary,
    ItemStateCaptureLimitError,
    ItemStateCaptureLimits,
    ItemStateCoverage,
    ItemStateDiagnostics,
    ItemStateProvenance,
    SnapshotItem,
    StorageContents,
    StorageDestinationDiagnostics,
    StorageHydrationDiagnostics,
    StorageSnapshotSummary,
    analyze_character_load_pcap as analyze_item_state_pcap,
    format_character_state as format_item_state,
)

__all__ = [
    "CharacterLoadSession",
    "CharacterItem",
    "CharacterLayoutProfile",
    "CharacterLoadout",
    "CharacterRoster",
    "CharacterSection",
    "InventoryContainerSummary",
    "InventoryHydrationDiagnostics",
    "InventorySnapshotSummary",
    "ItemStateCaptureLimitError",
    "ItemStateCaptureLimits",
    "ItemStateCoverage",
    "ItemStateDiagnostics",
    "ItemStateProvenance",
    "ItemStateSnapshot",
    "SnapshotItem",
    "StorageContents",
    "StorageDestinationDiagnostics",
    "StorageHydrationDiagnostics",
    "StorageSnapshotSummary",
    "analyze_item_state_pcap",
    "format_item_state",
]
