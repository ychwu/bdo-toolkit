"""Experimental character-load snapshot APIs.

Implementation is organized by responsibility in the private ``_item_state``
package. This module preserves the established public imports and object names;
``bdo_toolkit.item_state`` provides the equivalent item-domain naming.
"""

# Public class annotations still resolve through this established module path.
from typing import Optional

from .diagnostics import DecoderHealth
from ._item_state.formatting import format_character_state
from ._item_state.models import (
    CharacterStateSnapshot,
    InventoryContainerSummary,
    InventorySnapshotSummary,
    ItemStateCaptureLimitError,
    ItemStateCaptureLimits,
    ItemStateCoverage,
    ItemStateDiagnostics,
    ItemStateProvenance,
    InventoryHydrationDiagnostics,
    SnapshotItem,
    StorageDestinationDiagnostics,
    StorageHydrationDiagnostics,
    StorageContents,
    StorageSnapshotSummary,
)
from ._item_state.session import (
    CharacterLoadSession,
    analyze_character_load_pcap,
)
__all__ = [
    "CharacterLoadSession",
    "CharacterStateSnapshot",
    "InventoryContainerSummary",
    "InventorySnapshotSummary",
    "ItemStateCaptureLimitError",
    "ItemStateCaptureLimits",
    "ItemStateCoverage",
    "ItemStateDiagnostics",
    "ItemStateProvenance",
    "InventoryHydrationDiagnostics",
    "SnapshotItem",
    "StorageDestinationDiagnostics",
    "StorageHydrationDiagnostics",
    "StorageContents",
    "StorageSnapshotSummary",
    "analyze_character_load_pcap",
    "format_character_state",
]

# Preserve public object locations for introspection and existing pickles.
for _name in __all__:
    globals()[_name].__module__ = __name__
del _name
