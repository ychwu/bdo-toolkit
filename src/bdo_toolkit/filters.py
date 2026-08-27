"""Composable event filters for app-facing streams."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, TypeVar

from .events import BDOEvent


T = TypeVar("T")


_ACTIVITY_EVENT_TYPES = frozenset(
    {"loot_preview", "item_received", "storage_delta"}
)
_SNAPSHOT_RECORD_EVENT_TYPES = frozenset(
    {"inventory_snapshot", "storage_snapshot"}
)


def _freeze(values: Optional[Iterable[T]]) -> Optional[frozenset[T]]:
    if values is None:
        return None
    if isinstance(values, (str, bytes)):
        raise TypeError("filter values must be an iterable of values, not a string")
    return frozenset(values)


@dataclass(frozen=True, init=False)
class EventFilter:
    """Filter completed events before yielding them to an application.

    Constructing ``EventFilter()`` directly remains an unconstrained filter.
    The named presets make common delivery policies explicit without changing
    the meaning of any caller-supplied filter.
    """

    event_types: Optional[frozenset[str]] = None
    # Exact semantic origin, producing-system, or event-context labels.
    sources: Optional[frozenset[str]] = None
    # Authoritative numeric storage destination identities.
    storage_ids: Optional[frozenset[int]] = None
    item_ids: Optional[frozenset[int]] = None

    def __init__(
        self,
        *,
        event_types: Optional[Iterable[str]] = None,
        sources: Optional[Iterable[str]] = None,
        storage_ids: Optional[Iterable[int]] = None,
        item_ids: Optional[Iterable[int]] = None,
    ) -> None:
        # Normalize at the public constructor boundary so callers can use
        # ordinary sets/lists while the frozen object remains truly immutable.
        object.__setattr__(self, "event_types", _freeze(event_types))
        object.__setattr__(self, "sources", _freeze(sources))
        object.__setattr__(self, "storage_ids", _freeze(storage_ids))
        object.__setattr__(self, "item_ids", _freeze(item_ids))

    @classmethod
    def from_values(
        cls,
        *,
        event_types: Optional[Iterable[str]] = None,
        sources: Optional[Iterable[str]] = None,
        storage_ids: Optional[Iterable[int]] = None,
        item_ids: Optional[Iterable[int]] = None,
    ) -> "EventFilter":
        return cls(
            event_types=event_types,
            sources=sources,
            storage_ids=storage_ids,
            item_ids=item_ids,
        )

    @classmethod
    def activity(cls) -> "EventFilter":
        """Ordinary live events, excluding hydration and neutral diagnostics."""

        return cls(event_types=_ACTIVITY_EVENT_TYPES)

    @classmethod
    def snapshot_records(cls) -> "EventFilter":
        """Per-record inventory and storage character-load hydration."""

        return cls(event_types=_SNAPSHOT_RECORD_EVENT_TYPES)

    @classmethod
    def all(cls) -> "EventFilter":
        """Every completed decoded event, equivalent to ``EventFilter()``."""

        return cls()

    def allows(self, event: BDOEvent) -> bool:
        if self.event_types is not None and event.event_type not in self.event_types:
            return False
        if self.sources is not None and event.source not in self.sources:
            return False
        if self.storage_ids is not None and event.storage_id not in self.storage_ids:
            return False
        if self.item_ids is not None and event.item_id not in self.item_ids:
            return False
        return True

