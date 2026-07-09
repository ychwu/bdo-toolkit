"""Composable event filters for app-facing streams."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .events import BDOEvent


def _freeze(values: Optional[Iterable[object]]) -> Optional[frozenset[object]]:
    if values is None:
        return None
    return frozenset(values)


@dataclass(frozen=True)
class EventFilter:
    """Filter decoded events before yielding them to an application."""

    event_types: Optional[frozenset[str]] = None
    sources: Optional[frozenset[str]] = None
    item_ids: Optional[frozenset[int]] = None
    deposit_origins: Optional[frozenset[str]] = None

    @classmethod
    def from_values(
        cls,
        *,
        event_types: Optional[Iterable[str]] = None,
        sources: Optional[Iterable[str]] = None,
        item_ids: Optional[Iterable[int]] = None,
        deposit_origins: Optional[Iterable[str]] = None,
    ) -> "EventFilter":
        return cls(
            event_types=_freeze(event_types),
            sources=_freeze(sources),
            item_ids=_freeze(item_ids),
            deposit_origins=_freeze(deposit_origins),
        )

    def allows(self, event: BDOEvent) -> bool:
        if self.event_types is not None and event.event_type not in self.event_types:
            return False
        if self.sources is not None and event.source not in self.sources:
            return False
        if self.item_ids is not None and event.item_id not in self.item_ids:
            return False
        if (
            self.deposit_origins is not None
            and event.deposit_origin not in self.deposit_origins
        ):
            # Non-storage events have deposit_origin None and never match.
            return False
        return True

