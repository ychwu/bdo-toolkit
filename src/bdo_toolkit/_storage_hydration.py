"""Stateful, offset-free storage hydration classification."""

from __future__ import annotations

import dataclasses
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable, Optional

from .events import BDOEvent, Flow


type _HydrationKey = tuple[Flow, int]


def _hydration_key(event: BDOEvent) -> _HydrationKey:
    return event.flow, event._flow_generation


@dataclass
class _HydrationBurst:
    first_timestamp: float
    last_timestamp: float
    anchored: bool
    opcode: Optional[int]
    events: list[BDOEvent] = field(default_factory=list)
    destinations: set[int] = field(default_factory=set)
    max_record_count: int = 0
    confirmed: bool = False


class StorageHydrationTracker:
    """Promote neutral storage cohorts to snapshots before app filtering.

    Inventory hydration opens a bounded epoch on the same flow.  Neutral
    storage wrappers are grouped by wire timestamp after manual/worker origin
    evidence has had first refusal.  A multi-destination cohort proves state
    hydration without consulting any patch-specific mode or token byte.

    A broader unanchored threshold retains storage-only snapshot evidence when
    inventory framing was missed.  Isolated unresolved records remain neutral
    and therefore never enter ordinary activity filters.
    """

    BURST_GAP_SECONDS = 0.5
    MAX_BURST_SECONDS = 1.0
    HYDRATION_EPOCH_SECONDS = 30.0
    INVENTORY_GENERATION_GAP_SECONDS = 1.0
    MIN_ANCHORED_DESTINATIONS = 8
    MIN_UNANCHORED_DESTINATIONS = 17
    MIN_UNANCHORED_RECORD_COUNT = 8
    MAX_PENDING_EVENTS = 10_000

    def __init__(self, emit: Callable[[BDOEvent], object]) -> None:
        self._emit = emit
        self._lock = RLock()
        self._inventory_anchor: dict[_HydrationKey, float] = {}
        self._inventory_last: dict[_HydrationKey, float] = {}
        self._bursts: dict[_HydrationKey, _HydrationBurst] = {}
        self._outbox: deque[BDOEvent] = deque()
        self._dispatching = False

    def observe_inventory(self, event: BDOEvent) -> None:
        """Record a proven inventory-hydration boundary and emit the event."""
        key = _hydration_key(event)
        with self._lock:
            last = self._inventory_last.get(key)
            if (
                last is None
                or event.timestamp - last > self.INVENTORY_GENERATION_GAP_SECONDS
            ):
                self._flush_key_locked(key)
                self._inventory_anchor[key] = event.timestamp
            self._inventory_last[key] = event.timestamp
            self._queue_locked(event)
        self._drain_outbox()

    def observe_storage(self, event: BDOEvent) -> None:
        """Stage one neutral record or pass through an independently live one."""
        key = _hydration_key(event)
        if event.event_type != "storage_record":
            with self._lock:
                # Positive mutation evidence is an explicit semantic boundary.
                # It must not inherit a prior confirmed hydration burst, and a
                # subsequent unknown record must prove a new epoch. Origin
                # lookahead can deliver an older live event after a newer
                # hydration anchor, so only retire state at or before this
                # event's own wire timestamp.
                burst = self._bursts.get(key)
                if burst is None or event.timestamp >= burst.first_timestamp:
                    self._flush_key_locked(key)
                anchor = self._inventory_anchor.get(key)
                if anchor is None or event.timestamp >= anchor:
                    self._inventory_anchor.pop(key, None)
                    self._inventory_last.pop(key, None)
                self._queue_locked(event)
            self._drain_outbox()
            return

        with self._lock:
            anchor = self._inventory_anchor.get(key)
            anchored = (
                anchor is not None
                and anchor <= event.timestamp
                and event.timestamp - anchor <= self.HYDRATION_EPOCH_SECONDS
            )
            burst = self._bursts.get(key)
            if (
                burst is None
                or event.timestamp - burst.last_timestamp > self.BURST_GAP_SECONDS
                or event.timestamp - burst.first_timestamp > self.MAX_BURST_SECONDS
                or event.timestamp < burst.last_timestamp
                or burst.anchored != anchored
                or burst.opcode != event.opcode
            ):
                self._flush_key_locked(key)
                burst = _HydrationBurst(
                    first_timestamp=event.timestamp,
                    last_timestamp=event.timestamp,
                    anchored=anchored,
                    opcode=event.opcode,
                )
                self._bursts[key] = burst

            burst.last_timestamp = event.timestamp
            if event.storage_id is not None:
                burst.destinations.add(event.storage_id)
            if isinstance(event.record_count, int) and not isinstance(
                event.record_count, bool
            ):
                burst.max_record_count = max(
                    burst.max_record_count,
                    event.record_count,
                )

            if burst.confirmed:
                self._queue_locked(self._as_snapshot(event, burst))
            else:
                burst.events.append(event)
                enough_destinations = len(burst.destinations) >= (
                    self.MIN_ANCHORED_DESTINATIONS
                    if anchored
                    else self.MIN_UNANCHORED_DESTINATIONS
                )
                credible_unanchored = (
                    anchored
                    or burst.max_record_count >= self.MIN_UNANCHORED_RECORD_COUNT
                )
                if enough_destinations and credible_unanchored:
                    burst.confirmed = True
                    for pending in burst.events:
                        self._queue_locked(self._as_snapshot(pending, burst))
                    burst.events.clear()
                elif len(burst.events) > self.MAX_PENDING_EVENTS:
                    # Bounded fail-neutral behavior: an unproven cohort must not
                    # consume unbounded memory or become activity by default.
                    self._flush_key_locked(key)
        self._drain_outbox()

    def flush_stale(self, now: float) -> None:
        with self._lock:
            stale = tuple(
                key
                for key, burst in self._bursts.items()
                if now - burst.last_timestamp > self.BURST_GAP_SECONDS
            )
            for key in stale:
                self._flush_key_locked(key)
            expired_anchors = tuple(
                key
                for key, anchor in self._inventory_anchor.items()
                if now - anchor > self.HYDRATION_EPOCH_SECONDS
            )
            for key in expired_anchors:
                self._inventory_anchor.pop(key, None)
                self._inventory_last.pop(key, None)
        self._drain_outbox()

    def close_flow(self, flow: Flow) -> None:
        with self._lock:
            keys = {
                key
                for key in (
                    set(self._bursts)
                    | set(self._inventory_anchor)
                    | set(self._inventory_last)
                )
                if key[0] == flow
            }
            for key in keys:
                self._flush_key_locked(key)
                self._inventory_anchor.pop(key, None)
                self._inventory_last.pop(key, None)
        self._drain_outbox()

    def finalize_all(self) -> None:
        with self._lock:
            for key in tuple(self._bursts):
                self._flush_key_locked(key)
            self._inventory_anchor.clear()
            self._inventory_last.clear()
        self._drain_outbox()

    def _flush_key_locked(self, key: _HydrationKey) -> None:
        burst = self._bursts.pop(key, None)
        if burst is None:
            return
        # Confirmed events were emitted as they arrived. Only an unconfirmed
        # burst retains entries, and those remain explicitly neutral.
        for event in burst.events:
            self._queue_locked(event)

    @staticmethod
    def _as_snapshot(event: BDOEvent, burst: _HydrationBurst) -> BDOEvent:
        return dataclasses.replace(
            event,
            event_type="storage_snapshot",
            source=None,
        )

    def _queue_locked(self, event: BDOEvent) -> None:
        self._outbox.append(event)

    def _drain_outbox(self) -> None:
        with self._lock:
            if self._dispatching:
                return
            self._dispatching = True
        try:
            while True:
                with self._lock:
                    if not self._outbox:
                        self._dispatching = False
                        return
                    event = self._outbox.popleft()
                self._emit(event)
        except BaseException:
            with self._lock:
                self._dispatching = False
            raise
