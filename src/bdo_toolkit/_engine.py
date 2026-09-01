"""Native packet engine: flow tracking, dedup, and event normalization."""

from __future__ import annotations

from collections import deque
import hashlib
from threading import Lock
from typing import Callable, Iterable, Optional

from ._framing import FrameCollectorScanner, MessageObserver, TargetMessageScanner
from ._protocol import (
    CHARACTER_LOAD_CONTEXT,
    DEDUP_HISTORY_LIMIT,
    BDOFrame,
    EventSpec,
    FlowKey,
    LootEvent,
    source_label,
    split_item_id_enhancement,
    storage_location,
    PacketContext,
)
from ._reassembly import FlowManager
from .events import BDOEvent, Flow


_ITEM_MAX_ACTIVE_FLOWS = 64
_ITEM_FLOW_IDLE_SECONDS = 300.0


class _TeeScanner:
    """Feed one reassembled stream to the target scanner and observers.

    Observers run FIRST so correlation logic already holds every raw span and
    generic frame of a TCP segment when the target scanner emits events.
    """

    def __init__(
        self,
        primary: TargetMessageScanner,
        tap: Optional[FrameCollectorScanner],
        stream_observer: Optional[Callable[[bytes, PacketContext], None]],
    ) -> None:
        self._primary = primary
        self._tap = tap
        self._stream_observer = stream_observer

    def feed(self, data, context) -> None:
        if self._stream_observer is not None:
            self._stream_observer(data, context)
        if self._tap is not None:
            self._tap.feed(data, context)
        self._primary.feed(data, context)

    def scan_standalone(self, data, context) -> None:
        if self._stream_observer is not None:
            self._stream_observer(data, context)
        if self._tap is not None:
            self._tap.scan_standalone(data, context)
        self._primary.scan_standalone(data, context)

    def can_anchor_at_start(self, data: bytes) -> bool:
        # Observers must never make primary event reassembly less conservative.
        # The generic tap accepts weaker standalone-frame evidence that is safe
        # for observation but can be a coincidental header in a target suffix.
        return self._primary.can_anchor_at_start(data)

    def reset(self) -> None:
        if self._tap is not None:
            self._tap.reset()
        self._primary.reset()


def toolkit_event_from_record(event: LootEvent) -> BDOEvent:
    """Normalize a decoded protocol record into the stable app-facing event."""
    decoded_base_item_id, enhancement_level, enhancement = split_item_id_enhancement(
        event.item_id
    )
    base_item_id: Optional[int] = (
        decoded_base_item_id if enhancement_level is not None else None
    )

    is_storage = event.label == "INVENTORY_TO_STORAGE"
    storage_id = event.storage_id
    if storage_id is not None and not 0 < storage_id <= 0xFFFFFFFF:
        storage_id = None
    if (
        is_storage
        and storage_id is None
        and event.source_context_candidate is not None
        and len(event.source_context_candidate) == 4
        and event.source_context_candidate != b"\x00" * 4
    ):
        storage_id = int.from_bytes(event.source_context_candidate, "little")
    location = storage_location(storage_id) if is_storage else None
    source = (
        None
        if is_storage
        else source_label(event.source_context_candidate, event.default_context)
    )

    extra = {}
    if event.stream_sequence is not None:
        extra["stream_sequence"] = event.stream_sequence
    return BDOEvent(
        event_type=_event_type_for_record(event),
        timestamp=event.context.timestamp,
        flow=Flow(
            source_ip=event.context.flow.source_ip,
            source_port=event.context.flow.source_port,
            destination_ip=event.context.flow.destination_ip,
            destination_port=event.context.flow.destination_port,
        ),
        item_id=event.item_id,
        quantity=event.quantity,
        source=source,
        raw_context=_hex(event.source_context_candidate),
        opcode=event.opcode,
        message_length=event.message_length,
        base_item_id=base_item_id,
        enhancement_level=enhancement_level,
        enhancement=enhancement,
        inventory_slot=event.inventory_slot,
        item_instance=_hex(event.item_instance),
        storage_instance=_hex(event.storage_instance),
        storage_id=storage_id,
        storage_name=location.name if location is not None else None,
        storage_name_confidence=(
            location.confidence if location is not None else None
        ),
        record_index=event.record_index,
        record_count=event.record_count,
        record_offset=event.record_offset,
        confidence="observed",
        extra=extra,
        _flow_generation=event.context.flow_generation,
    )


def _event_type_for_label(label: str) -> str:
    return {
        "LOOT_PREVIEW": "loot_preview",
        "INVENTORY_TRANSFER": "item_received",
        "INVENTORY_TO_STORAGE": "storage_delta",
    }.get(label, label.lower())


def _event_type_for_record(event: LootEvent) -> str:
    if event.label == "INVENTORY_TRANSFER":
        if event.source_context_candidate == CHARACTER_LOAD_CONTEXT:
            return "inventory_snapshot"
        if event.source_context_candidate is None:
            # Without a calibrated context field, hydration and ordinary
            # receipts cannot be separated safely. Keep the record neutral so
            # an incomplete post-patch profile cannot flood activity filters.
            return "inventory_record"
        return "item_received"
    if event.label == "INVENTORY_TO_STORAGE":
        if event.storage_operation == "snapshot":
            return "storage_snapshot"
        if event.storage_operation == "live":
            return "storage_delta"
        return "storage_record"
    return _event_type_for_label(event.label)


def _hex(value: Optional[bytes]) -> Optional[str]:
    if value is None:
        return None
    return f"0x{value.hex()}"


class PacketEngine:
    """Reassemble server-to-client TCP flows and emit deduplicated events."""

    def __init__(
        self,
        *,
        server_ports: Iterable[int],
        event_specs: Iterable[EventSpec],
        on_event: Callable[[LootEvent, bytes], None],
        frame_observer: Optional[Callable[[BDOFrame], None]] = None,
        stream_observer: Optional[Callable[[bytes, PacketContext], None]] = None,
        flow_close_observer: Optional[Callable[[FlowKey], None]] = None,
        flow_reset_observer: Optional[
            Callable[[FlowKey, int, int], None]
        ] = None,
        message_observer: Optional[MessageObserver] = None,
    ) -> None:
        self.event_specs = tuple(event_specs)
        self.events_found = 0
        self._on_event = on_event
        self._flow_state_evictions = 0
        # Counter-only: never extend across flow work, callbacks, or delivery.
        self._diagnostics_lock = Lock()

        def build_scanner():
            primary = TargetMessageScanner(
                self._handle_record,
                self.event_specs,
                message_observer=message_observer,
            )
            if frame_observer is None and stream_observer is None:
                return primary
            tap = (
                FrameCollectorScanner(
                    frame_observer,
                    known_opcodes=(spec.opcode for spec in self.event_specs),
                )
                if frame_observer is not None
                else None
            )
            return _TeeScanner(primary, tap, stream_observer)

        self._flow_manager = FlowManager(
            server_ports=server_ports,
            scanner_factory=build_scanner,
            track_flow_generations=True,
            max_flows=_ITEM_MAX_ACTIVE_FLOWS,
            on_flow_eviction=self._count_flow_state_eviction,
            on_flow_close=flow_close_observer,
            on_flow_reset=flow_reset_observer,
            idle_timeout=_ITEM_FLOW_IDLE_SECONDS,
        )
        self._seen_event_keys: set[
            tuple[FlowKey, int, int, int, Optional[int], bytes]
        ] = set()
        self._seen_event_order: deque[
            tuple[FlowKey, int, int, int, Optional[int], bytes]
        ] = deque()
        self._last_raw_message: Optional[bytes] = None
        self._last_raw_message_digest: Optional[bytes] = None

    @property
    def server_ports(self) -> frozenset[int]:
        return self._flow_manager.server_ports

    @property
    def tcp_gap_resets(self) -> int:
        """Cumulative reassembly resets caused by missing TCP segments."""

        return self._flow_manager.tcp_gap_resets

    @property
    def flow_state_evictions(self) -> int:
        """Number of active flow states lost to the defensive resource cap."""

        with self._diagnostics_lock:
            return self._flow_state_evictions

    def service_gaps(self, now: float) -> int:
        """Advance TCP gap deadlines even when no new packet arrives."""

        return self._flow_manager.service_gaps(now)

    def _count_flow_state_eviction(self) -> None:
        with self._diagnostics_lock:
            self._flow_state_evictions += 1

    def process_tcp_segment(
        self,
        *,
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        sequence: int,
        payload: bytes,
        timestamp: float,
        syn: bool = False,
        rst: bool = False,
        fin: bool = False,
    ) -> None:
        self._flow_manager.process_tcp_segment(
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            sequence=sequence,
            payload=payload,
            timestamp=timestamp,
            syn=syn,
            rst=rst,
            fin=fin,
        )

    def finish(self) -> None:
        """Drain per-flow segments still pending at end of capture."""
        self._flow_manager.finish()

    def _handle_record(self, event: LootEvent, raw_message: bytes) -> None:
        if self._is_duplicate_event(event, raw_message):
            return
        self.events_found += 1
        self._on_event(event, raw_message)

    def _is_duplicate_event(self, event: LootEvent, raw_message: bytes) -> bool:
        if event.stream_sequence is None:
            return False

        key = (
            event.context.flow,
            event.context.flow_generation,
            event.stream_sequence,
            event.opcode,
            event.record_offset,
            self._raw_message_digest(raw_message),
        )
        if key in self._seen_event_keys:
            return True

        self._seen_event_keys.add(key)
        self._seen_event_order.append(key)
        while len(self._seen_event_order) > DEDUP_HISTORY_LIMIT:
            expired_key = self._seen_event_order.popleft()
            self._seen_event_keys.discard(expired_key)
        return False

    def _raw_message_digest(self, raw_message: bytes) -> bytes:
        # TargetMessageScanner delivers every record from one batch with the
        # same immutable bytes object. Cache by identity so a 72-record load
        # hashes its message once rather than 72 times.
        if (
            raw_message is self._last_raw_message
            and self._last_raw_message_digest is not None
        ):
            return self._last_raw_message_digest
        digest = hashlib.blake2b(raw_message, digest_size=16).digest()
        self._last_raw_message = raw_message
        self._last_raw_message_digest = digest
        return digest
