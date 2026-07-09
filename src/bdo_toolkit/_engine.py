"""Native packet engine: flow tracking, dedup, and event normalization."""

from __future__ import annotations

from collections import deque
from typing import Callable, Iterable, Optional

from ._framing import FrameCollectorScanner, TargetMessageScanner
from ._protocol import (
    DEDUP_HISTORY_LIMIT,
    BDOFrame,
    EventSpec,
    FlowKey,
    LootEvent,
    source_label,
    split_item_id_enhancement,
)
from ._reassembly import FlowManager
from .events import BDOEvent, Flow


class _TeeScanner:
    """Feed one reassembled stream to the target scanner and a frame tap.

    The tap runs FIRST so correlation logic already holds every frame of a
    TCP segment by the time the target scanner emits events from it.
    """

    def __init__(self, primary: TargetMessageScanner, tap: FrameCollectorScanner) -> None:
        self._primary = primary
        self._tap = tap

    def feed(self, data, context) -> None:
        self._tap.feed(data, context)
        self._primary.feed(data, context)

    def scan_standalone(self, data, context) -> None:
        self._tap.scan_standalone(data, context)
        self._primary.scan_standalone(data, context)

    def reset(self) -> None:
        self._tap.reset()
        self._primary.reset()


def toolkit_event_from_record(event: LootEvent) -> BDOEvent:
    """Normalize a decoded protocol record into the stable app-facing event."""
    base_item_id, enhancement_level, enhancement = split_item_id_enhancement(
        event.item_id
    )
    if enhancement_level is None:
        base_item_id = None

    extra = {}
    if event.stream_sequence is not None:
        extra["stream_sequence"] = event.stream_sequence
    if event.label == "INVENTORY_TO_STORAGE":
        extra["storage_delta"] = event.quantity

    return BDOEvent(
        event_type=_event_type_for_label(event.label),
        timestamp=event.context.timestamp,
        flow=Flow(
            source_ip=event.context.flow.source_ip,
            source_port=event.context.flow.source_port,
            destination_ip=event.context.flow.destination_ip,
            destination_port=event.context.flow.destination_port,
        ),
        item_id=event.item_id,
        quantity=event.quantity,
        source=source_label(event.source_context_candidate, event.default_context),
        raw_context=_hex(event.source_context_candidate),
        opcode=event.opcode,
        message_length=event.message_length,
        legacy_label=event.label,
        base_item_id=base_item_id,
        enhancement_level=enhancement_level,
        enhancement=enhancement,
        inventory_slot=event.inventory_slot,
        item_instance=_hex(event.item_instance),
        storage_instance=_hex(event.storage_instance),
        record_index=event.record_index,
        record_count=event.record_count,
        record_offset=event.record_offset,
        confidence="observed",
        extra=extra,
    )


def _event_type_for_label(label: str) -> str:
    return {
        "LOOT_PREVIEW": "loot_preview",
        "INVENTORY_TRANSFER": "item_received",
        "INVENTORY_TO_STORAGE": "storage_delta",
    }.get(label, label.lower())


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
    ) -> None:
        self.event_specs = tuple(event_specs)
        self.events_found = 0
        self._on_event = on_event

        def build_scanner():
            primary = TargetMessageScanner(self._handle_record, self.event_specs)
            if frame_observer is None:
                return primary
            return _TeeScanner(primary, FrameCollectorScanner(frame_observer))

        self._flow_manager = FlowManager(
            server_ports=server_ports,
            scanner_factory=build_scanner,
        )
        self._seen_event_keys: set[
            tuple[FlowKey, int, int, Optional[int], bytes]
        ] = set()
        self._seen_event_order: deque[
            tuple[FlowKey, int, int, Optional[int], bytes]
        ] = deque()

    @property
    def server_ports(self) -> frozenset[int]:
        return self._flow_manager.server_ports

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
            event.stream_sequence,
            event.opcode,
            event.record_offset,
            raw_message,
        )
        if key in self._seen_event_keys:
            return True

        self._seen_event_keys.add(key)
        self._seen_event_order.append(key)
        while len(self._seen_event_order) > DEDUP_HISTORY_LIMIT:
            expired_key = self._seen_event_order.popleft()
            self._seen_event_keys.discard(expired_key)
        return False
