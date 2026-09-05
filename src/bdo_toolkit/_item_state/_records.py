"""Internal frame identities, assembly records, and item conversion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .._protocol import BDOFrame, EventSpec
from ..events import BDOEvent

from ._constants import _CURRENCY_NAMES, _INVENTORY_CONTAINER_LABELS
from .models import (
    InventoryHydrationDiagnostics,
    InventorySnapshotSummary,
    SnapshotItem,
    StorageDestinationDiagnostics,
    StorageSnapshotSummary,
)


@dataclass(frozen=True)
class _InventoryAssembly:
    summary: InventorySnapshotSummary
    missing_instance_records: int
    diagnostics: InventoryHydrationDiagnostics


@dataclass(frozen=True)
class _StorageAssembly:
    summaries: tuple[StorageSnapshotSummary, ...]
    diagnostics: tuple[StorageDestinationDiagnostics, ...]
    records_without_destination: int
    records_missing_instance: int
    sweeps_observed: int
    selected_sweep: Optional[int]
    unknown_empty_envelopes: int


@dataclass(frozen=True)
class _FrameKey:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    flow_generation: int
    stream_sequence: Optional[int]


@dataclass(frozen=True)
class _HydrationAnchor:
    """One validated inventory-wrapper observation anchoring a load epoch."""

    timestamp: float
    frame_key: _FrameKey


@dataclass(frozen=True)
class _InventoryGeneration:
    """Latest inventory hydration burst, including recordless wrappers."""

    events: tuple[BDOEvent, ...]
    anchors: tuple[_HydrationAnchor, ...]
    start: Optional[float]
    flow_generation_key: Optional[tuple[str, int, str, int, int]]
    generations_observed: int


@dataclass(frozen=True)
class _StorageGroupObservation:
    """One decoded nonempty frame or validated count-zero storage wrapper."""

    storage_id: int
    frame_key: _FrameKey
    timestamp: float
    opcode: int
    message_length: Optional[int]
    items: tuple[SnapshotItem, ...]
    raw_records: int
    missing_instance_records: int
    empty: bool


@dataclass(frozen=True)
class _StorageDestinationBlock:
    """Consecutive chunks belonging to one destination within one sweep."""

    storage_id: int
    stream_key: tuple[str, int, str, int, int, int]
    groups: tuple[_StorageGroupObservation, ...]

    @property
    def empty(self) -> bool:
        return all(group.empty for group in self.groups)


@dataclass(frozen=True)
class _StorageEmptySchema:
    spec: EventSpec
    prefix_length: int


def _event_frame_key(event: BDOEvent) -> _FrameKey:
    sequence = event.extra.get("stream_sequence")
    return _FrameKey(
        event.flow.source_ip,
        event.flow.source_port,
        event.flow.destination_ip,
        event.flow.destination_port,
        event._flow_generation,
        sequence if isinstance(sequence, int) else None,
    )


def _frame_key(frame: BDOFrame) -> _FrameKey:
    return _FrameKey(
        frame.context.flow.source_ip,
        frame.context.flow.source_port,
        frame.context.flow.destination_ip,
        frame.context.flow.destination_port,
        frame.context.flow_generation,
        frame.stream_sequence,
    )


def _event_flow_generation_key(event: BDOEvent) -> tuple[str, int, str, int, int]:
    frame_key = _event_frame_key(event)
    return (
        event.flow.source_ip,
        event.flow.source_port,
        event.flow.destination_ip,
        event.flow.destination_port,
        frame_key.flow_generation,
    )


def _frame_flow_generation_key(frame: BDOFrame) -> tuple[str, int, str, int, int]:
    return (
        frame.context.flow.source_ip,
        frame.context.flow.source_port,
        frame.context.flow.destination_ip,
        frame.context.flow.destination_port,
        frame.context.flow_generation,
    )


def _anchor_flow_generation_key(
    anchor: _HydrationAnchor,
) -> tuple[str, int, str, int, int]:
    key = anchor.frame_key
    return (
        key.source_ip,
        key.source_port,
        key.destination_ip,
        key.destination_port,
        key.flow_generation,
    )


@dataclass(frozen=True)
class _InventoryRecordMetadata:
    slot: Optional[int]
    container_code: int


def _snapshot_item(
    event: BDOEvent,
    instance: str,
    inventory_metadata: Optional[_InventoryRecordMetadata] = None,
) -> SnapshotItem:
    container_name = None
    container_confidence = None
    currency_name = None
    if inventory_metadata is not None:
        container_name, container_confidence = _INVENTORY_CONTAINER_LABELS[
            inventory_metadata.container_code
        ]
        currency_name = _CURRENCY_NAMES.get(
            (inventory_metadata.container_code, event.item_id)
        )
    return SnapshotItem(
        item_id=event.item_id,
        quantity=event.quantity,
        instance=instance,
        observed_at=event.timestamp,
        base_item_id=event.base_item_id,
        enhancement_level=event.enhancement_level,
        enhancement=event.enhancement,
        inventory_slot=(
            inventory_metadata.slot if inventory_metadata is not None else None
        ),
        container_code=(
            inventory_metadata.container_code
            if inventory_metadata is not None
            else None
        ),
        container_name=container_name,
        container_confidence=container_confidence,
        currency_name=currency_name,
    )


def _spec_candidates_by_opcode(
    specs: Iterable[EventSpec],
) -> dict[int, tuple[EventSpec, ...]]:
    """Retain every distinct same-opcode layout in deterministic profile order."""
    grouped: dict[int, list[EventSpec]] = {}
    for spec in specs:
        candidates = grouped.setdefault(spec.opcode, [])
        if spec not in candidates:
            candidates.append(spec)
    return {opcode: tuple(candidates) for opcode, candidates in grouped.items()}
