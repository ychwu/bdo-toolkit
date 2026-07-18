"""Experimental character-load snapshot diagnostics and state summaries.

The framed inventory and storage hydration messages are strong enough to
enumerate occupied item records.  Current inventory frames also expose a
structurally validated raw container code and slot.  Their human-readable
container interpretations remain provisional, and the packets still do not
prove storage capacity or whether hydration was triggered by initial login
versus a character switch.  This module keeps those limits explicit while
providing a queryable model for tools and early adopters.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from threading import Event, RLock
from typing import Any, Iterable, Optional

from ._capture_backend import (
    build_bpf_filter,
    detect_default_capture_target,
    import_scapy,
    iter_pcap_file,
    make_packet_handler,
)
from ._capture_options import PacketCaptureOptions
from ._engine import PacketEngine, toolkit_event_from_record
from ._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    DEFAULT_SERVER_PORTS,
    STORAGE_LOCATIONS,
    EventSpec,
    storage_location,
)
from ._specs import event_specs_from_profile
from .events import BDOEvent
from .profiles import ProfileError, default_profile_path, load_opcode_profile

_INVENTORY_GENERATION_GAP_SECONDS = 1.0
_INVENTORY_TRAILING_DISCOVERY_BYTES = 12
_ITEM_STATE_SCHEMA_VERSION = 1

# These interpretations agree across the July 17 initial-load and character-
# switch captures, and the 0x00/0x10/0x0B families agree with legacy research.
# They deliberately remain local to the experimental character-state API.
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


@dataclass(frozen=True)
class SnapshotItem:
    """One occupied item-stack record observed during state hydration."""

    item_id: int
    quantity: int
    instance: str
    timestamp: float
    opcode: Optional[int]
    message_length: Optional[int]
    base_item_id: Optional[int] = None
    enhancement_level: Optional[int] = None
    enhancement: Optional[str] = None
    inventory_slot: Optional[int] = None
    container_code: Optional[int] = None
    container_name: Optional[str] = None
    container_confidence: Optional[str] = None
    currency_name: Optional[str] = None

    @property
    def is_currency_balance(self) -> bool:
        """Whether this serialized record represents a known wallet balance."""
        return self.currency_name is not None

    def to_dict(self) -> dict[str, object]:
        output: dict[str, object] = {
            "item_id": self.item_id,
            "quantity": self.quantity,
            "instance": self.instance,
            "timestamp": self.timestamp,
        }
        optional = {
            "opcode": (f"0x{self.opcode:04X}" if self.opcode is not None else None),
            "message_length": self.message_length,
            "base_item_id": self.base_item_id,
            "enhancement_level": self.enhancement_level,
            "enhancement": self.enhancement,
            "inventory_slot": self.inventory_slot,
            "container_code": self.container_code,
            "container_code_hex": (
                f"0x{self.container_code:02X}"
                if self.container_code is not None
                else None
            ),
            "container_name": self.container_name,
            "container_confidence": self.container_confidence,
            "currency_name": self.currency_name,
        }
        output.update(
            {key: value for key, value in optional.items() if value is not None}
        )
        return output


class _ItemQueries:
    items: tuple[SnapshotItem, ...]

    @property
    def occupied_stacks(self) -> int:
        return len(self.items)

    def records_for(self, item_id: int) -> tuple[SnapshotItem, ...]:
        """Return every distinct occupied stack with the exact encoded item ID."""
        return tuple(item for item in self.items if item.item_id == item_id)

    def quantity_for(self, item_id: int) -> int:
        """Sum quantities across distinct stacks with the exact encoded item ID."""
        return sum(item.quantity for item in self.records_for(item_id))


@dataclass(frozen=True)
class InventoryContainerSummary(_ItemQueries):
    """One structurally classified inventory container (experimental)."""

    raw_code: int
    name: str
    confidence: str
    items: tuple[SnapshotItem, ...]
    currency_balances: tuple[SnapshotItem, ...]

    @property
    def serialized_records(self) -> int:
        return len(self.items) + len(self.currency_balances)

    def currency(self, item_id_or_name: int | str) -> Optional[SnapshotItem]:
        """Look up a known balance by encoded item ID or display name."""
        if isinstance(item_id_or_name, int):
            return next(
                (
                    balance
                    for balance in self.currency_balances
                    if balance.item_id == item_id_or_name
                ),
                None,
            )
        folded = item_id_or_name.casefold()
        return next(
            (
                balance
                for balance in self.currency_balances
                if balance.currency_name is not None
                and balance.currency_name.casefold() == folded
            ),
            None,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "raw_code": self.raw_code,
            "raw_code_hex": f"0x{self.raw_code:02X}",
            "name": self.name,
            "confidence": self.confidence,
            "serialized_records": self.serialized_records,
            "occupied_stacks": self.occupied_stacks,
            "currency_balance_records": len(self.currency_balances),
            "items": [item.to_dict() for item in self.items],
            "currency_balances": [
                balance.to_dict() for balance in self.currency_balances
            ],
        }


@dataclass(frozen=True)
class InventorySnapshotSummary(_ItemQueries):
    """Inventory hydration summary with provisional container metadata."""

    items: tuple[SnapshotItem, ...]
    raw_records: int
    duplicate_records: int
    group_counts: tuple[int, ...]
    inferred_strides: tuple[int, ...]
    currency_balances: tuple[SnapshotItem, ...]
    containers: tuple[InventoryContainerSummary, ...]
    unclassified_records: int

    @property
    def groups(self) -> int:
        return len(self.group_counts)

    @property
    def populated_groups(self) -> int:
        return sum(count > 0 for count in self.group_counts)

    @property
    def empty_groups(self) -> int:
        return sum(count == 0 for count in self.group_counts)

    @property
    def serialized_records(self) -> int:
        """Distinct current records, including known currency-wallet balances."""
        return self.occupied_stacks + self.currency_balance_records

    @property
    def currency_balance_records(self) -> int:
        return len(self.currency_balances)

    def container(self, raw_code: int) -> Optional[InventoryContainerSummary]:
        """Look up a provisionally classified container by its raw byte."""
        return next(
            (
                container
                for container in self.containers
                if container.raw_code == raw_code
            ),
            None,
        )

    def container_named(self, name: str) -> Optional[InventoryContainerSummary]:
        """Convenience lookup by provisional display name."""
        folded = name.casefold()
        return next(
            (
                container
                for container in self.containers
                if container.name.casefold() == folded
            ),
            None,
        )

    def currency(self, item_id_or_name: int | str) -> Optional[SnapshotItem]:
        """Look up a known currency balance by encoded ID or display name."""
        if isinstance(item_id_or_name, int):
            return next(
                (
                    balance
                    for balance in self.currency_balances
                    if balance.item_id == item_id_or_name
                ),
                None,
            )
        folded = item_id_or_name.casefold()
        return next(
            (
                balance
                for balance in self.currency_balances
                if balance.currency_name is not None
                and balance.currency_name.casefold() == folded
            ),
            None,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "occupied_stacks": self.occupied_stacks,
            "raw_records": self.raw_records,
            "serialized_records": self.serialized_records,
            "duplicate_records": self.duplicate_records,
            "groups": self.groups,
            "populated_groups": self.populated_groups,
            "empty_groups": self.empty_groups,
            "group_counts": list(self.group_counts),
            "inferred_strides": list(self.inferred_strides),
            "currency_balance_records": self.currency_balance_records,
            "unclassified_records": self.unclassified_records,
            "containers": [container.to_dict() for container in self.containers],
            "currency_balances": [
                balance.to_dict() for balance in self.currency_balances
            ],
            "capacity": None,
            "items": [item.to_dict() for item in self.items],
        }


@dataclass(frozen=True)
class StorageSnapshotSummary(_ItemQueries):
    """Latest observed occupied records for one numeric storage destination."""

    storage_id: int
    name: Optional[str]
    name_confidence: Optional[str]
    items: tuple[SnapshotItem, ...]
    raw_records: int
    duplicate_records: int
    groups: int
    empty_envelope_seen: bool
    capacity: Optional[int] = None

    def to_dict(self) -> dict[str, object]:
        return {
            "storage_id": self.storage_id,
            "storage_id_hex": f"0x{self.storage_id:08x}",
            "name": self.name,
            "name_confidence": self.name_confidence,
            "occupied_stacks": self.occupied_stacks,
            "raw_records": self.raw_records,
            "duplicate_records": self.duplicate_records,
            "groups": self.groups,
            "empty_envelope_seen": self.empty_envelope_seen,
            "capacity": self.capacity,
            "items": [item.to_dict() for item in self.items],
        }


class StorageContents(tuple[StorageSnapshotSummary, ...]):
    """Tuple-preserving query collection for storage snapshots.

    Subclassing ``tuple`` retains the complete historical sequence contract,
    including tuple type checks, operators, and generic dataclass traversal,
    while adding cross-destination queries.
    """

    def __new__(
        cls,
        values: Iterable[StorageSnapshotSummary] = (),
    ) -> "StorageContents":
        return super().__new__(cls, values)

    def by_id(self, storage_id: int) -> Optional[StorageSnapshotSummary]:
        """Look up a destination by its numeric protocol key."""
        return next(
            (storage for storage in self if storage.storage_id == storage_id),
            None,
        )

    def named(self, name: str) -> Optional[StorageSnapshotSummary]:
        """Look up a destination by its confidence-qualified display name."""
        folded = name.casefold()
        return next(
            (
                storage
                for storage in self
                if storage.name is not None and storage.name.casefold() == folded
            ),
            None,
        )

    def find_item(self, item_id: int) -> tuple[SnapshotItem, ...]:
        """Return every distinct stack with ``item_id`` across all storages."""
        return tuple(item for storage in self for item in storage.records_for(item_id))

    def total_quantity(self, item_id: int) -> int:
        """Sum an exact encoded item ID across every observed storage."""
        return sum(item.quantity for item in self.find_item(item_id))

    def locations_for(
        self,
        item_id: int,
    ) -> tuple[StorageSnapshotSummary, ...]:
        """Return storage summaries containing at least one matching stack."""
        return tuple(storage for storage in self if storage.records_for(item_id))


@dataclass(frozen=True)
class ItemStateCoverage:
    """Observed aggregate coverage; never a protocol-completion claim."""

    completion_status: str
    completion_basis: str
    capture_may_be_partial: bool
    hydration_detected: bool
    inventory_records_decoded: int
    inventory_unique_records: int
    inventory_groups_observed: int
    inventory_empty_groups_observed: int
    inventory_unclassified_records: int
    storage_records_decoded: int
    storage_locations_observed: int
    registered_storage_locations_observed: int
    registered_storage_locations_total: int
    registered_storage_ids_not_observed: tuple[int, ...]
    unregistered_storage_ids_observed: tuple[int, ...]
    explicitly_empty_storage_locations_observed: int

    def to_dict(self) -> dict[str, object]:
        return {
            "completion_status": self.completion_status,
            "completion_basis": self.completion_basis,
            "capture_may_be_partial": self.capture_may_be_partial,
            "hydration_detected": self.hydration_detected,
            "inventory_records_decoded": self.inventory_records_decoded,
            "inventory_unique_records": self.inventory_unique_records,
            "inventory_groups_observed": self.inventory_groups_observed,
            "inventory_empty_groups_observed": self.inventory_empty_groups_observed,
            "inventory_unclassified_records": self.inventory_unclassified_records,
            "storage_records_decoded": self.storage_records_decoded,
            "storage_locations_observed": self.storage_locations_observed,
            "registered_storage_locations_observed": (
                self.registered_storage_locations_observed
            ),
            "registered_storage_locations_total": (
                self.registered_storage_locations_total
            ),
            "registered_storage_ids_not_observed": list(
                self.registered_storage_ids_not_observed
            ),
            "unregistered_storage_ids_observed": list(
                self.unregistered_storage_ids_observed
            ),
            "explicitly_empty_storage_locations_observed": (
                self.explicitly_empty_storage_locations_observed
            ),
        }


@dataclass(frozen=True)
class ItemStateProvenance:
    """Machine-readable origin of one assembled item-state snapshot."""

    capture_mode: str
    profile_source: str
    input_path: Optional[str] = None
    saved_capture_path: Optional[str] = None
    generation_selection: str = "unknown"
    load_reason: Optional[str] = None
    load_reason_basis: str = "not_decoded_from_protocol"

    def to_dict(self) -> dict[str, object]:
        return {
            "capture_mode": self.capture_mode,
            "profile_source": self.profile_source,
            "input_path": self.input_path,
            "saved_capture_path": self.saved_capture_path,
            "generation_selection": self.generation_selection,
            "load_reason": self.load_reason,
            "load_reason_basis": self.load_reason_basis,
        }


@dataclass(frozen=True, init=False)
class CharacterStateSnapshot:
    """Query model assembled from observed character-load hydration records."""

    profile_source: str
    frames_seen: int
    inventory: InventorySnapshotSummary
    storages: StorageContents
    storage_snapshot_records: int
    hydration_generations_seen: int
    warnings: tuple[str, ...]
    capture_mode: str = "unknown"
    input_path: Optional[str] = None
    saved_capture_path: Optional[str] = None

    def __init__(
        self,
        profile_source: str,
        frames_seen: int,
        inventory: InventorySnapshotSummary,
        storages: Iterable[StorageSnapshotSummary],
        storage_snapshot_records: int,
        hydration_generations_seen: int,
        warnings: tuple[str, ...],
        capture_mode: str = "unknown",
        input_path: Optional[str] = None,
        saved_capture_path: Optional[str] = None,
    ) -> None:
        # ``storages`` was originally a tuple. Accept every historical tuple
        # call site while exposing a tuple subclass with additive query methods.
        object.__setattr__(self, "profile_source", profile_source)
        object.__setattr__(self, "frames_seen", frames_seen)
        object.__setattr__(self, "inventory", inventory)
        object.__setattr__(self, "storages", StorageContents(storages))
        object.__setattr__(self, "storage_snapshot_records", storage_snapshot_records)
        object.__setattr__(
            self, "hydration_generations_seen", hydration_generations_seen
        )
        object.__setattr__(self, "warnings", warnings)
        object.__setattr__(self, "capture_mode", capture_mode)
        object.__setattr__(self, "input_path", input_path)
        object.__setattr__(self, "saved_capture_path", saved_capture_path)

    @property
    def schema_version(self) -> int:
        return _ITEM_STATE_SCHEMA_VERSION

    @property
    def provenance(self) -> ItemStateProvenance:
        if self.hydration_generations_seen:
            generation_selection = "latest_observed_inventory_hydration"
        elif self.storage_snapshot_records or self.storages:
            generation_selection = "all_observed_storage_no_inventory_boundary"
        else:
            generation_selection = "none_no_hydration_boundary"
        return ItemStateProvenance(
            capture_mode=self.capture_mode,
            profile_source=self.profile_source,
            input_path=self.input_path,
            saved_capture_path=self.saved_capture_path,
            generation_selection=generation_selection,
            load_reason=self.load_reason,
        )

    @property
    def coverage(self) -> ItemStateCoverage:
        observed_registered = {
            storage.storage_id
            for storage in self.storages
            if storage.storage_id in STORAGE_LOCATIONS
        }
        missing_registered = tuple(
            storage_id
            for storage_id in STORAGE_LOCATIONS
            if storage_id not in observed_registered
        )
        unregistered = tuple(
            sorted(
                storage.storage_id
                for storage in self.storages
                if storage.storage_id not in STORAGE_LOCATIONS
            )
        )
        return ItemStateCoverage(
            completion_status="unknown",
            completion_basis="no_proven_protocol_end_marker",
            capture_may_be_partial=True,
            hydration_detected=self.hydration_detected,
            inventory_records_decoded=self.inventory.raw_records,
            inventory_unique_records=self.inventory.serialized_records,
            inventory_groups_observed=self.inventory.groups,
            inventory_empty_groups_observed=self.inventory.empty_groups,
            inventory_unclassified_records=self.inventory.unclassified_records,
            storage_records_decoded=self.storage_snapshot_records,
            storage_locations_observed=len(self.storages),
            registered_storage_locations_observed=len(observed_registered),
            registered_storage_locations_total=len(STORAGE_LOCATIONS),
            registered_storage_ids_not_observed=missing_registered,
            unregistered_storage_ids_observed=unregistered,
            explicitly_empty_storage_locations_observed=sum(
                storage.empty_envelope_seen and storage.occupied_stacks == 0
                for storage in self.storages
            ),
        )

    @property
    def hydration_detected(self) -> bool:
        return bool(
            self.inventory.groups or self.storage_snapshot_records or self.storages
        )

    @property
    def load_reason(self) -> None:
        """Packet-level reason is intentionally unknown (login vs switch)."""
        return None

    @property
    def known_storage_destinations_total(self) -> int:
        return len(STORAGE_LOCATIONS)

    @property
    def known_storage_destinations_detected(self) -> int:
        return sum(summary.storage_id in STORAGE_LOCATIONS for summary in self.storages)

    @property
    def nonempty_storage_destinations(self) -> int:
        return sum(summary.occupied_stacks > 0 for summary in self.storages)

    @property
    def empty_storage_destinations(self) -> int:
        return sum(summary.occupied_stacks == 0 for summary in self.storages)

    @property
    def storage_occupied_stacks(self) -> int:
        return sum(summary.occupied_stacks for summary in self.storages)

    def storage(self, storage_id: int) -> Optional[StorageSnapshotSummary]:
        """Look up a destination by its durable numeric protocol key."""
        return self.storages.by_id(storage_id)

    def storage_named(self, name: str) -> Optional[StorageSnapshotSummary]:
        """Convenience lookup by display name; numeric IDs remain authoritative."""
        return self.storages.named(name)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "profile_source": self.profile_source,
            "frames_seen": self.frames_seen,
            "hydration_detected": self.hydration_detected,
            "load_reason": self.load_reason,
            "hydration_generations_seen": self.hydration_generations_seen,
            "provenance": self.provenance.to_dict(),
            "coverage": self.coverage.to_dict(),
            "inventory": self.inventory.to_dict(),
            "storage": {
                "known_destinations_detected": self.known_storage_destinations_detected,
                "known_destinations_total": self.known_storage_destinations_total,
                "nonempty_destinations": self.nonempty_storage_destinations,
                "empty_destinations": self.empty_storage_destinations,
                "occupied_stacks": self.storage_occupied_stacks,
                "raw_records": self.storage_snapshot_records,
                "destinations": [summary.to_dict() for summary in self.storages],
            },
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class _FrameKey:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    stream_sequence: Optional[int]


def _event_frame_key(event: BDOEvent) -> _FrameKey:
    sequence = event.extra.get("stream_sequence")
    return _FrameKey(
        event.flow.source_ip,
        event.flow.source_port,
        event.flow.destination_ip,
        event.flow.destination_port,
        sequence if isinstance(sequence, int) else None,
    )


def _frame_key(frame: BDOFrame) -> _FrameKey:
    return _FrameKey(
        frame.context.flow.source_ip,
        frame.context.flow.source_port,
        frame.context.flow.destination_ip,
        frame.context.flow.destination_port,
        frame.stream_sequence,
    )


@dataclass(frozen=True)
class _InventoryRecordMetadata:
    slot: int
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
        timestamp=event.timestamp,
        opcode=event.opcode,
        message_length=event.message_length,
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


def _inventory_frame_stride(
    frame: BDOFrame,
    spec: EventSpec,
    group: list[BDOEvent],
) -> Optional[int]:
    """Derive and validate one frame's repeated-record geometry."""
    count = len(group)
    base_length = spec.single_record_message_length
    if count < 2 or base_length is None:
        return None
    extra_length = frame.length - base_length
    if extra_length <= 0 or extra_length % (count - 1):
        return None
    stride = extra_length // (count - 1)
    if stride <= _INVENTORY_TRAILING_DISCOVERY_BYTES:
        return None
    if frame.length != base_length + (count - 1) * stride:
        return None
    if len(frame.message) < frame.length:
        return None
    if not _inventory_event_geometry_valid(spec, group, stride):
        return None
    return stride


def _inventory_event_geometry_valid(
    spec: EventSpec,
    group: list[BDOEvent],
    stride: int,
) -> bool:
    """Require a complete, ordered record set for a candidate stride."""
    count = len(group)
    if count == 0:
        return False
    ordered = sorted(
        group,
        key=lambda event: (
            event.record_offset if event.record_offset is not None else -1
        ),
    )
    offsets = [event.record_offset for event in ordered]
    if any(offset is None for offset in offsets):
        return False
    if offsets != [spec.item_offset + index * stride for index in range(count)]:
        return False
    if any(
        event.record_count is not None and event.record_count != count
        for event in ordered
    ):
        return False
    indexes = [event.record_index for event in ordered]
    if any(index is not None for index in indexes):
        if indexes != list(range(1, count + 1)):
            return False
    return True


def _discover_inventory_tail_layout(
    frame_groups: list[tuple[BDOFrame, list[BDOEvent], EventSpec, int]],
) -> Optional[tuple[int, int]]:
    """Jointly discover slot/container columns near the repeated-record tail.

    The layout is accepted only when exactly one pair explains every complete
    multi-record group. Requiring at least two distinct known container codes
    rejects padding columns that happen to contain only zeroes.
    """
    if len(frame_groups) < 2:
        return None
    common_stride = {stride for _, _, _, stride in frame_groups}
    if len(common_stride) != 1:
        return None
    stride = next(iter(common_stride))
    window_start = max(0, stride - _INVENTORY_TRAILING_DISCOVERY_BYTES)
    candidates: list[tuple[int, int]] = []

    for slot_relative in range(window_start, stride):
        slot_groups: list[list[int]] = []
        for frame, group, _, _ in frame_groups:
            ordered = sorted(group, key=lambda event: int(event.record_offset or 0))
            slots = [
                frame.message[int(event.record_offset) + slot_relative]
                for event in ordered
                if event.record_offset is not None
                and int(event.record_offset) + slot_relative < len(frame.message)
            ]
            slot_groups.append(slots)
        if any(
            len(slots) != len(group)
            for slots, (_, group, _, _) in zip(slot_groups, frame_groups)
        ):
            continue
        if any(
            not slots
            or any(slot == 0xFF for slot in slots)
            or slots != sorted(slots)
            or len(set(slots)) != len(slots)
            for slots in slot_groups
        ):
            continue

        for container_relative in range(
            slot_relative + 1, min(stride, slot_relative + 5)
        ):
            observed_codes: set[int] = set()
            valid = True
            for frame, group, _, _ in frame_groups:
                codes = {
                    frame.message[int(event.record_offset) + container_relative]
                    for event in group
                    if event.record_offset is not None
                    and int(event.record_offset) + container_relative
                    < len(frame.message)
                }
                if len(codes) != 1:
                    valid = False
                    break
                code = next(iter(codes))
                if code not in _INVENTORY_CONTAINER_LABELS:
                    valid = False
                    break
                observed_codes.add(code)
            if valid and len(observed_codes) >= 2:
                candidates.append((slot_relative, container_relative))

    if len(candidates) != 1:
        return None
    return candidates[0]


def _inventory_record_metadata(
    frame: BDOFrame,
    group: list[BDOEvent],
    spec: EventSpec,
    stride: int,
    layout: tuple[int, int],
) -> Optional[dict[int, _InventoryRecordMetadata]]:
    """Extract one validated frame's dynamically discovered tail fields."""
    base_length = spec.single_record_message_length
    if base_length is None:
        return None
    count = len(group)
    expected_length = base_length if count == 1 else base_length + (count - 1) * stride
    if frame.length != expected_length or len(frame.message) < frame.length:
        return None
    if not _inventory_event_geometry_valid(spec, group, stride):
        return None

    slot_relative, container_relative = layout
    extracted: dict[int, _InventoryRecordMetadata] = {}
    slots: list[int] = []
    codes: set[int] = set()
    for event in sorted(group, key=lambda candidate: int(candidate.record_offset or 0)):
        assert event.record_offset is not None
        slot_offset = event.record_offset + slot_relative
        container_offset = event.record_offset + container_relative
        if max(slot_offset, container_offset) >= len(frame.message):
            return None
        slot = frame.message[slot_offset]
        code = frame.message[container_offset]
        if slot == 0xFF or code not in _INVENTORY_CONTAINER_LABELS:
            return None
        slots.append(slot)
        codes.add(code)
        extracted[event.record_offset] = _InventoryRecordMetadata(slot, code)

    if slots != sorted(slots) or len(slots) != len(set(slots)) or len(codes) != 1:
        return None
    return extracted


class _CharacterStateAccumulator:
    def __init__(
        self,
        *,
        profile_source: str,
        specs: Iterable[EventSpec],
        capture_mode: str = "unknown",
        input_path: str | Path | None = None,
        saved_capture_path: str | Path | None = None,
    ) -> None:
        self.profile_source = profile_source
        self.capture_mode = capture_mode
        self.input_path = str(input_path) if input_path is not None else None
        self.saved_capture_path = (
            str(saved_capture_path) if saved_capture_path is not None else None
        )
        self.specs = tuple(specs)
        self.inventory_specs = tuple(
            spec for spec in self.specs if spec.label == "INVENTORY_TRANSFER"
        )
        self.storage_specs = tuple(
            spec for spec in self.specs if spec.label == "INVENTORY_TO_STORAGE"
        )
        self.relevant_opcodes = {
            spec.opcode for spec in self.inventory_specs + self.storage_specs
        }
        self._lock = RLock()
        self._frames_seen = 0
        self._frames: list[BDOFrame] = []
        self._seen_frames: set[tuple[_FrameKey, bytes]] = set()
        self._inventory_events: list[BDOEvent] = []
        self._storage_events: list[BDOEvent] = []

    @property
    def frames_seen(self) -> int:
        with self._lock:
            return self._frames_seen

    def observe_frame(self, frame: BDOFrame) -> None:
        with self._lock:
            self._frames_seen += 1
            if frame.opcode not in self.relevant_opcodes:
                return
            digest = hashlib.blake2b(frame.message, digest_size=16).digest()
            dedupe_key = (_frame_key(frame), digest)
            if dedupe_key in self._seen_frames:
                return
            self._seen_frames.add(dedupe_key)
            self._frames.append(frame)

    def observe_record(self, record: Any, raw_message: bytes) -> None:
        del raw_message
        event = toolkit_event_from_record(record)
        with self._lock:
            if event.event_type == "inventory_snapshot":
                self._inventory_events.append(event)
            elif event.event_type == "storage_snapshot":
                self._storage_events.append(event)

    def snapshot(self) -> CharacterStateSnapshot:
        with self._lock:
            frames_seen = self._frames_seen
            frames = tuple(self._frames)
            inventory_events = tuple(self._inventory_events)
            storage_events = tuple(self._storage_events)

        (
            inventory_events,
            generation_start,
            generations_seen,
        ) = _latest_inventory_generation(inventory_events)
        if generation_start is not None:
            # Current captures send the compact inventory hydration first and
            # storage hydration afterward. It is therefore a clean boundary
            # between separate character loads while retaining repeated
            # storage sweeps belonging to the same load.
            storage_events = tuple(
                event for event in storage_events if event.timestamp >= generation_start
            )
            frames = tuple(
                frame for frame in frames if frame.context.timestamp >= generation_start
            )

        inventory = self._inventory_summary(frames, inventory_events)
        storages, unresolved_storage = self._storage_summaries(frames, storage_events)
        warnings = [
            "Initial login and character switch use the same observed hydration "
            "shape; the packet-level trigger is not decoded.",
            "Inventory container names are provisional interpretations of a "
            "dynamically discovered raw record field; use the numeric code as "
            "the experimental identity.",
            "Count-zero inventory wrappers contain no record-level slot or "
            "container field and remain unclassified.",
            "Storage capacity is not decoded; occupied stacks are not maximum capacity.",
            "Snapshot completion has no proven end marker; stopping capture during "
            "loading can produce a partial report.",
        ]
        if generations_seen > 1:
            warnings.append(
                f"{generations_seen} inventory hydration generations were observed; "
                "the report contains only the latest generation."
            )
        if not inventory_events:
            warnings.append(
                "No inventory snapshot records were decoded; verify that the active "
                "profile has an inventory opcode, context offset, item instance offset, "
                "and calibrated single-record length."
            )
            if storage_events or storages:
                warnings.append(
                    "No inventory hydration boundary was decoded; storage state "
                    "contains all observed snapshot records and may span multiple loads."
                )
        if not storage_events:
            warnings.append(
                "No storage snapshot records were decoded; the capture may be partial "
                "or the storage wrapper/profile may have changed."
            )
        if unresolved_storage:
            warnings.append(
                f"{unresolved_storage} storage snapshot records lacked a numeric "
                "destination and were excluded from per-storage state."
            )
        return CharacterStateSnapshot(
            profile_source=self.profile_source,
            frames_seen=frames_seen,
            inventory=inventory,
            storages=StorageContents(storages),
            storage_snapshot_records=len(storage_events),
            hydration_generations_seen=generations_seen,
            warnings=tuple(warnings),
            capture_mode=self.capture_mode,
            input_path=self.input_path,
            saved_capture_path=self.saved_capture_path,
        )

    def _inventory_summary(
        self,
        frames: tuple[BDOFrame, ...],
        events: tuple[BDOEvent, ...],
    ) -> InventorySnapshotSummary:
        groups: dict[_FrameKey, list[BDOEvent]] = {}
        for event in events:
            groups.setdefault(_event_frame_key(event), []).append(event)

        frames_by_key = {_frame_key(frame): frame for frame in frames}
        specs_by_opcode = {spec.opcode: spec for spec in self.inventory_specs}
        multi_groups_by_opcode: dict[
            int, list[tuple[BDOFrame, list[BDOEvent], EventSpec, int]]
        ] = {}
        strides_by_key: dict[_FrameKey, int] = {}
        sibling_strides: dict[int, set[int]] = {}
        prefix_candidates: dict[int, set[int]] = {}

        # A multi-record frame proves its own stride from L, B, and N. Layout
        # discovery is intentionally separate: stride alone does not prove
        # where slot/container metadata moved in a new protocol generation.
        for key, group in groups.items():
            frame = frames_by_key.get(key)
            if frame is None:
                continue
            spec = specs_by_opcode.get(frame.opcode)
            if spec is None or not _frame_has_zero_context(frame, spec):
                continue
            stride = _inventory_frame_stride(frame, spec, group)
            if stride is None:
                continue
            strides_by_key[key] = stride
            sibling_strides.setdefault(frame.opcode, set()).add(stride)
            prefix_candidates.setdefault(frame.opcode, set()).add(
                frame.length - len(group) * stride
            )
            multi_groups_by_opcode.setdefault(frame.opcode, []).append(
                (frame, group, spec, stride)
            )

        layouts = {
            opcode: _discover_inventory_tail_layout(frame_groups)
            for opcode, frame_groups in multi_groups_by_opcode.items()
        }
        metadata_by_record: dict[tuple[_FrameKey, int], _InventoryRecordMetadata] = {}
        for key, group in groups.items():
            frame = frames_by_key.get(key)
            if frame is None:
                continue
            spec = specs_by_opcode.get(frame.opcode)
            layout = layouts.get(frame.opcode)
            if spec is None or layout is None:
                continue
            stride = strides_by_key.get(key)
            if stride is None and len(group) == 1:
                proven = sibling_strides.get(frame.opcode, set())
                if len(proven) == 1:
                    stride = next(iter(proven))
            if stride is None:
                continue
            extracted = _inventory_record_metadata(
                frame,
                group,
                spec,
                stride,
                layout,
            )
            if extracted is None:
                continue
            metadata_by_record.update(
                {
                    (key, record_offset): metadata
                    for record_offset, metadata in extracted.items()
                }
            )

        latest: dict[str, SnapshotItem] = {}
        missing_instance = 0
        for event in events:
            if event.item_instance is None:
                missing_instance += 1
                instance = (
                    f"unavailable:{event.item_id}:{event.record_offset}:"
                    f"{_event_frame_key(event).stream_sequence}"
                )
            else:
                instance = event.item_instance
            metadata = (
                metadata_by_record.get((_event_frame_key(event), event.record_offset))
                if event.record_offset is not None
                else None
            )
            latest[instance] = _snapshot_item(event, instance, metadata)

        prefixes = {
            opcode: next(iter(candidates))
            for opcode, candidates in prefix_candidates.items()
            if len(candidates) == 1
        }

        frame_counts: list[int] = []
        counted_keys: set[_FrameKey] = set()
        for frame in frames:
            spec = next(
                (
                    candidate
                    for candidate in self.inventory_specs
                    if candidate.opcode == frame.opcode
                ),
                None,
            )
            if spec is None or not _frame_has_zero_context(frame, spec):
                continue
            key = _frame_key(frame)
            frame_group = groups.get(key)
            if frame_group is not None:
                frame_counts.append(len(frame_group))
                counted_keys.add(key)
                continue
            prefix = prefixes.get(frame.opcode)
            if prefix is not None and frame.length == prefix:
                frame_counts.append(0)
                counted_keys.add(key)

        # Events can still be useful when a caller feeds normalized records
        # without generic frame observations.
        for key, group in groups.items():
            if key not in counted_keys:
                frame_counts.append(len(group))

        duplicate_records = len(events) - len(latest)
        if missing_instance:
            # Synthetic fallback identities are unique, so they must never be
            # described as confidently deduplicated instances.
            duplicate_records = max(0, duplicate_records)

        latest_records = tuple(sorted(latest.values(), key=lambda item: item.instance))
        items = tuple(item for item in latest_records if not item.is_currency_balance)
        currency_balances = tuple(
            item for item in latest_records if item.is_currency_balance
        )
        containers: list[InventoryContainerSummary] = []
        for raw_code, (name, confidence) in _INVENTORY_CONTAINER_LABELS.items():
            container_records = tuple(
                item for item in latest_records if item.container_code == raw_code
            )
            if not container_records:
                continue
            containers.append(
                InventoryContainerSummary(
                    raw_code=raw_code,
                    name=name,
                    confidence=confidence,
                    items=tuple(
                        item
                        for item in container_records
                        if not item.is_currency_balance
                    ),
                    currency_balances=tuple(
                        item for item in container_records if item.is_currency_balance
                    ),
                )
            )
        return InventorySnapshotSummary(
            items=items,
            raw_records=len(events),
            duplicate_records=duplicate_records,
            group_counts=tuple(frame_counts),
            inferred_strides=tuple(
                sorted(
                    {
                        stride
                        for strides in sibling_strides.values()
                        for stride in strides
                    }
                )
            ),
            currency_balances=currency_balances,
            containers=tuple(containers),
            unclassified_records=sum(
                item.container_code is None for item in latest_records
            ),
        )

    def _storage_summaries(
        self,
        frames: tuple[BDOFrame, ...],
        events: tuple[BDOEvent, ...],
    ) -> tuple[tuple[StorageSnapshotSummary, ...], int]:
        records: dict[int, dict[str, SnapshotItem]] = {}
        raw_counts: dict[int, int] = {}
        group_keys: dict[int, set[_FrameKey]] = {}
        unresolved = 0
        for event in events:
            if event.storage_id is None:
                unresolved += 1
                continue
            storage_id = event.storage_id
            raw_counts[storage_id] = raw_counts.get(storage_id, 0) + 1
            group_keys.setdefault(storage_id, set()).add(_event_frame_key(event))
            if event.storage_instance is None:
                instance = (
                    f"unavailable:{event.item_id}:{event.record_offset}:"
                    f"{_event_frame_key(event).stream_sequence}"
                )
            else:
                instance = event.storage_instance
            records.setdefault(storage_id, {})[instance] = _snapshot_item(
                event, instance
            )

        empty_ids, empty_groups = _empty_storage_envelopes(frames, self.storage_specs)
        all_ids = set(records) | empty_ids
        summaries: list[StorageSnapshotSummary] = []
        for storage_id in all_ids:
            location = storage_location(storage_id)
            items_by_instance = records.get(storage_id, {})
            raw_count = raw_counts.get(storage_id, 0)
            summaries.append(
                StorageSnapshotSummary(
                    storage_id=storage_id,
                    name=location.name if location is not None else None,
                    name_confidence=(
                        location.confidence if location is not None else None
                    ),
                    items=tuple(
                        sorted(
                            items_by_instance.values(), key=lambda item: item.instance
                        )
                    ),
                    raw_records=raw_count,
                    duplicate_records=max(0, raw_count - len(items_by_instance)),
                    groups=len(group_keys.get(storage_id, set()))
                    + empty_groups.get(storage_id, 0),
                    empty_envelope_seen=storage_id in empty_ids,
                )
            )

        summaries.sort(
            key=lambda summary: (
                summary.name is None,
                summary.name.casefold() if summary.name is not None else "",
                summary.storage_id,
            )
        )
        return tuple(summaries), unresolved


def _frame_has_zero_context(frame: BDOFrame, spec: EventSpec) -> bool:
    if spec.source_context_offset is None:
        return False
    start = spec.source_context_offset
    end = start + spec.source_context_length
    return (
        end <= len(frame.message) and frame.message[start:end] == CHARACTER_LOAD_CONTEXT
    )


def _latest_inventory_generation(
    events: tuple[BDOEvent, ...],
) -> tuple[tuple[BDOEvent, ...], Optional[float], int]:
    """Select the latest compact inventory-hydration burst in a capture."""
    if not events:
        return events, None, 0

    frame_times = sorted(
        {(event.timestamp, _event_frame_key(event)) for event in events},
        key=lambda item: item[0],
    )
    generation_starts = [frame_times[0][0]]
    previous_timestamp = frame_times[0][0]
    for timestamp, _ in frame_times[1:]:
        if timestamp - previous_timestamp > _INVENTORY_GENERATION_GAP_SECONDS:
            generation_starts.append(timestamp)
        previous_timestamp = timestamp

    latest_start = generation_starts[-1]
    return (
        tuple(event for event in events if event.timestamp >= latest_start),
        latest_start,
        len(generation_starts),
    )


def _empty_storage_envelopes(
    frames: Iterable[BDOFrame],
    specs: Iterable[EventSpec],
) -> tuple[set[int], dict[int, int]]:
    """Recognize empty current-wrapper envelopes without creating fake items."""
    by_opcode = {spec.opcode: spec for spec in specs}
    empty_ids: set[int] = set()
    group_counts: dict[int, int] = {}
    for frame in frames:
        spec = by_opcode.get(frame.opcode)
        if spec is None:
            continue
        item_offset = spec.item_offset
        mode_offset = item_offset - 30
        token_start = item_offset - 29
        token_end = item_offset - 21
        count_offset = item_offset - 20
        storage_offset = item_offset - 9
        if min(mode_offset, token_start, count_offset, storage_offset) < 5:
            continue
        if max(token_end, count_offset + 2, storage_offset + 4) > len(frame.message):
            continue
        if frame.message[mode_offset] != 2:
            continue
        if frame.message[token_start:token_end] != b"\x00" * 8:
            continue
        if (
            int.from_bytes(frame.message[count_offset : count_offset + 2], "little")
            != 0
        ):
            continue
        # A declared-empty envelope ends before the first calibrated item.
        # This rejects malformed nonempty frames whose count field happens to
        # be zero while retaining the observed 35-byte current wrapper.
        if frame.length > item_offset:
            continue
        storage_id = int.from_bytes(
            frame.message[storage_offset : storage_offset + 4], "little"
        )
        # For an empty wrapper there are no item records to validate. Restrict
        # this provisional envelope path to a registered numeric destination.
        if storage_id not in STORAGE_LOCATIONS:
            continue
        empty_ids.add(storage_id)
        group_counts[storage_id] = group_counts.get(storage_id, 0) + 1
    return empty_ids, group_counts


def _active_specs(
    opcode_profile: str | Path | None,
) -> tuple[str, tuple[EventSpec, ...]]:
    profile_path = (
        Path(opcode_profile) if opcode_profile is not None else default_profile_path()
    )
    profile = load_opcode_profile(profile_path)
    if not profile.active:
        raise ProfileError(
            f"Opcode profile is inactive: {profile_path}. Activate or recalibrate it."
        )
    loaded = event_specs_from_profile(profile)
    return str(profile_path), loaded.specs


def analyze_character_load_pcap(
    path: str | Path,
    *,
    opcode_profile: str | Path | None = None,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
) -> CharacterStateSnapshot:
    """Replay a capture and summarize framed inventory/storage hydration."""
    options = PacketCaptureOptions(ports=ports)
    profile_source, specs = _active_specs(opcode_profile)
    accumulator = _CharacterStateAccumulator(
        profile_source=profile_source,
        specs=specs,
        capture_mode="pcap_replay",
        input_path=path,
    )
    engine = PacketEngine(
        server_ports=options.ports,
        event_specs=specs,
        on_event=accumulator.observe_record,
        frame_observer=accumulator.observe_frame,
    )
    for _ in iter_pcap_file(Path(path), engine):
        pass
    return accumulator.snapshot()


def _validate_save_pcap_path(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)):
        raise TypeError("save_pcap must be a path string, Path, or None")
    capture_path = Path(path)
    if capture_path.suffix.casefold() not in {".pcap", ".pcapng"}:
        raise ValueError("save_pcap must end in .pcap or .pcapng")
    return capture_path


def _open_packet_writer(path: Path) -> Any:
    """Open a Scapy writer matching the requested capture container."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing capture: {path}")
    if path.suffix.casefold() == ".pcapng":
        from scapy.utils import PcapNgWriter  # type: ignore

        return PcapNgWriter(str(path))

    from scapy.utils import PcapWriter  # type: ignore

    # sync=True makes a live .pcap useful even if the process exits before a
    # normal stop. PcapNgWriter has no equivalent constructor option and is
    # still explicitly closed on every session exit path below.
    return PcapWriter(str(path), append=False, sync=True)


class CharacterLoadSession:
    """Experimental live capture session returning a character-state summary."""

    def __init__(
        self,
        *,
        opcode_profile: str | Path | None = None,
        capture_options: Optional[PacketCaptureOptions] = None,
        save_pcap: str | Path | None = None,
    ) -> None:
        if capture_options is not None and not isinstance(
            capture_options, PacketCaptureOptions
        ):
            raise TypeError("capture_options must be a PacketCaptureOptions or None")
        self._capture_options = capture_options or PacketCaptureOptions()
        self._save_pcap_path = (
            _validate_save_pcap_path(save_pcap) if save_pcap is not None else None
        )
        self._profile_source, self._specs = _active_specs(opcode_profile)
        self._accumulator: Optional[_CharacterStateAccumulator] = None
        self._engine: Optional[PacketEngine] = None
        self._capture: Any = None
        self._capture_writer: Any = None
        self._result: Optional[CharacterStateSnapshot] = None
        self._error: Optional[BaseException] = None

    @property
    def running(self) -> bool:
        return self._capture is not None and bool(self._capture.running)

    @property
    def frames_seen(self) -> int:
        return self._accumulator.frames_seen if self._accumulator is not None else 0

    @property
    def error(self) -> Optional[BaseException]:
        """First background capture or decoder failure, if any."""
        return self._error

    @property
    def save_pcap_path(self) -> Optional[Path]:
        """Destination for opt-in raw live packets, if configured."""
        return self._save_pcap_path

    def start(self) -> None:
        """Begin passive background capture."""
        if self._capture is not None or self._result is not None:
            raise RuntimeError(
                "character-load session is single-use and already started"
            )
        self._error = None

        IP, TCP, _, _, _ = import_scapy()
        from scapy.sendrecv import AsyncSniffer  # type: ignore

        accumulator = _CharacterStateAccumulator(
            profile_source=self._profile_source,
            specs=self._specs,
            capture_mode="live_capture",
            saved_capture_path=self._save_pcap_path,
        )
        engine = PacketEngine(
            server_ports=self._capture_options.ports,
            event_specs=self._specs,
            on_event=accumulator.observe_record,
            frame_observer=accumulator.observe_frame,
        )

        detected_target = None
        if self._capture_options.interface is None:
            detected_target = detect_default_capture_target()
            capture_interface = detected_target.interface
        else:
            capture_interface = self._capture_options.interface
        capture_local_ip = self._capture_options.local_ip
        if (
            capture_local_ip is None
            and self._capture_options.interface is None
            and self._capture_options.auto_local_ip
        ):
            assert detected_target is not None
            capture_local_ip = detected_target.local_ip

        bpf_filter = (
            None
            if not self._capture_options.use_bpf
            else build_bpf_filter(self._capture_options.ports, capture_local_ip)
        )
        lfilter = None
        if not self._capture_options.use_bpf:
            lfilter = lambda packet: (  # noqa: E731
                IP in packet
                and TCP in packet
                and int(packet[TCP].sport) in engine.server_ports
                and (
                    capture_local_ip is None or str(packet[IP].dst) == capture_local_ip
                )
            )

        packet_handler = make_packet_handler(engine)
        capture_writer = (
            _open_packet_writer(self._save_pcap_path)
            if self._save_pcap_path is not None
            else None
        )

        def handle_packet(packet: object) -> None:
            try:
                # Persist the untouched Scapy packet before decoding it. This
                # retains the packet that exposed a parser error and keeps the
                # diagnostic writer independent from reassembly semantics.
                if capture_writer is not None:
                    capture_writer.write(packet)
                packet_handler(packet)
            except BaseException as exc:
                if self._error is None:
                    self._error = exc
                raise

        capture_ready = Event()
        capture = None
        self._accumulator = accumulator
        self._engine = engine
        self._capture_writer = capture_writer
        try:
            capture = AsyncSniffer(
                iface=capture_interface,
                filter=bpf_filter,
                lfilter=lfilter,
                prn=handle_packet,
                store=False,
                started_callback=capture_ready.set,
            )
            capture.start()
            # AsyncSniffer.start() returns before its capture thread opens the
            # adapter. Do not invite the user to switch until traffic can
            # actually be observed.
            while not capture_ready.wait(timeout=0.05):
                capture_error = getattr(capture, "exception", None)
                if isinstance(capture_error, BaseException):
                    raise capture_error
                capture_thread = getattr(capture, "thread", None)
                if (
                    capture_thread is not None
                    and capture_thread.ident is not None
                    and not capture_thread.is_alive()
                ):
                    raise RuntimeError("live capture thread ended during startup")
        except BaseException:
            if capture is not None and capture.running:
                try:
                    capture.stop()
                except BaseException:
                    # Preserve the original startup failure.
                    pass
            if capture_writer is not None:
                try:
                    capture_writer.close()
                except BaseException:
                    # Preserve the original startup failure.
                    pass
            self._capture_writer = None
            self._accumulator = None
            self._engine = None
            raise
        assert capture is not None
        self._capture = capture

    def stop(self) -> CharacterStateSnapshot:
        """Stop capture, finish reassembly, and return the queryable summary."""
        if self._result is not None:
            return self._result
        if self._capture is None or self._engine is None or self._accumulator is None:
            raise RuntimeError("character-load session was not started")
        capture, self._capture = self._capture, None
        capture_writer, self._capture_writer = self._capture_writer, None
        try:
            if capture.running:
                capture.stop()
        except BaseException as exc:
            if self._error is None:
                self._error = exc
        try:
            self._engine.finish()
        except BaseException as exc:
            if self._error is None:
                self._error = exc
        if capture_writer is not None:
            try:
                capture_writer.close()
            except BaseException as exc:
                if self._error is None:
                    self._error = exc
        self._engine = None
        self._result = self._accumulator.snapshot()
        capture_error = getattr(capture, "exception", None)
        if self._error is None and isinstance(capture_error, BaseException):
            self._error = capture_error
        if self._error is not None:
            raise self._error
        return self._result

    def __enter__(self) -> "CharacterLoadSession":
        if self._capture is None and self._result is None:
            self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._capture is not None:
            self.stop()


def format_character_state(
    snapshot: CharacterStateSnapshot,
    *,
    show_items: bool = False,
) -> str:
    """Render a stable, honest diagnostic summary for console tools."""
    lines = [
        "CHARACTER LOAD SNAPSHOT DIAGNOSTIC",
        f"Profile: {snapshot.profile_source}",
        f"Generic BDO frames observed: {snapshot.frames_seen}",
        (
            "Hydration packets detected; trigger is unclassified "
            "(initial login vs character switch)."
            if snapshot.hydration_detected
            else "No hydration packets were detected."
        ),
        "",
        "INVENTORY SNAPSHOT",
    ]
    inventory = snapshot.inventory
    if inventory.groups:
        lines.extend(
            [
                (
                    f"  {inventory.serialized_records} serialized records: "
                    f"{inventory.occupied_stacks} occupied item stacks + "
                    f"{inventory.currency_balance_records} currency balances"
                ),
                (
                    f"  {inventory.groups} groups: {inventory.populated_groups} populated, "
                    f"{inventory.empty_groups} empty"
                ),
                "  group record counts: "
                + ", ".join(str(count) for count in inventory.group_counts),
                "  inferred record strides: "
                + (
                    ", ".join(str(stride) for stride in inventory.inferred_strides)
                    if inventory.inferred_strides
                    else "unavailable"
                ),
            ]
        )
        if inventory.containers:
            lines.append("  provisional containers (raw code is authoritative):")
            for container in inventory.containers:
                lines.append(
                    f"    {container.name} [0x{container.raw_code:02X}, "
                    f"{container.confidence}]: {container.occupied_stacks} item stacks, "
                    f"{len(container.currency_balances)} currency balances"
                )
        else:
            lines.append("  container/tab labels: unclassified")
        if inventory.empty_groups:
            lines.append(
                f"  {inventory.empty_groups} empty wrappers: unclassified "
                "(no record-level container field)"
            )
        if inventory.unclassified_records:
            lines.append(
                f"  records without a validated container: "
                f"{inventory.unclassified_records}"
            )
        if inventory.currency_balances:
            lines.append("  currency balances:")
            for balance in sorted(
                inventory.currency_balances,
                key=lambda item: item.item_id,
            ):
                lines.append(
                    f"    {balance.currency_name}: {balance.quantity:,} "
                    f"(item_id={balance.item_id}, "
                    f"container={balance.container_name}, "
                    f"slot={balance.inventory_slot})"
                )
        if inventory.duplicate_records:
            lines.append(
                f"  repeated records merged by item instance: {inventory.duplicate_records}"
            )
        if show_items:
            for item in inventory.items:
                lines.append(
                    f"    item_id={item.item_id} quantity={item.quantity} "
                    f"instance={item.instance} container={item.container_name or 'unknown'} "
                    f"container_code="
                    f"{f'0x{item.container_code:02X}' if item.container_code is not None else 'unknown'} "
                    f"slot={item.inventory_slot}"
                )
    else:
        lines.append("  NOT DETECTED")

    lines.extend(["", "STORAGE SNAPSHOT"])
    if snapshot.storage_snapshot_records or snapshot.storages:
        observed_known_ids = {
            storage.storage_id
            for storage in snapshot.storages
            if storage.storage_id in STORAGE_LOCATIONS
        }
        missing_known_ids = tuple(
            storage_id
            for storage_id in STORAGE_LOCATIONS
            if storage_id not in observed_known_ids
        )
        lines.extend(
            [
                (
                    f"  {snapshot.known_storage_destinations_detected}/"
                    f"{snapshot.known_storage_destinations_total} known destinations observed"
                ),
                (
                    f"  {snapshot.nonempty_storage_destinations} non-empty, "
                    f"{snapshot.empty_storage_destinations} explicitly empty, "
                    f"{len(missing_known_ids)} not observed"
                ),
                (
                    f"  {snapshot.storage_occupied_stacks} unique occupied item stacks "
                    f"from {snapshot.storage_snapshot_records} decoded snapshot records"
                ),
                "  capacity: unavailable (not present in the decoded item wrappers)",
                "",
            ]
        )
        if missing_known_ids:
            missing_names = sorted(
                STORAGE_LOCATIONS[storage_id].name for storage_id in missing_known_ids
            )
            lines.append(
                "  known destinations not observed: " + ", ".join(missing_names)
            )
            lines.append("")
        for storage in snapshot.storages:
            label = storage.name or f"UNKNOWN_STORAGE(0x{storage.storage_id:08x})"
            lines.append(
                f"  {label}: {storage.occupied_stacks} occupied item stacks detected"
            )
            if show_items:
                for item in storage.items:
                    lines.append(
                        f"    item_id={item.item_id} quantity={item.quantity} "
                        f"instance={item.instance}"
                    )
    else:
        lines.append("  NOT DETECTED")

    lines.extend(["", "LIMITATIONS"])
    lines.extend(f"  - {warning}" for warning in snapshot.warnings)
    return "\n".join(lines)


__all__ = [
    "CharacterLoadSession",
    "CharacterStateSnapshot",
    "InventoryContainerSummary",
    "InventorySnapshotSummary",
    "ItemStateCoverage",
    "ItemStateProvenance",
    "SnapshotItem",
    "StorageContents",
    "StorageSnapshotSummary",
    "analyze_character_load_pcap",
    "format_character_state",
]
