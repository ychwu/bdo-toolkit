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
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from typing import Any, Iterable, Optional

from ._capture_backend import (
    iter_pcap_file,
    make_packet_handler,
)
from ._capture_options import PacketCaptureOptions
from ._capture_runtime import (
    DEFAULT_STARTUP_TIMEOUT_SECONDS,
    LivePacketCapture,
    _attach_cleanup_owner,
)
from .capture import _EventCollector, _ProfileAuthority, _load_profile_authority
from ._engine import PacketEngine, toolkit_event_from_record
from ._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    DEFAULT_SERVER_PORTS,
    STORAGE_LOCATIONS,
    EventSpec,
    storage_location,
)
from .diagnostics import DecoderHealth
from .events import BDOEvent
from .filters import EventFilter
from .profiles import OpcodeProfile, ProfileError

_INVENTORY_GENERATION_GAP_SECONDS = 1.0
_INVENTORY_TRAILING_DISCOVERY_BYTES = 12
_STORAGE_DESTINATION_CHUNK_GAP_SECONDS = 1.0
_STORAGE_EMPTY_WINDOW_MARGIN_SECONDS = 1.0
_STORAGE_HYDRATION_BURST_GAP_SECONDS = 0.5
_STORAGE_HYDRATION_MAX_BURST_SECONDS = 1.0
_STORAGE_HYDRATION_EPOCH_SECONDS = 30.0
_STORAGE_HYDRATION_MIN_DESTINATIONS = 8
_ITEM_STATE_SCHEMA_VERSION = 5
_CHARACTER_LOAD_STARTUP_TIMEOUT_SECONDS = DEFAULT_STARTUP_TIMEOUT_SECONDS

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
class ItemStateCaptureLimits:
    """Hard fail-closed bounds for retained item-state observations."""

    max_relevant_frames: int = 10_000
    max_snapshot_records: int = 50_000
    max_relevant_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, value in (
            ("max_relevant_frames", self.max_relevant_frames),
            ("max_snapshot_records", self.max_snapshot_records),
            ("max_relevant_bytes", self.max_relevant_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_relevant_frames": self.max_relevant_frames,
            "max_snapshot_records": self.max_snapshot_records,
            "max_relevant_bytes": self.max_relevant_bytes,
        }


class ItemStateCaptureLimitError(RuntimeError):
    """Raised before an item-state accumulator would exceed a hard bound."""

    def __init__(self, *, limit_name: str, limit: int, attempted: int) -> None:
        self.limit_name = limit_name
        self.limit = limit
        self.attempted = attempted
        super().__init__(
            f"item-state accumulation limit exceeded: {limit_name} "
            f"attempted={attempted} limit={limit}; no partial snapshot was returned"
        )


@dataclass(frozen=True, kw_only=True)
class SnapshotItem:
    """One occupied item-stack record observed during state hydration."""

    item_id: int
    quantity: int
    instance: str
    observed_at: float
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
            "observed_at": self.observed_at,
        }
        optional = {
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


@dataclass(frozen=True, kw_only=True)
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


@dataclass(frozen=True, kw_only=True)
class InventorySnapshotSummary(_ItemQueries):
    """Canonical inventory state with computed container views."""

    hydration_observed: bool
    items: tuple[SnapshotItem, ...]
    currency_balances: tuple[SnapshotItem, ...]

    @property
    def serialized_records(self) -> int:
        """Distinct current records, including known currency-wallet balances."""
        return self.occupied_stacks + self.currency_balance_records

    @property
    def currency_balance_records(self) -> int:
        return len(self.currency_balances)

    @property
    def unclassified_records(self) -> int:
        return sum(
            item.container_code is None
            for item in (*self.items, *self.currency_balances)
        )

    @property
    def containers(self) -> tuple[InventoryContainerSummary, ...]:
        """Compute provisional container views without duplicating stored state."""

        records = (*self.items, *self.currency_balances)
        containers: list[InventoryContainerSummary] = []
        for raw_code, (name, confidence) in _INVENTORY_CONTAINER_LABELS.items():
            container_records = tuple(
                item for item in records if item.container_code == raw_code
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
        return tuple(containers)

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
            "hydration_observed": self.hydration_observed,
            "occupied_stacks": self.occupied_stacks,
            "serialized_records": self.serialized_records,
            "currency_balance_records": self.currency_balance_records,
            "unclassified_records": self.unclassified_records,
            "currency_balances": [
                balance.to_dict() for balance in self.currency_balances
            ],
            "items": [item.to_dict() for item in self.items],
        }


@dataclass(frozen=True, kw_only=True)
class StorageSnapshotSummary(_ItemQueries):
    """Selected current state for one observed storage destination."""

    storage_id: int
    name: Optional[str]
    name_confidence: Optional[str]
    items: tuple[SnapshotItem, ...]
    current_state_observed: bool
    current_empty: Optional[bool]
    current_identity_complete: Optional[bool]

    def to_dict(self) -> dict[str, object]:
        return {
            "storage_id": self.storage_id,
            "name": self.name,
            "name_confidence": self.name_confidence,
            "occupied_stacks": self.occupied_stacks,
            "current_state_observed": self.current_state_observed,
            "current_empty": self.current_empty,
            "current_identity_complete": self.current_identity_complete,
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

    @property
    def registered_count(self) -> int:
        """Number of observed destinations present in the installed registry."""
        return sum(storage.storage_id in STORAGE_LOCATIONS for storage in self)

    @property
    def selected_count(self) -> int:
        """Number of destinations selected as current state."""
        return sum(storage.current_state_observed for storage in self)

    @property
    def nonempty_count(self) -> int:
        """Selected destinations containing at least one occupied stack."""
        return sum(
            storage.current_state_observed and storage.occupied_stacks > 0
            for storage in self
        )

    @property
    def empty_count(self) -> int:
        """Selected destinations proven empty by a count-zero wrapper."""
        return sum(storage.current_empty is True for storage in self)

    @property
    def occupied_stacks(self) -> int:
        """Occupied stacks across the selected current destination states."""
        return sum(storage.occupied_stacks for storage in self)

    def to_dict(self) -> dict[str, object]:
        """Serialize current aggregate counts and each observed destination."""
        return {
            "observed_count": len(self),
            "registered_count": self.registered_count,
            "selected_count": self.selected_count,
            "nonempty_count": self.nonempty_count,
            "empty_count": self.empty_count,
            "occupied_stacks": self.occupied_stacks,
            "destinations": [storage.to_dict() for storage in self],
        }


@dataclass(frozen=True)
class ItemStateCoverage:
    """Actionable gaps in the observed item-state evidence."""

    inventory_records_missing_instance: int
    storage_records_missing_instance: int
    selected_storage_records_missing_instance: int
    registered_storage_ids_not_observed: tuple[int, ...]
    unregistered_storage_ids_observed: tuple[int, ...]
    storage_locations_not_selected: int
    storage_locations_with_incomplete_current_identity: int

    def to_dict(self) -> dict[str, object]:
        return {
            "inventory_records_missing_instance": (
                self.inventory_records_missing_instance
            ),
            "storage_records_missing_instance": self.storage_records_missing_instance,
            "selected_storage_records_missing_instance": (
                self.selected_storage_records_missing_instance
            ),
            "registered_storage_ids_not_observed": list(
                self.registered_storage_ids_not_observed
            ),
            "unregistered_storage_ids_observed": list(
                self.unregistered_storage_ids_observed
            ),
            "storage_locations_not_selected": self.storage_locations_not_selected,
            "storage_locations_with_incomplete_current_identity": (
                self.storage_locations_with_incomplete_current_identity
            ),
        }


@dataclass(frozen=True)
class ItemStateProvenance:
    """Machine-readable origin of one assembled item-state snapshot."""

    capture_mode: str
    profile_source: str
    generation_selection: str = "unknown"
    capture_path: Optional[str] = None

    def to_dict(self, *, include_capture_path: bool = False) -> dict[str, object]:
        output: dict[str, object] = {
            "capture_mode": self.capture_mode,
            "profile_source": self.profile_source,
            "generation_selection": self.generation_selection,
        }
        if include_capture_path and self.capture_path is not None:
            output["capture_path"] = self.capture_path
        return output


@dataclass(frozen=True, kw_only=True)
class InventoryHydrationDiagnostics:
    """Inventory wrapper geometry and selection measurements."""

    raw_records: int
    duplicate_records: int
    group_counts: tuple[int, ...]
    inferred_strides: tuple[int, ...]
    generations_observed: int
    source_opcodes: tuple[int, ...]
    message_lengths: tuple[int, ...]

    @property
    def groups(self) -> int:
        return len(self.group_counts)

    @property
    def populated_groups(self) -> int:
        return sum(count > 0 for count in self.group_counts)

    @property
    def empty_groups(self) -> int:
        return sum(count == 0 for count in self.group_counts)

    def to_dict(self) -> dict[str, object]:
        return {
            "raw_records": self.raw_records,
            "duplicate_records": self.duplicate_records,
            "groups": self.groups,
            "populated_groups": self.populated_groups,
            "empty_groups": self.empty_groups,
            "group_counts": list(self.group_counts),
            "inferred_strides": list(self.inferred_strides),
            "generations_observed": self.generations_observed,
            "source_opcodes": [
                f"0x{opcode:04X}" for opcode in self.source_opcodes
            ],
            "message_lengths": list(self.message_lengths),
        }


@dataclass(frozen=True, kw_only=True)
class StorageDestinationDiagnostics:
    """All-sweep assembly evidence for one numeric storage destination."""

    storage_id: int
    raw_records: int
    duplicate_records: int
    groups: int
    empty_envelope_seen: bool
    selected_records: int
    selected_groups: int
    sweeps_observed: int
    selected_sweep: Optional[int]
    missing_instance_records: int
    selected_missing_instance_records: int
    source_opcodes: tuple[int, ...]
    message_lengths: tuple[int, ...]

    @property
    def superseded_records(self) -> int:
        return max(0, self.raw_records - self.selected_records)

    @property
    def superseded_groups(self) -> int:
        return max(0, self.groups - self.selected_groups)

    def to_dict(self) -> dict[str, object]:
        return {
            "storage_id": self.storage_id,
            "raw_records": self.raw_records,
            "duplicate_records": self.duplicate_records,
            "groups": self.groups,
            "empty_envelope_seen": self.empty_envelope_seen,
            "selected_records": self.selected_records,
            "superseded_records": self.superseded_records,
            "selected_groups": self.selected_groups,
            "superseded_groups": self.superseded_groups,
            "sweeps_observed": self.sweeps_observed,
            "selected_sweep": self.selected_sweep,
            "missing_instance_records": self.missing_instance_records,
            "selected_missing_instance_records": (
                self.selected_missing_instance_records
            ),
            "source_opcodes": [
                f"0x{opcode:04X}" for opcode in self.source_opcodes
            ],
            "message_lengths": list(self.message_lengths),
        }


@dataclass(frozen=True, kw_only=True)
class StorageHydrationDiagnostics:
    """Aggregate storage assembly evidence with per-destination detail."""

    records_decoded: int
    records_without_destination: int
    sweeps_observed: int
    selected_sweep: Optional[int]
    destinations: tuple[StorageDestinationDiagnostics, ...]

    def destination(
        self,
        storage_id: int,
    ) -> Optional[StorageDestinationDiagnostics]:
        """Return diagnostics for one exact numeric destination key."""

        return next(
            (
                diagnostic
                for diagnostic in self.destinations
                if diagnostic.storage_id == storage_id
            ),
            None,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "records_decoded": self.records_decoded,
            "records_without_destination": self.records_without_destination,
            "sweeps_observed": self.sweeps_observed,
            "selected_sweep": self.selected_sweep,
            "destinations": [
                diagnostic.to_dict() for diagnostic in self.destinations
            ],
        }


@dataclass(frozen=True, kw_only=True)
class ItemStateDiagnostics:
    """Advanced capture and selection measurements for troubleshooting."""

    frames_seen: int
    relevant_frames_retained: int
    relevant_bytes_retained: int
    snapshot_records_retained: int
    capture_limits: ItemStateCaptureLimits
    inventory: InventoryHydrationDiagnostics
    storage: StorageHydrationDiagnostics

    def to_dict(self) -> dict[str, object]:
        return {
            "frames_seen": self.frames_seen,
            "relevant_frames_retained": self.relevant_frames_retained,
            "relevant_bytes_retained": self.relevant_bytes_retained,
            "snapshot_records_retained": self.snapshot_records_retained,
            "capture_limits": self.capture_limits.to_dict(),
            "inventory": self.inventory.to_dict(),
            "storage": self.storage.to_dict(),
        }


@dataclass(frozen=True)
class CharacterStateSnapshot:
    """Query model assembled from observed character-load hydration records."""

    inventory: InventorySnapshotSummary
    storages: StorageContents
    provenance: ItemStateProvenance
    coverage: ItemStateCoverage
    decoder_health: DecoderHealth = DecoderHealth()
    warnings: tuple[str, ...] = ()
    diagnostics: Optional[ItemStateDiagnostics] = None

    def __post_init__(self) -> None:
        if not isinstance(self.inventory, InventorySnapshotSummary):
            raise TypeError("inventory must be an InventorySnapshotSummary")
        if not isinstance(self.provenance, ItemStateProvenance):
            raise TypeError("provenance must be an ItemStateProvenance")
        if not isinstance(self.coverage, ItemStateCoverage):
            raise TypeError("coverage must be an ItemStateCoverage")
        if not isinstance(self.decoder_health, DecoderHealth):
            raise TypeError("decoder_health must be a DecoderHealth")
        if self.diagnostics is not None and not isinstance(
            self.diagnostics, ItemStateDiagnostics
        ):
            raise TypeError("diagnostics must be an ItemStateDiagnostics or None")
        object.__setattr__(self, "storages", StorageContents(self.storages))

    @property
    def schema_version(self) -> int:
        return _ITEM_STATE_SCHEMA_VERSION

    @property
    def identity_complete(self) -> bool:
        return (
            self.coverage.inventory_records_missing_instance == 0
            and self.coverage.storage_records_missing_instance == 0
        )

    @property
    def hydration_detected(self) -> bool:
        storage_evidence_observed = (
            self.diagnostics.storage.records_decoded
            if self.diagnostics is not None
            else 0
        )
        return bool(
            self.inventory.hydration_observed
            or storage_evidence_observed
            or self.storages
        )

    def to_dict(self, *, include_diagnostics: bool = False) -> dict[str, object]:
        output: dict[str, object] = {
            "schema_version": self.schema_version,
            "hydration_detected": self.hydration_detected,
            "identity_complete": self.identity_complete,
            "provenance": self.provenance.to_dict(
                include_capture_path=include_diagnostics
            ),
            "coverage": self.coverage.to_dict(),
            "decoder_health": self.decoder_health.to_dict(),
            "inventory": self.inventory.to_dict(),
            "storages": self.storages.to_dict(),
            "warnings": list(self.warnings),
        }
        if include_diagnostics and self.diagnostics is not None:
            output["diagnostics"] = self.diagnostics.to_dict()
        return output


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


def _unique_inventory_multi_layout(
    frame: BDOFrame,
    group: list[BDOEvent],
    candidates: Iterable[EventSpec],
) -> Optional[tuple[EventSpec, int]]:
    matches: list[tuple[EventSpec, int]] = []
    for spec in candidates:
        if not _frame_has_zero_context(frame, spec):
            continue
        stride = _inventory_frame_stride(frame, spec, group)
        if stride is not None:
            matches.append((spec, stride))
    return matches[0] if len(matches) == 1 else None


def _unique_inventory_single_layout(
    frame: BDOFrame,
    group: list[BDOEvent],
    candidates: Iterable[EventSpec],
    sibling_strides: dict[EventSpec, set[int]],
) -> Optional[tuple[EventSpec, int]]:
    matches: list[tuple[EventSpec, int]] = []
    for spec in candidates:
        proven = sibling_strides.get(spec, set())
        if len(proven) != 1:
            continue
        stride = next(iter(proven))
        if (
            not _frame_has_zero_context(frame, spec)
            or spec.single_record_message_length != frame.length
            or not _inventory_event_geometry_valid(spec, group, stride)
        ):
            continue
        matches.append((spec, stride))
    return matches[0] if len(matches) == 1 else None


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


def _discover_inventory_header_container_offset(
    frame_groups: list[tuple[BDOFrame, list[BDOEvent], EventSpec, int]],
) -> Optional[int]:
    """Discover a wrapper-level container byte shared by every sibling record.

    The August wrapper moved the known 00/10/18/0B container identity out of
    each repeated-record tail and into the prefix immediately before item one.
    Search the framed prefix instead of pinning that new position, and accept
    it only when one unique byte column explains at least two container groups.
    """
    if len(frame_groups) < 2:
        return None
    search_end = min(spec.item_offset for _, _, spec, _ in frame_groups)
    candidates: list[int] = []
    for offset in range(5, search_end):
        codes = []
        for frame, _, _, _ in frame_groups:
            if offset >= len(frame.message):
                break
            code = frame.message[offset]
            if code not in _INVENTORY_CONTAINER_LABELS:
                break
            codes.append(code)
        else:
            if len(set(codes)) >= 2:
                candidates.append(offset)
    return candidates[0] if len(candidates) == 1 else None


def _inventory_header_metadata(
    frame: BDOFrame,
    group: list[BDOEvent],
    container_offset: int,
) -> Optional[dict[int, _InventoryRecordMetadata]]:
    if container_offset >= len(frame.message):
        return None
    code = frame.message[container_offset]
    if code not in _INVENTORY_CONTAINER_LABELS:
        return None
    return {
        event.record_offset: _InventoryRecordMetadata(None, code)
        for event in group
        if event.record_offset is not None
    }


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
        capture_limits: Optional[ItemStateCaptureLimits] = None,
    ) -> None:
        if capture_limits is not None and not isinstance(
            capture_limits, ItemStateCaptureLimits
        ):
            raise TypeError("capture_limits must be an ItemStateCaptureLimits or None")
        self.profile_source = profile_source
        self.capture_mode = capture_mode
        self.input_path = str(input_path) if input_path is not None else None
        self.saved_capture_path = (
            str(saved_capture_path) if saved_capture_path is not None else None
        )
        self.capture_limits = capture_limits or ItemStateCaptureLimits()
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
        self._relevant_frames_retained = 0
        self._relevant_bytes_retained = 0
        self._snapshot_records_retained = 0
        self._limit_error: Optional[ItemStateCaptureLimitError] = None
        self._frames: list[BDOFrame] = []
        self._seen_frames: set[tuple[_FrameKey, bytes]] = set()
        self._inventory_events: list[BDOEvent] = []
        self._storage_events: list[BDOEvent] = []
        self._neutral_storage_events: list[BDOEvent] = []
        self._live_storage_boundaries: list[BDOEvent] = []

    @property
    def frames_seen(self) -> int:
        with self._lock:
            return self._frames_seen

    def observe_frame(self, frame: BDOFrame) -> None:
        with self._lock:
            self._frames_seen += 1
            if self._limit_error is not None:
                raise self._limit_error
            if frame.opcode not in self.relevant_opcodes:
                return
            digest = hashlib.blake2b(frame.message, digest_size=16).digest()
            dedupe_key = (_frame_key(frame), digest)
            if dedupe_key in self._seen_frames:
                return
            attempted_frames = self._relevant_frames_retained + 1
            if attempted_frames > self.capture_limits.max_relevant_frames:
                self._raise_limit(
                    "max_relevant_frames",
                    self.capture_limits.max_relevant_frames,
                    attempted_frames,
                )
            attempted_bytes = self._relevant_bytes_retained + len(frame.message)
            if attempted_bytes > self.capture_limits.max_relevant_bytes:
                self._raise_limit(
                    "max_relevant_bytes",
                    self.capture_limits.max_relevant_bytes,
                    attempted_bytes,
                )
            self._seen_frames.add(dedupe_key)
            self._frames.append(frame)
            self._relevant_frames_retained = attempted_frames
            self._relevant_bytes_retained = attempted_bytes

    def observe_record(self, record: Any, raw_message: bytes) -> None:
        del raw_message
        self.observe_event(toolkit_event_from_record(record))

    def observe_event(self, event: BDOEvent) -> None:
        """Retain snapshot records and fail-neutral storage candidates."""

        with self._lock:
            if self._limit_error is not None:
                raise self._limit_error
            if event.event_type not in {
                "inventory_snapshot",
                "storage_snapshot",
                "storage_record",
                "storage_delta",
            }:
                return
            attempted_evidence = (
                self._snapshot_records_retained
                + len(self._live_storage_boundaries)
                + 1
            )
            if attempted_evidence > self.capture_limits.max_snapshot_records:
                self._raise_limit(
                    "max_snapshot_records",
                    self.capture_limits.max_snapshot_records,
                    attempted_evidence,
                )
            if event.event_type == "inventory_snapshot":
                self._inventory_events.append(event)
            elif event.event_type == "storage_snapshot":
                self._storage_events.append(event)
            elif event.event_type == "storage_delta":
                # A proven live mutation is not snapshot content, but it is a
                # semantic boundary: neutral records on opposite sides must
                # never be reconciled into one character-load sweep.
                self._live_storage_boundaries.append(event)
                return
            else:
                self._neutral_storage_events.append(event)
            self._snapshot_records_retained += 1

    def _raise_limit(self, limit_name: str, limit: int, attempted: int) -> None:
        error = ItemStateCaptureLimitError(
            limit_name=limit_name,
            limit=limit,
            attempted=attempted,
        )
        self._limit_error = error
        raise error

    def snapshot(
        self,
        *,
        decoder_health: Optional[DecoderHealth] = None,
    ) -> CharacterStateSnapshot:
        with self._lock:
            if self._limit_error is not None:
                raise self._limit_error
            frames_seen = self._frames_seen
            relevant_frames_retained = self._relevant_frames_retained
            relevant_bytes_retained = self._relevant_bytes_retained
            snapshot_records_retained = self._snapshot_records_retained
            frames = tuple(self._frames)
            inventory_events = tuple(self._inventory_events)
            storage_events = tuple(self._storage_events)
            neutral_storage_events = tuple(self._neutral_storage_events)
            live_storage_boundaries = tuple(self._live_storage_boundaries)

        inventory_generation = _latest_inventory_generation(
            frames,
            inventory_events,
            self.inventory_specs,
        )
        inventory_events = inventory_generation.events
        inventory_anchors = inventory_generation.anchors
        generation_start = inventory_generation.start
        generations_seen = inventory_generation.generations_observed
        if generation_start is not None:
            # Current captures send the compact inventory hydration first and
            # storage hydration afterward. It is therefore a clean boundary
            # between separate character loads while retaining repeated
            # storage sweeps belonging to the same load.
            selected_flow_generations = {
                inventory_generation.flow_generation_key
            }
            storage_events = tuple(
                event
                for event in storage_events
                if event.timestamp >= generation_start
                and _event_flow_generation_key(event) in selected_flow_generations
            )
            neutral_storage_events = tuple(
                event
                for event in neutral_storage_events
                if event.timestamp >= generation_start
                and _event_flow_generation_key(event) in selected_flow_generations
            )
            live_storage_boundaries = tuple(
                event
                for event in live_storage_boundaries
                if event.timestamp >= generation_start
                and _event_flow_generation_key(event) in selected_flow_generations
            )
            frames = tuple(
                frame
                for frame in frames
                if frame.context.timestamp >= generation_start
                and _frame_flow_generation_key(frame) in selected_flow_generations
            )

        fallback_observations: Optional[
            tuple[_StorageGroupObservation, ...]
        ] = None
        sparse_fallback_used = False
        split_reconciliation_used = False
        if not storage_events:
            storage_events, selected_observations = (
                _character_storage_snapshot_fallback(
                    frames,
                    neutral_storage_events,
                    inventory_anchors,
                    self.storage_specs,
                )
            )
            if selected_observations:
                fallback_observations = selected_observations
                sparse_fallback_used = True

        if storage_events and neutral_storage_events:
            (
                reconciled_events,
                reconciled_observations,
                reconciled_count,
            ) = _reconcile_split_storage_hydration(
                frames,
                storage_events,
                neutral_storage_events,
                live_storage_boundaries,
                inventory_anchors,
                self.storage_specs,
            )
            if reconciled_count:
                storage_events = reconciled_events
                fallback_observations = reconciled_observations
                split_reconciliation_used = True

        inventory_assembly = self._inventory_summary(
            frames,
            inventory_events,
            generations_observed=generations_seen,
        )
        inventory = inventory_assembly.summary
        storage_assembly = self._storage_summaries(
            frames,
            storage_events,
            observations=fallback_observations,
            hydration_anchors=inventory_anchors,
        )
        storages = storage_assembly.summaries
        unresolved_storage = storage_assembly.records_without_destination
        storage_records_missing_instance = (
            storage_assembly.records_missing_instance
        )
        storage_sweeps_observed = storage_assembly.sweeps_observed
        selected_storage_sweep = storage_assembly.selected_sweep
        unknown_empty_envelopes = storage_assembly.unknown_empty_envelopes
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
        if not inventory.hydration_observed:
            warnings.append(
                "No inventory snapshot records were decoded; verify that the active "
                "profile has an inventory opcode, context offset, item instance offset, "
                "and calibrated single-record length."
            )
            if storage_events or storages:
                warnings.append(
                    "No inventory hydration boundary was decoded; storage state "
                    "diagnostics contain all observed records, while current contents "
                    "use the latest inferred sweep and may span multiple loads."
                )
        elif not inventory_events:
            warnings.append(
                "Inventory hydration was observed only through calibrated count-zero "
                "wrappers; the empty current state is preserved, but no record-level "
                "container metadata was available."
            )
        if sparse_fallback_used:
            warnings.append(
                "Storage hydration was proven by the dedicated character-load "
                "boundary plus a broad count-zero/nonempty destination cohort; "
                "the ordinary live stream remained fail-neutral."
            )
        if split_reconciliation_used:
            warnings.append(
                "Storage hydration records split across timing bursts were "
                "reconciled only within one inventory-anchored flow generation, "
                "opcode family, inferred sweep, and live-mutation boundary."
            )
        if not storage_events and not storages:
            warnings.append(
                "No storage snapshot records were decoded; the capture may be partial "
                "or the storage wrapper/profile may have changed."
            )
        resolved_health = decoder_health or DecoderHealth()
        if storages and resolved_health.storage_status == "not_observed":
            validated_messages = len(fallback_observations or ())
            resolved_health = replace(
                resolved_health,
                storage_status="compatible",
                storage_messages_observed=max(
                    resolved_health.storage_messages_observed,
                    validated_messages,
                ),
                storage_messages_decoded=max(
                    resolved_health.storage_messages_decoded,
                    validated_messages,
                ),
            )
        unregistered_storage_ids = {
            storage.storage_id
            for storage in storages
            if storage.storage_id not in STORAGE_LOCATIONS
        }
        if unregistered_storage_ids:
            selected_unknown_records = sum(
                event.storage_id is not None
                and event.storage_id not in STORAGE_LOCATIONS
                for event in storage_events
            )
            resolved_health = replace(
                resolved_health,
                storage_status="incompatible",
                storage_destination_failures=(
                    max(
                        resolved_health.storage_destination_failures,
                        selected_unknown_records,
                    )
                    + unknown_empty_envelopes
                ),
            )
        if resolved_health.storage_status == "incompatible":
            warnings.append(
                "The storage decoder reported an incompatible wrapper, geometry, "
                "or destination field. Recalibrate before treating missing towns "
                "as empty."
            )
        elif (
            resolved_health.storage_status == "not_observed" and inventory_anchors
        ):
            warnings.append(
                "Inventory hydration was observed, but the calibrated storage "
                "opcode was not observed. The capture may be partial or the storage "
                "profile may be stale; not_observed is not proof of compatibility."
            )
        if unregistered_storage_ids:
            warnings.append(
                f"{len(unregistered_storage_ids)} storage destination ID(s) are "
                "not in the town registry. Their numeric identities were preserved, "
                "but display names and name-based queries require a registry update."
            )
        if unresolved_storage:
            warnings.append(
                f"{unresolved_storage} storage snapshot records lacked a numeric "
                "destination and were excluded from per-storage state."
            )
        if inventory_assembly.missing_instance_records:
            warnings.append(
                f"{inventory_assembly.missing_instance_records} inventory snapshot records "
                "lacked observed instance identity and were excluded from "
                "distinct-stack state."
            )
        if storage_records_missing_instance:
            warnings.append(
                f"{storage_records_missing_instance} storage snapshot records "
                "lacked observed instance identity and were excluded from "
                "distinct-stack state."
            )
        not_selected = sum(not storage.current_state_observed for storage in storages)
        if storage_sweeps_observed > 1:
            warnings.append(
                f"{storage_sweeps_observed} storage sweeps were conservatively "
                f"inferred; current contents use sweep {selected_storage_sweep}, "
                "while raw record and group counts cover every observed sweep."
            )
        if not_selected:
            warnings.append(
                f"The latest inferred storage sweep did not revisit {not_selected} "
                "earlier-observed destinations. Their older items were excluded "
                "instead of being reported as current; the selected sweep may be "
                "partial."
            )
        observed_registered = {
            storage.storage_id
            for storage in storages
            if storage.storage_id in STORAGE_LOCATIONS
        }
        missing_registered = tuple(
            storage_id
            for storage_id in STORAGE_LOCATIONS
            if storage_id not in observed_registered
        )
        if generations_seen:
            generation_selection = "latest_observed_inventory_hydration"
        elif storage_events or storages:
            generation_selection = "all_observed_storage_no_inventory_boundary"
        else:
            generation_selection = "none_no_hydration_boundary"
        return CharacterStateSnapshot(
            inventory=inventory,
            storages=StorageContents(storages),
            provenance=ItemStateProvenance(
                capture_mode=self.capture_mode,
                profile_source=self.profile_source,
                generation_selection=generation_selection,
                capture_path=self.input_path or self.saved_capture_path,
            ),
            coverage=ItemStateCoverage(
                inventory_records_missing_instance=(
                    inventory_assembly.missing_instance_records
                ),
                storage_records_missing_instance=storage_records_missing_instance,
                selected_storage_records_missing_instance=sum(
                    diagnostic.selected_missing_instance_records
                    for diagnostic in storage_assembly.diagnostics
                ),
                registered_storage_ids_not_observed=missing_registered,
                unregistered_storage_ids_observed=tuple(
                    sorted(unregistered_storage_ids)
                ),
                storage_locations_not_selected=not_selected,
                storage_locations_with_incomplete_current_identity=sum(
                    storage.current_state_observed
                    and storage.current_identity_complete is False
                    for storage in storages
                ),
            ),
            decoder_health=resolved_health,
            warnings=tuple(warnings),
            diagnostics=ItemStateDiagnostics(
                frames_seen=frames_seen,
                relevant_frames_retained=relevant_frames_retained,
                relevant_bytes_retained=relevant_bytes_retained,
                snapshot_records_retained=snapshot_records_retained,
                capture_limits=self.capture_limits,
                inventory=inventory_assembly.diagnostics,
                storage=StorageHydrationDiagnostics(
                    records_decoded=len(storage_events),
                    records_without_destination=unresolved_storage,
                    sweeps_observed=storage_sweeps_observed,
                    selected_sweep=selected_storage_sweep,
                    destinations=storage_assembly.diagnostics,
                ),
            ),
        )

    def _inventory_summary(
        self,
        frames: tuple[BDOFrame, ...],
        events: tuple[BDOEvent, ...],
        *,
        generations_observed: int,
    ) -> _InventoryAssembly:
        groups: dict[_FrameKey, list[BDOEvent]] = {}
        for event in events:
            groups.setdefault(_event_frame_key(event), []).append(event)

        frames_by_key = {_frame_key(frame): frame for frame in frames}
        specs_by_opcode = _spec_candidates_by_opcode(self.inventory_specs)
        multi_groups_by_spec: dict[
            EventSpec, list[tuple[BDOFrame, list[BDOEvent], EventSpec, int]]
        ] = {}
        strides_by_key: dict[_FrameKey, int] = {}
        selected_specs_by_key: dict[_FrameKey, EventSpec] = {}
        sibling_strides: dict[EventSpec, set[int]] = {}
        prefix_candidates: dict[EventSpec, set[int]] = {}

        # A multi-record frame proves its own stride from L, B, and N. Layout
        # discovery is intentionally separate: stride alone does not prove
        # where slot/container metadata moved in a new protocol generation.
        for key, group in groups.items():
            frame = frames_by_key.get(key)
            if frame is None:
                continue
            selected = _unique_inventory_multi_layout(
                frame,
                group,
                specs_by_opcode.get(frame.opcode, ()),
            )
            if selected is None:
                continue
            spec, stride = selected
            strides_by_key[key] = stride
            selected_specs_by_key[key] = spec
            sibling_strides.setdefault(spec, set()).add(stride)
            prefix_candidates.setdefault(spec, set()).add(
                frame.length - len(group) * stride
            )
            multi_groups_by_spec.setdefault(spec, []).append(
                (frame, group, spec, stride)
            )

        tail_layouts = {
            spec: _discover_inventory_tail_layout(frame_groups)
            for spec, frame_groups in multi_groups_by_spec.items()
        }
        header_container_offsets = {
            spec: _discover_inventory_header_container_offset(frame_groups)
            for spec, frame_groups in multi_groups_by_spec.items()
            if tail_layouts.get(spec) is None
        }

        # A calibrated single-record base and repeat stride also prove the
        # zero-record prefix. This preserves empty inventory hydration as an
        # observed state even when the capture contains no occupied records.
        for candidates in specs_by_opcode.values():
            for spec in candidates:
                if (
                    spec.single_record_message_length is not None
                    and spec.repeat_stride is not None
                    and spec.repeat_stride > 0
                    and spec.single_record_message_length > spec.repeat_stride
                ):
                    prefix_candidates.setdefault(spec, set()).add(
                        spec.single_record_message_length - spec.repeat_stride
                    )
        metadata_by_record: dict[tuple[_FrameKey, int], _InventoryRecordMetadata] = {}
        for key, group in groups.items():
            frame = frames_by_key.get(key)
            if frame is None:
                continue
            spec_for_group = selected_specs_by_key.get(key)
            stride_for_group = strides_by_key.get(key)
            if stride_for_group is None and len(group) == 1:
                selected = _unique_inventory_single_layout(
                    frame,
                    group,
                    specs_by_opcode.get(frame.opcode, ()),
                    sibling_strides,
                )
                if selected is not None:
                    spec_for_group, stride_for_group = selected
                    selected_specs_by_key[key] = spec_for_group
                    strides_by_key[key] = stride_for_group
            if spec_for_group is None or stride_for_group is None:
                continue
            tail_layout = tail_layouts.get(spec_for_group)
            if tail_layout is not None:
                extracted = _inventory_record_metadata(
                    frame,
                    group,
                    spec_for_group,
                    stride_for_group,
                    tail_layout,
                )
            else:
                header_offset = header_container_offsets.get(spec_for_group)
                if header_offset is None:
                    continue
                extracted = _inventory_header_metadata(
                    frame,
                    group,
                    header_offset,
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
                continue
            instance = event.item_instance
            metadata = (
                metadata_by_record.get((_event_frame_key(event), event.record_offset))
                if event.record_offset is not None
                else None
            )
            latest[instance] = _snapshot_item(event, instance, metadata)

        prefixes = {
            spec: next(iter(candidates))
            for spec, candidates in prefix_candidates.items()
            if len(candidates) == 1
        }

        frame_counts: list[int] = []
        counted_keys: set[_FrameKey] = set()
        for frame in frames:
            key = _frame_key(frame)
            frame_group = groups.get(key)
            if frame_group is not None and key in selected_specs_by_key:
                frame_counts.append(len(frame_group))
                counted_keys.add(key)
                continue
            empty_matches = [
                candidate
                for candidate in specs_by_opcode.get(frame.opcode, ())
                if _frame_has_zero_context(frame, candidate)
                and prefixes.get(candidate) == frame.length
            ]
            if frame_group is None and len(empty_matches) == 1:
                frame_counts.append(0)
                counted_keys.add(key)

        # Events can still be useful when a caller feeds normalized records
        # without generic frame observations.
        for key, group in groups.items():
            if key not in counted_keys:
                frame_counts.append(len(group))

        identified_records = len(events) - missing_instance
        duplicate_records = identified_records - len(latest)

        latest_records = tuple(sorted(latest.values(), key=lambda item: item.instance))
        items = tuple(item for item in latest_records if not item.is_currency_balance)
        currency_balances = tuple(
            item for item in latest_records if item.is_currency_balance
        )
        source_opcodes = {
            frame.opcode
            for frame in frames
            if _frame_key(frame) in counted_keys
        }
        message_lengths = {
            frame.length
            for frame in frames
            if _frame_key(frame) in counted_keys
        }
        source_opcodes.update(
            event.opcode for event in events if event.opcode is not None
        )
        message_lengths.update(
            event.message_length
            for event in events
            if isinstance(event.message_length, int)
            and not isinstance(event.message_length, bool)
        )
        return _InventoryAssembly(
            summary=InventorySnapshotSummary(
                hydration_observed=bool(frame_counts),
                items=items,
                currency_balances=currency_balances,
            ),
            missing_instance_records=missing_instance,
            diagnostics=InventoryHydrationDiagnostics(
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
                generations_observed=generations_observed,
                source_opcodes=tuple(sorted(source_opcodes)),
                message_lengths=tuple(sorted(message_lengths)),
            ),
        )

    def _storage_summaries(
        self,
        frames: tuple[BDOFrame, ...],
        events: tuple[BDOEvent, ...],
        *,
        observations: Optional[tuple[_StorageGroupObservation, ...]] = None,
        hydration_anchors: Iterable[_HydrationAnchor] = (),
    ) -> _StorageAssembly:
        events = tuple(events)
        unresolved = sum(event.storage_id is None for event in events)
        records_missing_instance = sum(
            event.storage_instance is None for event in events
        )
        resolved_events = tuple(
            event for event in events if event.storage_id is not None
        )
        if observations is None:
            observations = _storage_group_observations(
                frames,
                resolved_events,
                self.storage_specs,
                hydration_anchors=hydration_anchors,
            )
        unknown_empty_envelopes = sum(
            observation.empty and observation.storage_id not in STORAGE_LOCATIONS
            for observation in observations
        )
        sweeps = _infer_storage_sweeps(observations)
        selected_sweep = len(sweeps) if sweeps else None
        selected_blocks = (
            {block.storage_id: block for block in sweeps[-1]} if sweeps else {}
        )

        raw_counts: dict[int, int] = {}
        missing_instance_counts: dict[int, int] = {}
        all_records: dict[int, dict[str, SnapshotItem]] = {}
        group_counts: dict[int, int] = {}
        empty_ids: set[int] = set()
        source_opcodes: dict[int, set[int]] = {}
        message_lengths: dict[int, set[int]] = {}
        for observation in observations:
            storage_id = observation.storage_id
            raw_counts[storage_id] = (
                raw_counts.get(storage_id, 0) + observation.raw_records
            )
            missing_instance_counts[storage_id] = (
                missing_instance_counts.get(storage_id, 0)
                + observation.missing_instance_records
            )
            group_counts[storage_id] = group_counts.get(storage_id, 0) + 1
            source_opcodes.setdefault(storage_id, set()).add(observation.opcode)
            if observation.message_length is not None:
                message_lengths.setdefault(storage_id, set()).add(
                    observation.message_length
                )
            if observation.empty:
                empty_ids.add(storage_id)
            for item in observation.items:
                all_records.setdefault(storage_id, {})[item.instance] = item

        sweeps_by_storage: dict[int, int] = {}
        for sweep in sweeps:
            for block in sweep:
                sweeps_by_storage[block.storage_id] = (
                    sweeps_by_storage.get(block.storage_id, 0) + 1
                )

        all_ids = set(group_counts)
        summaries: list[StorageSnapshotSummary] = []
        diagnostics_by_id: dict[int, StorageDestinationDiagnostics] = {}
        for storage_id in all_ids:
            location = storage_location(storage_id)
            selected_block = selected_blocks.get(storage_id)
            current_state_observed = selected_block is not None
            items_by_instance: dict[str, SnapshotItem] = {}
            selected_records = 0
            selected_groups = 0
            selected_missing_instance_records = 0
            current_empty: Optional[bool] = None
            if selected_block is not None:
                selected_records = sum(
                    group.raw_records for group in selected_block.groups
                )
                selected_groups = len(selected_block.groups)
                selected_missing_instance_records = sum(
                    group.missing_instance_records for group in selected_block.groups
                )
                current_empty = selected_block.empty
                if not current_empty:
                    for group in selected_block.groups:
                        for item in group.items:
                            items_by_instance[item.instance] = item
            raw_count = raw_counts.get(storage_id, 0)
            missing_instance_records = missing_instance_counts.get(storage_id, 0)
            groups = group_counts.get(storage_id, 0)
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
                    current_state_observed=current_state_observed,
                    current_empty=current_empty,
                    current_identity_complete=(
                        selected_missing_instance_records == 0
                        if current_state_observed
                        else None
                    ),
                )
            )
            diagnostics_by_id[storage_id] = StorageDestinationDiagnostics(
                storage_id=storage_id,
                raw_records=raw_count,
                duplicate_records=max(
                    0,
                    raw_count
                    - missing_instance_records
                    - len(all_records.get(storage_id, {})),
                ),
                groups=groups,
                empty_envelope_seen=storage_id in empty_ids,
                selected_records=selected_records,
                selected_groups=selected_groups,
                sweeps_observed=sweeps_by_storage.get(storage_id, 0),
                selected_sweep=(selected_sweep if current_state_observed else None),
                missing_instance_records=missing_instance_records,
                selected_missing_instance_records=selected_missing_instance_records,
                source_opcodes=tuple(sorted(source_opcodes.get(storage_id, ()))),
                message_lengths=tuple(sorted(message_lengths.get(storage_id, ()))),
            )

        summaries.sort(
            key=lambda summary: (
                summary.name is None,
                summary.name.casefold() if summary.name is not None else "",
                summary.storage_id,
            )
        )
        return _StorageAssembly(
            summaries=tuple(summaries),
            diagnostics=tuple(
                diagnostics_by_id[summary.storage_id] for summary in summaries
            ),
            records_without_destination=unresolved,
            records_missing_instance=records_missing_instance,
            sweeps_observed=len(sweeps),
            selected_sweep=selected_sweep,
            unknown_empty_envelopes=unknown_empty_envelopes,
        )


def _frame_has_zero_context(frame: BDOFrame, spec: EventSpec) -> bool:
    if spec.source_context_offset is None:
        return False
    start = spec.source_context_offset
    end = start + spec.source_context_length
    return (
        end <= len(frame.message) and frame.message[start:end] == CHARACTER_LOAD_CONTEXT
    )


def _latest_inventory_generation(
    frames: tuple[BDOFrame, ...],
    events: tuple[BDOEvent, ...],
    specs: Iterable[EventSpec],
) -> _InventoryGeneration:
    """Select the latest inventory burst, including proven count-zero wrappers."""
    specs_by_opcode = _spec_candidates_by_opcode(specs)
    observations = {
        _HydrationAnchor(event.timestamp, _event_frame_key(event)) for event in events
    }
    event_frame_keys = {_event_frame_key(event) for event in events}
    for frame in frames:
        frame_key = _frame_key(frame)
        if frame_key in event_frame_keys:
            continue
        empty_matches = [
            spec
            for spec in specs_by_opcode.get(frame.opcode, ())
            if spec.single_record_message_length is not None
            and spec.repeat_stride is not None
            and spec.repeat_stride > 0
            and spec.single_record_message_length > spec.repeat_stride
            and frame.length == spec.single_record_message_length - spec.repeat_stride
            and _frame_has_zero_context(frame, spec)
        ]
        if len(empty_matches) == 1:
            observations.add(_HydrationAnchor(frame.context.timestamp, frame_key))

    if not observations:
        return _InventoryGeneration(
            events=events,
            anchors=(),
            start=None,
            flow_generation_key=None,
            generations_observed=0,
        )

    ordered = sorted(
        observations,
        key=lambda item: (
            item.timestamp,
            item.frame_key.source_ip,
            item.frame_key.source_port,
            item.frame_key.destination_ip,
            item.frame_key.destination_port,
            item.frame_key.flow_generation,
            item.frame_key.stream_sequence is None,
            item.frame_key.stream_sequence or 0,
        ),
    )
    first = ordered[0]
    previous_generation_key = _anchor_flow_generation_key(first)
    generation_starts = [first.timestamp]
    generation_keys = [previous_generation_key]
    previous_timestamp = first.timestamp
    for observation in ordered[1:]:
        timestamp = observation.timestamp
        generation_key = _anchor_flow_generation_key(observation)
        if (
            timestamp - previous_timestamp > _INVENTORY_GENERATION_GAP_SECONDS
            or generation_key != previous_generation_key
        ):
            generation_starts.append(timestamp)
            generation_keys.append(generation_key)
        previous_timestamp = timestamp
        previous_generation_key = generation_key

    latest_start = generation_starts[-1]
    latest_key = generation_keys[-1]
    return _InventoryGeneration(
        events=tuple(
            event
            for event in events
            if event.timestamp >= latest_start
            and _event_flow_generation_key(event) == latest_key
        ),
        anchors=tuple(
            observation
            for observation in ordered
            if observation.timestamp >= latest_start
            and _anchor_flow_generation_key(observation) == latest_key
        ),
        start=latest_start,
        flow_generation_key=latest_key,
        generations_observed=len(generation_starts),
    )


def _character_storage_snapshot_fallback(
    frames: Iterable[BDOFrame],
    neutral_events: Iterable[BDOEvent],
    hydration_anchors: Iterable[_HydrationAnchor],
    specs: Iterable[EventSpec],
) -> tuple[tuple[BDOEvent, ...], tuple[_StorageGroupObservation, ...]]:
    """Prove a sparse storage hydration cohort inside the dedicated API.

    The general live classifier intentionally requires eight *populated*
    destinations so an uncorrelated worker batch cannot become a snapshot.
    Character-load capture additionally retains exact count-zero envelopes.
    Those envelopes can prove the same broad, tightly timed town sweep for an
    account with only a few populated storages without weakening live event
    filtering for every application.
    """

    frames = tuple(frames)
    neutral_events = tuple(neutral_events)
    hydration_anchors = tuple(hydration_anchors)
    if not hydration_anchors:
        return (), ()

    anchors: dict[tuple[str, int, str, int, int], float] = {}
    for hydration_anchor in hydration_anchors:
        key = _anchor_flow_generation_key(hydration_anchor)
        anchors[key] = max(
            anchors.get(key, hydration_anchor.timestamp),
            hydration_anchor.timestamp,
        )

    observations = _storage_group_observations(
        frames,
        neutral_events,
        specs,
        hydration_anchors=hydration_anchors,
    )
    by_stream: dict[
        tuple[str, int, str, int, int, int],
        list[_StorageGroupObservation],
    ] = {}
    for observation in observations:
        frame_key = observation.frame_key
        stream_key = (
            frame_key.source_ip,
            frame_key.source_port,
            frame_key.destination_ip,
            frame_key.destination_port,
            frame_key.flow_generation,
            observation.opcode,
        )
        by_stream.setdefault(stream_key, []).append(observation)

    candidates: list[tuple[_StorageGroupObservation, ...]] = []
    for stream_key, stream_observations in by_stream.items():
        anchor = anchors.get(stream_key[:5])
        if anchor is None:
            continue
        ordered = sorted(
            stream_observations,
            key=lambda observation: observation.timestamp,
        )
        burst: list[_StorageGroupObservation] = []

        def consider() -> None:
            if not burst:
                return
            distinct_destinations = {
                observation.storage_id
                for observation in burst
                if observation.storage_id > 0
            }
            if (
                len(distinct_destinations) >= _STORAGE_HYDRATION_MIN_DESTINATIONS
                and any(observation.empty for observation in burst)
                and anchor <= burst[0].timestamp
                and burst[-1].timestamp - anchor
                <= _STORAGE_HYDRATION_EPOCH_SECONDS
            ):
                candidates.append(tuple(burst))

        for observation in ordered:
            if burst and (
                observation.timestamp - burst[-1].timestamp
                > _STORAGE_HYDRATION_BURST_GAP_SECONDS
                or observation.timestamp - burst[0].timestamp
                > _STORAGE_HYDRATION_MAX_BURST_SECONDS
            ):
                consider()
                burst = []
            burst.append(observation)
        consider()

    if not candidates:
        return (), ()
    selected = max(candidates, key=lambda cohort: cohort[-1].timestamp)
    selected_records = {
        (observation.frame_key, observation.timestamp, observation.storage_id)
        for observation in selected
        if not observation.empty
    }
    promoted: list[BDOEvent] = []
    for event in neutral_events:
        if (
            _event_frame_key(event),
            event.timestamp,
            event.storage_id,
        ) not in selected_records:
            continue
        promoted.append(
            replace(
                event,
                event_type="storage_snapshot",
                source=None,
            )
        )
    return tuple(promoted), selected


def _reconcile_split_storage_hydration(
    frames: Iterable[BDOFrame],
    snapshot_events: Iterable[BDOEvent],
    neutral_events: Iterable[BDOEvent],
    live_boundaries: Iterable[BDOEvent],
    hydration_anchors: Iterable[_HydrationAnchor],
    specs: Iterable[EventSpec],
) -> tuple[
    tuple[BDOEvent, ...],
    tuple[_StorageGroupObservation, ...],
    int,
]:
    """Extend a proven snapshot sweep across harmless timing-burst splits.

    The continuous live classifier deliberately treats a timing gap as a
    fail-neutral boundary.  The dedicated character-state API has stronger
    evidence: a selected inventory hydration generation plus storage records
    that were already promoted by the live classifier.  Neutral records may
    join such a proven sweep only on the same flow generation and opcode, in
    the bounded inventory epoch, and without crossing a positive live
    mutation.  Repeated destinations remain separate sweeps through
    :func:`_infer_storage_sweeps`.
    """

    frames = tuple(frames)
    snapshot_events = tuple(snapshot_events)
    neutral_events = tuple(neutral_events)
    live_boundaries = tuple(live_boundaries)
    hydration_anchors = tuple(hydration_anchors)
    specs = tuple(specs)
    if not snapshot_events or not neutral_events or not hydration_anchors:
        return snapshot_events, (), 0

    anchors: dict[tuple[str, int, str, int, int], float] = {}
    for hydration_anchor in hydration_anchors:
        key = _anchor_flow_generation_key(hydration_anchor)
        anchors[key] = max(
            anchors.get(key, hydration_anchor.timestamp),
            hydration_anchor.timestamp,
        )

    confirmed_groups = {
        (_event_frame_key(event), event.timestamp, event.storage_id)
        for event in snapshot_events
        if event.storage_id is not None
    }
    observations = _storage_group_observations(
        frames,
        (*snapshot_events, *neutral_events),
        specs,
        hydration_anchors=hydration_anchors,
    )

    boundaries_by_flow: dict[
        tuple[str, int, str, int, int],
        list[tuple[float, bool, int]],
    ] = {}
    for event in live_boundaries:
        frame_key = _event_frame_key(event)
        boundaries_by_flow.setdefault(
            _event_flow_generation_key(event),
            [],
        ).append(
            (
                event.timestamp,
                frame_key.stream_sequence is None,
                frame_key.stream_sequence or 0,
            )
        )
    for boundaries in boundaries_by_flow.values():
        boundaries.sort()

    cohorts: dict[
        tuple[str, int, str, int, int, int, int],
        list[_StorageGroupObservation],
    ] = {}
    for observation in observations:
        frame_key = observation.frame_key
        flow_key = (
            frame_key.source_ip,
            frame_key.source_port,
            frame_key.destination_ip,
            frame_key.destination_port,
            frame_key.flow_generation,
        )
        anchor = anchors.get(flow_key)
        if (
            anchor is None
            or observation.timestamp < anchor
            or observation.timestamp - anchor > _STORAGE_HYDRATION_EPOCH_SECONDS
        ):
            continue
        order_key = (
            observation.timestamp,
            frame_key.stream_sequence is None,
            frame_key.stream_sequence or 0,
        )
        boundary_index = sum(
            boundary <= order_key
            for boundary in boundaries_by_flow.get(flow_key, ())
        )
        cohorts.setdefault(
            (*flow_key, observation.opcode, boundary_index),
            [],
        ).append(observation)

    eligible_groups: set[tuple[_FrameKey, float, int]] = set()
    for cohort in cohorts.values():
        for sweep in _infer_storage_sweeps(cohort):
            sweep_groups = {
                (group.frame_key, group.timestamp, group.storage_id)
                for block in sweep
                for group in block.groups
                if not group.empty
            }
            if sweep_groups & confirmed_groups:
                eligible_groups.update(sweep_groups)

    promoted: list[BDOEvent] = []
    for event in neutral_events:
        group_key = (
            _event_frame_key(event),
            event.timestamp,
            event.storage_id,
        )
        if (
            event.storage_id is None
            or group_key in confirmed_groups
            or group_key not in eligible_groups
        ):
            continue
        promoted.append(
            replace(
                event,
                event_type="storage_snapshot",
                source=None,
            )
        )

    if not promoted:
        return snapshot_events, (), 0

    reconciled = tuple(
        sorted(
            (*snapshot_events, *promoted),
            key=lambda event: (
                event.timestamp,
                event.flow.source_ip,
                event.flow.source_port,
                event.flow.destination_ip,
                event.flow.destination_port,
                _event_frame_key(event).flow_generation,
                _event_frame_key(event).stream_sequence is None,
                _event_frame_key(event).stream_sequence or 0,
                event.record_index or 0,
            ),
        )
    )
    reconciled_observations = _storage_group_observations(
        frames,
        reconciled,
        specs,
        hydration_anchors=hydration_anchors,
    )
    return reconciled, reconciled_observations, len(promoted)


def _storage_group_observations(
    frames: Iterable[BDOFrame],
    events: Iterable[BDOEvent],
    specs: Iterable[EventSpec],
    *,
    hydration_anchors: Iterable[_HydrationAnchor] = (),
) -> tuple[_StorageGroupObservation, ...]:
    """Merge record-bearing frames and empty wrappers into capture order."""
    frames = tuple(frames)
    events = tuple(events)
    event_groups: dict[tuple[_FrameKey, float, int], list[BDOEvent]] = {}
    for event in events:
        if event.storage_id is None:
            continue
        event_groups.setdefault(
            (_event_frame_key(event), event.timestamp, event.storage_id),
            [],
        ).append(event)

    observations: list[_StorageGroupObservation] = []
    for (frame_key, timestamp, storage_id), group in event_groups.items():
        items_by_instance: dict[str, SnapshotItem] = {}
        missing_instance_records = 0
        for event in group:
            instance = event.storage_instance
            if instance is None:
                missing_instance_records += 1
                continue
            items_by_instance[instance] = _snapshot_item(event, instance)
        observations.append(
            _StorageGroupObservation(
                storage_id=storage_id,
                frame_key=frame_key,
                timestamp=timestamp,
                opcode=group[0].opcode or 0,
                message_length=group[0].message_length,
                items=tuple(
                    sorted(
                        items_by_instance.values(),
                        key=lambda item: item.instance,
                    )
                ),
                raw_records=len(group),
                missing_instance_records=missing_instance_records,
                empty=False,
            )
        )

    empty_schemas, hydration_windows = _storage_empty_schemas(
        events,
        specs,
        frames=frames,
        hydration_anchors=hydration_anchors,
    )
    for frame in frames:
        matches: list[int] = []
        for schema in empty_schemas.get(frame.opcode, ()):
            candidate_storage_id = _empty_storage_envelope_id(
                frame,
                schema,
                hydration_windows,
            )
            if candidate_storage_id is not None:
                matches.append(candidate_storage_id)
        if len(matches) != 1:
            continue
        storage_id = matches[0]
        observations.append(
            _StorageGroupObservation(
                storage_id=storage_id,
                frame_key=_frame_key(frame),
                timestamp=frame.context.timestamp,
                opcode=frame.opcode,
                message_length=frame.length,
                items=(),
                raw_records=0,
                missing_instance_records=0,
                empty=True,
            )
        )

    observations.sort(
        key=lambda observation: (
            observation.timestamp,
            observation.frame_key.source_ip,
            observation.frame_key.source_port,
            observation.frame_key.destination_ip,
            observation.frame_key.destination_port,
            observation.frame_key.flow_generation,
            observation.frame_key.stream_sequence is None,
            observation.frame_key.stream_sequence or 0,
            observation.opcode,
            observation.storage_id,
            observation.empty,
        )
    )
    return tuple(observations)


def _infer_storage_sweeps(
    observations: Iterable[_StorageGroupObservation],
) -> tuple[tuple[_StorageDestinationBlock, ...], ...]:
    """Conservatively split ordered destination blocks into repeated sweeps.

    Tightly timed consecutive nonempty groups for one destination are record
    chunks and stay together. A state change or a gap beyond the observed
    chunk window closes the block even when the destination is unchanged.
    Once a closed destination appears again, that repeat begins a new sweep.
    """
    blocks: list[_StorageDestinationBlock] = []
    current_storage_id: Optional[int] = None
    current_stream_key: Optional[tuple[str, int, str, int, int, int]] = None
    current_groups: list[_StorageGroupObservation] = []
    current_empty: Optional[bool] = None

    def close_current() -> None:
        nonlocal current_storage_id, current_stream_key, current_groups, current_empty
        if (
            current_storage_id is not None
            and current_stream_key is not None
            and current_groups
        ):
            blocks.append(
                _StorageDestinationBlock(
                    storage_id=current_storage_id,
                    stream_key=current_stream_key,
                    groups=tuple(current_groups),
                )
            )
        current_storage_id = None
        current_stream_key = None
        current_groups = []
        current_empty = None

    for observation in observations:
        observation_stream_key = (
            observation.frame_key.source_ip,
            observation.frame_key.source_port,
            observation.frame_key.destination_ip,
            observation.frame_key.destination_port,
            observation.frame_key.flow_generation,
            observation.opcode,
        )
        previous_timestamp = current_groups[-1].timestamp if current_groups else None
        if current_storage_id is not None and (
            observation.storage_id != current_storage_id
            or observation_stream_key != current_stream_key
            or observation.empty != current_empty
            or (
                previous_timestamp is not None
                and observation.timestamp - previous_timestamp
                > _STORAGE_DESTINATION_CHUNK_GAP_SECONDS
            )
        ):
            close_current()
        if current_storage_id is None:
            current_storage_id = observation.storage_id
            current_stream_key = observation_stream_key
            current_empty = observation.empty
        current_groups.append(observation)
    close_current()

    sweeps: list[tuple[_StorageDestinationBlock, ...]] = []
    current_sweep: list[_StorageDestinationBlock] = []
    destinations_seen: set[int] = set()
    current_sweep_stream: Optional[tuple[str, int, str, int, int, int]] = None
    for block in blocks:
        if current_sweep and (
            block.storage_id in destinations_seen
            or block.stream_key != current_sweep_stream
        ):
            sweeps.append(tuple(current_sweep))
            current_sweep = []
            destinations_seen = set()
        if not current_sweep:
            current_sweep_stream = block.stream_key
        current_sweep.append(block)
        destinations_seen.add(block.storage_id)
    if current_sweep:
        sweeps.append(tuple(current_sweep))
    return tuple(sweeps)


def _anchored_empty_prefix_lengths(
    frames: Iterable[BDOFrame],
    events: Iterable[BDOEvent],
    spec: EventSpec,
    hydration_windows: dict[
        tuple[str, int, str, int, int, int],
        tuple[float, float],
    ],
) -> set[int]:
    """Infer an empty-wrapper length from a broad anchored town cohort.

    Older complete profiles may predate ``repeat_stride`` persistence. The
    dedicated character-load boundary still lets us prove a prefix without a
    patch table: exact count-zero wrappers at one length plus decoded nonempty
    records must form a tightly timed cohort spanning at least eight numeric
    destinations. Competing lengths fail closed.
    """

    count_offset = spec.record_count_offset
    destination_offset = spec.source_context_offset
    if count_offset is None or destination_offset is None:
        return set()

    empty_by_stream_and_length: dict[
        tuple[tuple[str, int, str, int, int, int], int],
        list[tuple[float, int, bool]],
    ] = {}
    for frame in frames:
        if frame.opcode != spec.opcode or frame.length > spec.item_offset:
            continue
        if max(count_offset + 2, destination_offset + 4) > len(frame.message):
            continue
        if int.from_bytes(frame.message[count_offset : count_offset + 2], "little"):
            continue
        storage_id = int.from_bytes(
            frame.message[destination_offset : destination_offset + 4],
            "little",
        )
        if storage_id == 0:
            continue
        stream_key = (
            frame.context.flow.source_ip,
            frame.context.flow.source_port,
            frame.context.flow.destination_ip,
            frame.context.flow.destination_port,
            frame.context.flow_generation,
            frame.opcode,
        )
        window = hydration_windows.get(stream_key)
        if window is None or not window[0] <= frame.context.timestamp <= window[1]:
            continue
        empty_by_stream_and_length.setdefault(
            (stream_key, frame.length),
            [],
        ).append((frame.context.timestamp, storage_id, True))

    nonempty_by_stream: dict[
        tuple[str, int, str, int, int, int],
        list[tuple[float, int, bool]],
    ] = {}
    for event in events:
        if event.opcode != spec.opcode or not event.storage_id:
            continue
        frame_key = _event_frame_key(event)
        stream_key = (
            event.flow.source_ip,
            event.flow.source_port,
            event.flow.destination_ip,
            event.flow.destination_port,
            frame_key.flow_generation,
            spec.opcode,
        )
        nonempty_by_stream.setdefault(stream_key, []).append(
            (event.timestamp, event.storage_id, False)
        )

    proven: set[int] = set()
    for (stream_key, prefix_length), empty_points in empty_by_stream_and_length.items():
        points = sorted(
            empty_points + nonempty_by_stream.get(stream_key, []),
            key=lambda point: point[0],
        )
        burst: list[tuple[float, int, bool]] = []

        def consider() -> None:
            if (
                burst
                and any(point[2] for point in burst)
                and len({point[1] for point in burst})
                >= _STORAGE_HYDRATION_MIN_DESTINATIONS
            ):
                proven.add(prefix_length)

        for point in points:
            if burst and (
                point[0] - burst[-1][0] > _STORAGE_HYDRATION_BURST_GAP_SECONDS
                or point[0] - burst[0][0] > _STORAGE_HYDRATION_MAX_BURST_SECONDS
            ):
                consider()
                burst = []
            burst.append(point)
        consider()
    return proven


def _storage_empty_schemas(
    events: Iterable[BDOEvent],
    specs: Iterable[EventSpec],
    *,
    frames: Iterable[BDOFrame] = (),
    hydration_anchors: Iterable[_HydrationAnchor] = (),
) -> tuple[
    dict[int, tuple[_StorageEmptySchema, ...]],
    dict[tuple[str, int, str, int, int, int], tuple[float, float]],
]:
    """Learn empty-wrapper geometry from profile authority and live records."""

    events = tuple(events)
    frames = tuple(frames)
    hydration_anchors = tuple(hydration_anchors)
    storage_specs = tuple(
        spec for spec in specs if spec.label == "INVENTORY_TO_STORAGE"
    )
    by_opcode = _spec_candidates_by_opcode(storage_specs)
    observed_strides: dict[EventSpec, set[int]] = {
        spec: set() for spec in storage_specs
    }
    windows: dict[tuple[str, int, str, int, int, int], tuple[float, float]] = {}
    groups: dict[tuple[_FrameKey, float, Optional[int]], list[BDOEvent]] = {}
    for event in events:
        groups.setdefault(
            (_event_frame_key(event), event.timestamp, event.opcode),
            [],
        ).append(event)
        if event.opcode is None:
            continue
        window_key = (
            event.flow.source_ip,
            event.flow.source_port,
            event.flow.destination_ip,
            event.flow.destination_port,
            _event_frame_key(event).flow_generation,
            event.opcode,
        )
        previous = windows.get(window_key)
        windows[window_key] = (
            event.timestamp if previous is None else min(previous[0], event.timestamp),
            event.timestamp if previous is None else max(previous[1], event.timestamp),
        )

    # The dedicated character-state API has a stronger semantic boundary than
    # the continuous event stream: a proven inventory hydration generation.
    # It may therefore retain exact count-zero storage envelopes even when an
    # account has too few populated towns to satisfy the live classifier's
    # conservative nonempty-destination threshold. The profile still supplies
    # the authoritative opcode, count column, destination column, and stride;
    # this only supplies the bounded time window in which those envelopes may
    # represent the same character-load cohort.
    for anchor in hydration_anchors:
        anchor_key = anchor.frame_key
        for spec in storage_specs:
            window_key = (
                anchor_key.source_ip,
                anchor_key.source_port,
                anchor_key.destination_ip,
                anchor_key.destination_port,
                anchor_key.flow_generation,
                spec.opcode,
            )
            start = anchor.timestamp
            end = anchor.timestamp + _STORAGE_HYDRATION_EPOCH_SECONDS
            previous = windows.get(window_key)
            windows[window_key] = (
                start if previous is None else min(previous[0], start),
                end if previous is None else max(previous[1], end),
            )

    for (_frame_key_value, _timestamp, opcode), group in groups.items():
        if opcode is None or len(group) < 2:
            continue
        offsets = sorted(
            event.record_offset
            for event in group
            if isinstance(event.record_offset, int)
            and not isinstance(event.record_offset, bool)
        )
        if len(offsets) != len(group):
            continue
        strides = {later - earlier for earlier, later in zip(offsets, offsets[1:])}
        if len(strides) != 1:
            continue
        stride = next(iter(strides))
        if stride <= 0:
            continue
        for spec in by_opcode.get(opcode, ()):
            base_length = spec.single_record_message_length
            if base_length is None or offsets[0] != spec.item_offset:
                continue
            message_lengths = {
                event.message_length
                for event in group
                if isinstance(event.message_length, int)
                and not isinstance(event.message_length, bool)
            }
            if len(message_lengths) != 1:
                continue
            message_length = next(iter(message_lengths))
            if message_length != base_length + (len(group) - 1) * stride:
                continue
            observed_strides[spec].add(stride)

    schemas_by_opcode: dict[int, list[_StorageEmptySchema]] = {}
    for spec in storage_specs:
        strides = observed_strides[spec]
        selected_stride: Optional[int] = None
        prefix_length: Optional[int] = None
        if len(strides) == 1:
            selected_stride = next(iter(strides))
        elif len(strides) > 1:
            # Conflicting same-capture record geometry is stronger evidence
            # of ambiguity than a coincidental count-zero cohort. Fail closed.
            continue
        elif spec.repeat_stride is not None:
            selected_stride = spec.repeat_stride
        else:
            # Only a profile with no record-stride authority may learn its
            # empty-envelope length from the dedicated character-load cohort.
            # A weaker cohort must never override observed or calibrated
            # repeated-record geometry.
            inferred_prefixes = _anchored_empty_prefix_lengths(
                frames,
                events,
                spec,
                windows,
            )
            if len(inferred_prefixes) != 1:
                continue
            prefix_length = next(iter(inferred_prefixes))
        base_length = spec.single_record_message_length
        count_offset = spec.record_count_offset
        destination_offset = spec.source_context_offset
        if (
            count_offset is None
            or destination_offset is None
        ):
            continue
        if prefix_length is None:
            if base_length is None or selected_stride is None:
                continue
            prefix_length = base_length - selected_stride
        if (
            prefix_length < 5
            or count_offset + 2 > prefix_length
            or destination_offset + 4 > prefix_length
            or prefix_length > spec.item_offset
        ):
            continue
        schemas_by_opcode.setdefault(spec.opcode, []).append(
            _StorageEmptySchema(spec=spec, prefix_length=prefix_length)
        )
    return (
        {opcode: tuple(schemas) for opcode, schemas in schemas_by_opcode.items()},
        windows,
    )


def _empty_storage_envelope_id(
    frame: BDOFrame,
    schema: _StorageEmptySchema,
    hydration_windows: dict[
        tuple[str, int, str, int, int, int],
        tuple[float, float],
    ],
) -> Optional[int]:
    """Return a town only from a learned, in-cohort count-zero envelope."""

    spec = schema.spec
    count_offset = spec.record_count_offset
    destination_offset = spec.source_context_offset
    if count_offset is None or destination_offset is None:
        return None
    if frame.length != schema.prefix_length or frame.length > spec.item_offset:
        return None
    if max(count_offset + 2, destination_offset + 4) > len(frame.message):
        return None
    if int.from_bytes(frame.message[count_offset : count_offset + 2], "little") != 0:
        return None
    window_key = (
        frame.context.flow.source_ip,
        frame.context.flow.source_port,
        frame.context.flow.destination_ip,
        frame.context.flow.destination_port,
        frame.context.flow_generation,
        frame.opcode,
    )
    window = hydration_windows.get(window_key)
    if window is None or not (
        window[0] - _STORAGE_EMPTY_WINDOW_MARGIN_SECONDS
        <= frame.context.timestamp
        <= window[1] + _STORAGE_EMPTY_WINDOW_MARGIN_SECONDS
    ):
        return None
    storage_id = int.from_bytes(
        frame.message[destination_offset : destination_offset + 4],
        "little",
    )
    # The calibrated column is authoritative even when a new town has not yet
    # been added to the display-name registry. Preserve its numeric identity so
    # coverage and decoder health can report the unresolved mapping instead of
    # silently dropping an otherwise proven empty destination.
    return storage_id or None


def _validate_item_state_identity_specs(specs: Iterable[EventSpec]) -> None:
    """Reject layouts that cannot prove complete character-state semantics."""
    missing: list[tuple[EventSpec, tuple[str, ...]]] = []
    for spec in specs:
        fields: list[str] = []
        if spec.label == "INVENTORY_TRANSFER":
            if spec.item_instance_offset is None:
                fields.append("item instance")
            if spec.source_context_offset is None:
                fields.append("snapshot context")
        elif spec.label == "INVENTORY_TO_STORAGE":
            if spec.storage_instance_offset is None:
                fields.append("storage instance")
            if spec.source_context_offset is None:
                fields.append("storage destination")
            if spec.record_count_offset is None:
                fields.append("record count")
        if fields:
            missing.append((spec, tuple(fields)))
    if not missing:
        return
    descriptions = ", ".join(
        f"{spec.label}(0x{spec.opcode:04X}: {', '.join(fields)})"
        for spec, fields in missing
    )
    raise ProfileError(
        "item-state snapshots require calibrated identity and wrapper authority; "
        f"missing geometry: {descriptions}. Recalibrate the active profile."
    )


def _active_profile_authority(
    opcode_profile: str | Path | OpcodeProfile,
) -> _ProfileAuthority:
    authority = _load_profile_authority(opcode_profile)
    _validate_item_state_identity_specs(authority.loaded_specs.specs)
    return authority


def analyze_character_load_pcap(
    path: str | Path,
    *,
    opcode_profile: str | Path | OpcodeProfile,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    capture_limits: Optional[ItemStateCaptureLimits] = None,
) -> CharacterStateSnapshot:
    """Replay a capture and summarize framed inventory/storage hydration."""
    options = PacketCaptureOptions(ports=ports)
    authority = _active_profile_authority(opcode_profile)
    profile_source = str(authority.profile.path)
    specs = authority.loaded_specs.specs
    accumulator = _CharacterStateAccumulator(
        profile_source=profile_source,
        specs=specs,
        capture_mode="pcap_replay",
        input_path=path,
        capture_limits=capture_limits,
    )
    collector = _EventCollector(
        server_ports=options.ports,
        event_filter=EventFilter(
            event_types={
                "inventory_snapshot",
                "storage_snapshot",
                "storage_record",
                "storage_delta",
            }
        ),
        on_event=accumulator.observe_event,
        frame_observer=accumulator.observe_frame,
        _profile_authority=authority,
    )
    for _ in iter_pcap_file(Path(path), collector.engine):
        pass
    collector.finalize()
    return accumulator.snapshot(decoder_health=collector.decoder_health)


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
        opcode_profile: str | Path | OpcodeProfile,
        capture_options: Optional[PacketCaptureOptions] = None,
        save_pcap: str | Path | None = None,
        capture_limits: Optional[ItemStateCaptureLimits] = None,
    ) -> None:
        if capture_options is not None and not isinstance(
            capture_options, PacketCaptureOptions
        ):
            raise TypeError("capture_options must be a PacketCaptureOptions or None")
        if capture_limits is not None and not isinstance(
            capture_limits, ItemStateCaptureLimits
        ):
            raise TypeError("capture_limits must be an ItemStateCaptureLimits or None")
        self._capture_options = capture_options or PacketCaptureOptions()
        self._capture_limits = capture_limits or ItemStateCaptureLimits()
        self._save_pcap_path = (
            _validate_save_pcap_path(save_pcap) if save_pcap is not None else None
        )
        self._profile_authority = _active_profile_authority(opcode_profile)
        self._profile_source = str(self._profile_authority.profile.path)
        self._specs = self._profile_authority.loaded_specs.specs
        self._start_attempted = False
        self._accumulator: Optional[_CharacterStateAccumulator] = None
        self._collector: Optional[_EventCollector] = None
        self._engine: Optional[PacketEngine] = None
        self._capture: Optional[LivePacketCapture] = None
        self._capture_writer: Any = None
        self._result: Optional[CharacterStateSnapshot] = None
        self._error: Optional[BaseException] = None

    @property
    def running(self) -> bool:
        capture = self._capture
        return capture is not None and capture.running

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether capture shutdown retained resources for a stop retry."""

        capture = self._capture
        return capture is not None and capture.cleanup_incomplete

    @property
    def frames_seen(self) -> int:
        return self._accumulator.frames_seen if self._accumulator is not None else 0

    @property
    def decoder_health(self) -> DecoderHealth:
        """Current storage-decoder compatibility for this capture."""

        if self._collector is not None:
            return self._collector.decoder_health
        if self._result is not None:
            return self._result.decoder_health
        return DecoderHealth()

    @property
    def error(self) -> Optional[BaseException]:
        """First background capture or decoder failure, if any."""
        if self._error is not None:
            return self._error
        capture = self._capture
        return capture.error if capture is not None else None

    @property
    def save_pcap_path(self) -> Optional[Path]:
        """Destination for opt-in raw live packets, if configured."""
        return self._save_pcap_path

    def start(self) -> None:
        """Begin passive capture and return once the adapter is ready.

        A session is single-use, including after a failed startup. Construct a
        new session to retry with a fresh writer, decoder, and capture handle.
        If startup reports incomplete cleanup, first call ``stop()`` on this
        session until the retained capture backend is verified stopped.
        """
        if self._start_attempted:
            raise RuntimeError(
                "character-load session is single-use and already started"
            )
        self._start_attempted = True
        self._error = None

        accumulator = _CharacterStateAccumulator(
            profile_source=self._profile_source,
            specs=self._specs,
            capture_mode="live_capture",
            saved_capture_path=self._save_pcap_path,
            capture_limits=self._capture_limits,
        )
        collector = _EventCollector(
            server_ports=self._capture_options.ports,
            event_filter=EventFilter(
                event_types={
                    "inventory_snapshot",
                    "storage_snapshot",
                    "storage_record",
                    "storage_delta",
                }
            ),
            on_event=accumulator.observe_event,
            frame_observer=accumulator.observe_frame,
            _profile_authority=self._profile_authority,
        )
        engine = collector.engine
        packet_handler = make_packet_handler(engine)
        capture_writer = None
        capture: Optional[LivePacketCapture] = None
        try:
            capture_writer = (
                _open_packet_writer(self._save_pcap_path)
                if self._save_pcap_path is not None
                else None
            )

            def handle_packet(packet: object) -> None:
                try:
                    # Persist the untouched packet before decoding so parser
                    # failures still retain the packet that exposed them.
                    if capture_writer is not None:
                        capture_writer.write(packet)
                    packet_handler(packet)
                except BaseException as exc:
                    self._record_error(exc)
                    raise

            capture = LivePacketCapture(
                capture_options=self._capture_options,
                on_packet=handle_packet,
                startup_timeout=_CHARACTER_LOAD_STARTUP_TIMEOUT_SECONDS,
            )
            self._accumulator = accumulator
            self._collector = collector
            self._engine = engine
            self._capture_writer = capture_writer
            self._capture = capture
            capture.start()
        except BaseException as exc:
            self._record_error(exc)
            if capture is not None and capture.cleanup_incomplete:
                # The backend may still invoke handle_packet(). Keep its
                # writer, engine, accumulator, and capture owner reachable so
                # stop() can safely retry before any dependent resource closes.
                _attach_cleanup_owner(
                    exc,
                    self,
                    context="character-load capture startup",
                )
                raise
            if capture_writer is not None:
                try:
                    capture_writer.close()
                except BaseException:
                    # Preserve the original startup failure.
                    pass
            self._capture = None
            self._capture_writer = None
            self._accumulator = None
            self._collector = None
            self._engine = None
            raise

    def stop(self) -> CharacterStateSnapshot:
        """Stop capture, finish reassembly, and return the queryable summary."""
        if self._result is not None:
            if self._error is not None:
                # A cached diagnostic snapshot must never turn a previously
                # failed run into an apparent success on a repeated stop().
                raise self._error
            return self._result
        if (
            self._capture is None
            or self._collector is None
            or self._engine is None
            or self._accumulator is None
        ):
            raise RuntimeError("character-load session was not started")
        capture = self._capture
        collector = self._collector
        engine = self._engine
        accumulator = self._accumulator
        capture_writer = self._capture_writer
        stop_failure: Optional[BaseException] = None
        try:
            capture.stop()
        except BaseException as exc:
            stop_failure = exc
            self._record_error(exc)
        if not capture.stopped:
            if stop_failure is None:
                stop_failure = capture.cleanup_error or RuntimeError(
                    "character-load capture cleanup is incomplete"
                )
                self._record_error(stop_failure)
            # The capture callback still owns the writer and decoder. Leave
            # every dependency intact for a later, verified stop attempt.
            raise stop_failure
        capture_error = capture.error
        if capture_error is not None:
            self._record_error(capture_error)
        try:
            engine.finish()
        except BaseException as exc:
            self._record_error(exc)
        try:
            collector.finalize()
        except BaseException as exc:
            self._record_error(exc)
        if capture_writer is not None:
            try:
                capture_writer.close()
            except BaseException as exc:
                self._record_error(exc)
        result: Optional[CharacterStateSnapshot] = None
        try:
            result = accumulator.snapshot(decoder_health=collector.decoder_health)
        except BaseException as exc:
            self._record_error(exc)
        self._capture = None
        self._capture_writer = None
        self._collector = None
        self._engine = None
        if result is not None:
            self._result = result
        if self._error is not None:
            raise self._error
        assert result is not None
        return result

    def _record_error(self, error: BaseException) -> None:
        if self._error is None:
            self._error = error

    def __enter__(self) -> "CharacterLoadSession":
        if not self._start_attempted:
            self.start()
        elif self._capture is None and self._result is None:
            raise RuntimeError(
                "character-load session is single-use and cannot be restarted"
            )
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._capture is not None:
            try:
                self.stop()
            except BaseException as cleanup_error:
                if exc_value is None:
                    raise
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc_value,
                        self,
                        context="character-load capture context",
                    )
                exc_value.add_note(
                    "character-load context cleanup also failed: "
                    f"{cleanup_error!r}"
                )


def format_character_state(
    snapshot: CharacterStateSnapshot,
    *,
    show_items: bool = False,
) -> str:
    """Render a stable, honest diagnostic summary for console tools."""
    diagnostics = snapshot.diagnostics
    frames_seen = diagnostics.frames_seen if diagnostics is not None else "unavailable"
    lines = [
        "CHARACTER LOAD SNAPSHOT DIAGNOSTIC",
        f"Profile: {snapshot.provenance.profile_source}",
        f"Generic BDO frames observed: {frames_seen}",
        (
            "Storage decoder: "
            f"{snapshot.decoder_health.storage_status} "
            f"({snapshot.decoder_health.storage_messages_decoded}/"
            f"{snapshot.decoder_health.storage_messages_observed} "
            "observed wrappers decoded)"
        ),
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
    inventory_diagnostics = diagnostics.inventory if diagnostics is not None else None
    if inventory.hydration_observed:
        lines.append(
            f"  {inventory.serialized_records} serialized records: "
            f"{inventory.occupied_stacks} occupied item stacks + "
            f"{inventory.currency_balance_records} currency balances"
        )
        if inventory_diagnostics is not None:
            lines.extend(
                [
                    (
                        f"  {inventory_diagnostics.groups} groups: "
                        f"{inventory_diagnostics.populated_groups} populated, "
                        f"{inventory_diagnostics.empty_groups} empty"
                    ),
                    "  group record counts: "
                    + ", ".join(
                        str(count) for count in inventory_diagnostics.group_counts
                    ),
                    "  inferred record strides: "
                    + (
                        ", ".join(
                            str(stride)
                            for stride in inventory_diagnostics.inferred_strides
                        )
                        if inventory_diagnostics.inferred_strides
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
        if inventory_diagnostics is not None and inventory_diagnostics.empty_groups:
            lines.append(
                f"  {inventory_diagnostics.empty_groups} empty wrappers: unclassified "
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
        if (
            inventory_diagnostics is not None
            and inventory_diagnostics.duplicate_records
        ):
            lines.append(
                "  repeated records merged by item instance: "
                f"{inventory_diagnostics.duplicate_records}"
            )
        if snapshot.coverage.inventory_records_missing_instance:
            lines.append(
                f"  identity-unresolved records excluded: "
                f"{snapshot.coverage.inventory_records_missing_instance}"
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
    storage_records_decoded = (
        diagnostics.storage.records_decoded
        if diagnostics is not None
        else None
    )
    if storage_records_decoded or snapshot.storages:
        missing_known_ids = snapshot.coverage.registered_storage_ids_not_observed
        earlier_only = tuple(
            storage
            for storage in snapshot.storages
            if not storage.current_state_observed
        )
        identity_incomplete = tuple(
            storage
            for storage in snapshot.storages
            if storage.current_state_observed
            and storage.current_identity_complete is False
        )
        if earlier_only or identity_incomplete:
            current_state_parts = [
                f"  {snapshot.storages.nonempty_count} non-empty",
                f"{snapshot.storages.empty_count} explicitly empty",
            ]
            if identity_incomplete:
                current_state_parts.append(
                    f"{len(identity_incomplete)} identity-incomplete"
                )
            if earlier_only:
                current_state_parts.append(
                    f"{len(earlier_only)} earlier-only (current state unavailable)"
                )
            current_state_parts.append(f"{len(missing_known_ids)} not observed")
            current_state_line = ", ".join(current_state_parts)
        else:
            current_state_line = (
                f"  {snapshot.storages.nonempty_count} non-empty, "
                f"{snapshot.storages.empty_count} explicitly empty, "
                f"{len(missing_known_ids)} not observed"
            )
        storage_item_line = (
            f"  {snapshot.storages.occupied_stacks} unique occupied item stacks"
        )
        if storage_records_decoded is not None:
            storage_item_line += (
                f" from {storage_records_decoded} decoded snapshot records"
            )
        lines.extend(
            [
                (
                    f"  {snapshot.storages.registered_count}/"
                    f"{len(STORAGE_LOCATIONS)} known destinations observed"
                ),
                current_state_line,
                storage_item_line,
                "  capacity: unavailable (not present in the decoded item wrappers)",
                "",
            ]
        )
        if diagnostics is not None and diagnostics.storage.sweeps_observed:
            lines.insert(
                len(lines) - 1,
                f"  selected inferred storage sweep "
                f"{diagnostics.storage.selected_sweep}/"
                f"{diagnostics.storage.sweeps_observed}",
            )
        if snapshot.coverage.storage_records_missing_instance:
            lines.insert(
                len(lines) - 1,
                f"  identity-unresolved records excluded: "
                f"{snapshot.coverage.storage_records_missing_instance}",
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
            if not storage.current_state_observed:
                lines.append(
                    f"  {label}: current state unavailable "
                    f"(observed only in an earlier inferred sweep)"
                )
                continue
            lines.append(
                f"  {label}: {storage.occupied_stacks} occupied item stacks detected"
            )
            storage_diagnostics = (
                diagnostics.storage.destination(storage.storage_id)
                if diagnostics is not None
                else None
            )
            if (
                storage_diagnostics is not None
                and storage_diagnostics.selected_missing_instance_records
            ):
                lines.append(
                    f"    identity-unresolved current records excluded: "
                    f"{storage_diagnostics.selected_missing_instance_records}"
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
