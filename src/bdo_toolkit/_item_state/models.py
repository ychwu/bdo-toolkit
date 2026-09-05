"""Public item-state models, queries, and serialization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .._protocol import STORAGE_LOCATIONS
from ..diagnostics import DecoderHealth

from ._constants import _INVENTORY_CONTAINER_LABELS, _ITEM_STATE_SCHEMA_VERSION


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
