"""Bounded observation accumulation and item-state snapshot assembly."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from threading import RLock
from typing import Any, Iterable, Optional

from .._engine import toolkit_event_from_record
from .._protocol import (
    BDOFrame,
    EventSpec,
    STORAGE_LOCATIONS,
)
from ..diagnostics import DecoderHealth
from ..events import BDOEvent

from ._records import (
    _FrameKey,
    _StorageGroupObservation,
    _event_flow_generation_key,
    _frame_flow_generation_key,
    _frame_key,
)
from .inventory import _assemble_inventory, _latest_inventory_generation
from .models import (
    CharacterStateSnapshot,
    ItemStateCaptureLimitError,
    ItemStateCaptureLimits,
    ItemStateCoverage,
    ItemStateDiagnostics,
    ItemStateProvenance,
    StorageContents,
    StorageHydrationDiagnostics,
)
from .storage import (
    _assemble_storage,
    _character_storage_snapshot_fallback,
    _reconcile_split_storage_hydration,
)


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

        inventory_assembly = _assemble_inventory(
            self.inventory_specs,
            frames,
            inventory_events,
            generations_observed=generations_seen,
        )
        inventory = inventory_assembly.summary
        storage_assembly = _assemble_storage(
            self.storage_specs,
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
