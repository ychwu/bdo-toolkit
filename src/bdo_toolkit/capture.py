"""Packet capture and pcap replay APIs."""

from __future__ import annotations

from collections import OrderedDict, deque
from contextvars import ContextVar
from dataclasses import dataclass
import math
import time
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, RLock, Thread, Timer, current_thread
from typing import Callable, Iterator, Optional

from ._capture_backend import (
    iter_pcap_file,
    make_packet_handler,
    validate_server_ports,
)
from ._capture_options import LiveCaptureOptions
from ._capture_runtime import (
    CaptureEndpoint,
    CaptureStats,
    LivePacketCapture,
    _attach_cleanup_owner,
    _capture_is_clean,
)
from ._deposit_origin import DecrementSpec, DepositOriginTracker
from ._engine import PacketEngine, toolkit_event_from_record
from ._profile_runtime import validate_runtime_profile
from ._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    DEFAULT_SERVER_PORTS,
    FlowKey,
    LootEvent,
    PacketContext,
)
from ._storage_destination_validation import StorageDestinationValidator
from ._storage_hydration import StorageHydrationTracker
from .diagnostics import DecoderDiagnostic, DecoderHealth
from ._specs import LoadedSpecProfile
from .events import BDOEvent, Flow
from .filters import EventFilter
from .origin_learning import CompanionObservation
from .profiles import (
    OpcodeProfile,
    OriginCompanionFamily,
    load_opcode_profile,
)


_PACKET_WORKER_STOP = object()
_TARGET_FRAME_HISTORY_LIMIT = 4096
_TargetFrameKey = tuple[FlowKey, int, Optional[int], float, int, int]
_INVENTORY_BOUNDARY_COHORT_LIMIT = 64
_InventoryBoundaryKey = tuple[FlowKey, int, int]


@dataclass
class _InventoryBoundaryState:
    """One fully decoded inventory wrapper awaiting boundary evidence."""

    frame_key: _TargetFrameKey
    stream_end: int
    raw_message: bytes
    records: list[LootEvent]
    accepted: bool


_ACTIVE_ORIGIN_SESSIONS: ContextVar[tuple[object, ...]] = ContextVar(
    "bdo_toolkit_active_origin_session",
    default=(),
)


class CaptureIntegrityError(RuntimeError):
    """Live acquisition lost data before the decoder could inspect it."""


@dataclass(frozen=True)
class LiveCaptureHealth:
    """Bounded-queue, TCP-reassembly, and native-capture diagnostics.

    A non-clean result means the event stream may be incomplete.  Queue
    overflow is fail-closed: the session records :class:`CaptureIntegrityError`
    and requests shutdown instead of silently continuing with missing packets.
    """

    packets_accepted: int = 0
    packet_queue_peak: int = 0
    packet_queue_overflows: int = 0
    event_queue_peak: int = 0
    tcp_gap_resets: int = 0
    flow_state_evictions: int = 0
    pcap_received: Optional[int] = None
    pcap_dropped: Optional[int] = None
    pcap_interface_dropped: Optional[int] = None
    capture_buffer_bytes: Optional[int] = None
    capture_buffer_fallback: bool = False

    @property
    def capture_is_clean(self) -> bool:
        """Whether known acquisition-loss indicators remained clear."""

        return _capture_is_clean(
            tcp_gap_resets=self.tcp_gap_resets,
            pcap_dropped=self.pcap_dropped,
            pcap_interface_dropped=self.pcap_interface_dropped,
            packet_queue_overflows=self.packet_queue_overflows,
            flow_state_evictions=self.flow_state_evictions,
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready diagnostic mapping."""

        result: dict[str, object] = {
            "packets_accepted": self.packets_accepted,
            "packet_queue_peak": self.packet_queue_peak,
            "packet_queue_overflows": self.packet_queue_overflows,
            "event_queue_peak": self.event_queue_peak,
            "tcp_gap_resets": self.tcp_gap_resets,
            "flow_state_evictions": self.flow_state_evictions,
            "capture_buffer_fallback": self.capture_buffer_fallback,
            "capture_is_clean": self.capture_is_clean,
        }
        optional = {
            "pcap_received": self.pcap_received,
            "pcap_dropped": self.pcap_dropped,
            "pcap_interface_dropped": self.pcap_interface_dropped,
            "capture_buffer_bytes": self.capture_buffer_bytes,
        }
        result.update(
            {key: value for key, value in optional.items() if value is not None}
        )
        return result


@dataclass(frozen=True)
class _ProfileAuthority:
    """One profile revision and its derived runtime decoder specifications."""

    profile: OpcodeProfile
    loaded_specs: LoadedSpecProfile
    decrement_specs: tuple[DecrementSpec, ...]


def _load_profile_authority(
    source: str | Path | OpcodeProfile,
) -> _ProfileAuthority:
    if isinstance(source, OpcodeProfile):
        profile = source
    else:
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError(f"Opcode profile does not exist: {path}")
        profile = load_opcode_profile(path)
    runtime = validate_runtime_profile(profile)
    return _ProfileAuthority(
        profile=profile,
        loaded_specs=runtime.loaded_specs,
        decrement_specs=runtime.decrement_specs,
    )


def _decrement_specs(
    profile: OpcodeProfile,
) -> tuple[DecrementSpec, ...]:
    """Compatibility shim for the shared fail-closed runtime validator."""

    return validate_runtime_profile(profile).decrement_specs


def _origin_companion_families(
    profile: OpcodeProfile,
) -> tuple[OriginCompanionFamily, ...]:
    return profile.origin_companion_families


def _needs_origin_tracking(
    event_filter: Optional[EventFilter],
    origin_observer: Optional[Callable[[CompanionObservation], object]],
) -> bool:
    if origin_observer is not None or event_filter is None:
        return True
    return event_filter.event_types is None or bool(
        event_filter.event_types
        & {"storage_delta", "storage_record", "storage_snapshot"}
    )


class _EventCollector:
    """Wire a PacketEngine to app-facing events with optional filtering.

    Live storage deltas and neutral storage records take a short detour through
    the deposit-origin tracker (a few frames of lookahead). Independent manual
    or worker evidence can promote an unfamiliar-mode ``storage_record`` to a
    confirmed-live ``storage_delta``; records without that evidence remain
    neutral. All other events emit immediately, which can place a deferred
    storage event slightly after later events of other types. Timestamps are
    unaffected.
    """

    def __init__(
        self,
        *,
        server_ports: tuple[int, ...],
        event_filter: Optional[EventFilter] = None,
        on_event: Optional[Callable[[BDOEvent], None]] = None,
        opcode_profile: str | Path | OpcodeProfile | None = None,
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
        frame_observer: Optional[Callable[[BDOFrame], object]] = None,
        on_diagnostic: Optional[Callable[[DecoderDiagnostic], object]] = None,
        preflight: bool = True,
        _profile_authority: Optional[_ProfileAuthority] = None,
    ) -> None:
        if _profile_authority is not None:
            if opcode_profile is not None:
                raise TypeError(
                    "provide opcode_profile or _profile_authority, not both"
                )
            authority = _profile_authority
        elif opcode_profile is not None:
            authority = _load_profile_authority(opcode_profile)
        else:
            raise TypeError("opcode_profile is required")
        profile = authority.profile
        loaded_specs = authority.loaded_specs
        self._events: deque[BDOEvent] = deque()
        self.event_filter = event_filter
        self.on_event = on_event
        self.on_diagnostic = on_diagnostic
        self.profile_source = f"{loaded_specs.source} active profile"
        self.event_specs = loaded_specs.specs
        self._diagnostic_lock = Lock()
        self._diagnostic_keys: set[tuple[str, Optional[int]]] = set()
        self._storage_messages_observed = 0
        self._storage_messages_decoded = 0
        self._storage_records_decoded = 0
        self._storage_destination_failures = 0
        self._storage_geometry_failures = 0
        self._diagnostics_emitted = 0
        self._storage_incompatible = False
        self._storage_destination_validator = StorageDestinationValidator()
        self._generic_storage_frames: set[_TargetFrameKey] = set()
        self._generic_storage_frame_order: deque[_TargetFrameKey] = deque()
        self._accepted_storage_frames: set[_TargetFrameKey] = set()
        self._accepted_storage_frame_order: deque[_TargetFrameKey] = deque()
        self._generic_inventory_frames: set[_TargetFrameKey] = set()
        self._generic_inventory_frame_order: deque[_TargetFrameKey] = deque()
        self._inventory_boundary_states: OrderedDict[
            _InventoryBoundaryKey, _InventoryBoundaryState
        ] = OrderedDict()
        self._storage_opcodes = frozenset(
            spec.opcode
            for spec in self.event_specs
            if spec.label == "INVENTORY_TO_STORAGE"
        )
        self._inventory_transfer_opcodes = frozenset(
            spec.opcode
            for spec in self.event_specs
            if spec.label == "INVENTORY_TRANSFER"
        )
        self._requested_storage_ids = tuple(
            sorted(event_filter.storage_ids)
            if event_filter is not None and event_filter.storage_ids is not None
            else ()
        )
        self._hydration = StorageHydrationTracker(self._deliver)
        self._tracker: Optional[DepositOriginTracker] = None
        if _needs_origin_tracking(event_filter, origin_observer):
            self._tracker = DepositOriginTracker(
                decrement_specs=authority.decrement_specs,
                emit=self._after_origin,
                origin_observer=origin_observer,
                known_companion_families=_origin_companion_families(profile),
                storage_delta_opcodes=(
                    spec.opcode
                    for spec in loaded_specs.specs
                    if spec.label == "INVENTORY_TO_STORAGE"
                ),
            )
        tracker = self._tracker
        observe_storage_messages = self._storage_is_requested() or tracker is not None

        def observe_frame(frame: BDOFrame) -> None:
            self._remember_generic_target_frame(frame)
            if tracker is not None:
                tracker.observe_frame(frame)
            if frame_observer is not None:
                frame_observer(frame)

        self.engine = PacketEngine(
            server_ports=server_ports,
            event_specs=loaded_specs.specs,
            on_event=self._handle_record,
            frame_observer=(
                observe_frame
                if tracker is not None
                or frame_observer is not None
                or self._storage_is_requested()
                or self._inventory_snapshot_is_requested()
                else None
            ),
            stream_observer=(tracker.observe_stream if tracker is not None else None),
            flow_close_observer=self._close_flow,
            message_observer=(
                self._observe_storage_message if observe_storage_messages else None
            ),
        )
        self._preflight_done = False
        if preflight:
            self.preflight()

    def _handle_record(self, record: LootEvent, raw_message: bytes) -> None:
        is_storage = record.label == "INVENTORY_TO_STORAGE"
        is_inventory_snapshot = (
            record.label == "INVENTORY_TRANSFER"
            and record.source_context_candidate == CHARACTER_LOAD_CONTEXT
        )
        if is_storage:
            frame_key = (
                record.context.flow,
                record.context.flow_generation,
                record.stream_sequence,
                record.context.timestamp,
                record.opcode,
                record.message_length,
            )
            with self._diagnostic_lock:
                if frame_key not in self._accepted_storage_frames:
                    # Target-signature recovery may find a valid-looking
                    # storage wrapper inside another BDO frame. Only a
                    # decoder candidate that also matched the generic
                    # top-level boundary may enter origin/hydration/event state.
                    return
        if is_inventory_snapshot:
            for accepted_record, accepted_message in self._inventory_records_ready(
                record,
                raw_message,
            ):
                self._handle_accepted_record(accepted_record, accepted_message)
            return
        self._handle_accepted_record(record, raw_message)

    def _handle_accepted_record(
        self,
        record: LootEvent,
        raw_message: bytes,
    ) -> None:
        """Normalize and classify one record with proven message boundaries."""

        is_storage = record.label == "INVENTORY_TO_STORAGE"
        if is_storage:
            self._revalidate_storage_destination(record, raw_message)
        event = toolkit_event_from_record(record)
        if is_storage:
            with self._diagnostic_lock:
                self._storage_records_decoded += 1
                missing_destination = event.storage_id is None
                unrecognized_destination = (
                    event.storage_id is not None and event.storage_name is None
                )
                if missing_destination or unrecognized_destination:
                    self._storage_destination_failures += 1
                    self._storage_incompatible = True
            if missing_destination:
                self._emit_diagnostic(
                    code="storage_destination_unavailable",
                    opcode=event.opcode,
                    message=(
                        "A storage wrapper decoded, but its destination field "
                        "did not resolve to a registered town. Recalibrate the "
                        "inventory-to-storage action; storage-ID-filtered events "
                        "may otherwise be omitted."
                    ),
                )
            elif unrecognized_destination:
                self._emit_diagnostic(
                    code="storage_destination_unrecognized",
                    opcode=event.opcode,
                    message=(
                        f"The calibrated storage destination field decoded ID "
                        f"0x{event.storage_id:08X}, but that key is not in the "
                        "town registry. Its numeric identity was preserved and "
                        "no display name is registered for it. Update the "
                        "registry before relying on destination display metadata."
                    ),
                )
        if event.event_type == "inventory_snapshot":
            self._hydration.observe_inventory(event)
        elif (
            self._tracker is not None
            and event.event_type in {"storage_delta", "storage_record"}
        ):
            # Filtering happens at delivery, AFTER classification, so filters
            # on event_type/source see any evidence-based promotion and the
            # final semantic source verdict.
            self._tracker.register(event, raw_message=raw_message)
        elif event.event_type in {"storage_delta", "storage_record"}:
            self._hydration.observe_storage(event)
        else:
            self._deliver(event)

    def _inventory_records_ready(
        self,
        record: LootEvent,
        raw_message: bytes,
    ) -> tuple[tuple[LootEvent, bytes], ...]:
        """Require a top-level frame or an exact adjacent target-wrapper pair.

        The generic scanner can remain synchronized to a false outer-frame
        chain after capture begins midstream. Two fully decoded inventory
        wrappers that are exactly adjacent in one TCP generation recover that
        historical case without restoring the unsafe "any nested signature"
        rule. A lone unframed wrapper is retained only until another wrapper
        proves adjacency; flow close/finalization discard it.
        """

        stream_sequence = record.stream_sequence
        frame_key: _TargetFrameKey = (
            record.context.flow,
            record.context.flow_generation,
            stream_sequence,
            record.context.timestamp,
            record.opcode,
            record.message_length,
        )
        with self._diagnostic_lock:
            top_level = frame_key in self._generic_inventory_frames
            if stream_sequence is None:
                return ((record, raw_message),) if top_level else ()

            boundary_key: _InventoryBoundaryKey = (
                record.context.flow,
                record.context.flow_generation,
                record.opcode,
            )
            state = self._inventory_boundary_states.pop(boundary_key, None)
            ready: tuple[tuple[LootEvent, bytes], ...]

            if state is not None and state.frame_key == frame_key:
                if state.accepted:
                    ready = ((record, raw_message),)
                elif top_level:
                    ready = tuple(
                        (pending, state.raw_message) for pending in state.records
                    ) + ((record, raw_message),)
                    state.records.clear()
                    state.accepted = True
                else:
                    state.records.append(record)
                    ready = ()
                self._inventory_boundary_states[boundary_key] = state
                return ready

            if state is not None and state.stream_end == stream_sequence:
                ready = (
                    tuple((pending, state.raw_message) for pending in state.records)
                    + ((record, raw_message),)
                )
                accepted = True
            elif top_level:
                ready = ((record, raw_message),)
                accepted = True
            else:
                ready = ()
                accepted = False

            self._inventory_boundary_states[boundary_key] = _InventoryBoundaryState(
                frame_key=frame_key,
                stream_end=(stream_sequence + record.message_length) & 0xFFFFFFFF,
                raw_message=raw_message,
                records=[] if accepted else [record],
                accepted=accepted,
            )
            while (
                len(self._inventory_boundary_states)
                > _INVENTORY_BOUNDARY_COHORT_LIMIT
            ):
                self._inventory_boundary_states.popitem(last=False)
            return ready

    def _after_origin(self, event: BDOEvent) -> None:
        """Give independent live evidence precedence over hydration inference."""

        self._hydration.observe_storage(event)

    def _revalidate_storage_destination(
        self,
        record: LootEvent,
        raw_message: bytes,
    ) -> None:
        """Warn when cross-wrapper evidence disproves the profile's column."""

        first_item_offset = record.record_offset
        if first_item_offset is None:
            return
        matching_specs = tuple(
            spec
            for spec in self.event_specs
            if spec.label == "INVENTORY_TO_STORAGE"
            and spec.opcode == record.opcode
            and spec.item_offset == first_item_offset
        )
        # Only record one lands at the configured item offset.  Multiple
        # matching layouts would not identify which spec the scanner selected,
        # so ambiguous profile state remains fail-neutral here.
        if len(matching_specs) != 1:
            return
        spec = matching_specs[0]
        mismatch = self._storage_destination_validator.observe(
            flow=record.context.flow,
            flow_generation=record.context.flow_generation,
            opcode=record.opcode,
            message=raw_message,
            first_item_offset=first_item_offset,
            configured_offset=spec.source_context_offset,
        )
        if mismatch is None:
            return
        with self._diagnostic_lock:
            self._storage_incompatible = True
        self._emit_diagnostic(
            code="storage_destination_schema_mismatch",
            opcode=record.opcode,
            message=(
                f"Cross-wrapper evidence from {mismatch.wrapper_count} storage "
                f"wrappers and {mismatch.distinct_destinations} registered "
                f"destinations uniquely proves the destination field at byte "
                f"{mismatch.observed_offset}, but the active profile uses byte "
                f"{mismatch.configured_offset}. Events were not relabeled; "
                "recalibrate before relying on storage names or storage-ID filters."
            ),
        )

    def _close_flow(self, flow: FlowKey) -> None:
        # Origin finalization may emit neutral records into the hydration
        # tracker. Close that tracker only after those records arrive.
        if self._tracker is not None:
            self._tracker.close_flow(flow)
        self._storage_destination_validator.close_flow(flow)
        with self._diagnostic_lock:
            for key in tuple(self._inventory_boundary_states):
                if key[0] == flow:
                    del self._inventory_boundary_states[key]
        self._hydration.close_flow(
            Flow(
                source_ip=flow.source_ip,
                source_port=flow.source_port,
                destination_ip=flow.destination_ip,
                destination_port=flow.destination_port,
            )
        )

    def _deliver(self, event: BDOEvent) -> None:
        if self.event_filter is not None and not self.event_filter.allows(event):
            return
        if self.on_event is not None:
            self.on_event(event)
        else:
            self._events.append(event)

    @property
    def decoder_health(self) -> DecoderHealth:
        with self._diagnostic_lock:
            status = (
                "incompatible"
                if self._storage_incompatible
                else "compatible"
                if self._storage_messages_decoded
                else "not_observed"
            )
            return DecoderHealth(
                storage_status=status,
                storage_messages_observed=self._storage_messages_observed,
                storage_messages_decoded=self._storage_messages_decoded,
                storage_records_decoded=self._storage_records_decoded,
                storage_destination_failures=self._storage_destination_failures,
                storage_geometry_failures=self._storage_geometry_failures,
                diagnostics_emitted=self._diagnostics_emitted,
            )

    def _storage_is_requested(self) -> bool:
        if self.event_filter is None or self.event_filter.event_types is None:
            return True
        return bool(
            self.event_filter.event_types
            & {"storage_delta", "storage_record", "storage_snapshot"}
        )

    def _inventory_snapshot_is_requested(self) -> bool:
        if self.event_filter is None or self.event_filter.event_types is None:
            return True
        return "inventory_snapshot" in self.event_filter.event_types

    def preflight(self) -> None:
        """Emit profile-level compatibility diagnostics exactly once."""

        with self._diagnostic_lock:
            if self._preflight_done:
                return
            self._preflight_done = True
        self._preflight_storage_profile()

    def _preflight_storage_profile(self) -> None:
        if not self._storage_is_requested():
            return
        storage_specs = tuple(
            spec
            for spec in self.event_specs
            if spec.label == "INVENTORY_TO_STORAGE"
        )
        if not storage_specs:
            with self._diagnostic_lock:
                self._storage_incompatible = True
            self._emit_diagnostic(
                code="storage_decoder_incompatible",
                opcode=None,
                message=(
                    "The active opcode profile has no storage decoder. "
                    "Run inventory-to-storage calibration before relying on "
                    "storage events or storage-ID filters."
                ),
            )
            return
        for spec in storage_specs:
            missing = []
            if (
                spec.source_context_offset is None
                or spec.source_context_length != 4
            ):
                missing.append("destination field")
            if spec.record_count_offset is None:
                missing.append("record-count field")
            if spec.storage_instance_offset is None:
                missing.append("storage-instance field")
            if spec.single_record_message_length is None:
                missing.append("single-record length")
            if not missing:
                continue
            with self._diagnostic_lock:
                self._storage_incompatible = True
            self._emit_diagnostic(
                code="storage_decoder_incompatible",
                opcode=spec.opcode,
                message=(
                    "The active storage profile is missing its calibrated "
                    f"{' and '.join(missing)}. Recalibrate with two validated "
                    "record counts (for example a single and an unstackable "
                    "multi-record deposit) before relying on storage events "
                    "or storage-ID filters."
                ),
            )

    def _observe_storage_message(
        self,
        opcode: int,
        message_length: int,
        status: str,
        record_count: int,
        context: PacketContext,
        stream_sequence: Optional[int],
    ) -> None:
        del record_count
        frame_key = (
            context.flow,
            context.flow_generation,
            stream_sequence,
            context.timestamp,
            opcode,
            message_length,
        )
        rejected = status != "decoded"
        with self._diagnostic_lock:
            if frame_key not in self._generic_storage_frames:
                return
            self._storage_messages_observed += 1
            if rejected:
                self._storage_geometry_failures += 1
                # The target scanner reports only a complete candidate that
                # exactly matches a generic top-level frame boundary; nested
                # signatures and uniquely valid same-opcode families are
                # excluded before this callback. One rejected storage wrapper
                # is therefore enough to tell a production app that its active
                # profile is incompatible with observed traffic.
                self._storage_incompatible = True
            else:
                self._storage_messages_decoded += 1
                if frame_key not in self._accepted_storage_frames:
                    self._accepted_storage_frames.add(frame_key)
                    self._accepted_storage_frame_order.append(frame_key)
                    while (
                        len(self._accepted_storage_frame_order)
                        > _TARGET_FRAME_HISTORY_LIMIT
                    ):
                        expired = self._accepted_storage_frame_order.popleft()
                        self._accepted_storage_frames.discard(expired)
        if rejected:
            self._emit_diagnostic(
                code="storage_decoder_incompatible",
                opcode=opcode,
                message=(
                    f"Observed storage opcode 0x{opcode:04X} with length "
                    f"{message_length}, but its calibrated count and record "
                    "geometry did not validate. Recalibrate; if the warning "
                    "persists, retain a diagnostic PCAP for decoder review."
                ),
            )

    def _remember_generic_target_frame(self, frame: BDOFrame) -> None:
        is_storage = frame.opcode in self._storage_opcodes
        is_inventory = frame.opcode in self._inventory_transfer_opcodes
        if not is_storage and not is_inventory:
            return
        key = (
            frame.context.flow,
            frame.context.flow_generation,
            frame.stream_sequence,
            frame.context.timestamp,
            frame.opcode,
            frame.length,
        )
        with self._diagnostic_lock:
            if is_storage and key not in self._generic_storage_frames:
                self._generic_storage_frames.add(key)
                self._generic_storage_frame_order.append(key)
                while (
                    len(self._generic_storage_frame_order)
                    > _TARGET_FRAME_HISTORY_LIMIT
                ):
                    expired = self._generic_storage_frame_order.popleft()
                    self._generic_storage_frames.discard(expired)
            if is_inventory and key not in self._generic_inventory_frames:
                self._generic_inventory_frames.add(key)
                self._generic_inventory_frame_order.append(key)
                while (
                    len(self._generic_inventory_frame_order)
                    > _TARGET_FRAME_HISTORY_LIMIT
                ):
                    expired = self._generic_inventory_frame_order.popleft()
                    self._generic_inventory_frames.discard(expired)

    def _emit_diagnostic(
        self,
        *,
        code: str,
        opcode: Optional[int],
        message: str,
    ) -> None:
        key = (code, opcode)
        with self._diagnostic_lock:
            if key in self._diagnostic_keys:
                return
            self._diagnostic_keys.add(key)
            self._diagnostics_emitted += 1
        callback = self.on_diagnostic
        if callback is not None:
            callback(
                DecoderDiagnostic(
                    code=code,
                    message=message,
                    opcode=opcode,
                    requested_storage_ids=self._requested_storage_ids,
                )
            )

    def drain_events(self) -> Iterator[BDOEvent]:
        """Yield and remove all currently delivered events."""
        while self._events:
            yield self._events.popleft()

    def flush_stale(self, now: float) -> None:
        if self._tracker is not None:
            self._tracker.flush_stale(now)
        self._hydration.flush_stale(now)

    def finalize(self) -> None:
        with self._diagnostic_lock:
            self._inventory_boundary_states.clear()
        if self._tracker is not None:
            self._tracker.finalize_all()
        self._hydration.finalize_all()


def replay_pcap(
    path: str | Path,
    *,
    opcode_profile: str | Path | OpcodeProfile,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    event_filter: Optional[EventFilter] = None,
    origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
    on_diagnostic: Optional[Callable[[DecoderDiagnostic], object]] = None,
) -> Iterator[BDOEvent]:
    """Replay a pcap/pcapng file and yield structured events.

    ``event_filter=None`` preserves the complete decoded replay stream. Live
    capture has a narrower activity-only default because hydration can contain
    thousands of state records.
    """

    if event_filter is not None and not isinstance(event_filter, EventFilter):
        raise TypeError("event_filter must be an EventFilter or None")
    validated_ports = validate_server_ports(ports)
    collector = _EventCollector(
        server_ports=validated_ports,
        event_filter=event_filter,
        opcode_profile=opcode_profile,
        origin_observer=origin_observer,
        on_diagnostic=on_diagnostic,
    )
    for _ in iter_pcap_file(Path(path), collector.engine):
        yield from collector.drain_events()
    collector.finalize()
    yield from collector.drain_events()


class LiveCaptureSession:
    """Controllable live capture for applications and long-running services.

    ``start()`` begins capture in Scapy's background thread.  Consume events
    with the blocking ``events()`` iterator or the timeout-aware ``poll()``
    method, and call ``stop()`` from the UI/control thread to wake consumers,
    finish TCP reassembly, and finalize pending deposit-origin decisions.

    A session is single-use and supports one event consumer. Create a new
    session when a stopped feature is started again. With ``event_filter=None``
    the session delivers :meth:`EventFilter.activity` events. Pass an explicit
    filter, including ``EventFilter.all()``, to select different semantics.
    """

    _POLL_INTERVAL_SECONDS = 0.2
    _DECODER_STOP_TIMEOUT_SECONDS = 5.0

    def __init__(
        self,
        *,
        opcode_profile: str | Path | OpcodeProfile,
        live_options: Optional[LiveCaptureOptions] = None,
        event_filter: Optional[EventFilter] = None,
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
        on_diagnostic: Optional[Callable[[DecoderDiagnostic], object]] = None,
    ) -> None:
        if live_options is not None and not isinstance(live_options, LiveCaptureOptions):
            raise TypeError("live_options must be a LiveCaptureOptions or None")
        if event_filter is not None and not isinstance(event_filter, EventFilter):
            raise TypeError("event_filter must be an EventFilter or None")
        resolved_live_options = live_options or LiveCaptureOptions()

        self._opcode_profile = opcode_profile
        self._live_options = resolved_live_options
        self._event_filter = (
            event_filter if event_filter is not None else EventFilter.activity()
        )
        self._origin_observer = origin_observer
        self._on_diagnostic = on_diagnostic

        self._queue: Queue[BDOEvent] = Queue(
            maxsize=resolved_live_options.event_queue_size
        )
        self._packet_queue: Queue[object] = Queue(
            maxsize=resolved_live_options.packet_queue_size
        )
        self._tail_events: deque[BDOEvent] = deque()
        self._tail_lock = Lock()
        self._delivery_lock = RLock()
        self._decoder_lock = Lock()
        self._state_lock = Lock()
        self._cleanup_lock = RLock()
        self._stop_requested = Event()
        self._finalizing = Event()
        self._stopped = Event()
        self._started = False
        self._capture: Optional[LivePacketCapture] = None
        self._collector: Optional[_EventCollector] = None
        self._packet_handler: Optional[Callable[[object], None]] = None
        self._packet_worker: Optional[Thread] = None
        self._packet_worker_stop_signaled = False
        self._stop_monitor: Optional[Thread] = None
        self._error: Optional[BaseException] = None
        self._stop_reason: Optional[str] = None
        self._capture_stats = CaptureStats()
        self._packets_accepted = 0
        self._packet_queue_peak = 0
        self._packet_queue_overflows = 0
        self._event_queue_peak = 0
        self._cleanup_incomplete = False

    @property
    def running(self) -> bool:
        capture = self._capture
        return (
            self._started
            and not self._stopped.is_set()
            and capture is not None
            and capture.running
        )

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether a failed stop retained pipeline ownership for retry."""

        capture = self._capture
        with self._state_lock:
            pipeline_incomplete = self._cleanup_incomplete
        return pipeline_incomplete or (
            capture is not None and capture.cleanup_incomplete
        )

    @property
    def stop_reason(self) -> Optional[str]:
        """Why capture ended: requested, capture-ended, or error."""
        with self._state_lock:
            return self._stop_reason

    @property
    def error(self) -> Optional[BaseException]:
        """First decoder, observer, or cleanup exception, if one occurred."""
        with self._state_lock:
            return self._error

    @property
    def endpoint(self) -> Optional[CaptureEndpoint]:
        """Resolved interface, local address, and packet filter after start."""

        capture = self._capture
        return capture.endpoint if capture is not None else None

    @property
    def health(self) -> LiveCaptureHealth:
        """Return an immutable, observational integrity snapshot.

        Active counter families may be sampled at adjacent instants. Sampling
        does not acquire structural TCP-reassembly ownership.
        """

        capture = self._capture
        stats = self._capture_stats
        if capture is not None and not capture.stopped:
            # Reading native counters is best-effort and must never turn a
            # diagnostic property into a capture failure.
            try:
                stats = capture.snapshot_stats()
            except BaseException:
                stats = capture.stats
        collector = self._collector
        engine = collector.engine if collector is not None else None
        tcp_gap_resets = int(getattr(engine, "tcp_gap_resets", 0))
        flow_state_evictions = int(getattr(engine, "flow_state_evictions", 0))
        pcap_received = stats.received
        pcap_dropped = stats.dropped
        pcap_interface_dropped = stats.interface_dropped
        capture_buffer_bytes = stats.capture_buffer_bytes
        capture_buffer_fallback = (
            capture is not None and capture.buffer_error is not None
        )
        with self._state_lock:
            packets_accepted = self._packets_accepted
            packet_queue_peak = self._packet_queue_peak
            packet_queue_overflows = self._packet_queue_overflows
            event_queue_peak = self._event_queue_peak
        return LiveCaptureHealth(
            packets_accepted=packets_accepted,
            packet_queue_peak=packet_queue_peak,
            packet_queue_overflows=packet_queue_overflows,
            event_queue_peak=event_queue_peak,
            tcp_gap_resets=tcp_gap_resets,
            flow_state_evictions=flow_state_evictions,
            pcap_received=pcap_received,
            pcap_dropped=pcap_dropped,
            pcap_interface_dropped=pcap_interface_dropped,
            capture_buffer_bytes=capture_buffer_bytes,
            capture_buffer_fallback=capture_buffer_fallback,
        )

    @property
    def decoder_health(self) -> DecoderHealth:
        """Protocol compatibility, independent of packet-capture integrity."""

        collector = self._collector
        return collector.decoder_health if collector is not None else DecoderHealth()

    def start(self) -> None:
        """Open capture and hand packets to a bounded decoder worker."""
        with self._cleanup_lock:
            if self._started:
                raise RuntimeError("live capture session was already started")
            collector = _EventCollector(
                server_ports=self._live_options.ports,
                event_filter=self._event_filter,
                on_event=self._enqueue,
                opcode_profile=self._opcode_profile,
                origin_observer=(
                    self._notify_origin_observer
                    if self._origin_observer is not None
                    else None
                ),
                on_diagnostic=(
                    self._notify_diagnostic
                    if self._on_diagnostic is not None
                    else None
                ),
                preflight=False,
            )

            packet_handler = make_packet_handler(collector.engine)
            live_capture = LivePacketCapture(
                capture_options=self._live_options,
                # This callback deliberately performs only one non-blocking
                # queue handoff. Protocol decode and event backpressure live
                # on the worker below, not Scapy's native capture thread.
                on_packet=self._enqueue_packet,
            )
            worker = Thread(
                target=self._run_packet_worker,
                name="bdo-toolkit-items",
                daemon=True,
            )
            self._collector = collector
            self._capture = live_capture
            self._packet_handler = packet_handler
            self._packet_worker = worker
            with self._state_lock:
                self._started = True
                self._stopped.clear()
                self._stop_requested.clear()
                self._finalizing.clear()
            capture_started = False
            try:
                worker.start()
                live_capture.start()
                capture_started = True
                # The session is now fully addressable, so a startup diagnostic
                # callback may safely call request_stop(). stop()/poll() remain
                # rejected by the shared decoder-callback guard.
                preflight = getattr(collector, "preflight", None)
                if preflight is not None:
                    preflight()

                monitor = Thread(
                    target=self._monitor_stop_request,
                    name="bdo-toolkit-items-stop",
                    daemon=True,
                )
                self._stop_monitor = monitor
                monitor.start()
            except BaseException as exc:
                self._rollback_failed_start(
                    exc,
                    capture_started=capture_started,
                )
                raise

    def _rollback_failed_start(
        self,
        error: BaseException,
        *,
        capture_started: bool,
    ) -> None:
        """Release every successfully started owner after startup fails.

        This helper runs while ``_cleanup_lock`` is held. A failed auxiliary
        ``Thread.start()`` is just as transactional as a native startup
        failure: verified cleanup restores the pre-start state; anything that
        cannot be verified remains attached to the original exception for a
        same-session ``stop()`` retry.
        """

        self._finalizing.set()
        self._stop_requested.set()
        capture = self._capture
        cleanup_failures: list[BaseException] = []

        if capture_started and capture is not None and not capture.stopped:
            try:
                self._capture_stats = capture.stop()
            except BaseException as stop_error:
                cleanup_failures.append(stop_error)

        capture_incomplete = capture is not None and (
            capture.cleanup_incomplete
            or (capture_started and not capture.stopped)
        )
        worker = self._packet_worker
        worker_alive = worker is not None and worker.is_alive()

        # A native callback may still race with this session until capture
        # termination is verified. Keep the decoder alive in that case; the
        # stop request makes every later native callback a no-op.
        if not capture_incomplete:
            decoder_deadline = (
                time.monotonic() + self._DECODER_STOP_TIMEOUT_SECONDS
            )
            self._signal_packet_worker_stop(decoder_deadline)
            if (
                worker_alive
                and worker is not None
                and worker is not current_thread()
            ):
                worker.join(
                    timeout=max(0.0, decoder_deadline - time.monotonic())
                )
            worker_alive = worker is not None and worker.is_alive()

        if capture_incomplete or worker_alive:
            self._record_error(error)
            with self._state_lock:
                self._cleanup_incomplete = True
            for failure in cleanup_failures:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "live item capture startup cleanup also failed: "
                        f"{failure!r}"
                    )
            _attach_cleanup_owner(
                error,
                self,
                context="live item capture startup",
            )
            return

        for failure in cleanup_failures:
            if hasattr(error, "add_note"):
                error.add_note(
                    "live item capture startup cleanup reported a fully "
                    f"released error: {failure!r}"
                )
        self._reset_after_failed_start()

    def _reset_after_failed_start(self) -> None:
        """Restore reusable pre-start state after verified rollback."""

        self._collector = None
        self._capture = None
        self._packet_handler = None
        self._packet_worker = None
        self._packet_worker_stop_signaled = False
        self._stop_monitor = None
        self._capture_stats = CaptureStats()
        while True:
            try:
                self._packet_queue.get_nowait()
            except Empty:
                break
        while True:
            try:
                self._queue.get_nowait()
            except Empty:
                break
        with self._tail_lock:
            self._tail_events.clear()
        with self._state_lock:
            self._started = False
            self._error = None
            self._stop_reason = None
            self._cleanup_incomplete = False
            self._packets_accepted = 0
            self._packet_queue_peak = 0
            self._packet_queue_overflows = 0
            self._event_queue_peak = 0
            # Atomic with _started=False so an old request_stop() either wins
            # before rollback and is cleared here, or observes not-started.
            self._stopped.clear()
            self._stop_requested.clear()
            self._finalizing.clear()

    def stop(self) -> None:
        """Stop capture and finalize queued events; safe from a control thread."""
        if (
            self._packet_worker is current_thread()
            or self._inside_origin_observer()
        ):
            raise RuntimeError(
                "stop() cannot block inside the live decoder or origin "
                "observer; use request_stop() instead"
            )
        self._require_started()
        self._finish_stop("requested")

    def request_stop(self) -> None:
        """Request callback-safe shutdown without waiting for finalization."""

        # Deliberately lock-free: a decoder/origin callback must be able to
        # request shutdown while a control thread owns _cleanup_lock and waits
        # for that callback's worker to finish.
        with self._state_lock:
            if not self._started:
                raise RuntimeError("live capture session was not started")
            if self._stopped.is_set():
                return
            # Events produced by packets already accepted before this request
            # remain deliverable while the monitor joins and drains the worker.
            self._finalizing.set()
            self._stop_requested.set()

    def poll(self, timeout: Optional[float] = None) -> Optional[BDOEvent]:
        """Return one event, or ``None`` on timeout or after the final event.

        ``timeout=None`` waits until an event arrives or the session stops.
        Even an indefinite poll wakes promptly when another thread calls
        ``stop()``.
        """
        if self._inside_origin_observer():
            raise RuntimeError(
                "poll() cannot consume events inside origin_observer; "
                "consume them after the callback returns"
            )
        self._require_started()
        _validate_poll_timeout(timeout)
        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            self._service_capture_state()
            try:
                return self._queue.get_nowait()
            except Empty:
                pass

            # Serialize the empty-queue recheck with producers. This lets a
            # non-blocking UI poll safely flush stale origin decisions without
            # racing a producer that fills the one available queue slot.
            with self._delivery_lock:
                try:
                    return self._queue.get_nowait()
                except Empty:
                    pass
                self._flush_stale()
                try:
                    return self._queue.get_nowait()
                except Empty:
                    pass

            if self._stopped.is_set():
                with self._tail_lock:
                    if self._tail_events:
                        return self._tail_events.popleft()
                self.raise_if_failed()
                return None

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                wait_seconds = min(self._POLL_INTERVAL_SECONDS, remaining)
            else:
                wait_seconds = self._POLL_INTERVAL_SECONDS

            try:
                return self._queue.get(timeout=wait_seconds)
            except Empty:
                continue

    def events(self) -> Iterator[BDOEvent]:
        """Return a blocking iterator that ends after ``stop()`` and draining."""
        self._require_started()
        return self._iterate_events()

    def raise_if_failed(self) -> None:
        """Re-raise a background capture failure in the calling thread."""
        error = self.error
        if error is not None:
            raise error

    def _iterate_events(self) -> Iterator[BDOEvent]:
        while True:
            event = self.poll(timeout=self._POLL_INTERVAL_SECONDS)
            if event is not None:
                yield event
            elif self._stopped.is_set():
                return

    def _enqueue_packet(self, packet: object) -> None:
        """Perform the native-callback handoff without blocking Scapy."""

        if self._stop_requested.is_set():
            return
        try:
            self._packet_queue.put_nowait(packet)
        except Full:
            with self._state_lock:
                self._packet_queue_overflows += 1
            self._record_error(
                CaptureIntegrityError(
                    "live packet queue overflowed; the event stream may be incomplete"
                )
            )
            self._stop_requested.set()
            return
        depth = self._packet_queue.qsize()
        with self._state_lock:
            self._packets_accepted += 1
            self._packet_queue_peak = max(self._packet_queue_peak, depth)

    def _run_packet_worker(self) -> None:
        """Decode accepted packets in FIFO order away from capture callback."""

        decode_enabled = True
        while True:
            packet = self._packet_queue.get()
            if packet is _PACKET_WORKER_STOP:
                return
            if not decode_enabled:
                # After decoder state fails, retain deterministic shutdown by
                # draining accepted packets without invoking a corrupt decoder.
                continue
            handler = self._packet_handler
            if handler is None:
                self._record_error(RuntimeError("live packet decoder was unavailable"))
                self._stop_requested.set()
                decode_enabled = False
                continue
            try:
                with self._decoder_lock:
                    handler(packet)
            except BaseException as exc:
                self._record_error(exc)
                self._stop_requested.set()
                decode_enabled = False

    def _monitor_stop_request(self) -> None:
        """Service idle state and stop failures without an active consumer."""

        while not self._stop_requested.wait(self._POLL_INTERVAL_SECONDS):
            capture = self._capture
            capture_error = capture.error if capture is not None else None
            if isinstance(capture_error, BaseException):
                self._record_error(capture_error)
                self._stop_requested.set()
                break
            if capture is not None and not capture.running:
                self._stop_requested.set()
                break
            self._service_engine_clock()
        if not self._stopped.is_set():
            capture = self._capture
            capture_error = capture.error if capture is not None else None
            if isinstance(capture_error, BaseException):
                self._record_error(capture_error)
            reason = (
                "error"
                if self.error is not None
                else "requested"
                if capture is None or capture.running
                else "capture-ended"
            )
            try:
                self._finish_stop(reason)
            except BaseException as exc:
                # A non-cooperative backend remains owned and retryable. The
                # public stop()/poll() paths surface the same retained error;
                # do not leak an unhandled exception from this daemon monitor.
                self._record_error(exc)

    def _service_engine_clock(self) -> None:
        collector = self._collector
        service_gaps = (
            getattr(collector.engine, "service_gaps", None)
            if collector is not None
            else None
        )
        if service_gaps is None:
            return
        try:
            with self._decoder_lock:
                service_gaps(time.time())
        except BaseException as exc:
            self._record_error(exc)
            self._stop_requested.set()

    def _signal_packet_worker_stop(self, deadline: Optional[float] = None) -> bool:
        worker = self._packet_worker
        if worker is None:
            return True
        if self._packet_worker_stop_signaled:
            return True
        if deadline is None:
            deadline = time.monotonic() + self._DECODER_STOP_TIMEOUT_SECONDS
        while worker.is_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                self._packet_queue.put(
                    _PACKET_WORKER_STOP,
                    timeout=min(self._POLL_INTERVAL_SECONDS, remaining),
                )
                self._packet_worker_stop_signaled = True
                return True
            except Full:
                continue
        return True

    def _enqueue(self, event: BDOEvent) -> None:
        # During shutdown the sniffer is joined before the consumer necessarily
        # drains its bounded queue. Route finalized events to a short-lived
        # tail instead of deadlocking the stop caller.
        with self._delivery_lock:
            if self._finalizing.is_set():
                with self._tail_lock:
                    self._tail_events.append(event)
                return
            while not self._stop_requested.is_set():
                try:
                    self._queue.put(event, timeout=self._POLL_INTERVAL_SECONDS)
                    depth = self._queue.qsize()
                    with self._state_lock:
                        self._event_queue_peak = max(
                            self._event_queue_peak,
                            depth,
                        )
                    return
                except Full:
                    if self._finalizing.is_set():
                        with self._tail_lock:
                            self._tail_events.append(event)
                        return

    def _service_capture_state(self) -> None:
        if self._stopped.is_set():
            return
        if self._stop_requested.is_set():
            self._finish_stop("error" if self.error is not None else "requested")
            return
        capture = self._capture
        capture_error = capture.error if capture is not None else None
        if isinstance(capture_error, BaseException):
            self._record_error(capture_error)
            self._finish_stop("error")
            return
        if capture is not None and not capture.running:
            self._finish_stop("error" if self.error is not None else "capture-ended")

    def _flush_stale(self) -> None:
        collector = self._collector
        if collector is None or self._stopped.is_set():
            return
        try:
            collector.flush_stale(time.time())
        except BaseException as exc:
            self._record_error(exc)
            self._stop_requested.set()

    def _finish_stop(self, reason: str) -> None:
        with self._cleanup_lock:
            if self._stopped.is_set():
                return
            self._finalizing.set()
            self._stop_requested.set()
            capture = self._capture
            collector = self._collector

            capture_error = capture.error if capture is not None else None
            if isinstance(capture_error, BaseException):
                self._record_error(capture_error)

            if capture is not None and not capture.stopped:
                stop_failure: Optional[BaseException] = None
                try:
                    self._capture_stats = capture.stop()
                except BaseException as exc:
                    stop_failure = exc
                    self._record_error(exc)
                if not capture.stopped:
                    cleanup_error = (
                        capture.cleanup_error
                        or stop_failure
                        or RuntimeError(
                            "live capture cleanup is incomplete after stop"
                        )
                    )
                    self._record_error(cleanup_error)
                    with self._state_lock:
                        self._cleanup_incomplete = True
                    # Do not queue the worker sentinel or finalize decoder
                    # state while the native callback may still be active.
                    # _stop_requested makes every later callback a no-op.
                    raise cleanup_error
                capture_error = capture.error
                if isinstance(capture_error, BaseException):
                    self._record_error(capture_error)
            elif capture is not None:
                self._capture_stats = capture.stats

            # Capture is joined before the sentinel is queued, so every packet
            # accepted by the callback appears ahead of it in FIFO order.
            decoder_deadline = (
                time.monotonic() + self._DECODER_STOP_TIMEOUT_SECONDS
            )
            self._signal_packet_worker_stop(decoder_deadline)
            worker = self._packet_worker
            if worker is not None and worker.is_alive():
                if worker is not current_thread():
                    worker.join(
                        timeout=max(0.0, decoder_deadline - time.monotonic())
                    )
                if worker.is_alive():
                    cleanup_error = RuntimeError(
                        "live packet decoder cleanup is incomplete after the "
                        f"{self._DECODER_STOP_TIMEOUT_SECONDS:g}-second deadline"
                    )
                    self._record_error(cleanup_error)
                    with self._state_lock:
                        self._cleanup_incomplete = True
                    # The worker may still hold _decoder_lock or call into the
                    # collector. Retain every dependency and retry only after
                    # its termination can be verified.
                    raise cleanup_error
            if collector is not None:
                try:
                    with self._decoder_lock:
                        collector.engine.finish()
                except BaseException as exc:
                    self._record_error(exc)
                try:
                    collector.finalize()
                except BaseException as exc:
                    self._record_error(exc)

            self._packet_handler = None

            with self._state_lock:
                self._stop_reason = "error" if self._error is not None else reason
                self._cleanup_incomplete = False
            self._stopped.set()

    def _record_error(self, error: BaseException) -> None:
        with self._state_lock:
            if self._error is None:
                self._error = error

    def _notify_origin_observer(
        self,
        observation: CompanionObservation,
    ) -> object:
        callback = self._origin_observer
        if callback is None:
            return None
        active_sessions = _ACTIVE_ORIGIN_SESSIONS.get()
        token = _ACTIVE_ORIGIN_SESSIONS.set(active_sessions + (self,))
        try:
            return callback(observation)
        finally:
            _ACTIVE_ORIGIN_SESSIONS.reset(token)

    def _notify_diagnostic(self, diagnostic: DecoderDiagnostic) -> object:
        callback = self._on_diagnostic
        if callback is None:
            return None
        active_sessions = _ACTIVE_ORIGIN_SESSIONS.get()
        token = _ACTIVE_ORIGIN_SESSIONS.set(active_sessions + (self,))
        try:
            return callback(diagnostic)
        finally:
            _ACTIVE_ORIGIN_SESSIONS.reset(token)

    def _inside_origin_observer(self) -> bool:
        return self in _ACTIVE_ORIGIN_SESSIONS.get()

    def _require_started(self) -> None:
        # Startup and verified rollback both mutate ``_started`` under the
        # cleanup lock. Waiting here prevents a concurrent stop/poll from
        # observing the provisional True and acting on a rolled-back session.
        with self._cleanup_lock:
            with self._state_lock:
                if not self._started:
                    raise RuntimeError("live capture session was not started")

    def __enter__(self) -> "LiveCaptureSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._started and not self._stopped.is_set():
            try:
                self.stop()
            except BaseException as cleanup_error:
                if exc_value is None:
                    raise
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc_value,
                        self,
                        context="live item capture context",
                    )
                if hasattr(exc_value, "add_note"):
                    exc_value.add_note(
                        "live item capture context cleanup also failed: "
                        f"{cleanup_error!r}"
                    )


def capture_live(
    *,
    opcode_profile: str | Path | OpcodeProfile,
    live_options: Optional[LiveCaptureOptions] = None,
    event_filter: Optional[EventFilter] = None,
    capture_seconds: Optional[float] = None,
    origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
    on_diagnostic: Optional[Callable[[DecoderDiagnostic], object]] = None,
) -> Iterator[BDOEvent]:
    """Start passive live capture and yield structured events.

    This blocking convenience wrapper is intended for scripts. Applications
    that need programmatic start/stop control should use
    :class:`LiveCaptureSession`. When ``event_filter`` is omitted, only
    :meth:`EventFilter.activity` events are delivered; pass
    ``EventFilter.all()`` for the complete decoded stream.
    """
    _validate_capture_seconds(capture_seconds)
    session = LiveCaptureSession(
        opcode_profile=opcode_profile,
        live_options=live_options,
        event_filter=event_filter,
        origin_observer=origin_observer,
        on_diagnostic=on_diagnostic,
    )
    session.start()
    started_at = time.monotonic()
    deadline_timer: Optional[Timer] = None
    if capture_seconds is not None:
        # The deadline belongs to capture ownership, not generator progress.
        # It therefore fires even while the consumer is suspended after a
        # yielded event.
        def finish_at_deadline() -> None:
            try:
                session._finish_stop("timeout")
            except BaseException as exc:
                # _finish_stop has retained both the first error and every
                # owner required for a retry. Avoid an unhandled Timer-thread
                # traceback while the generator remains the public owner.
                session._record_error(exc)

        try:
            deadline_timer = Timer(capture_seconds, finish_at_deadline)
            deadline_timer.name = "bdo-toolkit-items-deadline"
            deadline_timer.daemon = True
            deadline_timer.start()
        except BaseException as exc:
            if deadline_timer is not None:
                deadline_timer.cancel()
            try:
                session.stop()
            except BaseException as cleanup_error:
                if session.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc,
                        session,
                        context="timed live item capture startup",
                    )
                if hasattr(exc, "add_note"):
                    exc.add_note(
                        "timed live item capture startup cleanup also "
                        f"failed: {cleanup_error!r}"
                    )
            raise
    try:
        while True:
            if capture_seconds is None:
                poll_timeout = LiveCaptureSession._POLL_INTERVAL_SECONDS
            else:
                remaining = capture_seconds - (time.monotonic() - started_at)
                if remaining <= 0:
                    session._finish_stop("timeout")
                    poll_timeout = 0.0
                else:
                    poll_timeout = min(
                        LiveCaptureSession._POLL_INTERVAL_SECONDS,
                        remaining,
                    )

            event = session.poll(timeout=poll_timeout)
            if event is not None:
                yield event
            elif session.stopped:
                break
    finally:
        if deadline_timer is not None:
            deadline_timer.cancel()
        # No yields during generator close. The session finalizes pending TCP
        # and origin state; a normal stop path drains it in the loop above.
        if not session.stopped:
            try:
                session.stop()
            except BaseException as exc:
                if session.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc,
                        session,
                        context="live item capture convenience wrapper",
                    )
                raise


def _validate_poll_timeout(value: Optional[float]) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("timeout must be a number or None")
    if not math.isfinite(value) or value < 0:
        raise ValueError("timeout must be finite and non-negative")


def _validate_capture_seconds(value: Optional[float]) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("capture_seconds must be a number or None")
    if not math.isfinite(value) or value < 0:
        raise ValueError("capture_seconds must be finite and non-negative")
