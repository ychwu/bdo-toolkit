"""Fail-closed worker/manual classification for storage events.

Manual deposits carry a calibrated source-stack decrement immediately before
the storage delta. Worker deposits carry two ordered companion frames within a
bounded lookahead window that repeat the same high-entropy token from the
delta's pre-record prefix. The relationship survived a patch that changed
every involved opcode, length, and token offset, so classification does not
trust raw opcode values.

Missing or conflicting evidence produces ``unknown`` on an already-live
``storage_delta``. A neutral ``storage_record`` is promoted to a live delta
only when the same independent evidence proves a manual or worker mutation;
otherwise it remains neutral. Storage context bytes identify the destination
storage, not whether a player or worker caused it.
"""

from __future__ import annotations

import dataclasses
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable, Iterable, Optional

from ._protocol import MAX_TARGET_MESSAGE_LENGTH, BDOFrame, FlowKey, PacketContext
from .events import BDOEvent
from .origin_learning import (
    CompanionObservation,
    discover_companion_observation,
)
from .profiles import OriginCompanionFamily

ORIGIN_WORKER = "worker"
ORIGIN_MANUAL = "manual"
ORIGIN_UNKNOWN = "unknown"


@dataclass(frozen=True)
class DecrementSpec:
    """One source-stack-decrement shape to test candidates against."""

    opcode: int
    min_message_length: int
    quantity_offset: int
    source_instance_offset: Optional[int] = None
    repeat_stride: Optional[int] = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.opcode, bool)
            or not isinstance(self.opcode, int)
            or not 0 <= self.opcode <= 0xFFFF
        ):
            raise ValueError("decrement opcode must be a uint16")
        if (
            isinstance(self.min_message_length, bool)
            or not isinstance(self.min_message_length, int)
            or self.min_message_length < 5
        ):
            raise ValueError("decrement minimum message length must be at least 5")
        if (
            isinstance(self.quantity_offset, bool)
            or not isinstance(self.quantity_offset, int)
            or not 0 <= self.quantity_offset <= self.min_message_length - 4
        ):
            raise ValueError("decrement quantity offset must fit its minimum shape")
        if self.source_instance_offset is not None and (
            isinstance(self.source_instance_offset, bool)
            or not isinstance(self.source_instance_offset, int)
            or self.source_instance_offset < 0
            or self.source_instance_offset + 8 > self.min_message_length
        ):
            raise ValueError(
                "decrement source instance offset must fit its minimum shape"
            )
        if self.repeat_stride is not None and (
            isinstance(self.repeat_stride, bool)
            or not isinstance(self.repeat_stride, int)
            or self.repeat_stride <= 0
        ):
            raise ValueError("decrement repeat stride must be positive or None")
        if self.repeat_stride is not None:
            prefix_length = self.min_message_length - self.repeat_stride
            if (
                prefix_length < 5
                or self.quantity_offset < prefix_length
                or (
                    self.source_instance_offset is not None
                    and self.source_instance_offset < prefix_length
                )
            ):
                raise ValueError(
                    "decrement repeat stride must place repeated fields "
                    "after the frame prefix"
                )


@dataclass(frozen=True)
class _ManualDecrementMatch:
    """Strength and anchored geometry of one manual-deposit signal."""

    opcode: int
    message_length: int
    quantity_offset: int
    source_instance_offset: Optional[int]
    match_kind: str
    confidence: str
    instance_matches_destination: Optional[bool]

    def to_dict(self) -> dict[str, object]:
        output: dict[str, object] = {
            "opcode": f"0x{self.opcode:04X}",
            "message_length": self.message_length,
            "quantity_offset": self.quantity_offset,
            "match_kind": self.match_kind,
            "confidence": self.confidence,
        }
        if self.source_instance_offset is not None:
            output["source_instance_offset"] = self.source_instance_offset
        if self.instance_matches_destination is not None:
            output["instance_matches_destination"] = (
                self.instance_matches_destination
            )
        return output


@dataclass
class _PendingDeposit:
    event: BDOEvent
    flow: FlowKey
    stream_sequence: Optional[int]
    timestamp: float
    matching_decrement: bool
    events: tuple[BDOEvent, ...] = ()
    matching_decrement_record_indexes: tuple[int, ...] = ()
    manual_decrement_matches: tuple[
        tuple[int, _ManualDecrementMatch], ...
    ] = ()
    frames_after: int = 0
    end_sequence: Optional[int] = None
    companion_observation: Optional[CompanionObservation] = None
    delta_message: Optional[bytes] = None
    delta_prefix_end: Optional[int] = None
    candidate_observations: dict[
        tuple[int, int, int, int, int], CompanionObservation
    ] = field(default_factory=dict)
    finalized: bool = False


@dataclass(frozen=True)
class _StreamSpan:
    start: int
    data: bytes

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass(frozen=True)
class _CompanionScan:
    observations: tuple[CompanionObservation, ...]
    complete: bool
    immediate_family_keys: frozenset[tuple[int, int, int, int, int]] = frozenset()


@dataclass
class _StagedNeutralBatch:
    """Records from one unfamiliar-mode wrapper awaiting atomic routing."""

    expected_count: int
    entries: dict[int, tuple[BDOEvent, Optional[bytes]]] = field(
        default_factory=dict
    )
    invalid: bool = False


class DepositOriginTracker:
    """Correlate live-or-neutral storage records with origin evidence."""

    LOOKAHEAD_FRAMES = 8
    STALE_SECONDS = 2.0
    BACKWARD_WINDOW = 16
    STREAM_SPAN_HISTORY_LIMIT = 64
    MANUAL_LOOKBACK_FRAMES = 2
    OBSERVATION_HISTORY_LIMIT = 4096
    RECORD_BOUNDARY_HISTORY_LIMIT = 4096
    RUNTIME_CONFIRMED_FAMILY_LIMIT = 4096
    FAMILY_CONFIRMATION_OBSERVATIONS = 2

    def __init__(
        self,
        *,
        decrement_specs: Iterable[DecrementSpec],
        emit: Callable[[BDOEvent], None],
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
        known_companion_families: Iterable[OriginCompanionFamily] = (),
        storage_delta_opcodes: Iterable[int] = (),
    ) -> None:
        known_families = tuple(known_companion_families)
        self._decrement_specs: dict[int, list[DecrementSpec]] = {}
        for spec in decrement_specs:
            matches = self._decrement_specs.setdefault(spec.opcode, [])
            if spec not in matches:
                matches.append(spec)
        self._emit_callback = emit
        self._origin_observer = origin_observer
        # Live capture previously mutated correlation state from Scapy's
        # producer thread while the application consumer called
        # ``flush_stale``.  Keep every state transition under one lock and
        # dispatch application callbacks only after releasing it.  A separate
        # re-entrant dispatch lock preserves outbox order while allowing a
        # callback to re-enter the tracker without deadlocking.
        self._state_lock = RLock()
        self._dispatch_lock = RLock()
        self._outbox: deque[tuple[str, object]] = deque()
        self._known_companion_families = {
            family.family_key for family in known_families
        }
        self._confirmed_companion_families = set(self._known_companion_families)
        self._family_confirmation = {
            family_key: "profile" for family_key in self._known_companion_families
        }
        self._runtime_confirmed_family_order: deque[
            tuple[int, int, int, int, int]
        ] = deque()
        self._family_chains: dict[
            tuple[int, int, int, int, int],
            set[tuple[FlowKey, Optional[int]]],
        ] = {}
        self._family_chain_order: deque[
            tuple[
                tuple[int, int, int, int, int],
                tuple[FlowKey, Optional[int]],
            ]
        ] = deque()
        self._storage_delta_opcodes: set[int] = {
            family.delta_opcode for family in known_families
        }
        self._storage_delta_opcodes.update(storage_delta_opcodes)
        self._recent: dict[FlowKey, deque[BDOFrame]] = {}
        self._stream_spans: dict[FlowKey, deque[_StreamSpan]] = {}
        self._pending: list[_PendingDeposit] = []
        self._staged_neutral_batches: dict[
            tuple[FlowKey, Optional[int], Optional[int], Optional[int], float],
            _StagedNeutralBatch,
        ] = {}
        self._observed_chains: set[
            tuple[
                FlowKey,
                Optional[int],
                tuple[int, int, int, int, int],
            ]
        ] = set()
        self._observed_chain_order: deque[
            tuple[
                FlowKey,
                Optional[int],
                tuple[int, int, int, int, int],
            ]
        ] = deque()
        self._first_record_boundaries: dict[tuple[FlowKey, int], int] = {}
        self._first_record_boundary_order: deque[tuple[FlowKey, int]] = deque()

    # --- frame stream ---

    def observe_stream(self, data: bytes, context: PacketContext) -> None:
        """Observe reassembled bytes as one serialized tracker operation."""
        with self._state_lock:
            self._observe_stream_locked(data, context)
        self._drain_outbox()

    def _observe_stream_locked(self, data: bytes, context: PacketContext) -> None:
        """Retain raw reassembled bytes for alignment-independent correlation.

        The generic frame tap can begin in the middle of an application frame
        when live capture starts on an established TCP connection. Target
        opcodes can still resynchronize in that situation, so worker evidence
        must not depend exclusively on the generic tap finding a boundary.
        """
        if not data or context.stream_start is None:
            return
        span = _StreamSpan(context.stream_start, bytes(data))
        window = self._stream_spans.setdefault(
            context.flow,
            deque(maxlen=self.STREAM_SPAN_HISTORY_LIMIT),
        )
        window.append(span)

        if not self._pending:
            return
        still: list[_PendingDeposit] = []
        for pending in self._pending:
            if pending.finalized:
                continue
            if pending.flow != context.flow:
                still.append(pending)
                continue
            if pending.end_sequence is not None and span.end <= pending.end_sequence:
                still.append(pending)
                continue
            if not self._resolve_companions(pending):
                still.append(pending)
        self._pending = still

    def observe_frame(self, frame: BDOFrame) -> None:
        """Observe one generic frame as one serialized tracker operation."""
        with self._state_lock:
            self._observe_frame_locked(frame)
        self._drain_outbox()

    def _observe_frame_locked(self, frame: BDOFrame) -> None:
        window = self._recent.setdefault(
            frame.context.flow,
            deque(maxlen=self.BACKWARD_WINDOW),
        )
        window.append(frame)
        if not self._pending:
            return

        still: list[_PendingDeposit] = []
        for pending in self._pending:
            if pending.finalized:
                continue
            if pending.flow != frame.context.flow:
                if frame.context.timestamp - pending.timestamp > self.STALE_SECONDS:
                    self._close_pending(pending)
                else:
                    still.append(pending)
                continue
            if not self._frame_is_after(frame, pending):
                still.append(pending)
                continue
            if self._resolve_companions(pending):
                continue
            pending.frames_after += 1
            if (
                pending.frames_after >= self.LOOKAHEAD_FRAMES
                or frame.context.timestamp - pending.timestamp > self.STALE_SECONDS
            ):
                self._close_pending(pending)
            else:
                still.append(pending)
        self._pending = still

    @staticmethod
    def _frame_is_after(frame: BDOFrame, pending: _PendingDeposit) -> bool:
        if pending.stream_sequence is None or frame.stream_sequence is None:
            return True
        return frame.stream_sequence > pending.stream_sequence

    # --- event stream ---

    def register(
        self,
        event: BDOEvent,
        raw_message: Optional[bytes] = None,
    ) -> None:
        """Defer one live-or-neutral storage event until evidence resolves."""
        with self._state_lock:
            self._register_locked(event, raw_message)
        self._drain_outbox()

    def _register_locked(
        self,
        event: BDOEvent,
        raw_message: Optional[bytes] = None,
    ) -> None:
        flow = FlowKey(
            source_ip=event.flow.source_ip,
            source_port=event.flow.source_port,
            destination_ip=event.flow.destination_ip,
            destination_port=event.flow.destination_port,
        )
        raw_sequence = event.extra.get("stream_sequence")
        stream_sequence = raw_sequence if isinstance(raw_sequence, int) else None

        if self._stage_neutral_batch(
            event,
            raw_message,
            flow=flow,
            stream_sequence=stream_sequence,
        ):
            return
        self._register_group(
            (event,),
            raw_message,
            flow=flow,
            stream_sequence=stream_sequence,
        )

    def _stage_neutral_batch(
        self,
        event: BDOEvent,
        raw_message: Optional[bytes],
        *,
        flow: FlowKey,
        stream_sequence: Optional[int],
    ) -> bool:
        """Buffer unknown-operation multi-record wrappers as one decision."""
        record_index = event.record_index
        record_count = event.record_count
        if (
            event.event_type != "storage_record"
            or isinstance(record_index, bool)
            or not isinstance(record_index, int)
            or isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or record_count <= 1
            or not 1 <= record_index <= record_count
        ):
            return False

        key = (
            flow,
            stream_sequence,
            event.opcode,
            event.message_length,
            event.timestamp,
        )
        staged = self._staged_neutral_batches.get(key)
        if staged is None:
            staged = _StagedNeutralBatch(expected_count=record_count)
            self._staged_neutral_batches[key] = staged
        elif staged.expected_count != record_count:
            staged.invalid = True

        previous = staged.entries.get(record_index)
        if previous is not None:
            if previous[0] != event or previous[1] != raw_message:
                staged.invalid = True
        else:
            staged.entries[record_index] = (event, raw_message)

        if len(staged.entries) < staged.expected_count:
            return True

        self._staged_neutral_batches.pop(key, None)
        expected_indexes = set(range(1, staged.expected_count + 1))
        if staged.invalid or set(staged.entries) != expected_indexes:
            self._emit_neutral_entries(staged)
            return True

        ordered = tuple(staged.entries[index] for index in sorted(staged.entries))
        messages = {entry[1] for entry in ordered if entry[1] is not None}
        if len(messages) > 1:
            self._emit_neutral_entries(staged)
            return True
        group_raw = next(iter(messages), None)
        self._register_group(
            tuple(entry[0] for entry in ordered),
            group_raw,
            flow=flow,
            stream_sequence=stream_sequence,
        )
        return True

    def _emit_neutral_entries(self, staged: _StagedNeutralBatch) -> None:
        for record_index in sorted(staged.entries):
            self._queue_emit(staged.entries[record_index][0])

    def _register_group(
        self,
        events: tuple[BDOEvent, ...],
        raw_message: Optional[bytes],
        *,
        flow: FlowKey,
        stream_sequence: Optional[int],
    ) -> None:
        """Register one raw storage message, emitting all records atomically."""
        event = events[0]
        if event.opcode is not None:
            self._storage_delta_opcodes.add(event.opcode)
        end_sequence = None
        if stream_sequence is not None and event.message_length is not None:
            end_sequence = stream_sequence + event.message_length
        delta_message = None
        if raw_message is not None and event.message_length is not None:
            candidate = bytes(raw_message)
            if (
                len(candidate) == event.message_length
                and len(candidate) >= 5
                and int.from_bytes(candidate[0:2], "little") == len(candidate)
            ):
                delta_message = candidate
        record_boundaries = [
            candidate.record_offset
            for candidate in events
            if isinstance(candidate.record_offset, int)
            and not isinstance(candidate.record_offset, bool)
            and candidate.message_length is not None
            and 5 + 8 <= candidate.record_offset <= candidate.message_length
        ]
        delta_prefix_end = min(record_boundaries) if record_boundaries else None
        if delta_prefix_end is not None and stream_sequence is not None:
            boundary_key = (flow, stream_sequence)
            previous = self._first_record_boundaries.get(boundary_key)
            if previous is None:
                if (
                    len(self._first_record_boundary_order)
                    >= self.RECORD_BOUNDARY_HISTORY_LIMIT
                ):
                    expired = self._first_record_boundary_order.popleft()
                    self._first_record_boundaries.pop(expired, None)
                self._first_record_boundary_order.append(boundary_key)
                self._first_record_boundaries[boundary_key] = delta_prefix_end
            else:
                delta_prefix_end = min(previous, delta_prefix_end)
                self._first_record_boundaries[boundary_key] = delta_prefix_end
        manual_matches: list[tuple[int, _ManualDecrementMatch]] = []
        for index, candidate_event in enumerate(events, 1):
            match = self._matching_decrement(
                flow,
                stream_sequence,
                candidate_event,
            )
            if match is not None:
                manual_matches.append(
                    (candidate_event.record_index or index, match)
                )
        matching_indexes = tuple(index for index, _match in manual_matches)
        pending = _PendingDeposit(
            event=event,
            flow=flow,
            stream_sequence=stream_sequence,
            timestamp=event.timestamp,
            matching_decrement=bool(matching_indexes),
            events=events,
            matching_decrement_record_indexes=matching_indexes,
            manual_decrement_matches=tuple(manual_matches),
            end_sequence=end_sequence,
            delta_message=delta_message,
            delta_prefix_end=delta_prefix_end,
        )
        if self._resolve_companions(pending):
            return

        # The frame tap runs before event decoding. Credit already observed
        # frames when the full TCP segment contained the delta and lookahead.
        for frame in self._recent.get(flow, ()):
            if self._frame_is_after(frame, pending):
                pending.frames_after += 1
        if pending.frames_after >= self.LOOKAHEAD_FRAMES:
            self._close_pending(pending)
        else:
            self._pending.append(pending)

    # --- anchored structural companion scan ---

    def _read_span(self, flow: FlowKey, start: int, length: int) -> Optional[bytes]:
        """Read stream bytes ``[start, start + length)`` from frame spans."""
        if length <= 0:
            return None
        output = bytearray()
        position = start
        remaining = length
        while remaining > 0:
            source_start = None
            source_data = None
            # Prefer raw reassembled spans. Iterate newest-first so an overlap
            # or standalone retransmission cannot shadow newer contiguous data.
            for span in reversed(self._stream_spans.get(flow, ())):
                offset = position - span.start
                if 0 <= offset < len(span.data):
                    source_start = span.start
                    source_data = span.data
                    break
            if source_data is None:
                # Unit-level callers and older integrations may only provide
                # generic frames; retain that compatible fallback.
                for frame in reversed(self._recent.get(flow, ())):
                    if frame.stream_sequence is None:
                        continue
                    offset = position - frame.stream_sequence
                    if 0 <= offset < len(frame.message):
                        source_start = frame.stream_sequence
                        source_data = frame.message
                        break
            if source_data is None or source_start is None:
                return None
            offset = position - source_start
            chunk = source_data[offset : offset + remaining]
            if not chunk:
                return None
            output += chunk
            position += len(chunk)
            remaining -= len(chunk)
        return bytes(output)

    def _scan_companions_after(
        self,
        pending: _PendingDeposit,
    ) -> Optional[_CompanionScan]:
        """Scan a bounded message window, skipping unrelated message families."""
        if (
            pending.end_sequence is None
            or pending.stream_sequence is None
            or pending.event.message_length is None
            or pending.delta_prefix_end is None
        ):
            return None
        delta_message = pending.delta_message or self._read_span(
            pending.flow, pending.stream_sequence, pending.event.message_length
        )
        if delta_message is None:
            return None

        position = pending.end_sequence
        following: list[bytes] = []
        observations: dict[
            tuple[int, int, int, int, int], CompanionObservation
        ] = {}
        immediate: set[tuple[int, int, int, int, int]] = set()
        for message_index in range(self.LOOKAHEAD_FRAMES):
            header = self._read_span(pending.flow, position, 5)
            if header is None:
                return _CompanionScan(
                    tuple(observations.values()),
                    False,
                    frozenset(immediate),
                )
            length = int.from_bytes(header[0:2], "little")
            if not 5 <= length <= MAX_TARGET_MESSAGE_LENGTH:
                return _CompanionScan(
                    tuple(observations.values()),
                    True,
                    frozenset(immediate),
                )
            message = self._read_span(pending.flow, position, length)
            if message is None:
                return _CompanionScan(
                    tuple(observations.values()),
                    False,
                    frozenset(immediate),
                )
            opcode = int.from_bytes(message[3:5], "little")
            if opcode in self._storage_delta_opcodes:
                return _CompanionScan(
                    tuple(observations.values()),
                    True,
                    frozenset(immediate),
                )
            for first_index, first_message in enumerate(following):
                observation = discover_companion_observation(
                    delta_message=delta_message,
                    first_message=first_message,
                    second_message=message,
                    timestamp=pending.timestamp,
                    flow=pending.flow,
                    stream_sequence=pending.stream_sequence,
                    delta_prefix_end=pending.delta_prefix_end,
                )
                if observation is None:
                    continue
                observations.setdefault(observation.family_key, observation)
                if first_index == 0 and message_index == 1:
                    immediate.add(observation.family_key)
            following.append(message)
            position += length

        return _CompanionScan(
            tuple(observations.values()),
            True,
            frozenset(immediate),
        )

    def _resolve_companions(self, pending: _PendingDeposit) -> bool:
        if pending.finalized:
            return True
        if self._select_confirmed_observation(pending):
            self._finalize(pending)
            return True
        result = self._scan_companions_after(pending)
        if result is None:
            return False
        for observation in result.observations:
            pending.candidate_observations.setdefault(
                observation.family_key,
                observation,
            )
            self._record_family_observation(observation)
        if pending.finalized:
            return True
        if self._select_confirmed_observation(pending):
            self._finalize(pending)
            return True

        # An adjacent, unique pair is strong enough to bootstrap a family
        # without a separately promoted profile. Delayed/ambiguous pairs wait
        # for the bounded window to close or for repeated-family confirmation.
        immediate = result.immediate_family_keys.intersection(
            pending.candidate_observations
        )
        if len(immediate) == 1 and len(pending.candidate_observations) == 1:
            self._confirm_family(next(iter(immediate)), "adjacent-structural-chain")
            if not pending.finalized:
                self._select_confirmed_observation(pending)
                self._finalize(pending)
            return True

        if result.complete:
            self._close_pending(pending)
            return pending.finalized
        return False

    def _record_family_observation(
        self,
        observation: CompanionObservation,
    ) -> None:
        chain_key = (observation.flow, observation.stream_sequence)
        if observation.family_key in self._confirmed_companion_families:
            self._notify_origin_observer(observation)
            return
        chains = self._family_chains.get(observation.family_key)
        is_new = chains is None or chain_key not in chains
        if is_new:
            if len(self._family_chain_order) >= self.OBSERVATION_HISTORY_LIMIT:
                expired_family, expired_chain = self._family_chain_order.popleft()
                expired_chains = self._family_chains.get(expired_family)
                if expired_chains is not None:
                    expired_chains.discard(expired_chain)
                    if not expired_chains:
                        self._family_chains.pop(expired_family, None)
            chains = self._family_chains.setdefault(observation.family_key, set())
            chains.add(chain_key)
            self._family_chain_order.append((observation.family_key, chain_key))
            self._notify_origin_observer(observation)
        assert chains is not None
        if len(chains) >= self.FAMILY_CONFIRMATION_OBSERVATIONS:
            self._confirm_family(observation.family_key, "repeated-structural-chain")

    def _confirm_family(
        self,
        family_key: tuple[int, int, int, int, int],
        reason: str,
    ) -> None:
        if family_key in self._confirmed_companion_families:
            return
        self._confirmed_companion_families.add(family_key)
        self._family_confirmation[family_key] = reason
        if family_key not in self._known_companion_families:
            if (
                len(self._runtime_confirmed_family_order)
                >= self.RUNTIME_CONFIRMED_FAMILY_LIMIT
            ):
                expired = self._runtime_confirmed_family_order.popleft()
                self._confirmed_companion_families.discard(expired)
                self._family_confirmation.pop(expired, None)
            self._runtime_confirmed_family_order.append(family_key)
        self._family_chains.pop(family_key, None)
        # A later independent chain can resolve an earlier ambiguous one.
        for pending in self._pending:
            if pending.finalized or family_key not in pending.candidate_observations:
                continue
            if self._select_confirmed_observation(pending):
                self._finalize(pending)

    def _select_confirmed_observation(self, pending: _PendingDeposit) -> bool:
        eligible = [
            key
            for key in pending.candidate_observations
            if key in self._confirmed_companion_families
        ]
        if not eligible:
            return False
        # An explicitly promoted profile wins if an ambiguous window happens
        # to contain more than one confirmed candidate family.
        eligible.sort(
            key=lambda key: (key not in self._known_companion_families, key)
        )
        pending.companion_observation = pending.candidate_observations[eligible[0]]
        return True

    def _close_pending(self, pending: _PendingDeposit) -> None:
        """Close a complete/stale window, auto-confirming only if unambiguous."""
        if pending.finalized:
            return
        if self._select_confirmed_observation(pending):
            self._finalize(pending)
            return
        if len(pending.candidate_observations) == 1:
            family_key = next(iter(pending.candidate_observations))
            self._confirm_family(family_key, "unambiguous-bounded-window")
            if not pending.finalized:
                self._select_confirmed_observation(pending)
        self._finalize(pending)

    def _notify_origin_observer(self, observation: CompanionObservation) -> None:
        # A multi-record storage frame registers several events but represents
        # one independent companion-family observation.
        key = (observation.flow, observation.stream_sequence, observation.family_key)
        if key in self._observed_chains:
            return
        if len(self._observed_chain_order) >= self.OBSERVATION_HISTORY_LIMIT:
            expired = self._observed_chain_order.popleft()
            self._observed_chains.discard(expired)
        self._observed_chains.add(key)
        self._observed_chain_order.append(key)
        if self._origin_observer is not None:
            self._outbox.append(("observer", observation))

    # --- calibrated manual-decrement signal ---

    def _matching_decrement(
        self,
        flow: FlowKey,
        stream_sequence: Optional[int],
        event: BDOEvent,
    ) -> Optional[_ManualDecrementMatch]:
        quantity_bytes = event.quantity.to_bytes(4, "little")
        destination_instance = self._event_storage_instance(event)
        eligible = [
            frame
            for frame in self._recent.get(flow, ())
            if not (
                stream_sequence is not None
                and frame.stream_sequence is not None
                and frame.stream_sequence >= stream_sequence
            )
        ][-self.MANUAL_LOOKBACK_FRAMES :]
        matches: list[_ManualDecrementMatch] = []
        for frame in eligible:
            for spec in self._decrement_specs.get(frame.opcode, ()):
                # Profile lengths are calibrated single-record minima. Batch
                # decrements append more records to the same frame.
                if len(frame.message) < spec.min_message_length:
                    continue
                inferred_repeat_stride: Optional[int] = None
                if spec.repeat_stride is not None:
                    extra_length = len(frame.message) - spec.min_message_length
                    if extra_length % spec.repeat_stride:
                        continue
                    record_deltas: Iterable[int] = range(
                        0,
                        extra_length + 1,
                        spec.repeat_stride,
                    )
                elif (
                    spec.source_instance_offset is not None
                    and destination_instance is not None
                    and isinstance(event.record_index, int)
                    and not isinstance(event.record_index, bool)
                    and isinstance(event.record_count, int)
                    and not isinstance(event.record_count, bool)
                    and event.record_count > 1
                    and 1 <= event.record_index <= event.record_count
                ):
                    # Older calibrated profiles predate repeat_stride, but
                    # their multi-record captures still expose enough
                    # geometry to recover it safely: the captured decrement
                    # and storage batch cardinalities align, while exact
                    # source/destination instance equality validates every
                    # inferred record after the first. This never expands
                    # quantity-only matching.
                    extra_length = len(frame.message) - spec.min_message_length
                    divisor = event.record_count - 1
                    if extra_length <= 0 or extra_length % divisor:
                        record_deltas = (0,)
                    else:
                        inferred_stride = extra_length // divisor
                        prefix_length = (
                            spec.min_message_length - inferred_stride
                        )
                        if (
                            inferred_stride <= 0
                            or prefix_length < 5
                            or spec.quantity_offset < prefix_length
                            or spec.source_instance_offset < prefix_length
                        ):
                            record_deltas = (0,)
                        else:
                            inferred_repeat_stride = inferred_stride
                            record_deltas = range(
                                0,
                                extra_length + 1,
                                inferred_stride,
                            )
                else:
                    record_deltas = (0,)

                for delta in record_deltas:
                    quantity_offset = spec.quantity_offset + delta
                    quantity_end = quantity_offset + 4
                    if (
                        quantity_end > len(frame.message)
                        or frame.message[quantity_offset:quantity_end]
                        != quantity_bytes
                    ):
                        continue

                    source_offset = spec.source_instance_offset
                    if source_offset is None:
                        matches.append(
                            _ManualDecrementMatch(
                                opcode=frame.opcode,
                                message_length=len(frame.message),
                                quantity_offset=quantity_offset,
                                source_instance_offset=None,
                                match_kind="quantity-only",
                                confidence="heuristic",
                                instance_matches_destination=None,
                            )
                        )
                        continue

                    source_offset += delta
                    source_end = source_offset + 8
                    if source_end > len(frame.message):
                        continue
                    source_instance = bytes(
                        frame.message[source_offset:source_end]
                    )
                    if not self._nonempty_source_instance(source_instance):
                        # A declared instance field that is empty invalidates
                        # this candidate. Do not fall back to a common
                        # quantity elsewhere in the frame.
                        continue

                    exact = (
                        destination_instance is not None
                        and source_instance == destination_instance
                    )
                    if not exact:
                        if inferred_repeat_stride is not None and delta:
                            # The profile did not declare this repeated field
                            # location. Exact identity is the guard that makes
                            # the inferred nonzero record offset trustworthy.
                            continue
                        # A partial stack move can allocate a different
                        # destination instance: the controlled legacy
                        # new_potato_1_1_1 capture proves that mismatch is not
                        # contradictory. Retain it as anchored structural
                        # evidence, but require entropy in both halves. Exact
                        # cross-frame equality needs no such heuristic guard.
                        if not self._structural_source_instance(
                            source_instance
                        ):
                            continue
                    matches.append(
                        _ManualDecrementMatch(
                            opcode=frame.opcode,
                            message_length=len(frame.message),
                            quantity_offset=quantity_offset,
                            source_instance_offset=source_offset,
                            match_kind=(
                                "instance-and-quantity"
                                if exact
                                else "anchored-instance-and-quantity"
                            ),
                            confidence="observed" if exact else "structural",
                            instance_matches_destination=(
                                exact if destination_instance is not None else None
                            ),
                        )
                    )

        if not matches:
            return None
        rank = {"observed": 0, "structural": 1, "heuristic": 2}
        matches.sort(key=lambda match: rank[match.confidence])
        return matches[0]

    @staticmethod
    def _event_storage_instance(event: BDOEvent) -> Optional[bytes]:
        value = event.storage_instance
        if not isinstance(value, str) or not value.startswith("0x"):
            return None
        try:
            decoded = bytes.fromhex(value[2:])
        except ValueError:
            return None
        return decoded if len(decoded) == 8 else None

    @staticmethod
    def _nonempty_source_instance(value: bytes) -> bool:
        return len(value) == 8 and value not in (b"\x00" * 8, b"\xff" * 8)

    @classmethod
    def _structural_source_instance(cls, value: bytes) -> bool:
        if not cls._nonempty_source_instance(value):
            return False
        empty_halves = {b"\x00" * 4, b"\xff" * 4}
        return value[:4] not in empty_halves and value[4:] not in empty_halves

    # --- flushing ---

    def flush_stale(self, now: float) -> None:
        """Finalize expired evidence without racing producer-side mutation."""
        with self._state_lock:
            self._flush_stale_locked(now)
        self._drain_outbox()

    def close_flow(self, flow: FlowKey) -> None:
        """Finalize one closed TCP flow and release all flow-keyed history."""

        with self._state_lock:
            staged_keys = [
                key for key in self._staged_neutral_batches if key[0] == flow
            ]
            for key in staged_keys:
                self._emit_neutral_entries(self._staged_neutral_batches.pop(key))

            for pending in tuple(self._pending):
                if pending.flow == flow and not pending.finalized:
                    self._close_pending(pending)
            self._pending = [
                pending
                for pending in self._pending
                if pending.flow != flow and not pending.finalized
            ]
            self._purge_flow_history_locked(flow)
        self._drain_outbox()

    def _purge_flow_history_locked(self, flow: FlowKey) -> None:
        self._recent.pop(flow, None)
        self._stream_spans.pop(flow, None)

        self._family_chain_order = deque(
            (family, chain)
            for family, chain in self._family_chain_order
            if chain[0] != flow
        )
        for family, chains in tuple(self._family_chains.items()):
            remaining = {chain for chain in chains if chain[0] != flow}
            if remaining:
                self._family_chains[family] = remaining
            else:
                self._family_chains.pop(family, None)

        self._observed_chain_order = deque(
            key for key in self._observed_chain_order if key[0] != flow
        )
        self._observed_chains = {
            key for key in self._observed_chains if key[0] != flow
        }

        self._first_record_boundary_order = deque(
            key for key in self._first_record_boundary_order if key[0] != flow
        )
        self._first_record_boundaries = {
            key: value
            for key, value in self._first_record_boundaries.items()
            if key[0] != flow
        }

    def _flush_stale_locked(self, now: float) -> None:
        stale_batches = [
            key
            for key, staged in self._staged_neutral_batches.items()
            if staged.entries
            and now
            - min(entry[0].timestamp for entry in staged.entries.values())
            > self.STALE_SECONDS
        ]
        for key in stale_batches:
            self._emit_neutral_entries(self._staged_neutral_batches.pop(key))

        still: list[_PendingDeposit] = []
        for pending in self._pending:
            if now - pending.timestamp > self.STALE_SECONDS:
                self._close_pending(pending)
            else:
                still.append(pending)
        self._pending = still

    def finalize_all(self) -> None:
        """Finalize every pending decision and dispatch it in tracker order."""
        with self._state_lock:
            self._finalize_all_locked()
        self._drain_outbox()

    def _finalize_all_locked(self) -> None:
        staged, self._staged_neutral_batches = self._staged_neutral_batches, {}
        for batch in staged.values():
            self._emit_neutral_entries(batch)

        pending, self._pending = self._pending, []
        for deposit in pending:
            self._close_pending(deposit)
        self._recent.clear()
        self._stream_spans.clear()
        self._family_chains.clear()
        self._family_chain_order.clear()
        self._observed_chains.clear()
        self._observed_chain_order.clear()
        self._first_record_boundaries.clear()
        self._first_record_boundary_order.clear()

    def _finalize(self, pending: _PendingDeposit) -> None:
        if pending.finalized:
            return
        pending.finalized = True
        companions = pending.companion_observation is not None
        # The shared-token chain remains stronger than any backward manual
        # signal, including an exact instance match, because it proves the
        # worker-specific three-frame relation for this operation.
        if companions:
            origin = ORIGIN_WORKER
        elif pending.matching_decrement:
            origin = ORIGIN_MANUAL
        else:
            origin = ORIGIN_UNKNOWN

        events = pending.events or (pending.event,)
        was_neutral = pending.event.event_type == "storage_record"
        if was_neutral and origin == ORIGIN_UNKNOWN:
            # An unfamiliar wrapper mode is not a deposit merely because the
            # target opcode and item fields decoded. Preserve the original
            # fail-closed event exactly when neither independent live signal
            # was present.
            for event in events:
                self._queue_emit(event)
            return

        evidence: dict[str, object] = {
            "worker_companions": companions,
            "matching_decrement": pending.matching_decrement,
        }
        if pending.manual_decrement_matches:
            rank = {"observed": 0, "structural": 1, "heuristic": 2}
            record_index, selected_manual = min(
                pending.manual_decrement_matches,
                key=lambda item: rank[item[1].confidence],
            )
            selected_payload = selected_manual.to_dict()
            selected_payload["record_index"] = record_index
            evidence["manual_decrement"] = selected_payload
            if len(pending.manual_decrement_matches) > 1:
                evidence["manual_decrement_matches"] = tuple(
                    {
                        "record_index": candidate_index,
                        **candidate.to_dict(),
                    }
                    for candidate_index, candidate in pending.manual_decrement_matches
                )
        if pending.companion_observation is not None:
            companion_evidence = pending.companion_observation.to_dict()
            companion_evidence["known_family"] = (
                pending.companion_observation.family_key
                in self._known_companion_families
            )
            companion_evidence["confirmed_family"] = (
                pending.companion_observation.family_key
                in self._confirmed_companion_families
            )
            companion_evidence["confirmation"] = self._family_confirmation.get(
                pending.companion_observation.family_key
            )
            evidence["companion_chain"] = companion_evidence
        if (
            was_neutral
            and len(events) > 1
            and pending.matching_decrement_record_indexes
        ):
            evidence["matching_decrement_record_indexes"] = (
                pending.matching_decrement_record_indexes
            )

        for original in events:
            extra = {
                **original.extra,
                "deposit_origin_evidence": evidence,
            }
            if was_neutral:
                # A calibrated source decrement or confirmed worker chain
                # proves that this unfamiliar wire mode is nevertheless a
                # live mutation. Preserve that inference in additive audit
                # metadata and promote before EventFilter is applied.
                extra["storage_delta"] = original.quantity
                extra["storage_operation_evidence"] = {
                    "wire_operation": "unknown",
                    "inferred_operation": "live",
                    "signal": (
                        "worker_companions" if companions else "matching_decrement"
                    ),
                }

            event = dataclasses.replace(
                original,
                event_type=("storage_delta" if was_neutral else original.event_type),
                storage_operation=(
                    "live" if was_neutral else original.storage_operation
                ),
                deposit_origin=origin,
                extra=extra,
            )
            self._queue_emit(event)

    def _queue_emit(self, event: BDOEvent) -> None:
        """Queue an application event while tracker state is locked."""
        self._outbox.append(("emit", event))

    def _drain_outbox(self) -> None:
        """Dispatch callbacks outside the state lock in mutation order."""
        with self._dispatch_lock:
            while True:
                with self._state_lock:
                    if not self._outbox:
                        return
                    kind, payload = self._outbox.popleft()
                if kind == "emit":
                    assert isinstance(payload, BDOEvent)
                    self._emit_callback(payload)
                else:
                    assert kind == "observer"
                    assert isinstance(payload, CompanionObservation)
                    observer = self._origin_observer
                    if observer is not None:
                        observer(payload)
