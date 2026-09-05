"""Private deposit-origin tracker implementation."""

from __future__ import annotations

import dataclasses
from collections import deque
from threading import RLock
from typing import Callable, Iterable, Optional
from .._protocol import BDOFrame, FlowKey, MAX_TARGET_MESSAGE_LENGTH, PacketContext
from ..events import BDOEvent
from ..origin_learning import CompanionObservation, TOKEN_WIDTH
from ..profiles import OriginCompanionFamily
from .discovery import _CompanionDiscoveryCache
from .manual import _ManualDecrementLedger
from .models import (
    DecrementSpec,
    ORIGIN_MANUAL,
    ORIGIN_UNKNOWN,
    ORIGIN_WORKER,
    SOURCE_PLAYER_INVENTORY,
    SOURCE_WORKER_PRODUCTION,
    _CompanionScan,
    _PendingDeposit,
    _StagedStorageBatch,
    _StreamSpan,
)


class DepositOriginTracker:
    """Correlate live-or-neutral storage records with origin evidence."""

    # Worker companions can be interleaved with ordinary inventory and
    # storage traffic. Keep a modestly wider message horizon than the original
    # eight-frame window, while the independent time and pending-count bounds
    # below prevent unbounded retention or scanning.
    LOOKAHEAD_FRAMES = 32
    MAX_PENDING_OPERATIONS_PER_FLOW = 64
    MAX_PENDING_OPERATIONS_TOTAL = 4096
    STALE_SECONDS = 2.0
    BACKWARD_WINDOW = 16
    STREAM_SPAN_HISTORY_LIMIT = 64
    OBSERVATION_HISTORY_LIMIT = 4096
    COMPANION_PAIR_HISTORY_LIMIT = 4096
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
        self._manual = _ManualDecrementLedger(decrement_specs, self.STALE_SECONDS)
        self._discovery = _CompanionDiscoveryCache()
        self._emit_callback = emit
        self._origin_observer = origin_observer
        # Live capture mutates correlation state from its decoder worker while
        # the application consumer can call ``flush_stale``.  Keep every state
        # transition under one lock and queue callbacks in that same order.
        # Exactly one caller owns outbox dispatch at a time, but callbacks run
        # without *any* tracker lock held: a callback may need a session lock
        # while another thread holding that session lock enters the tracker.
        self._state_lock = RLock()
        self._outbox: deque[tuple[str, object]] = deque()
        self._dispatching = False
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
            tuple[
                FlowKey,
                int,
                Optional[int],
                Optional[int],
                Optional[int],
                float,
            ],
            _StagedStorageBatch,
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
        self._contested_companion_pairs: set[
            tuple[FlowKey, int, int]
        ] = set()
        self._contested_companion_pair_order: deque[
            tuple[FlowKey, int, int]
        ] = deque()
        self._companion_contest_overflow_flows: set[FlowKey] = set()
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
            if context.timestamp - pending.timestamp > self.STALE_SECONDS:
                self._close_pending(pending)
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
        self._manual._observe_manual_frame_locked(frame)
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
            if frame.context.timestamp - pending.timestamp > self.STALE_SECONDS:
                self._close_pending(pending)
                continue
            if self._resolve_companions(pending):
                continue
            pending.frames_after += 1
            if (
                not pending.awaiting_storage_boundaries
                and pending.frames_after >= self.LOOKAHEAD_FRAMES
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
        self._manual._activate_manual_generation_locked(flow, event._flow_generation)

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
        """Buffer every multi-record storage wrapper as one decision."""
        record_index = event.record_index
        record_count = event.record_count
        if (
            isinstance(record_index, bool)
            or not isinstance(record_index, int)
            or isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or record_count <= 1
            or not 1 <= record_index <= record_count
        ):
            return False

        key = (
            flow,
            event._flow_generation,
            stream_sequence,
            event.opcode,
            event.message_length,
            event.timestamp,
        )
        staged = self._staged_neutral_batches.get(key)
        if staged is None:
            staged = _StagedStorageBatch(expected_count=record_count)
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
        if len({entry[0].event_type for entry in ordered}) != 1:
            self._emit_neutral_entries(staged)
            return True
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

    def _emit_neutral_entries(self, staged: _StagedStorageBatch) -> None:
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
            # The raw stream/frame observers run before target records are
            # decoded. An older operation may therefore have crossed this
            # wrapper without yet knowing where its transaction prefix ends.
            # Retry it now that the authoritative first-record boundary is
            # available; never substitute the entire record body as a prefix.
            self._retry_boundary_waiters(flow, stream_sequence)
        manual_matches = self._manual._reserve_matching_decrement(
            flow,
            event._flow_generation,
            stream_sequence,
            events,
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
        if (
            pending.frames_after >= self.LOOKAHEAD_FRAMES
            and not pending.awaiting_storage_boundaries
        ):
            self._close_pending(pending)
        else:
            self._append_pending(pending)

    def _retry_boundary_waiters(
        self,
        flow: FlowKey,
        stream_sequence: int,
    ) -> None:
        """Retry older operations deferred on one crossed storage wrapper."""

        still: list[_PendingDeposit] = []
        for pending in self._pending:
            if pending.finalized:
                continue
            if (
                pending.flow != flow
                or stream_sequence not in pending.awaiting_storage_boundaries
            ):
                still.append(pending)
                continue
            if self._resolve_companions(pending):
                continue
            if (
                pending.frames_after >= self.LOOKAHEAD_FRAMES
                and not pending.awaiting_storage_boundaries
            ):
                self._close_pending(pending)
                continue
            still.append(pending)
        self._pending = [entry for entry in still if not entry.finalized]

    def _append_pending(self, pending: _PendingDeposit) -> None:
        """Retain one unresolved operation under a hard operation bound."""

        self._pending = [entry for entry in self._pending if not entry.finalized]
        pending_key = self._pending_operation_key(pending)
        operation_keys = self._pending_operation_keys()
        flow_operation_keys = {
            key for key in operation_keys if key[0] == pending.flow
        }
        while pending_key not in operation_keys and (
            len(flow_operation_keys) >= self.MAX_PENDING_OPERATIONS_PER_FLOW
            or len(operation_keys) >= self.MAX_PENDING_OPERATIONS_TOTAL
        ):
            if len(flow_operation_keys) >= self.MAX_PENDING_OPERATIONS_PER_FLOW:
                oldest = next(
                    entry for entry in self._pending if entry.flow == pending.flow
                )
            else:
                oldest = self._pending[0]
            oldest_key = self._pending_operation_key(oldest)
            oldest_group = [
                entry
                for entry in self._pending
                if self._pending_operation_key(entry) == oldest_key
            ]
            self._pending = [
                entry
                for entry in self._pending
                if self._pending_operation_key(entry) != oldest_key
            ]
            for oldest in oldest_group:
                self._evict_pending_fail_closed(oldest)
            self._pending = [
                entry for entry in self._pending if not entry.finalized
            ]
            operation_keys = self._pending_operation_keys()
            flow_operation_keys = {
                key for key in operation_keys if key[0] == pending.flow
            }
        self._pending.append(pending)

    def _evict_pending_fail_closed(self, pending: _PendingDeposit) -> None:
        """Finalize under resource pressure without trusting partial chains."""

        if pending.finalized:
            return
        pending.candidate_observations.clear()
        pending.companion_observation = None
        pending.awaiting_storage_boundaries = frozenset()
        self._finalize(pending)

    def _pending_operation_keys(
        self,
    ) -> set[tuple[FlowKey, Optional[int], Optional[int], Optional[int], float]]:
        return {self._pending_operation_key(entry) for entry in self._pending}

    @staticmethod
    def _pending_operation_key(
        pending: _PendingDeposit,
    ) -> tuple[FlowKey, Optional[int], Optional[int], Optional[int], float]:
        return (
            pending.flow,
            pending.stream_sequence,
            pending.event.opcode,
            pending.event.message_length,
            pending.timestamp,
        )

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
        following: list[tuple[int, bytes]] = []
        crossed_storage_messages: list[tuple[int, bytes]] = []
        awaiting_storage_boundaries: set[int] = set()
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
                    frozenset(awaiting_storage_boundaries),
                )
            length = int.from_bytes(header[0:2], "little")
            if not 5 <= length <= MAX_TARGET_MESSAGE_LENGTH:
                return _CompanionScan(
                    tuple(observations.values()),
                    True,
                    frozenset(immediate),
                    frozenset(awaiting_storage_boundaries),
                )
            message = self._read_span(pending.flow, position, length)
            if message is None:
                return _CompanionScan(
                    tuple(observations.values()),
                    False,
                    frozenset(immediate),
                    frozenset(awaiting_storage_boundaries),
                )
            opcode = int.from_bytes(message[3:5], "little")
            if opcode in self._storage_delta_opcodes:
                # A manual or independent storage action can be serialized
                # between a worker delta and its companion pair. Do not use a
                # storage wrapper as a companion, but do continue scanning:
                # the high-entropy token below owns the eventual pair. If the
                # intervening wrapper repeats that same token, ownership is
                # ambiguous and the older candidate fails closed.
                crossed_storage_messages.append((position, message))
                position += length
                continue
            for first_index, (first_sequence, first_message) in enumerate(following):
                observation = self._discovery.discover(
                    pending, delta_message, first_message, message,
                    pending.delta_prefix_end,
                )
                if observation is None:
                    continue
                missing_boundaries = {
                    sequence
                    for sequence, _message in crossed_storage_messages
                    if (pending.flow, sequence)
                    not in self._first_record_boundaries
                }
                if missing_boundaries:
                    # Target decoding will register these authoritative
                    # boundaries later in the same scanner pass. Defer this
                    # ownership decision instead of searching record bodies.
                    awaiting_storage_boundaries.update(missing_boundaries)
                    continue
                bounded_storage_messages = (
                    (
                        sequence,
                        storage_message,
                        self._first_record_boundaries[(pending.flow, sequence)],
                    )
                    for sequence, storage_message in crossed_storage_messages
                )
                if not self._observation_has_unique_pending_owner(
                    pending,
                    observation,
                    bounded_storage_messages,
                    first_message=first_message,
                    second_message=message,
                    pair_key=(pending.flow, first_sequence, position),
                ):
                    continue
                observations.setdefault(observation.family_key, observation)
                if (
                    not crossed_storage_messages
                    and first_index == 0
                    and message_index == 1
                ):
                    immediate.add(observation.family_key)
            following.append((position, message))
            position += length

        return _CompanionScan(
            tuple(observations.values()),
            True,
            frozenset(immediate),
            frozenset(awaiting_storage_boundaries),
        )

    def _observation_has_unique_pending_owner(
        self,
        pending: _PendingDeposit,
        observation: CompanionObservation,
        crossed_storage_messages: Iterable[tuple[int, bytes, int]],
        *,
        first_message: bytes,
        second_message: bytes,
        pair_key: tuple[FlowKey, int, int],
    ) -> bool:
        """Reject a shared token claimed by another overlapping storage op.

        Companion discovery already proves that the token occurs in this
        pending delta and both companion messages. Crossing a storage wrapper
        is safe only when that wrapper does not repeat the same token and no
        other active pending delta prefix claims it. This keeps overlapping
        operations separable without borrowing a later worker's companions.
        """

        if (
            pending.flow in self._companion_contest_overflow_flows
            or pair_key in self._contested_companion_pairs
        ):
            return False

        delta_message = pending.delta_message
        if delta_message is None:
            if (
                pending.stream_sequence is None
                or pending.event.message_length is None
            ):
                return False
            delta_message = self._read_span(
                pending.flow,
                pending.stream_sequence,
                pending.event.message_length,
            )
        if delta_message is None:
            return False
        token_offset = observation.token_offsets[0]
        token = delta_message[token_offset : token_offset + TOKEN_WIDTH]
        if len(token) != TOKEN_WIDTH:
            return False

        competing = False
        for _sequence, message, boundary in crossed_storage_messages:
            if self._message_claims_companion_pair(
                message,
                boundary,
                pending,
                first_message,
                second_message,
            ):
                competing = True
                break

        for other in self._pending:
            if other is pending or other.finalized or other.flow != pending.flow:
                continue
            if (
                pending.stream_sequence is not None
                and other.stream_sequence == pending.stream_sequence
                and other.event.opcode == pending.event.opcode
                and other.event.message_length == pending.event.message_length
                and other.timestamp == pending.timestamp
            ):
                # Multiple decoded records from one raw storage wrapper share
                # one transaction token and are one claimant, not competing
                # operations. Neutral batches are grouped earlier; retain the
                # same rule for already-live multi-record wrappers.
                continue
            other_message = other.delta_message
            if other_message is None:
                if (
                    other.stream_sequence is None
                    or other.event.message_length is None
                ):
                    continue
                other_message = self._read_span(
                    other.flow,
                    other.stream_sequence,
                    other.event.message_length,
                )
            if other_message is None or other.delta_prefix_end is None:
                continue
            prefix_end = min(other.delta_prefix_end, len(other_message))
            if self._message_claims_companion_pair(
                other_message,
                prefix_end,
                other,
                first_message,
                second_message,
            ):
                competing = True
                break
        if competing:
            self._mark_companion_pair_contested(pair_key)
            return False
        return True

    def _message_claims_companion_pair(
        self,
        message: bytes,
        prefix_end: int,
        pending: _PendingDeposit,
        first_message: bytes,
        second_message: bytes,
    ) -> bool:
        if prefix_end < 5 + TOKEN_WIDTH:
            return False
        return (
            self._discovery.discover(
                pending, message, first_message, second_message,
                min(prefix_end, len(message)),
            )
            is not None
        )

    def _mark_companion_pair_contested(
        self,
        pair_key: tuple[FlowKey, int, int],
    ) -> None:
        flow = pair_key[0]
        if (
            flow in self._companion_contest_overflow_flows
            or pair_key in self._contested_companion_pairs
        ):
            return
        if self.COMPANION_PAIR_HISTORY_LIMIT <= 0:
            self._suppress_companion_candidates_for_flow(flow)
            return
        if (
            len(self._contested_companion_pair_order)
            >= self.COMPANION_PAIR_HISTORY_LIMIT
        ):
            expired = self._contested_companion_pair_order.popleft()
            self._contested_companion_pairs.discard(expired)
            # Never let bounded-history pressure turn a previously contested
            # pair back into acceptable evidence. Conservatively suppress
            # worker-chain attribution on that flow until it closes; manual
            # decrement evidence and neutral delivery remain available.
            self._suppress_companion_candidates_for_flow(expired[0])
        if flow in self._companion_contest_overflow_flows:
            return
        self._contested_companion_pairs.add(pair_key)
        self._contested_companion_pair_order.append(pair_key)

    def _suppress_companion_candidates_for_flow(self, flow: FlowKey) -> None:
        self._companion_contest_overflow_flows.add(flow)
        for pending in self._pending:
            if pending.flow != flow or pending.finalized:
                continue
            pending.candidate_observations.clear()
            pending.companion_observation = None

    def _resolve_companions(self, pending: _PendingDeposit) -> bool:
        if pending.finalized:
            return True
        if self._select_confirmed_observation(pending):
            self._finalize(pending)
            return True
        result = self._scan_companions_after(pending)
        if result is None:
            return False
        pending.awaiting_storage_boundaries = (
            result.awaiting_storage_boundaries
        )
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

        if pending.awaiting_storage_boundaries:
            return False
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
        if pending.flow in self._companion_contest_overflow_flows:
            pending.candidate_observations.clear()
            pending.companion_observation = None
            return False
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

    def reset_flow(
        self,
        flow: FlowKey,
        flow_generation: int,
        resume_sequence: int,
    ) -> None:
        """Drop unowned manual evidence across one TCP gap reset."""

        with self._state_lock:
            self._manual.reset(flow, flow_generation, resume_sequence)

    def _purge_flow_history_locked(self, flow: FlowKey) -> None:
        # Discovery is content-keyed across flows. Dropping this optional cache
        # releases closed-flow bytes without changing any retained evidence.
        self._discovery.clear()
        self._recent.pop(flow, None)
        self._stream_spans.pop(flow, None)
        self._manual._purge_manual_flow_locked(flow)

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

        self._contested_companion_pair_order = deque(
            key for key in self._contested_companion_pair_order if key[0] != flow
        )
        self._contested_companion_pairs = {
            key for key in self._contested_companion_pairs if key[0] != flow
        }
        self._companion_contest_overflow_flows.discard(flow)

        self._first_record_boundary_order = deque(
            key for key in self._first_record_boundary_order if key[0] != flow
        )
        self._first_record_boundaries = {
            key: value
            for key, value in self._first_record_boundaries.items()
            if key[0] != flow
        }


    def _flush_stale_locked(self, now: float) -> None:
        self._manual._prune_manual_candidates_locked(now)
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
        self._discovery.clear()
        self._recent.clear()
        self._stream_spans.clear()
        self._manual.clear()
        self._family_chains.clear()
        self._family_chain_order.clear()
        self._observed_chains.clear()
        self._observed_chain_order.clear()
        self._contested_companion_pairs.clear()
        self._contested_companion_pair_order.clear()
        self._companion_contest_overflow_flows.clear()
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
            event_evidence = dict(evidence)
            if pending.manual_decrement_matches:
                rank = {"observed": 0, "structural": 1, "heuristic": 2}
                matching_this_record = tuple(
                    candidate
                    for candidate in pending.manual_decrement_matches
                    if candidate[0] == original.record_index
                )
                selection_pool = (
                    matching_this_record
                    if matching_this_record
                    else pending.manual_decrement_matches
                )
                record_index, selected_manual = min(
                    selection_pool,
                    key=lambda item: rank[item[1].confidence],
                )
                selected_payload = selected_manual.to_dict()
                selected_payload["record_index"] = record_index
                event_evidence["manual_decrement"] = selected_payload
            extra = {
                **original.extra,
                "deposit_origin_evidence": event_evidence,
            }
            if was_neutral:
                # A calibrated source decrement or confirmed worker chain
                # proves that this unfamiliar wire mode is nevertheless a
                # live mutation. Preserve that inference in additive audit
                # metadata and promote before EventFilter is applied.
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
                source=(
                    SOURCE_WORKER_PRODUCTION
                    if origin == ORIGIN_WORKER
                    else SOURCE_PLAYER_INVENTORY
                    if origin == ORIGIN_MANUAL
                    else None
                ),
                extra=extra,
            )
            self._queue_emit(event)

    def _queue_emit(self, event: BDOEvent) -> None:
        """Queue an application event while tracker state is locked."""
        self._outbox.append(("emit", event))

    def _drain_outbox(self) -> None:
        """Dispatch callbacks in mutation order without holding tracker locks.

        A concurrent or re-entrant caller only appends to the protected outbox;
        the active dispatcher observes that append before relinquishing
        ownership.  Claiming and relinquishing ownership while ``_state_lock``
        is held avoids the empty-outbox handoff race.
        """

        with self._state_lock:
            if self._dispatching:
                return
            self._dispatching = True

        try:
            while True:
                with self._state_lock:
                    if not self._outbox:
                        self._dispatching = False
                        return
                    kind, payload = self._outbox.popleft()

                # Do not move either callback under ``_state_lock`` or add a
                # dispatch lock around it.  Live delivery takes a session lock
                # that can be held by a concurrent ``flush_stale`` caller.
                if kind == "emit":
                    assert isinstance(payload, BDOEvent)
                    self._emit_callback(payload)
                else:
                    assert kind == "observer"
                    assert isinstance(payload, CompanionObservation)
                    observer = self._origin_observer
                    if observer is not None:
                        observer(payload)
        except BaseException:
            # Preserve callback exception propagation while allowing cleanup
            # or a later tracker operation to resume any queued deliveries.
            with self._state_lock:
                self._dispatching = False
            raise
