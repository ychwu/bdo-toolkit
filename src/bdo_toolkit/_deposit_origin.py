"""Fail-closed worker/manual classification for storage-delta events.

Manual deposits carry a calibrated source-stack decrement immediately before
the storage delta. Worker deposits carry two immediately chained frames that
repeat the same high-entropy token present in the delta. The shared-token
three-frame relationship survived a patch that changed every involved opcode,
length, and token offset, so worker classification does not trust raw opcodes.

Missing or conflicting evidence produces ``unknown``. Storage context bytes
describe the storage operation, not whether a player or worker caused it.
"""

from __future__ import annotations

import dataclasses
from collections import deque
from dataclasses import dataclass
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


@dataclass
class _PendingDeposit:
    event: BDOEvent
    flow: FlowKey
    stream_sequence: Optional[int]
    timestamp: float
    matching_decrement: bool
    frames_after: int = 0
    end_sequence: Optional[int] = None
    companion_observation: Optional[CompanionObservation] = None
    delta_message: Optional[bytes] = None


@dataclass(frozen=True)
class _StreamSpan:
    start: int
    data: bytes

    @property
    def end(self) -> int:
        return self.start + len(self.data)


class DepositOriginTracker:
    """Correlate storage deltas with structural worker/manual evidence."""

    LOOKAHEAD_FRAMES = 4
    STALE_SECONDS = 2.0
    BACKWARD_WINDOW = 16
    STREAM_SPAN_HISTORY_LIMIT = 64
    MANUAL_LOOKBACK_FRAMES = 2
    OBSERVATION_HISTORY_LIMIT = 4096

    def __init__(
        self,
        *,
        decrement_specs: Iterable[DecrementSpec],
        emit: Callable[[BDOEvent], None],
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
        known_companion_families: Iterable[OriginCompanionFamily] = (),
    ) -> None:
        self._decrement_specs: dict[int, list[DecrementSpec]] = {}
        for spec in decrement_specs:
            matches = self._decrement_specs.setdefault(spec.opcode, [])
            if spec not in matches:
                matches.append(spec)
        self._emit = emit
        self._origin_observer = origin_observer
        self._known_companion_families = {
            family.family_key for family in known_companion_families
        }
        self._recent: dict[FlowKey, deque[BDOFrame]] = {}
        self._stream_spans: dict[FlowKey, deque[_StreamSpan]] = {}
        self._pending: list[_PendingDeposit] = []
        self._observed_chains: set[tuple[FlowKey, Optional[int]]] = set()
        self._observed_chain_order: deque[tuple[FlowKey, Optional[int]]] = deque()

    # --- frame stream ---

    def observe_stream(self, data: bytes, context: PacketContext) -> None:
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
        window = self._recent.setdefault(
            frame.context.flow,
            deque(maxlen=self.BACKWARD_WINDOW),
        )
        window.append(frame)
        if not self._pending:
            return

        still: list[_PendingDeposit] = []
        for pending in self._pending:
            if pending.flow != frame.context.flow:
                if frame.context.timestamp - pending.timestamp > self.STALE_SECONDS:
                    self._finalize(pending)
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
                self._finalize(pending)
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
        """Defer one storage-delta event until its evidence resolves."""
        flow = FlowKey(
            source_ip=event.flow.source_ip,
            source_port=event.flow.source_port,
            destination_ip=event.flow.destination_ip,
            destination_port=event.flow.destination_port,
        )
        raw_sequence = event.extra.get("stream_sequence")
        stream_sequence = raw_sequence if isinstance(raw_sequence, int) else None
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
        pending = _PendingDeposit(
            event=event,
            flow=flow,
            stream_sequence=stream_sequence,
            timestamp=event.timestamp,
            matching_decrement=self._has_matching_decrement(
                flow,
                stream_sequence,
                event,
            ),
            end_sequence=end_sequence,
            delta_message=delta_message,
        )
        if self._resolve_companions(pending):
            return

        # The frame tap runs before event decoding. Credit already observed
        # frames when the full TCP segment contained the delta and lookahead.
        for frame in self._recent.get(flow, ()):
            if self._frame_is_after(frame, pending):
                pending.frames_after += 1
        if pending.frames_after >= self.LOOKAHEAD_FRAMES:
            self._finalize(pending)
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
    ) -> CompanionObservation | bool | None:
        """Return an observation, ``False`` (resolved miss), or ``None`` (wait)."""
        if (
            pending.end_sequence is None
            or pending.stream_sequence is None
            or pending.event.message_length is None
        ):
            return None
        delta_message = pending.delta_message or self._read_span(
            pending.flow, pending.stream_sequence, pending.event.message_length
        )
        if delta_message is None:
            return None

        position = pending.end_sequence
        following: list[bytes] = []
        for _ in range(2):
            header = self._read_span(pending.flow, position, 5)
            if header is None:
                return None
            length = int.from_bytes(header[0:2], "little")
            if not 5 <= length <= MAX_TARGET_MESSAGE_LENGTH:
                return False
            message = self._read_span(pending.flow, position, length)
            if message is None:
                return None
            following.append(message)
            position += length

        observation = discover_companion_observation(
            delta_message=delta_message,
            first_message=following[0],
            second_message=following[1],
            timestamp=pending.timestamp,
            flow=pending.flow,
            stream_sequence=pending.stream_sequence,
        )
        return observation if observation is not None else False

    def _resolve_companions(self, pending: _PendingDeposit) -> bool:
        result = self._scan_companions_after(pending)
        if result is None:
            return False
        if isinstance(result, CompanionObservation):
            pending.companion_observation = result
            self._notify_origin_observer(result)
        self._finalize(pending)
        return True

    def _notify_origin_observer(self, observation: CompanionObservation) -> None:
        # A multi-record storage frame registers several events but represents
        # one independent companion-family observation.
        key = (observation.flow, observation.stream_sequence)
        if key in self._observed_chains:
            return
        if len(self._observed_chain_order) >= self.OBSERVATION_HISTORY_LIMIT:
            expired = self._observed_chain_order.popleft()
            self._observed_chains.discard(expired)
        self._observed_chains.add(key)
        self._observed_chain_order.append(key)
        if self._origin_observer is not None:
            self._origin_observer(observation)

    # --- calibrated manual-decrement signal ---

    def _has_matching_decrement(
        self,
        flow: FlowKey,
        stream_sequence: Optional[int],
        event: BDOEvent,
    ) -> bool:
        quantity_bytes = event.quantity.to_bytes(4, "little")
        eligible = [
            frame
            for frame in self._recent.get(flow, ())
            if not (
                stream_sequence is not None
                and frame.stream_sequence is not None
                and frame.stream_sequence >= stream_sequence
            )
        ][-self.MANUAL_LOOKBACK_FRAMES :]
        for frame in eligible:
            for spec in self._decrement_specs.get(frame.opcode, ()):
                # Profile lengths are calibrated single-record minima. Batch
                # decrements append more records to the same frame.
                if len(frame.message) < spec.min_message_length:
                    continue
                end = spec.quantity_offset + 4
                if end <= len(frame.message) and (
                    frame.message[spec.quantity_offset:end] == quantity_bytes
                ):
                    return True
        return False

    # --- flushing ---

    def flush_stale(self, now: float) -> None:
        still: list[_PendingDeposit] = []
        for pending in self._pending:
            if now - pending.timestamp > self.STALE_SECONDS:
                self._finalize(pending)
            else:
                still.append(pending)
        self._pending = still

    def finalize_all(self) -> None:
        pending, self._pending = self._pending, []
        for deposit in pending:
            self._finalize(deposit)

    def _finalize(self, pending: _PendingDeposit) -> None:
        companions = pending.companion_observation is not None
        # The shared-token chain is stronger than a quantity-only decrement,
        # which can collide for common quantities in ambient traffic.
        if companions:
            origin = ORIGIN_WORKER
        elif pending.matching_decrement:
            origin = ORIGIN_MANUAL
        else:
            origin = ORIGIN_UNKNOWN

        evidence: dict[str, object] = {
            "worker_companions": companions,
            "matching_decrement": pending.matching_decrement,
        }
        if pending.companion_observation is not None:
            companion_evidence = pending.companion_observation.to_dict()
            companion_evidence["known_family"] = (
                pending.companion_observation.family_key
                in self._known_companion_families
            )
            evidence["companion_chain"] = companion_evidence

        event = dataclasses.replace(
            pending.event,
            deposit_origin=origin,
            extra={
                **pending.event.extra,
                "deposit_origin_evidence": evidence,
            },
        )
        self._emit(event)
