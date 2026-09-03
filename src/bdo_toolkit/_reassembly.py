"""Per-flow TCP stream reassembly feeding a stream scanner."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock, RLock
from typing import Callable, Optional, Protocol

from ._protocol import (
    GAP_RESET_SECONDS,
    MAX_PENDING_SEGMENTS,
    MAX_TARGET_MESSAGE_LENGTH,
    TCP_SEQUENCE_HALF_RANGE,
    TCP_SEQUENCE_MODULUS,
    FlowKey,
    PacketContext,
)


# When capture begins after the SYN, the first callback can be a later TCP
# segment that raced ahead of its prefix. Hold a bounded initial reorder set
# until framing proves an origin or an owning root services the grace period;
# capacity pressure and finish() provide the remaining bounded release paths.
_INITIAL_REORDER_GRACE_SECONDS = 0.25
_INITIAL_ANCHOR_PROBE_BYTES = (MAX_TARGET_MESSAGE_LENGTH * 2) + 5


class StreamScanner(Protocol):
    """Anything that can consume reassembled stream bytes."""

    def feed(self, data: bytes, context: PacketContext) -> None: ...

    def scan_standalone(self, data: bytes, context: PacketContext) -> None: ...

    def reset(self) -> None: ...


@dataclass
class PendingSegment:
    data: bytes
    context: PacketContext


@dataclass
class TCPFlowState:
    scanner: StreamScanner
    max_pending_segments: int = MAX_PENDING_SEGMENTS
    max_pending_bytes: Optional[int] = None
    defer_gap_timeouts: bool = False
    next_sequence: Optional[int] = None
    pending: dict[int, PendingSegment] = field(default_factory=dict)
    unanchored: dict[int, PendingSegment] = field(default_factory=dict)
    unanchored_started_at: Optional[float] = None
    gap_started_at: Optional[float] = None
    generation: int = 0
    on_gap_reset: Optional[Callable[[int], None]] = None
    last_activity_at: Optional[float] = None
    fin_sequence: Optional[int] = None
    fin_observed_at: Optional[float] = None

    def reset(self) -> None:
        self.next_sequence = None
        self.pending.clear()
        self._clear_unanchored()
        self.gap_started_at = None
        self.fin_sequence = None
        self.fin_observed_at = None
        self.scanner.reset()

    def anchor_sequence(self, sequence: int) -> None:
        """Record a credible next-payload sequence without delivering bytes.

        An empty SYN is enough to establish this anchor because SYN consumes
        one TCP sequence number. Keeping the anchor lets a later payload that
        arrives out of order wait for its missing prefix instead of becoming
        the stream's accidental starting point.
        """
        if self.next_sequence is None:
            if self.unanchored:
                self._commit_unanchored(sequence & 0xFFFFFFFF)
            else:
                self.next_sequence = sequence & 0xFFFFFFFF

    def add_segment(
        self, sequence: int, payload: bytes, context: PacketContext
    ) -> None:
        if not payload:
            return

        if self.next_sequence is None:
            self._add_unanchored_segment(sequence, payload, context)
            return

        self._add_anchored_segment(sequence, payload, context)

    def mark_fin(self, sequence: int, timestamp: float) -> None:
        """Remember the first sequence after all payload preceding FIN."""

        self.fin_sequence = sequence & 0xFFFFFFFF
        self.fin_observed_at = timestamp
        self._start_fin_gap_timer_if_needed()

    def _start_fin_gap_timer_if_needed(self) -> None:
        if (
            self.fin_sequence is None
            or self.fin_observed_at is None
            or self.next_sequence is None
            or self.unanchored
            or self.pending
        ):
            return
        fin_sequence = _unwrap_tcp_sequence(
            self.fin_sequence,
            self.next_sequence,
        )
        if self.next_sequence < fin_sequence and self.gap_started_at is None:
            self.gap_started_at = self.fin_observed_at

    def fin_is_reassembled(self) -> bool:
        """Return whether every observed range through FIN is now contiguous."""

        if (
            self.fin_sequence is None
            or self.next_sequence is None
            or self.unanchored
            or self.pending
        ):
            return False
        return self.next_sequence >= _unwrap_tcp_sequence(
            self.fin_sequence,
            self.next_sequence,
        )

    def _add_unanchored_segment(
        self, sequence: int, payload: bytes, context: PacketContext
    ) -> None:
        """Establish a credible stream origin when no SYN was captured."""
        sequence &= 0xFFFFFFFF
        previous = self.unanchored.get(sequence)
        if previous is None or len(payload) > len(previous.data):
            self.unanchored[sequence] = PendingSegment(payload, context)
        if self.unanchored_started_at is None:
            self.unanchored_started_at = context.timestamp

        ordered = self._ordered_unanchored()
        start_sequence, probe = self._contiguous_unanchored_probe(ordered)
        can_anchor = getattr(self.scanner, "can_anchor_at_start", None)
        if can_anchor is not None and can_anchor(probe):
            self._commit_unanchored(start_sequence)
        elif self._pending_capacity_exceeded(self.unanchored):
            # Preserve the same hard bounds as ordinary gap buffering.
            # Under pressure, the earliest observed byte is the least-bad
            # origin and the scanner's normal resynchronization remains active.
            self._commit_unanchored(start_sequence)

    def _pending_capacity_exceeded(
        self,
        segments: dict[int, PendingSegment],
    ) -> bool:
        if len(segments) > self.max_pending_segments:
            return True
        return (
            self.max_pending_bytes is not None
            and sum(len(segment.data) for segment in segments.values())
            > self.max_pending_bytes
        )

    def _ordered_unanchored(self) -> list[tuple[int, PendingSegment]]:
        if not self.unanchored:
            return []
        reference = next(iter(self.unanchored))
        ordered = sorted(
            (
                _unwrap_tcp_sequence(sequence, reference),
                segment,
            )
            for sequence, segment in self.unanchored.items()
        )
        if ordered[0][0] < 0:
            ordered = [
                (sequence + TCP_SEQUENCE_MODULUS, segment)
                for sequence, segment in ordered
            ]
        return ordered

    @staticmethod
    def _contiguous_unanchored_probe(
        ordered: list[tuple[int, PendingSegment]],
    ) -> tuple[int, bytes]:
        assert ordered
        start_sequence = ordered[0][0]
        cursor = start_sequence
        probe = bytearray()
        for sequence, segment in ordered:
            if sequence > cursor:
                break
            overlap = max(0, cursor - sequence)
            if overlap >= len(segment.data):
                continue
            remaining = segment.data[overlap:]
            capacity = _INITIAL_ANCHOR_PROBE_BYTES - len(probe)
            if capacity <= 0:
                break
            probe.extend(remaining[:capacity])
            cursor = max(cursor, sequence + len(segment.data))
            if len(remaining) > capacity:
                break
        return start_sequence, bytes(probe)

    def _commit_unanchored(self, sequence: Optional[int] = None) -> None:
        # Origin commitment is intentionally one-way. Bytes already delivered
        # to a scanner cannot later be retracted and joined to an older prefix.
        if not self.unanchored:
            return
        ordered = self._ordered_unanchored()
        if sequence is None:
            sequence = ordered[0][0]
        self._clear_unanchored()
        self.next_sequence = sequence
        for segment_sequence, segment in ordered:
            self._add_anchored_segment(
                segment_sequence,
                segment.data,
                segment.context,
                scan_retransmission=False,
            )

    def _clear_unanchored(self) -> None:
        self.unanchored.clear()
        self.unanchored_started_at = None

    def _add_anchored_segment(
        self,
        sequence: int,
        payload: bytes,
        context: PacketContext,
        *,
        scan_retransmission: bool = True,
    ) -> None:
        assert self.next_sequence is not None
        sequence = _unwrap_tcp_sequence(sequence, self.next_sequence)

        # Ignore bytes already delivered by an earlier copy/retransmission.
        if sequence < self.next_sequence:
            overlap = self.next_sequence - sequence
            overlap_context = PacketContext(
                timestamp=context.timestamp,
                flow=context.flow,
                stream_start=sequence,
                flow_generation=context.flow_generation,
            )
            if overlap >= len(payload):
                # Local Windows captures can occasionally present a complete
                # earlier segment after a later sequence number. It cannot
                # advance the reassembled stream, but it may still contain a
                # self-contained target frame worth scanning.
                if scan_retransmission:
                    self.scanner.scan_standalone(payload, overlap_context)
                return
            if scan_retransmission:
                self.scanner.scan_standalone(payload[:overlap], overlap_context)
            payload = payload[overlap:]
            sequence = self.next_sequence

        if sequence > self.next_sequence:
            previous = self.pending.get(sequence)
            if previous is None or len(payload) > len(previous.data):
                self.pending[sequence] = PendingSegment(payload, context)
            if self.gap_started_at is None:
                self.gap_started_at = context.timestamp

            # A local capture should rarely lose TCP segments. If it does, do
            # not remain blocked forever: after a short gap, restart at the
            # earliest available segment and let the target scanner resync.
            if self._pending_capacity_exceeded(self.pending):
                # One restart may expose another later gap whose retained
                # segment is itself larger than the configured byte ceiling.
                # Keep making bounded progress until the retained map is back
                # within both limits. Every restart remains observable as
                # capture loss through the ordinary gap-reset accounting.
                while self._pending_capacity_exceeded(self.pending):
                    self._resume_after_gap()
            elif not self.defer_gap_timeouts:
                self.service_gaps(context.timestamp)
            return

        self._deliver(payload, context)
        self._flush_pending()

    def _deliver(self, payload: bytes, context: PacketContext) -> None:
        assert self.next_sequence is not None
        delivery_context = PacketContext(
            timestamp=context.timestamp,
            flow=context.flow,
            stream_start=self.next_sequence,
            flow_generation=context.flow_generation,
        )
        self.scanner.feed(payload, delivery_context)
        self.next_sequence += len(payload)
        self.gap_started_at = None

    def _flush_pending(self) -> None:
        assert self.next_sequence is not None

        while self.pending:
            sequence = min(self.pending)
            segment = self.pending[sequence]

            if sequence > self.next_sequence:
                if self.gap_started_at is None:
                    self.gap_started_at = min(
                        pending.context.timestamp
                        for pending in self.pending.values()
                    )
                return

            del self.pending[sequence]
            payload = segment.data

            if sequence < self.next_sequence:
                overlap = self.next_sequence - sequence
                if overlap >= len(payload):
                    continue
                payload = payload[overlap:]

            self._deliver(payload, segment.context)

    def service_gaps(self, now: float) -> int:
        """Release gaps whose timeout elapsed, even without a new packet.

        Returns the number of scanner resets performed. More than one reset
        is possible when several independently missing ranges are already old
        enough at the supplied clock value.
        """
        resets = 0
        if (
            self.unanchored
            and self.unanchored_started_at is not None
            and now - self.unanchored_started_at
            >= _INITIAL_REORDER_GRACE_SECONDS
        ):
            self._commit_unanchored()
        while (
            self.pending
            and self.gap_started_at is not None
            and now - self.gap_started_at >= GAP_RESET_SECONDS
        ):
            self._resume_after_gap()
            resets += 1
        self._start_fin_gap_timer_if_needed()
        if (
            not self.pending
            and not self.unanchored
            and self.fin_sequence is not None
            and self.next_sequence is not None
            and self.gap_started_at is not None
            and now - self.gap_started_at >= GAP_RESET_SECONDS
        ):
            fin_sequence = _unwrap_tcp_sequence(
                self.fin_sequence,
                self.next_sequence,
            )
            if self.next_sequence < fin_sequence:
                self.scanner.reset()
                if self.on_gap_reset is not None:
                    self.on_gap_reset(fin_sequence)
                self.next_sequence = fin_sequence
                self.gap_started_at = None
                resets += 1
        return resets

    def _resume_after_gap(self) -> None:
        if not self.pending:
            return

        sequence = min(self.pending)
        segment = self.pending.pop(sequence)
        self.scanner.reset()
        if self.on_gap_reset is not None:
            self.on_gap_reset(sequence)
        self.next_sequence = sequence
        self.gap_started_at = None
        self._deliver(segment.data, segment.context)
        self._flush_pending()

    def finish(self) -> None:
        """Drain segments still pending at end of capture.

        Without this, a capture that ends during a sequence gap would strand
        complete, decodable frames in ``pending`` forever; the gap timer only
        fires when another packet arrives on the flow.
        """
        self._commit_unanchored()
        while self.pending:
            self._resume_after_gap()


class FlowManager:
    """Route server-to-client TCP segments to per-flow reassembly state."""

    def __init__(
        self,
        *,
        server_ports,
        scanner_factory: Callable[[], StreamScanner],
        max_flows: Optional[int] = None,
        on_flow_eviction: Optional[Callable[[], None]] = None,
        on_flow_close: Optional[Callable[[FlowKey], None]] = None,
        on_flow_reset: Optional[Callable[[FlowKey, int, int], None]] = None,
        idle_timeout: Optional[float] = None,
        track_flow_generations: bool = False,
        max_pending_segments: int = MAX_PENDING_SEGMENTS,
        max_pending_bytes: Optional[int] = None,
        defer_gap_timeouts: bool = False,
    ) -> None:
        if max_flows is not None and max_flows <= 0:
            raise ValueError("max_flows must be positive or None")
        if idle_timeout is not None and idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive or None")
        if (
            isinstance(max_pending_segments, bool)
            or not isinstance(max_pending_segments, int)
        ):
            raise TypeError("max_pending_segments must be an integer")
        if max_pending_segments <= 0:
            raise ValueError("max_pending_segments must be positive")
        if max_pending_bytes is not None and (
            isinstance(max_pending_bytes, bool)
            or not isinstance(max_pending_bytes, int)
        ):
            raise TypeError("max_pending_bytes must be an integer or None")
        if max_pending_bytes is not None and max_pending_bytes <= 0:
            raise ValueError("max_pending_bytes must be positive or None")
        if not isinstance(defer_gap_timeouts, bool):
            raise TypeError("defer_gap_timeouts must be a boolean")
        self.server_ports = frozenset(server_ports)
        self._scanner_factory = scanner_factory
        self._max_flows = max_flows
        self._on_flow_eviction = on_flow_eviction
        self._on_flow_close = on_flow_close
        self._on_flow_reset = on_flow_reset
        self._idle_timeout = idle_timeout
        self._track_flow_generations = track_flow_generations
        self._max_pending_segments = max_pending_segments
        self._max_pending_bytes = max_pending_bytes
        self._defer_gap_timeouts = defer_gap_timeouts
        self._next_flow_generation = 0
        self._flows: OrderedDict[FlowKey, TCPFlowState] = OrderedDict()
        self._tcp_gap_resets = 0
        # Counter-only: never acquire _lock or protect callbacks/delivery here.
        self._diagnostics_lock = Lock()
        # Packet delivery and an eventual wall-clock service hook may run on
        # different threads. Serialize both paths around the same flow state.
        self._lock = RLock()

    def _new_flow_state(self, flow: FlowKey) -> TCPFlowState:
        generation = 0
        if self._track_flow_generations:
            self._next_flow_generation += 1
            generation = self._next_flow_generation
        return TCPFlowState(
            scanner=self._scanner_factory(),
            max_pending_segments=self._max_pending_segments,
            max_pending_bytes=self._max_pending_bytes,
            defer_gap_timeouts=self._defer_gap_timeouts,
            generation=generation,
            on_gap_reset=lambda resume_sequence: self._record_gap_reset(
                flow,
                generation,
                resume_sequence,
            ),
        )

    def _record_gap_reset(
        self,
        flow: FlowKey,
        generation: int,
        resume_sequence: int,
    ) -> None:
        with self._diagnostics_lock:
            self._tcp_gap_resets += 1
        if self._on_flow_reset is not None:
            self._on_flow_reset(flow, generation, resume_sequence)

    @property
    def tcp_gap_resets(self) -> int:
        """Total capture-gap recoveries, including flows already closed."""
        with self._diagnostics_lock:
            return self._tcp_gap_resets

    def service_gaps(self, now: float) -> int:
        """Advance pending-gap timers using a caller-supplied clock.

        ``FlowManager`` does not own a timer thread. Callers that defer
        per-packet timeouts may invoke this at a lifecycle boundary they know
        is safe. The return value is the number of new resets performed during
        this call; ``tcp_gap_resets`` is cumulative.
        """
        with self._lock:
            before = self.tcp_gap_resets
            completed_fin_flows: list[FlowKey] = []
            for flow, state in self._flows.items():
                state.service_gaps(now)
                if state.fin_is_reassembled():
                    completed_fin_flows.append(flow)
            for flow in completed_fin_flows:
                state = self._flows.pop(flow)
                state.finish()
                self._notify_flow_close(flow)
            if self._idle_timeout is not None:
                expired = [
                    flow
                    for flow, state in self._flows.items()
                    if state.last_activity_at is not None
                    and now - state.last_activity_at >= self._idle_timeout
                ]
                for flow in expired:
                    state = self._flows.pop(flow)
                    state.finish()
                    self._notify_flow_close(flow)
            return self.tcp_gap_resets - before

    def _notify_flow_close(self, flow: FlowKey) -> None:
        if self._on_flow_close is not None:
            self._on_flow_close(flow)

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
        with self._lock:
            self._process_tcp_segment(
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

    def _process_tcp_segment(
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
        # The observed item events are server-to-client and use a game-server
        # source port. Ignore all other traffic.
        if source_port not in self.server_ports:
            return

        flow = FlowKey(
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
        )

        known_flow = flow in self._flows
        # A capture may contain an ACK or a late FIN/RST for a connection that
        # began before capture or whose state was already closed/evicted. Such
        # a packet cannot contribute stream bytes, so it must not consume a
        # bounded flow slot (or evict an active flow to make room).
        if not known_flow and not payload and not syn:
            return

        if not known_flow and (
            self._max_flows is not None
            and len(self._flows) >= self._max_flows
        ):
            # OrderedDict order is updated on every observed packet, so the
            # first entry is the least recently active connection.
            oldest, evicted = self._flows.popitem(last=False)
            if self._on_flow_eviction is not None:
                self._on_flow_eviction()
            evicted.finish()
            self._notify_flow_close(oldest)

        if syn and flow in self._flows:
            previous = self._flows.pop(flow)
            previous.finish()
            self._notify_flow_close(flow)

        if flow not in self._flows:
            self._flows[flow] = self._new_flow_state(flow)

        state = self._flows[flow]
        state.last_activity_at = timestamp
        self._flows.move_to_end(flow)
        if syn:
            # SYN itself consumes one sequence number, including when it has
            # no payload. This establishes the first credible stream anchor.
            state.anchor_sequence((sequence + 1) & 0xFFFFFFFF)
        if payload:
            # SYN consumes one sequence number before any TCP Fast Open data.
            payload_sequence = (sequence + (1 if syn else 0)) & 0xFFFFFFFF
            state.add_segment(
                sequence=payload_sequence,
                payload=payload,
                context=PacketContext(
                    timestamp=timestamp,
                    flow=flow,
                    flow_generation=state.generation,
                ),
            )

        if not rst and state.fin_sequence is not None and state.fin_is_reassembled():
            state.finish()
            self._flows.pop(flow, None)
            self._notify_flow_close(flow)
            return

        if rst:
            # RST is an abortive close; drain what is already available, then
            # discard the connection state immediately.
            state.finish()
            self._flows.pop(flow, None)
            self._notify_flow_close(flow)
        elif fin:
            # FIN can race ahead of earlier payload callbacks. Keep bounded
            # provisional/gap state until all observed bytes through FIN are
            # contiguous, rather than splitting one frame across two states.
            fin_sequence = (
                sequence + (1 if syn else 0) + len(payload)
            ) & 0xFFFFFFFF
            state.mark_fin(fin_sequence, timestamp)
            if state.fin_is_reassembled():
                state.finish()
                self._flows.pop(flow, None)
                self._notify_flow_close(flow)

    def finish(self) -> None:
        with self._lock:
            flows = tuple(self._flows.items())
            self._flows.clear()
            for flow, state in flows:
                state.finish()
                self._notify_flow_close(flow)


def _unwrap_tcp_sequence(sequence: int, reference: int) -> int:
    """Map a 32-bit TCP sequence to the nearest absolute value to reference."""
    raw = sequence & 0xFFFFFFFF
    candidate = (reference & ~(TCP_SEQUENCE_MODULUS - 1)) | raw
    if candidate - reference > TCP_SEQUENCE_HALF_RANGE:
        candidate -= TCP_SEQUENCE_MODULUS
    elif reference - candidate > TCP_SEQUENCE_HALF_RANGE:
        candidate += TCP_SEQUENCE_MODULUS
    return candidate
