"""Per-flow TCP stream reassembly feeding a stream scanner."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable, Optional, Protocol

from ._protocol import (
    GAP_RESET_SECONDS,
    MAX_PENDING_SEGMENTS,
    TCP_SEQUENCE_HALF_RANGE,
    TCP_SEQUENCE_MODULUS,
    FlowKey,
    PacketContext,
)


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
    next_sequence: Optional[int] = None
    pending: dict[int, PendingSegment] = field(default_factory=dict)
    gap_started_at: Optional[float] = None
    generation: int = 0
    on_gap_reset: Optional[Callable[[], None]] = None
    last_activity_at: Optional[float] = None

    def reset(self) -> None:
        self.next_sequence = None
        self.pending.clear()
        self.gap_started_at = None
        self.scanner.reset()

    def anchor_sequence(self, sequence: int) -> None:
        """Record a credible next-payload sequence without delivering bytes.

        An empty SYN is enough to establish this anchor because SYN consumes
        one TCP sequence number. Keeping the anchor lets a later payload that
        arrives out of order wait for its missing prefix instead of becoming
        the stream's accidental starting point.
        """
        if self.next_sequence is None:
            self.next_sequence = sequence & 0xFFFFFFFF

    def add_segment(
        self, sequence: int, payload: bytes, context: PacketContext
    ) -> None:
        if not payload:
            return

        if self.next_sequence is None:
            self.next_sequence = sequence & 0xFFFFFFFF
        else:
            sequence = _unwrap_tcp_sequence(sequence, self.next_sequence)

        assert self.next_sequence is not None

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
                self.scanner.scan_standalone(payload, overlap_context)
                return
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
            if len(self.pending) > MAX_PENDING_SEGMENTS:
                self._resume_after_gap()
            else:
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
        while (
            self.pending
            and self.gap_started_at is not None
            and now - self.gap_started_at >= GAP_RESET_SECONDS
        ):
            self._resume_after_gap()
            resets += 1
        return resets

    def _resume_after_gap(self) -> None:
        if not self.pending:
            return

        sequence = min(self.pending)
        segment = self.pending.pop(sequence)
        self.scanner.reset()
        if self.on_gap_reset is not None:
            self.on_gap_reset()
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
        idle_timeout: Optional[float] = None,
        track_flow_generations: bool = False,
    ) -> None:
        if max_flows is not None and max_flows <= 0:
            raise ValueError("max_flows must be positive or None")
        if idle_timeout is not None and idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive or None")
        self.server_ports = frozenset(server_ports)
        self._scanner_factory = scanner_factory
        self._max_flows = max_flows
        self._on_flow_eviction = on_flow_eviction
        self._on_flow_close = on_flow_close
        self._idle_timeout = idle_timeout
        self._track_flow_generations = track_flow_generations
        self._next_flow_generation = 0
        self._flows: OrderedDict[FlowKey, TCPFlowState] = OrderedDict()
        self._tcp_gap_resets = 0
        # Packet delivery and an eventual wall-clock service hook may run on
        # different threads. Serialize both paths around the same flow state.
        self._lock = RLock()

    def _new_flow_state(self) -> TCPFlowState:
        generation = 0
        if self._track_flow_generations:
            self._next_flow_generation += 1
            generation = self._next_flow_generation
        return TCPFlowState(
            scanner=self._scanner_factory(),
            generation=generation,
            on_gap_reset=self._record_gap_reset,
        )

    def _record_gap_reset(self) -> None:
        self._tcp_gap_resets += 1

    @property
    def tcp_gap_resets(self) -> int:
        """Total capture-gap recoveries, including flows already closed."""
        with self._lock:
            return self._tcp_gap_resets

    def service_gaps(self, now: float) -> int:
        """Advance pending-gap timers using a caller-supplied wall clock.

        Live capture roots should call this during their normal poll/tick even
        when no packets arrived. The return value is the number of new resets
        performed during this call; ``tcp_gap_resets`` is cumulative.
        """
        with self._lock:
            before = self._tcp_gap_resets
            for state in self._flows.values():
                state.service_gaps(now)
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
            return self._tcp_gap_resets - before

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
            self._flows[flow] = self._new_flow_state()

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

        if rst or fin:
            # Processed any final payload first. Drain complete frames stranded
            # behind a capture gap before discarding the closed-flow state.
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
