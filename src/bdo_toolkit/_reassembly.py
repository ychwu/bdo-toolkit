"""Per-flow TCP stream reassembly feeding a stream scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from ._protocol import (
    GAP_RESET_SECONDS,
    MAX_PENDING_SEGMENTS,
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

    def reset(self) -> None:
        self.next_sequence = None
        self.pending.clear()
        self.gap_started_at = None
        self.scanner.reset()

    def add_segment(
        self, sequence: int, payload: bytes, context: PacketContext
    ) -> None:
        if not payload:
            return

        if self.next_sequence is None:
            self.next_sequence = sequence

        assert self.next_sequence is not None

        # Ignore bytes already delivered by an earlier copy/retransmission.
        if sequence < self.next_sequence:
            overlap = self.next_sequence - sequence
            overlap_context = PacketContext(
                timestamp=context.timestamp,
                flow=context.flow,
                stream_start=sequence,
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
            if (
                context.timestamp - self.gap_started_at >= GAP_RESET_SECONDS
                or len(self.pending) > MAX_PENDING_SEGMENTS
            ):
                self._resume_after_gap()
            return

        self._deliver(payload, context)
        self._flush_pending()

    def _deliver(self, payload: bytes, context: PacketContext) -> None:
        assert self.next_sequence is not None
        delivery_context = PacketContext(
            timestamp=context.timestamp,
            flow=context.flow,
            stream_start=self.next_sequence,
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
                return

            del self.pending[sequence]
            payload = segment.data

            if sequence < self.next_sequence:
                overlap = self.next_sequence - sequence
                if overlap >= len(payload):
                    continue
                payload = payload[overlap:]

            self._deliver(payload, segment.context)

    def _resume_after_gap(self) -> None:
        if not self.pending:
            return

        sequence = min(self.pending)
        segment = self.pending.pop(sequence)
        self.scanner.reset()
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
    ) -> None:
        self.server_ports = frozenset(server_ports)
        self._scanner_factory = scanner_factory
        self._flows: dict[FlowKey, TCPFlowState] = {}

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

        if syn or flow not in self._flows:
            self._flows[flow] = TCPFlowState(scanner=self._scanner_factory())

        state = self._flows[flow]
        if payload:
            state.add_segment(
                sequence=sequence,
                payload=payload,
                context=PacketContext(timestamp=timestamp, flow=flow),
            )

        if rst or fin:
            # Processed any final payload first; then discard closed-flow state.
            self._flows.pop(flow, None)

    def finish(self) -> None:
        for state in self._flows.values():
            state.finish()
