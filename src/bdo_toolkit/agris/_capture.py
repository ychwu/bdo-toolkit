"""Shared Agris transport adapter and immutable capture diagnostics."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from .._capture_backend import validate_server_ports
from .._framing import FrameCollectorScanner
from .._protocol import FlowKey
from .._reassembly import FlowManager
from ._discovery import AgrisTracker


@dataclass(frozen=True)
class AgrisCaptureHealth:
    """Loss indicators; unavailable native counters remain None, not zero."""

    packets_processed: int = 0
    packets_accepted: int = 0
    packet_queue_overflows: int = 0
    event_queue_overflows: int = 0
    tcp_gap_resets: int = 0
    flow_state_evictions: int = 0
    pcap_received: int | None = None
    pcap_dropped: int | None = None
    pcap_interface_dropped: int | None = None
    capture_buffer_bytes: int | None = None
    cleanup_incomplete: bool = False

    @property
    def capture_is_clean(self) -> bool:
        """No known loss; unknown kernel counters are not proof of completeness."""
        return not (self.packet_queue_overflows or self.event_queue_overflows
                    or self.tcp_gap_resets or self.flow_state_evictions
                    or self.pcap_dropped or self.pcap_interface_dropped)

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "capture_is_clean": self.capture_is_clean}


class AgrisFlowManager(FlowManager):
    """Generic framing, with no opcode hints or item-profile dependency."""

    def __init__(self, tracker: AgrisTracker, ports: Iterable[int], *, live: bool = False):
        self.tracker = tracker
        self.finishing = False
        self.clock = 0.0
        self.evictions = 0
        super().__init__(server_ports=validate_server_ports(ports),
                         scanner_factory=lambda: FrameCollectorScanner(tracker.observe),
                         max_flows=64, max_pending_bytes=4 * 1024 * 1024,
                         track_flow_generations=True, defer_gap_timeouts=live,
                         on_flow_reset=tracker.gap_reset, on_flow_close=self._closed,
                         on_flow_eviction=self._evicted)

    def _closed(self, flow: FlowKey) -> None:
        if not self.finishing:
            self.tracker.close_flow(flow)

    def _evicted(self) -> None:
        self.evictions += 1
        self.tracker.invalidate("Agris flow-state limit reached; discovery is incomplete")

    def process_tcp_segment(self, *, source_ip: str, source_port: int,
                            destination_ip: str, destination_port: int, sequence: int,
                            payload: bytes, timestamp: float, syn: bool = False,
                            rst: bool = False, fin: bool = False) -> None:
        super().process_tcp_segment(source_ip=source_ip, source_port=source_port,
                                    destination_ip=destination_ip, destination_port=destination_port,
                                    sequence=sequence, payload=payload, timestamp=timestamp,
                                    syn=syn, rst=rst, fin=fin)
        if source_port in self.server_ports:
            self.clock = max(self.clock, timestamp)

    def refresh(self, now: float | None = None) -> None:
        self.clock = max(self.clock, now if now is not None else self.clock)
        self.tracker.refresh(self.clock)

    def finish(self) -> None:
        # EOF is not a network disconnect. Preserve the final observation, but
        # do not forgive actual gaps exposed by draining buffered segments.
        self.finishing = True
        try:
            super().finish()
            self.refresh()
        finally:
            self.finishing = False
