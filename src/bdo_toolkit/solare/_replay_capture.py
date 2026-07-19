"""TCP reassembly and health accounting shared by Solare replay/live APIs."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Optional

from bdo_toolkit._capture_backend import validate_server_ports
from bdo_toolkit._protocol import BDOFrame
from bdo_toolkit._reassembly import FlowManager

from ._constants import (
    DISCOVERY_MAX_FRAME_LENGTH,
    DISCOVERY_MIN_FRAME_LENGTH,
    SOLARE_MAX_ACTIVE_FLOWS,
)
from ._scanner import SolareDiscoveryStreamScanner
from .models import SolareCaptureHealth


class SolareFrameCollector:
    """Collect generic server frames without selecting a Solare opcode.

    This object implements the segment-consumer protocol used by pcap replay
    and live packet capture.  It deliberately counts only inbound payload on
    the selected game-server ports, matching the bytes that can contribute to
    discovery.
    """

    def __init__(
        self,
        ports: Iterable[int],
        on_frame: Optional[Callable[[BDOFrame], None]] = None,
        on_traffic: Optional[Callable[[], None]] = None,
        *,
        retain_frames: bool = True,
    ) -> None:
        self.ports = validate_server_ports(ports)
        self.frames: list[BDOFrame] = []
        self.payload_segments = 0
        self.payload_bytes = 0
        self.tcp_gap_resets = 0
        self.flow_state_evictions = 0
        self.synchronized_messages = 0
        self._retention_enabled = True
        self._retain_frames = retain_frames
        self._on_frame = on_frame
        self._on_traffic = on_traffic
        self._manager = FlowManager(
            server_ports=self.ports,
            scanner_factory=lambda: SolareDiscoveryStreamScanner(
                self._accept_frame,
                self._count_gap_reset,
            ),
            max_flows=SOLARE_MAX_ACTIVE_FLOWS,
            on_flow_eviction=self._count_flow_eviction,
            track_flow_generations=True,
        )

    def _accept_frame(self, frame: BDOFrame) -> None:
        self.synchronized_messages += 1
        if not self._retention_enabled:
            return
        if self._on_frame is not None:
            self._on_frame(frame)
        if (
            self._retain_frames
            and frame.flag == 0
            and DISCOVERY_MIN_FRAME_LENGTH
            <= frame.length
            <= DISCOVERY_MAX_FRAME_LENGTH
        ):
            self.frames.append(frame)

    def stop_retaining(self) -> None:
        """Freeze discovery input after the first snapshot is latched.

        Packet capture and health accounting may continue (for example with
        ``stop_on_complete=False``), but later frames cannot change the atomic
        result and therefore must not grow memory without bound.
        """

        self._retention_enabled = False

    def _count_gap_reset(self) -> None:
        self.tcp_gap_resets += 1

    def _count_flow_eviction(self) -> None:
        self.flow_state_evictions += 1

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
        if source_port in self.ports and payload:
            self.payload_segments += 1
            self.payload_bytes += len(payload)
            if self._on_traffic is not None:
                self._on_traffic()
        self._manager.process_tcp_segment(
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

    def finish(self) -> None:
        self._manager.finish()

    def health(
        self,
        *,
        saved_packets: int = 0,
        pcap_received: Optional[int] = None,
        pcap_dropped: Optional[int] = None,
        pcap_interface_dropped: Optional[int] = None,
        capture_buffer_bytes: Optional[int] = None,
        retained_large_messages: Optional[int] = None,
        candidate_messages_observed: int = 0,
        candidate_frames_retained: int = 0,
        candidate_bytes_retained: int = 0,
        peak_candidate_frames: int = 0,
        peak_candidate_bytes: int = 0,
        candidate_frames_evicted: int = 0,
        candidate_bytes_evicted: int = 0,
        candidate_history_rolled_over: bool = False,
        packet_queue_peak: int = 0,
        packet_queue_overflows: int = 0,
        flow_state_evictions: int = 0,
    ) -> SolareCaptureHealth:
        return SolareCaptureHealth(
            payload_segments=self.payload_segments,
            payload_bytes=self.payload_bytes,
            synchronized_messages=self.synchronized_messages,
            retained_large_messages=(
                len(self.frames)
                if retained_large_messages is None
                else retained_large_messages
            ),
            tcp_gap_resets=self.tcp_gap_resets,
            pcap_received=pcap_received,
            pcap_dropped=pcap_dropped,
            pcap_interface_dropped=pcap_interface_dropped,
            capture_buffer_bytes=capture_buffer_bytes,
            saved_packets=saved_packets,
            candidate_messages_observed=candidate_messages_observed,
            candidate_frames_retained=candidate_frames_retained,
            candidate_bytes_retained=candidate_bytes_retained,
            peak_candidate_frames=peak_candidate_frames,
            peak_candidate_bytes=peak_candidate_bytes,
            candidate_frames_evicted=candidate_frames_evicted,
            candidate_bytes_evicted=candidate_bytes_evicted,
            candidate_history_rolled_over=candidate_history_rolled_over,
            packet_queue_peak=packet_queue_peak,
            packet_queue_overflows=packet_queue_overflows,
            flow_state_evictions=self.flow_state_evictions + flow_state_evictions,
        )
